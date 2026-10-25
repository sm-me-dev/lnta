package agent

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sashabaranov/go-openai"
	"github.com/sm-me-dev/lnta/internal/fingerprint"
	"github.com/sm-me-dev/lnta/internal/packs"
	"github.com/sm-me-dev/lnta/internal/sandbox"
	"github.com/sm-me-dev/lnta/internal/transport"
)

//go:embed testdata/dummy.md
var embedFS embed.FS

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__restricted_exec" {
		os.Exit(sandbox.RestrictedExecMain())
	}
	os.Exit(m.Run())
}

// --- mock LLM + stream ------------------------------------------------------

// mockStream is a fake chatStream yielding a fixed slice of responses, then io.EOF.
type mockStream struct {
	responses  []openai.ChatCompletionStreamResponse
	idx        int
	closeCount int
}

func (m *mockStream) Recv() (openai.ChatCompletionStreamResponse, error) {
	if m.idx >= len(m.responses) {
		return openai.ChatCompletionStreamResponse{}, io.EOF
	}
	r := m.responses[m.idx]
	m.idx++
	return r, nil
}

func (m *mockStream) Close() error {
	m.closeCount++
	return nil
}

// mockLLM returns one canned stream per ChatCompletionStream call, in order.
// turnCount reports how many streams were requested.
type mockLLM struct {
	mu        sync.Mutex
	scenarios [][]openai.ChatCompletionStreamResponse
	turn      int
}

func (m *mockLLM) ChatCompletionStream(ctx context.Context, req openai.ChatCompletionRequest) (ChatStream, error) {
	m.mu.Lock()
	turn := m.turn
	m.turn++
	m.mu.Unlock()
	var responses []openai.ChatCompletionStreamResponse
	if turn < len(m.scenarios) {
		responses = m.scenarios[turn]
	}
	return &mockStream{responses: responses}, nil
}

func (m *mockLLM) turnCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.turn
}

// toolCallResponse builds a single stream response whose assistant delta issues
// one tool call with the given name and JSON arguments.
func toolCallResponse(name, args string) openai.ChatCompletionStreamResponse {
	idx := 0
	return openai.ChatCompletionStreamResponse{
		Choices: []openai.ChatCompletionStreamChoice{
			{
				Index:        0,
				FinishReason: openai.FinishReasonToolCalls,
				Delta: openai.ChatCompletionStreamChoiceDelta{
					ToolCalls: []openai.ToolCall{
						{
							Index: &idx,
							ID:    "call-1",
							Type:  openai.ToolTypeFunction,
							Function: openai.FunctionCall{
								Name:      name,
								Arguments: args,
							},
						},
					},
				},
			},
		},
	}
}

// buildArgs marshals args to JSON string.
func buildArgs(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// --- tests ------------------------------------------------------------------

// testDirUnderHome creates an isolated HOME outside /tmp so sandbox tests can
// see it after Bubblewrap mounts its private /tmp.
func testDirUnderHome(t *testing.T) string {
	t.Helper()
	home, err := os.MkdirTemp(".", ".lnta-agent-home-")
	if err != nil {
		t.Fatalf("create isolated HOME: %v", err)
	}
	absHome, err := filepath.Abs(home)
	if err != nil {
		_ = os.RemoveAll(home)
		t.Fatal(err)
	}
	t.Setenv("HOME", absHome)
	t.Cleanup(func() { _ = os.RemoveAll(absHome) })
	d := filepath.Join(absHome, ".lnta-agent-test")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatalf("mkdir %q: %v", d, err)
	}
	if err := os.Mkdir(filepath.Join(d, ".git"), 0o700); err != nil {
		t.Fatalf("create isolated project marker: %v", err)
	}
	return d
}

// TestCompleteTaskFailingVerifyCmd verifies that complete_task returns
// HARNESS_VERIFICATION_FAILED when the pack's verify_cmd fails (the harness
// verification gate blocks completion).
func TestCompleteTaskFailingVerifyCmd(t *testing.T) {
	// Skip if sandbox is not available (e.g., CI without user namespaces)
	if err := sandbox.SandboxAvailable(); err != nil {
		t.Skipf("skipping: sandbox unavailable (%v)", err)
	}

	dir := testDirUnderHome(t)
	existing := filepath.Join(dir, "exists.desktop")
	if err := os.WriteFile(existing, []byte("[Desktop Entry]\nName=Test\nExec=/usr/bin/true\nType=Application\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	missing := filepath.Join(dir, "missing.desktop")
	home, _ := os.UserHomeDir()

	pack := packs.Pack{
		ID:           "test-pack",
		Name:         "Test Pack",
		VerifyCmd:    `test -f "$LNTA_TARGET"`,
		AllowedPaths: []string{filepath.Join(dir, "*.desktop")},
	}

	// complete_task with a missing target -> verify_cmd fails -> blocked.
	res, err := completeTask(context.Background(), mustMarshal(map[string]any{
		"summary":            "attempt 1",
		"target_artifacts":   missing,
		"verification_notes": "should fail",
	}), ToolDeps{RunID: "run-1", Pack: &pack, Approve: DefaultApprove, CWD: home, Executor: transport.NewLocalExecutor("run-1", home, pack.AllowedPaths)})
	if err != nil {
		t.Fatalf("completeTask returned error: %v", err)
	}
	if !strings.Contains(res, "HARNESS_VERIFICATION_FAILED") {
		t.Fatalf("expected HARNESS_VERIFICATION_FAILED, got %q", res)
	}

	// complete_task with an existing target -> verify_cmd passes -> TASK_COMPLETE.
	res2, err := completeTask(context.Background(), mustMarshal(map[string]any{
		"summary":            "attempt 2",
		"target_artifacts":   existing,
		"verification_notes": "should pass",
	}), ToolDeps{RunID: "run-1", Pack: &pack, Approve: DefaultApprove, CWD: home, Executor: transport.NewLocalExecutor("run-1", home, pack.AllowedPaths)})
	if err != nil {
		t.Fatalf("completeTask returned error: %v", err)
	}
	if !strings.Contains(res2, "TASK_COMPLETE") {
		t.Fatalf("expected TASK_COMPLETE, got %q", res2)
	}
}

// TestMutateSystemBlockedWithoutApproval verifies mutate_system never executes
// when the approval callback returns false.
func TestMutateSystemBlockedWithoutApproval(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker.txt")

	pack := packs.Pack{ID: "test-pack", Name: "Test Pack"}

	// approve = false: command must not run.
	res, err := mutateSystem(context.Background(), mustMarshal(map[string]any{
		"command":    "echo data > " + marker,
		"cwd":        dir,
		"risk_level": "high",
		"reason":     "should be blocked",
	}), ToolDeps{RunID: "run-1", Pack: &pack, Approve: func(_, _, _, _ string) bool { return false }, CWD: dir})
	if err != nil {
		t.Fatalf("mutateSystem returned error: %v", err)
	}
	if !strings.Contains(res, "MUTATE_BLOCKED") {
		t.Fatalf("expected MUTATE_BLOCKED, got %q", res)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("mutate_system executed despite approval=false: marker exists (%v)", statErr)
	}

	// approve = true: command runs and marker is created.
	res2, err := mutateSystem(context.Background(), mustMarshal(map[string]any{
		"command":    "echo data > " + marker,
		"cwd":        dir,
		"risk_level": "low",
		"reason":     "approved",
	}), ToolDeps{RunID: "run-1", Pack: &pack, Approve: func(_, _, _, _ string) bool { return true }, CWD: dir})
	if err != nil {
		t.Fatalf("mutateSystem (approved) returned error: %v", err)
	}
	if strings.Contains(res2, "MUTATE_BLOCKED") {
		t.Fatalf("expected command to run when approved, got %q", res2)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("expected marker file to be created when approved: %v", err)
	}
}

func TestScopedWriteRequiresApprovalAndBindsApprovedPreview(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "file")
	pack := &packs.Pack{AllowedPaths: []string{filepath.Join(dir, "*")}}
	args := mustMarshal(map[string]any{"path": target, "content": "new", "reason": "test"})
	res, err := writeScopedFile(context.Background(), args, ToolDeps{Pack: pack, CWD: dir, Executor: transport.NewLocalExecutor("run-no-approval", dir, pack.AllowedPaths)})
	if err != nil || !strings.Contains(res, "MUTATE_BLOCKED") {
		t.Fatalf("nil approval callback result=%q error=%v", res, err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("file was written without approval: %v", err)
	}
	deps := ToolDeps{Pack: pack, CWD: dir, Executor: transport.NewLocalExecutor("run-approved", dir, pack.AllowedPaths), Approve: func(command, cwd, risk, detail string) bool {
		return command == "write_scoped_file "+target && cwd == dir && risk == "write" && strings.Contains(detail, "Proposed diff:")
	}}
	res, err = writeScopedFile(context.Background(), args, deps)
	if err != nil || !strings.Contains(res, "wrote") {
		t.Fatalf("approved write result=%q error=%v", res, err)
	}
}

func TestVerificationTargetResolutionAndEnvironmentData(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.desktop")
	if err := os.WriteFile(target, []byte("[Desktop Entry]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	allowed := []string{filepath.Join(dir, "*.desktop")}
	for _, input := range []string{target, "target.desktop"} {
		resolved, err := resolveVerificationTarget(input, dir, allowed)
		if err != nil || resolved != target {
			t.Errorf("resolveVerificationTarget(%q) = %q, %v", input, resolved, err)
		}
	}
	link := filepath.Join(dir, "link.desktop")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveVerificationTarget(link, dir, allowed); err == nil {
		t.Fatal("symlink verification target was accepted")
	}
	if _, err := resolveVerificationTarget(filepath.Join(dir, "..", "outside.desktop"), dir, allowed); err == nil {
		t.Fatal("path traversal target was accepted")
	}
	env, err := makeVerificationEnv(`test "${target}" = "$LNTA_TARGET" && test "${device}" = "$(touch /tmp/nope)"`, target, map[string]string{"device": "$(touch /tmp/nope)"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(env, "device=$(touch /tmp/nope)") {
		t.Fatalf("input was not passed as data: %q", env)
	}
	if _, err := makeVerificationEnv(`tool "${missing}"`, target, nil); err == nil {
		t.Fatal("missing verification placeholder was accepted")
	}
}

func TestStreamedToolCallValidationRejectsMalformedAndRepeatedMutations(t *testing.T) {
	tools := toolByName(CoreTools())
	valid := &streamingToolCall{index: 0, id: "call-1", typ: string(openai.ToolTypeFunction), name: "mutate_system", args: `{"command":"echo safe"}`}
	tests := []struct {
		name  string
		calls map[int]*streamingToolCall
		order []int
	}{
		{name: "missing id", calls: map[int]*streamingToolCall{0: {index: 0, typ: string(openai.ToolTypeFunction), name: "inspect_system", args: `{"command":"id"}`}}, order: []int{0}},
		{name: "invalid JSON", calls: map[int]*streamingToolCall{0: {index: 0, id: "call-1", typ: string(openai.ToolTypeFunction), name: "inspect_system", args: `{`}}, order: []int{0}},
		{name: "unknown tool", calls: map[int]*streamingToolCall{0: {index: 0, id: "call-1", typ: string(openai.ToolTypeFunction), name: "shell", args: `{}`}}, order: []int{0}},
		{name: "repeated mutation", calls: map[int]*streamingToolCall{0: valid, 1: {index: 1, id: "call-2", typ: string(openai.ToolTypeFunction), name: "mutate_system", args: `{"command":"echo safe"}`}}, order: []int{0, 1}},
		{name: "complete with other call", calls: map[int]*streamingToolCall{0: {index: 0, id: "call-1", typ: string(openai.ToolTypeFunction), name: "complete_task", args: `{"summary":"done","target_artifacts":"x"}`}, 1: {index: 1, id: "call-2", typ: string(openai.ToolTypeFunction), name: "inspect_system", args: `{"command":"id"}`}}, order: []int{0, 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateStreamedToolCalls(tc.order, tc.calls, tools); err == nil {
				t.Fatal("malformed streamed tool call set was accepted")
			}
		})
	}
}

func TestMutateInvocationKeyDeduplicatesAliasesAndWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	first, err := mutateInvocationKey([]byte(`{"command":"echo x","cwd":"`+dir+`"}`), dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := mutateInvocationKey([]byte(`{"cmd":"echo x","cwd":""}`), dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("equivalent mutation keys differ: %q vs %q", first, second)
	}
}

func TestNativeDesktopVerifierFailsWhenValidatorMissing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "entry.desktop")
	if err := os.WriteFile(target, []byte("[Desktop Entry]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := findDesktopValidator([]string{dir}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing validator lookup result = %v", err)
	}
}

func TestCompleteTaskDesktopVerificationPasses(t *testing.T) {
	if err := sandbox.SandboxAvailable(); err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	if _, err := exec.LookPath("desktop-file-validate"); err != nil {
		t.Skipf("desktop-file-validate unavailable: %v", err)
	}
	dir := testDirUnderHome(t)
	target := filepath.Join(dir, "entry.desktop")
	content := "[Desktop Entry]\nName=Test\nExec=/usr/bin/true\nType=Application\n"
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pack := &packs.Pack{ID: "linux-desktop-entries", VerifyCmd: `desktop-file-validate "${target}"`, AllowedPaths: []string{filepath.Join(dir, "*.desktop")}}
	result, err := completeTask(context.Background(), mustMarshal(map[string]any{"summary": "checked", "target_artifacts": target}), ToolDeps{Pack: pack, CWD: dir, Executor: transport.NewLocalExecutor("test", dir, pack.AllowedPaths)})
	if err != nil || !strings.Contains(result, "TASK_COMPLETE") {
		t.Fatalf("result=%q error=%v", result, err)
	}
}

func TestCompleteTaskMarksMissingVerifierUnavailable(t *testing.T) {
	if err := sandbox.SandboxAvailable(); err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	dir := testDirUnderHome(t)
	target := filepath.Join(dir, "artifact")
	if err := os.WriteFile(target, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	pack := &packs.Pack{ID: "missing-verifier", VerifyCmd: `lnta-test-verifier-that-does-not-exist "$LNTA_TARGET"`, AllowedPaths: []string{filepath.Join(dir, "*")}}
	result, err := completeTask(context.Background(), mustMarshal(map[string]any{"summary": "check", "target_artifacts": target}), ToolDeps{Pack: pack, CWD: dir, Executor: transport.NewLocalExecutor("test", dir, pack.AllowedPaths)})
	if err != nil || !strings.Contains(result, "HARNESS_VERIFICATION_UNAVAILABLE") {
		t.Fatalf("result=%q error=%v", result, err)
	}
}

// TestOrchestratorSelfCorrectsAfterFailedVerify verifies the full loop: when
// complete_task returns HARNESS_VERIFICATION_FAILED the loop continues and the
// agent can self-correct on the next turn (mock LLM retries with a valid target).
func TestOrchestratorSelfCorrectsAfterFailedVerify(t *testing.T) {
	// Skip if sandbox is not available (e.g., CI without user namespaces)
	if err := sandbox.SandboxAvailable(); err != nil {
		t.Skipf("skipping: sandbox unavailable (%v)", err)
	}

	dir := testDirUnderHome(t)
	existing := filepath.Join(dir, "launcher.desktop")
	if err := os.WriteFile(existing, []byte("[Desktop Entry]\nName=Launcher\nExec=/usr/bin/true\nType=Application\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	missing := filepath.Join(dir, "missing.desktop")
	home, _ := os.UserHomeDir()

	// Write a pack file into dir and load it via the public NewRouter (userDir).
	packFile := fmt.Sprintf(
		"---\nid: test-pack\nname: Test Pack\ntriggers:\n  - launcher\nverify_cmd: test -f \"$LNTA_TARGET\"\ncontext_cmd: true\nallowed_paths:\n  - \"%s/*.desktop\"\n---\n# body\n",
		dir,
	)
	if err := os.WriteFile(filepath.Join(dir, "test-pack.md"), []byte(packFile), 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	router, err := packs.NewRouter(embedFS, "*.md", dir)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	// Turn 1: complete_task with a missing target -> verify fails -> loop continues.
	// Turn 2: complete_task with the existing target -> verify passes -> TASK_COMPLETE.
	llm := &mockLLM{
		scenarios: [][]openai.ChatCompletionStreamResponse{
			{toolCallResponse("complete_task", `{"summary":"attempt 1","target_artifacts":"`+missing+`","verification_notes":"should fail"}`)},
			{toolCallResponse("complete_task", `{"summary":"attempt 2","target_artifacts":"`+existing+`","verification_notes":"should pass"}`)},
		},
	}

	o := New(llm, router,
		WithRunID("run-t1"),
		WithCWD(home),
		WithApprove(func(_, _, _, _ string) bool { return true }),
		WithMaxTurns(8),
		WithConfig(&Config{Model: "test-model"}),
		WithExecutor(transport.NewLocalExecutor("run-t1", home, nil)),
	)

	result, err := o.Run(context.Background(), "create a launcher", "", false)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !strings.Contains(result, "TASK_COMPLETE") {
		t.Fatalf("expected final TASK_COMPLETE after self-correction, got %q", result)
	}
	if strings.Contains(result, "HARNESS_VERIFICATION_FAILED") {
		t.Fatalf("expected verification to ultimately pass, but result still contains failure: %q", result)
	}
	if llm.turnCount() < 2 {
		t.Fatalf("expected the loop to continue to a second turn after failed verify, got %d turn(s)", llm.turnCount())
	}
}

// TestOrchestratorValidDesktop tests the full orchestrator loop with a valid desktop scenario.
func TestOrchestratorValidDesktop(t *testing.T) {
	// Skip if sandbox is not available (e.g., CI without user namespaces)
	if err := sandbox.SandboxAvailable(); err != nil {
		t.Skipf("skipping: sandbox unavailable (%v)", err)
	}
	if _, err := exec.LookPath("desktop-file-validate"); err != nil {
		t.Skipf("skipping: required desktop validator unavailable (%v)", err)
	}

	tmpDir := testDirUnderHome(t)

	packFile := fmt.Sprintf(
		"---\nid: linux-desktop-entries\nname: Eval Desktop\ntriggers:\n  - desktop\nallowed_paths:\n  - \"%s/*.desktop\"\nrequired_bins:\n  - desktop-file-validate\ncontext_cmd: true\nverify_cmd: desktop-file-validate \"$LNTA_TARGET\"\n---\n# eval body\n",
		tmpDir,
	)
	if err := os.WriteFile(filepath.Join(tmpDir, "pack.md"), []byte(packFile), 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	router, err := packs.NewRouter(embedFS, "*.md", tmpDir)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	packs.SetDefaultRouter(router)

	sys, err := fingerprint.Fingerprint()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	selected, err := router.SelectPacks("create a desktop launcher", sys)
	if err != nil {
		t.Fatalf("select packs: %v", err)
	}
	t.Logf("Pre-selected pack: %s", selected[0].ID)

	desktop := `[Desktop Entry]
Name=Eval App
Exec=/usr/bin/true
Type=Application
Categories=Utility;
`
	target := filepath.Join(tmpDir, "app.desktop")
	responses := [][]openai.ChatCompletionStreamResponse{
		{toolCallResponse("write_scoped_file", buildArgs(map[string]any{
			"path": target, "content": desktop, "reason": "create valid desktop launcher", "mode": "0644",
		}))},
		{toolCallResponse("complete_task", buildArgs(map[string]any{
			"summary": "created valid .desktop launcher", "target_artifacts": target,
			"verification_notes": "native Exec check + desktop-file-validate passed",
		}))},
	}

	mock := &mockLLM{
		scenarios: responses,
	}
	opts := []Option{
		WithRunID("eval-test"),
		WithCWD(tmpDir),
		WithApprove(func(_, _, _, _ string) bool { return true }),
		WithMaxTurns(8),
		WithDryRun(false),
		WithConfig(&Config{Model: "test-model"}),
		WithExecutor(transport.NewLocalExecutor("eval-test", tmpDir, selected[0].AllowedPaths)),
	}
	o := New(mock, router, opts...)

	ctx, cancel := WithSignalCancellation()
	defer cancel()

	result, err := o.Run(ctx, "create a desktop launcher for my app", "", false)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	t.Logf("Result: %s", result)
	t.Logf("Turns: %d", mock.turnCount())

	if !strings.Contains(result, "TASK_COMPLETE") {
		t.Fatalf("expected TASK_COMPLETE in result, got %q", result)
	}
	if mock.turnCount() != 2 {
		t.Fatalf("expected 2 turns, got %d", mock.turnCount())
	}
}

// mustMarshal marshals v to JSON, fatal on error.
func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return json.RawMessage(b)
}
