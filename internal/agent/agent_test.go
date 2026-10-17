package agent

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sashabaranov/go-openai"
	"github.com/sm-me/lnta/internal/packs"
)

// --- mock LLM + stream ------------------------------------------------------

// mockStream is a fake chatStream yielding a fixed slice of responses, then io.EOF.
type mockStream struct {
	responses []openai.ChatCompletionStreamResponse
	idx       int
}

func (m *mockStream) Recv() (openai.ChatCompletionStreamResponse, error) {
	if m.idx >= len(m.responses) {
		return openai.ChatCompletionStreamResponse{}, io.EOF
	}
	r := m.responses[m.idx]
	m.idx++
	return r, nil
}

func (m *mockStream) Close() error { return nil }

// mockLLM returns one canned stream per ChatCompletionStream call, in order.
// turnCount reports how many streams were requested.
type mockLLM struct {
	mu        sync.Mutex
	scenarios [][]openai.ChatCompletionStreamResponse
	turn      int
}

func (m *mockLLM) ChatCompletionStream(ctx context.Context, req openai.ChatCompletionRequest) (chatStream, error) {
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
				Index: 0,
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

// --- tests ------------------------------------------------------------------

// testDirUnderHome creates a throwaway directory under $HOME. Files under $HOME
// remain visible inside the bwrap sandbox (only /tmp is masked with an empty
// tmpfs, and secret dot-dirs are masked), so bwrap-based verify_cmds can stat
// them.
func testDirUnderHome(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("HOME not available")
	}
	d := filepath.Join(home, ".lnta-agent-test")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatalf("mkdir %q: %v", d, err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// TestCompleteTaskFailingVerifyCmd verifies that complete_task returns
// HARNESS_VERIFICATION_FAILED when the pack's verify_cmd fails (the harness
// verification gate blocks completion).
func TestCompleteTaskFailingVerifyCmd(t *testing.T) {
	dir := testDirUnderHome(t)
	existing := filepath.Join(dir, "exists.desktop")
	if err := os.WriteFile(existing, []byte("[Desktop Entry]\nName=Test\nExec=/usr/bin/true\nType=Application\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	missing := filepath.Join(dir, "missing.desktop")
	home, _ := os.UserHomeDir()

	pack := packs.Pack{
		ID:          "test-pack",
		Name:        "Test Pack",
		VerifyCmd:   `test -f "${target}"`,
		AllowedPaths: []string{filepath.Join(dir, "*.desktop")},
	}

	// complete_task with a missing target -> verify_cmd fails -> blocked.
	res, err := completeTask(context.Background(), mustMarshal(map[string]any{
		"summary":            "attempt 1",
		"target_artifacts":   missing,
		"verification_notes": "should fail",
	}), ToolDeps{RunID: "run-1", Pack: &pack, Approve: DefaultApprove, CWD: home})
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
	}), ToolDeps{RunID: "run-1", Pack: &pack, Approve: DefaultApprove, CWD: home})
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

// TestOrchestratorSelfCorrectsAfterFailedVerify verifies the full loop: when
// complete_task returns HARNESS_VERIFICATION_FAILED the loop continues and the
// agent can self-correct on the next turn (mock LLM retries with a valid target).
func TestOrchestratorSelfCorrectsAfterFailedVerify(t *testing.T) {
	dir := testDirUnderHome(t)
	existing := filepath.Join(dir, "launcher.desktop")
	if err := os.WriteFile(existing, []byte("[Desktop Entry]\nName=Launcher\nExec=/usr/bin/true\nType=Application\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	missing := filepath.Join(dir, "missing.desktop")
	home, _ := os.UserHomeDir()

	// Write a pack file into dir and load it via the public NewRouter (userDir).
	packFile := fmt.Sprintf(
		"---\nid: test-pack\nname: Test Pack\ntriggers:\n  - launcher\nverify_cmd: test -f \"${target}\"\ncontext_cmd: true\nallowed_paths:\n  - \"%s/*.desktop\"\n---\n# body\n",
		dir,
	)
	if err := os.WriteFile(filepath.Join(dir, "test-pack.md"), []byte(packFile), 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	router, err := packs.NewRouter(embed.FS{}, "*.md", dir)
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
		WithApprove(func(_, _, _, _ string) bool { return false }),
		WithMaxTurns(8),
		WithConfig(&Config{Model: "test-model"}),
	)

	result, err := o.Run(context.Background(), "create a launcher")
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

// mustMarshal marshals v to JSON, fatal on error.
func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return json.RawMessage(b)
}
