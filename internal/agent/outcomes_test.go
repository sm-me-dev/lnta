package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sashabaranov/go-openai"
	"github.com/sm-me-dev/lnta/internal/audit"
	"github.com/sm-me-dev/lnta/internal/packs"
	"github.com/sm-me-dev/lnta/internal/sandbox"
	"github.com/sm-me-dev/lnta/internal/transport"
)

type failingReadExecutor struct {
	result sandbox.CommandResult
	err    error
	calls  int
}

func (e *failingReadExecutor) RunReadOnly(context.Context, string, string, string, time.Duration) (sandbox.CommandResult, error) {
	e.calls++
	return e.result, e.err
}
func (e *failingReadExecutor) RunReadOnlyEnv(ctx context.Context, command, root, cwd string, timeout time.Duration, _ []string) (sandbox.CommandResult, error) {
	return e.RunReadOnly(ctx, command, root, cwd, timeout)
}
func (*failingReadExecutor) ReadFile(context.Context, string) ([]byte, os.FileInfo, error) {
	return nil, nil, errors.New("not implemented")
}
func (*failingReadExecutor) WriteFile(context.Context, string, []byte, os.FileMode, []string, *sandbox.FileDiff) (sandbox.FileDiff, error) {
	return sandbox.FileDiff{}, errors.New("not implemented")
}
func (*failingReadExecutor) StatFile(context.Context, string) (os.FileInfo, error) {
	return nil, errors.New("not implemented")
}
func (*failingReadExecutor) Close() error                                    { return nil }
func (*failingReadExecutor) TargetID() string                                { return "test" }
func (*failingReadExecutor) IsRemote() bool                                  { return false }
func (*failingReadExecutor) RemoteFingerprint() *transport.RemoteFingerprint { return nil }
func (*failingReadExecutor) Preflight(context.Context) error                 { return nil }

func outcomeTestRouter(t *testing.T, dir, id, trigger string) *packs.Router {
	t.Helper()
	content := fmt.Sprintf("---\nid: %s\nname: Test Pack\ntriggers:\n  - %s\ncontext_cmd: true\nverify_cmd: true\nallowed_paths: []\n---\n# Test\n", id, trigger)
	if err := os.WriteFile(filepath.Join(dir, id+".md"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	router, err := packs.NewRouter(embedFS, "*.md", dir)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return router
}

func TestCompleteTaskBlockedOutcomeDoesNotVerify(t *testing.T) {
	collector := audit.NewRunSummaryCollector("run-blocked-outcome", "task", "test-pack", t.TempDir())
	result, err := completeTask(context.Background(), mustMarshal(map[string]any{
		"outcome": "blocked", "summary": "project inspection is blocked",
	}), ToolDeps{RunCollector: collector})
	if err != nil || !strings.HasPrefix(result, "TASK_BLOCKED:") {
		t.Fatalf("result=%q error=%v", result, err)
	}
	summary := collector.Snapshot()
	if summary.Status != audit.RunStatusBlocked || len(summary.VerificationReceipt) != 0 {
		t.Fatalf("blocked completion summary=%+v", summary)
	}
	if code := DetermineExitCode(nil, result, summary); code != ExitCodeBlocked {
		t.Fatalf("blocked exit code=%d", code)
	}
}

func TestCompletedWithoutVerifierIsUnverified(t *testing.T) {
	notRequired := false
	collector := audit.NewRunSummaryCollector("run-unverified-outcome", "task", "test-pack", t.TempDir())
	result, err := completeTask(context.Background(), mustMarshal(map[string]any{
		"outcome": "completed", "summary": "diagnostic findings ready",
	}), ToolDeps{Pack: &packs.Pack{ID: "no-verifier", VerificationRequired: &notRequired}, RunCollector: collector})
	if err != nil || !strings.HasPrefix(result, "TASK_COMPLETE_UNVERIFIED:") {
		t.Fatalf("result=%q error=%v", result, err)
	}
	summary := collector.Snapshot()
	if summary.Status != audit.RunStatusCompletedUnverified || len(summary.VerificationReceipt) != 1 || summary.VerificationReceipt[0].Passed {
		t.Fatalf("unverified completion summary=%+v", summary)
	}
	if code := DetermineExitCode(nil, result, summary); code != ExitCodeUnverified {
		t.Fatalf("unverified exit code=%d", code)
	}
}

func TestProjectSymlinkInspectionStopsBeforeMutation(t *testing.T) {
	project := testDirUnderHome(t)
	if err := os.Symlink(t.TempDir(), filepath.Join(project, "unsafe-link")); err != nil {
		t.Fatal(err)
	}
	router := outcomeTestRouter(t, project, "symlink-test", "symlink-test")
	marker := filepath.Join(project, "should-not-exist")
	llm := &mockLLM{scenarios: [][]openai.ChatCompletionStreamResponse{
		{toolCallResponse("inspect_system", buildArgs(map[string]any{"scope": "project", "command": "true", "cwd": project, "reason": "inspect project"}))},
		{toolCallResponse("mutate_system", buildArgs(map[string]any{"command": "touch " + marker, "cwd": project, "risk_level": "low", "reason": "fallback"}))},
	}}
	approvalCalls := 0
	executor := transport.NewLocalExecutor("run-symlink-blocked", project, nil, project)
	o := New(llm, router,
		WithRunID("run-symlink-blocked"), WithCWD(project), WithProjectRoot(project),
		WithExecutor(executor), WithConfig(&Config{Model: "test-model"}), WithMaxTurns(5),
		WithApprove(func(_, _, _, _ string) bool { approvalCalls++; return true }),
	)
	result, err := o.Run(context.Background(), "inspect symlink-test", "", false)
	if err != nil || !strings.HasPrefix(result, "INSPECT_BLOCKED:") {
		t.Fatalf("result=%q error=%v", result, err)
	}
	if llm.turnCount() != 1 || approvalCalls != 0 {
		t.Fatalf("turns=%d approval calls=%d; blocked inspection continued", llm.turnCount(), approvalCalls)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("mutation ran after blocked inspection: %v", err)
	}
	summary := o.RunSummary()
	if summary == nil || summary.Status != audit.RunStatusBlocked || DetermineExitCode(nil, result, summary) != ExitCodeBlocked {
		t.Fatalf("blocked run summary=%+v", summary)
	}
}

func TestRepeatedInspectionFailuresHaltAsBlocked(t *testing.T) {
	dir := testDirUnderHome(t)
	router := outcomeTestRouter(t, dir, "repeat-test", "repeat-test")
	inspectArgs := `{"scope":"project","command":"false","cwd":"` + dir + `","reason":"check"}`
	marker := filepath.Join(dir, "should-not-exist")
	llm := &mockLLM{scenarios: [][]openai.ChatCompletionStreamResponse{
		{toolCallResponse("inspect_system", inspectArgs)},
		{toolCallResponse("inspect_system", inspectArgs)},
		{toolCallResponse("mutate_system", buildArgs(map[string]any{"command": "touch " + marker, "cwd": dir, "risk_level": "low", "reason": "fallback"}))},
	}}
	executor := &failingReadExecutor{result: sandbox.CommandResult{ExitCode: 1, Stderr: "diagnostic failed"}}
	approvalCalls := 0
	o := New(llm, router,
		WithRunID("run-repeated-inspect"), WithCWD(dir), WithProjectRoot(dir),
		WithExecutor(executor), WithConfig(&Config{Model: "test-model"}), WithMaxTurns(5),
		WithApprove(func(_, _, _, _ string) bool { approvalCalls++; return true }),
	)
	result, err := o.Run(context.Background(), "repeat-test", "", false)
	if err != nil || !strings.HasPrefix(result, "INSPECT_BLOCKED:") {
		t.Fatalf("result=%q error=%v", result, err)
	}
	if llm.turnCount() != 2 || approvalCalls != 0 {
		t.Fatalf("turns=%d approval calls=%d; repeated inspection did not stop", llm.turnCount(), approvalCalls)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("mutation ran after repeated inspection failure: %v", err)
	}
	if summary := o.RunSummary(); summary == nil || summary.Status != audit.RunStatusBlocked || DetermineExitCode(nil, result, summary) != ExitCodeBlocked {
		t.Fatalf("blocked summary=%+v", summary)
	}
}

func TestBoundConversationHistoryKeepsNewestWholeTurns(t *testing.T) {
	history := []ConversationTurn{
		{User: "old-user-message", Assistant: "old-assistant-message"},
		{User: "new-user-message", Assistant: "new-assistant-message"},
	}
	bounded := BoundConversationHistory(history, 22)
	if len(bounded) != 1 || bounded[0] != history[1] {
		t.Fatalf("bounded history=%+v", bounded)
	}
	if reset := BoundConversationHistory(nil, 20); len(reset) != 0 {
		t.Fatalf("reset history=%+v", reset)
	}
}

func TestConversationHistoryKeepsCurrentPackRoutingSeparate(t *testing.T) {
	dir := testDirUnderHome(t)
	for _, pack := range []struct{ id, trigger string }{{"alpha-pack", "alpha"}, {"beta-pack", "beta"}} {
		content := fmt.Sprintf("---\nid: %s\nname: %s\ntriggers:\n  - %s\ncontext_cmd: true\nverify_cmd: true\nallowed_paths: []\n---\n# %s\n", pack.id, pack.id, pack.trigger, pack.id)
		if err := os.WriteFile(filepath.Join(dir, pack.id+".md"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	router, err := packs.NewRouter(embedFS, "*.md", dir)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	response := toolCallResponse("complete_task", `{"outcome":"blocked","summary":"stop test run"}`)
	history := []ConversationTurn{{User: "alpha previous task", Assistant: "alpha previous result"}}
	llm := &mockLLM{scenarios: [][]openai.ChatCompletionStreamResponse{{response}}}
	o := New(llm, router,
		WithRunID("run-conversation-history"), WithCWD(dir), WithMaxTurns(2),
		WithConfig(&Config{Model: "test-model"}),
		WithExecutor(&failingReadExecutor{}),
		WithConversationHistory(history, 100),
	)
	result, err := o.Run(context.Background(), "beta current task", "", false)
	if err != nil || !strings.HasPrefix(result, "TASK_BLOCKED:") {
		t.Fatalf("result=%q error=%v", result, err)
	}
	if got := o.RunSummary().SelectedPack; got != "beta-pack" {
		t.Fatalf("current prompt selected pack %q, want beta-pack", got)
	}
	requests := llm.requestsCopy()
	if len(requests) != 1 || len(requests[0].Messages) != 4 {
		t.Fatalf("provider requests=%d messages=%v", len(requests), requests)
	}
	if requests[0].Messages[1].Content != history[0].User || requests[0].Messages[2].Content != history[0].Assistant || requests[0].Messages[3].Content != "beta current task" {
		t.Fatalf("conversation messages were not retained in order: %+v", requests[0].Messages)
	}

	resetLLM := &mockLLM{scenarios: [][]openai.ChatCompletionStreamResponse{{response}}}
	reset := New(resetLLM, router,
		WithRunID("run-conversation-reset"), WithCWD(dir), WithMaxTurns(2),
		WithConfig(&Config{Model: "test-model"}), WithExecutor(&failingReadExecutor{}),
		WithConversationHistory(nil, 100),
	)
	if _, err := reset.Run(context.Background(), "beta current task", "", false); err != nil {
		t.Fatal(err)
	}
	resetMessages := resetLLM.requestsCopy()[0].Messages
	if len(resetMessages) != 2 || strings.Contains(resetMessages[1].Content, "alpha previous") {
		t.Fatalf("reset retained old conversation: %+v", resetMessages)
	}
}
