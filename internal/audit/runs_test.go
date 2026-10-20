package audit

import (
	"os"
	"testing"
	"time"
)

func TestSaveAndLoadRunSummary(t *testing.T) {
	// Create a test run summary
	runID := "run-test-" + time.Now().UTC().Format("20060102T150405")
	summary := &RunSummary{
		RunID:          runID,
		Timestamp:      time.Now().UTC(),
		Prompt:         "test prompt",
		SelectedPack:   "test-pack",
		CWD:            "/tmp",
		Status:         RunStatusVerified,
		FilesChanged: []FileDiffInfo{
			{
				TargetPath: "/tmp/test.txt",
				Created:    true,
				NewSHA256:  "abc123",
				SizeNew:    10,
				Diff:       "+++ b/test.txt\n+hello\n",
			},
		},
		CommandsExecuted: []CommandRecord{
			{
				Command:   "echo hello",
				ExitCode:  0,
				Stdout:    "hello\n",
				Timestamp: time.Now().UTC(),
				Source:    "inspect_system",
			},
		},
		TokensUsed: TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
		VerificationReceipt: []VerificationRecord{
			{
				Command:   "test-cmd",
				ExitCode:  0,
				Output:    "ok",
				Timestamp: time.Now().UTC(),
				Passed:    true,
			},
		},
	}

	// Clean up after test
	defer os.RemoveAll(snapshotDir(runID))

	// Save
	err := SaveRunSummary(runID, summary)
	if err != nil {
		t.Fatalf("SaveRunSummary failed: %v", err)
	}

	// Load
	loaded, err := LoadRunSummary(runID)
	if err != nil {
		t.Fatalf("LoadRunSummary failed: %v", err)
	}

	// Verify
	if loaded.RunID != summary.RunID {
		t.Errorf("RunID mismatch: got %q want %q", loaded.RunID, summary.RunID)
	}
	if loaded.Prompt != summary.Prompt {
		t.Errorf("Prompt mismatch: got %q want %q", loaded.Prompt, summary.Prompt)
	}
	if loaded.SelectedPack != summary.SelectedPack {
		t.Errorf("SelectedPack mismatch: got %q want %q", loaded.SelectedPack, summary.SelectedPack)
	}
	if loaded.Status != summary.Status {
		t.Errorf("Status mismatch: got %q want %q", loaded.Status, summary.Status)
	}
	if len(loaded.FilesChanged) != len(summary.FilesChanged) {
		t.Errorf("FilesChanged length mismatch: got %d want %d", len(loaded.FilesChanged), len(summary.FilesChanged))
	}
	if len(loaded.CommandsExecuted) != len(summary.CommandsExecuted) {
		t.Errorf("CommandsExecuted length mismatch: got %d want %d", len(loaded.CommandsExecuted), len(summary.CommandsExecuted))
	}
	if loaded.TokensUsed.TotalTokens != summary.TokensUsed.TotalTokens {
		t.Errorf("TokensUsed mismatch: got %d want %d", loaded.TokensUsed.TotalTokens, summary.TokensUsed.TotalTokens)
	}
	if len(loaded.VerificationReceipt) != len(summary.VerificationReceipt) {
		t.Errorf("VerificationReceipt length mismatch: got %d want %d", len(loaded.VerificationReceipt), len(summary.VerificationReceipt))
	}
}

func TestListRunSummaries(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	// Override snapshotRoot for testing
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	// Create test runs
	run1 := &RunSummary{
		RunID:        "run-20260101T000000",
		Timestamp:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Prompt:       "first run",
		SelectedPack: "pack1",
		CWD:          "/tmp",
		Status:       RunStatusVerified,
	}
	run2 := &RunSummary{
		RunID:        "run-20260102T000000",
		Timestamp:    time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		Prompt:       "second run",
		SelectedPack: "pack2",
		CWD:          "/tmp",
		Status:       RunStatusFailed,
	}
	run3 := &RunSummary{
		RunID:        "run-20260103T000000",
		Timestamp:    time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
		Prompt:       "third run",
		SelectedPack: "pack3",
		CWD:          "/tmp",
		Status:       RunStatusRolledBack,
	}

	_ = SaveRunSummary(run1.RunID, run1)
	_ = SaveRunSummary(run2.RunID, run2)
	_ = SaveRunSummary(run3.RunID, run3)

	// List runs
	runs, err := ListRunSummaries()
	if err != nil {
		t.Fatalf("ListRunSummaries failed: %v", err)
	}

	// Should be sorted by timestamp descending (newest first)
	if len(runs) != 3 {
		t.Fatalf("Expected 3 runs, got %d", len(runs))
	}
	if runs[0].RunID != run3.RunID {
		t.Errorf("First run should be newest (run3), got %s", runs[0].RunID)
	}
	if runs[1].RunID != run2.RunID {
		t.Errorf("Second run should be run2, got %s", runs[1].RunID)
	}
	if runs[2].RunID != run1.RunID {
		t.Errorf("Third run should be oldest (run1), got %s", runs[2].RunID)
	}
}

func TestUpdateRunStatus(t *testing.T) {
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	runID := "run-status-test"
	summary := &RunSummary{
		RunID:        runID,
		Timestamp:    time.Now().UTC(),
		Prompt:       "test",
		SelectedPack: "test",
		CWD:          "/tmp",
		Status:       RunStatusVerified,
	}

	_ = SaveRunSummary(runID, summary)

	// Update status to ROLLED_BACK
	err := UpdateRunStatus(runID, RunStatusRolledBack)
	if err != nil {
		t.Fatalf("UpdateRunStatus failed: %v", err)
	}

	// Reload and verify
	loaded, err := LoadRunSummary(runID)
	if err != nil {
		t.Fatalf("LoadRunSummary failed: %v", err)
	}

	if loaded.Status != RunStatusRolledBack {
		t.Errorf("Status not updated: got %q want %q", loaded.Status, RunStatusRolledBack)
	}
}

func TestRunSummaryCollector(t *testing.T) {
	collector := NewRunSummaryCollector("run-collector-test", "test prompt", "test-pack", "/tmp")

	// Record file diff
	collector.RecordFileDiff(FileDiffInfo{
		TargetPath: "/tmp/test.txt",
		Created:    true,
		NewSHA256:  "abc123",
		SizeNew:    10,
		Diff:       "+++ b/test.txt\n+hello\n",
	})

	// Record command
	collector.RecordCommand(CommandRecord{
		Command:   "echo hello",
		ExitCode:  0,
		Stdout:    "hello\n",
		Timestamp: time.Now().UTC(),
		Source:    "inspect_system",
	})

	// Record tokens
	collector.RecordTokens(100, 50)

	// Record verification
	collector.RecordVerification(VerificationRecord{
		Command:   "test-cmd",
		ExitCode:  0,
		Output:    "ok",
		Timestamp: time.Now().UTC(),
		Passed:    true,
	})

	// Set status
	collector.SetStatus(RunStatusVerified)

	// Get snapshot
	snapshot := collector.Snapshot()

	if snapshot.RunID != "run-collector-test" {
		t.Errorf("RunID mismatch: got %q", snapshot.RunID)
	}
	if len(snapshot.FilesChanged) != 1 {
		t.Errorf("Expected 1 file diff, got %d", len(snapshot.FilesChanged))
	}
	if len(snapshot.CommandsExecuted) != 1 {
		t.Errorf("Expected 1 command, got %d", len(snapshot.CommandsExecuted))
	}
	if snapshot.TokensUsed.TotalTokens != 150 {
		t.Errorf("Expected 150 total tokens, got %d", snapshot.TokensUsed.TotalTokens)
	}
	if len(snapshot.VerificationReceipt) != 1 {
		t.Errorf("Expected 1 verification, got %d", len(snapshot.VerificationReceipt))
	}
	if snapshot.Status != RunStatusVerified {
		t.Errorf("Expected VERIFIED status, got %q", snapshot.Status)
	}
}

func TestRunSummaryCollectorConcurrency(t *testing.T) {
	collector := NewRunSummaryCollector("run-concurrent-test", "test", "test", "/tmp")

	// Simulate concurrent access
	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func(idx int) {
			collector.RecordCommand(CommandRecord{
				Command:   "cmd",
				ExitCode:  0,
				Timestamp: time.Now().UTC(),
				Source:    "inspect_system",
			})
			collector.RecordTokens(idx, idx)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	snapshot := collector.Snapshot()
	if len(snapshot.CommandsExecuted) != 100 {
		t.Errorf("Expected 100 commands, got %d", len(snapshot.CommandsExecuted))
	}
	if snapshot.TokensUsed.PromptTokens != 4950 { // sum 0..99
		t.Errorf("Expected 4950 prompt tokens, got %d", snapshot.TokensUsed.PromptTokens)
	}
}

func TestEmptyRunsList(t *testing.T) {
	// Test ListRunSummaries with no runs
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	runs, err := ListRunSummaries()
	if err != nil {
		t.Fatalf("ListRunSummaries failed: %v", err)
	}
	if len(runs) != 0 {
		t.Errorf("Expected 0 runs, got %d", len(runs))
	}
}