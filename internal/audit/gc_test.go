package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotPruningKeepLast(t *testing.T) {
	tempDir := t.TempDir()
	snapDir := filepath.Join(tempDir, "snapshots")
	logDir := filepath.Join(tempDir, "logs")
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatalf("mkdir snapshots: %v", err)
	}

	// Create 15 snapshot run directories with ascending timestamps
	baseTime := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 15; i++ {
		runTime := baseTime.Add(time.Duration(i) * time.Minute)
		runID := fmt.Sprintf("run-%s", runTime.Format("20060102T150405"))
		dir := filepath.Join(snapDir, runID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		// Write dummy data inside
		if err := os.WriteFile(filepath.Join(dir, "diff.txt"), []byte("diff data"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	opts := GCOptions{
		SnapshotsDir: snapDir,
		LogsDir:      logDir,
		KeepLast:     5,
		MaxBytes:     1024 * 1024 * 100, // Large enough so count triggers pruning
	}

	res, err := RunGC(opts)
	if err != nil {
		t.Fatalf("RunGC failed: %v", err)
	}

	if res.SnapshotsRemoved != 10 {
		t.Errorf("expected 10 snapshots removed, got %d", res.SnapshotsRemoved)
	}
	if res.TotalRunsAfter != 5 {
		t.Errorf("expected 5 runs remaining, got %d", res.TotalRunsAfter)
	}

	entries, err := os.ReadDir(snapDir)
	if err != nil {
		t.Fatalf("read snapDir: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 directories remaining on disk, got %d", len(entries))
	}

	// Verify that the remaining runs are the newest ones (indices 10 to 14)
	oldestKeptExpected := fmt.Sprintf("run-%s", baseTime.Add(10*time.Minute).Format("20060102T150405"))
	if entries[0].Name() < oldestKeptExpected {
		t.Errorf("expected remaining runs to be newer than %s, got %s", oldestKeptExpected, entries[0].Name())
	}
}

func TestSnapshotPruningMaxBytes(t *testing.T) {
	tempDir := t.TempDir()
	snapDir := filepath.Join(tempDir, "snapshots")
	logDir := filepath.Join(tempDir, "logs")
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatalf("mkdir snapshots: %v", err)
	}

	// Create 5 snapshot run directories, each containing 10KB (10240 bytes)
	baseTime := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	tenKB := make([]byte, 10240)
	for i := 0; i < 5; i++ {
		runTime := baseTime.Add(time.Duration(i) * time.Minute)
		runID := fmt.Sprintf("run-%s", runTime.Format("20060102T150405"))
		dir := filepath.Join(snapDir, runID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "payload.bin"), tenKB, 0o600); err != nil {
			t.Fatalf("write payload: %v", err)
		}
	}

	// Set MaxBytes = 25KB (so only newest 2 runs can fit, total 20KB < 25KB)
	opts := GCOptions{
		SnapshotsDir: snapDir,
		LogsDir:      logDir,
		KeepLast:     10, // count limit high enough so byte limit triggers
		MaxBytes:     25 * 1024,
	}

	res, err := RunGC(opts)
	if err != nil {
		t.Fatalf("RunGC failed: %v", err)
	}

	if res.SnapshotsRemoved != 3 {
		t.Errorf("expected 3 snapshots removed by byte limit, got %d", res.SnapshotsRemoved)
	}
	if res.TotalRunsAfter != 2 {
		t.Errorf("expected 2 runs remaining, got %d", res.TotalRunsAfter)
	}
	if res.BytesFreed != 3*10240 {
		t.Errorf("expected %d bytes freed, got %d", 3*10240, res.BytesFreed)
	}
}

func TestAuditLogRotation(t *testing.T) {
	tempDir := t.TempDir()
	snapDir := filepath.Join(tempDir, "snapshots")
	logDir := filepath.Join(tempDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}

	logPath := filepath.Join(logDir, "audit.jsonl")
	// Write 5000 bytes into audit.jsonl
	data := make([]byte, 5000)
	for i := range data {
		data[i] = 'A'
	}
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	// Trigger rotation with threshold 2000 bytes
	opts := GCOptions{
		SnapshotsDir: snapDir,
		LogsDir:      logDir,
		KeepLast:     10,
		MaxBytes:     1024 * 1024,
		MaxLogBytes:  2000,
	}

	res, err := RunGC(opts)
	if err != nil {
		t.Fatalf("RunGC failed: %v", err)
	}

	if !res.LogRotated {
		t.Fatalf("expected LogRotated to be true")
	}
	if res.OldLogSize != 5000 {
		t.Errorf("expected OldLogSize to be 5000, got %d", res.OldLogSize)
	}

	// Check that audit.jsonl.1 exists and has 5000 bytes
	rotPath := logPath + ".1"
	rotFi, err := os.Stat(rotPath)
	if err != nil {
		t.Fatalf("stat rotated log: %v", err)
	}
	if rotFi.Size() != 5000 {
		t.Errorf("expected rotated log size 5000, got %d", rotFi.Size())
	}

	// Check that new audit.jsonl exists, is empty, and has 0600 permissions
	newFi, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat new log: %v", err)
	}
	if newFi.Size() != 0 {
		t.Errorf("expected new log size 0, got %d", newFi.Size())
	}
	if perm := newFi.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected new log perm 0600, got %04o", perm)
	}
}

func TestFormatGCResult(t *testing.T) {
	res := &GCResult{
		SnapshotsRemoved: 12,
		BytesFreed:       25 * 1024 * 1024,
		LogRotated:       true,
		OldLogSize:       12 * 1024 * 1024,
		TotalRunsAfter:   88,
		TotalBytesAfter:  75 * 1024 * 1024,
	}
	msg := FormatGCResult(res)
	if msg == "" {
		t.Fatal("expected non-empty formatted message")
	}
}
