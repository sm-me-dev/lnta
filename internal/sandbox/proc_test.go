package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProcessLifecycleDetailsAreBoundedAndPrivate(t *testing.T) {
	started := time.Now().Add(-23 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pid := int(^uint(0) >> 1) // Outside the kernel PID range, regardless of CI runner processes.
	pidText := strconv.Itoa(pid)
	start := processStartDetails("mutate_system", pid)
	complete := processCompletionDetails("mutate_system", pidText, started, ctx, 0, 15, 7)
	for key, want := range map[string]string{"role": "mutate_system", "pid": pidText, "pgid": pidText} {
		if start[key] != want {
			t.Errorf("start details[%q]=%q want %q", key, start[key], want)
		}
	}
	for key, want := range map[string]string{
		"role": "mutate_system", "pid": pidText, "pgid": pidText, "exit_status": "0",
		"canceled": "false", "timed_out": "false", "stdout_bytes": "15", "stderr_bytes": "7",
		"termination_reason": "completed", "cleanup_status": "not_recorded",
	} {
		if complete[key] != want {
			t.Errorf("completion details[%q]=%q want %q", key, complete[key], want)
		}
	}
	if _, ok := complete["elapsed_ms"]; !ok {
		t.Fatal("completion details missing elapsed time")
	}
	for _, details := range []map[string]string{start, complete} {
		for key := range details {
			if strings.Contains(key, "command") || strings.Contains(key, "output") || strings.Contains(key, "prompt") || strings.Contains(key, "env") {
				t.Errorf("unexpected private lifecycle field %q", key)
			}
		}
	}
}

func TestProcessLifecycleDetailsMarkTimeout(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	details := processCompletionDetails("bwrap", "55", time.Now(), ctx, 137, 0, 32)
	if details["canceled"] != "true" || details["timed_out"] != "true" {
		t.Fatalf("timeout flags missing: %#v", details)
	}
	if details["termination_reason"] != "deadline" {
		t.Fatalf("timeout reason missing: %#v", details)
	}
}

func TestProcessLifecycleDetailsRecordCleanupFailureSafely(t *testing.T) {
	details := processCompletionDetailsWithGroup("mutate_system", "23", "23", time.Now(), nil, 126, 0, 0, "cleanup_failed", "unobservable")
	if details["termination_reason"] != "cleanup_failed" || details["cleanup_status"] != "unobservable" {
		t.Fatalf("cleanup result missing from lifecycle metadata: %#v", details)
	}
	for _, value := range details {
		if strings.Contains(value, "secret") || strings.Contains(value, "command") {
			t.Fatalf("unexpected sensitive lifecycle value %q", value)
		}
	}
}

func TestWaitChildKillsGrandchildAfterParentExit(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30 & echo $! > \"$1\"; exit 0", "sh", pidFile)
	ConfigureProcessGroup(cmd)
	started, err := StartChild("proc_test", cmd)
	if err != nil {
		t.Fatal(err)
	}
	if err := WaitChild("proc_test", cmd, started, ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if _, err := fmt.Sscan(strings.TrimSpace(string(data)), &pid); err != nil {
		t.Fatal(err)
	}
	for range 50 {
		if !processExists(pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("grandchild process %d survived parent completion", pid)
}

func TestRepeatedCanceledChildrenAreCleanedUp(t *testing.T) {
	for range 10 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30 & wait")
		ConfigureProcessGroup(cmd)
		started, err := StartChild("proc_cancel_test", cmd)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_ = WaitChild("proc_cancel_test", cmd, started, ctx, nil, nil)
		cancel()
	}
	childRegistry.mu.Lock()
	defer childRegistry.mu.Unlock()
	if len(childRegistry.pgid) != 0 {
		t.Fatalf("process registry leaked entries: %v", childRegistry.pgid)
	}
}

func TestChildOutputCaptureRemainsBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "head -c 131072 /dev/zero")
	ConfigureProcessGroup(cmd)
	stdout := NewCappedBuffer(1024, 0, nil)
	stderr := NewCappedBuffer(1024, 0, nil)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	started, err := StartChild("proc_output_test", cmd)
	if err != nil {
		t.Fatal(err)
	}
	if err := WaitChild("proc_output_test", cmd, started, ctx, stdout, stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.Total() != 131072 || len(stdout.String()) > 1024 {
		t.Fatalf("output capture is not bounded: total=%d retained=%d", stdout.Total(), len(stdout.String()))
	}
	if stderr.Total() != 0 {
		t.Fatalf("unexpected stderr bytes: %d", stderr.Total())
	}
}

func processExists(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data))
	return len(fields) < 3 || fields[2] != "Z"
}
