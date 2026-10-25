package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProcessLifecycleDetailsAreBoundedAndPrivate(t *testing.T) {
	started := time.Now().Add(-23 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := processStartDetails("mutate_system", 1234)
	complete := processCompletionDetails("mutate_system", "1234", started, ctx, 0, 15, 7)
	for key, want := range map[string]string{"role": "mutate_system", "pid": "1234", "pgid": "1234"} {
		if start[key] != want {
			t.Errorf("start details[%q]=%q want %q", key, start[key], want)
		}
	}
	for key, want := range map[string]string{
		"role": "mutate_system", "pid": "1234", "pgid": "1234", "exit_status": "0",
		"canceled": "false", "timed_out": "false", "stdout_bytes": "15", "stderr_bytes": "7",
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
