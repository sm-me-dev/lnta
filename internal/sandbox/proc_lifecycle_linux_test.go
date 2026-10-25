//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func registrySize() int {
	childRegistry.mu.Lock()
	defer childRegistry.mu.Unlock()
	return len(childRegistry.pgid)
}

// readPIDFile waits (bounded) for a helper shell to publish a pid and makes
// sure the process is killed when the test ends, so a failing assertion can
// never leave an orphan behind.
func readPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			var pid int
			if _, err := fmt.Sscan(strings.TrimSpace(string(data)), &pid); err == nil && pid > 0 {
				t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("helper never published a pid at %s", path)
	return 0
}

func waitProcessGone(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !processExists(pid) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return !processExists(pid)
}

func TestStartChildRegistersAndWaitChildUnregisters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 0.2")
	ConfigureProcessGroup(cmd)
	started, err := StartChild("lifecycle_test", cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got := registeredProcessGroup(cmd.Process.Pid); got != cmd.Process.Pid {
		t.Fatalf("running child registered pgid %d, want its own pid %d", got, cmd.Process.Pid)
	}
	if err := WaitChild("lifecycle_test", cmd, started, ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	if n := registrySize(); n != 0 {
		t.Fatalf("registry holds %d entries after successful completion", n)
	}
}

func TestFailedStartLeavesNoRegistryEntry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for name, cmd := range map[string]*exec.Cmd{
		"missing binary":    exec.CommandContext(ctx, "/nonexistent/lnta-test-binary"),
		"missing directory": exec.CommandContext(ctx, "/bin/sh", "-c", "true"),
	} {
		if name == "missing directory" {
			cmd.Dir = "/nonexistent/lnta-test-dir"
		}
		ConfigureProcessGroup(cmd)
		if _, err := StartChild("lifecycle_test", cmd); err == nil {
			t.Fatalf("%s: start unexpectedly succeeded", name)
		}
		if n := registrySize(); n != 0 {
			t.Fatalf("%s: failed start left %d registry entries", name, n)
		}
	}
}

func TestStartChildRejectsMissingOwnedProcessGroupBeforeStarting(t *testing.T) {
	cmd := exec.Command("/bin/true")
	if _, err := StartChild("lifecycle_test", cmd); err == nil {
		t.Fatal("child without an owned process group was started")
	}
	if cmd.Process != nil {
		t.Fatal("invalid child setup started a process")
	}
	if n := registrySize(); n != 0 {
		t.Fatalf("invalid setup left %d registry entries", n)
	}
}

func TestGroupCleanupDoesNotSignalUnobservablePID(t *testing.T) {
	if got := killGroupAfterLeaderExit(1 << 30); got != "unobservable" {
		t.Fatalf("cleanup status=%q, want unobservable", got)
	}
}

func TestNonzeroExitIsOrdinaryFailureNotTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "exit 3")
	ConfigureProcessGroup(cmd)
	started, err := StartChild("lifecycle_test", cmd)
	if err != nil {
		t.Fatal(err)
	}
	err = WaitChild("lifecycle_test", cmd, started, ctx, nil, nil)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("want ExitError with code 3, got %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("ordinary failure was classified as a context error: %v", err)
	}
	if n := registrySize(); n != 0 {
		t.Fatalf("registry holds %d entries", n)
	}
}

func TestTimeoutIsDistinguishableAndKillsDescendants(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "gc.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30 & echo $! > \"$1\"; wait", "sh", pidFile)
	ConfigureProcessGroup(cmd)
	started, err := StartChild("lifecycle_test", cmd)
	if err != nil {
		t.Fatal(err)
	}
	pid := readPIDFile(t, pidFile)
	begin := time.Now()
	err = WaitChild("lifecycle_test", cmd, started, ctx, nil, nil)
	if elapsed := time.Since(begin); elapsed > 5*time.Second {
		t.Fatalf("timeout was not enforced promptly: %s", elapsed)
	}
	if err == nil {
		t.Fatal("timed-out child reported success")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("timeout lost ExitError details: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout is indistinguishable from an ordinary failure: %v", err)
	}
	if !waitProcessGone(pid, 2*time.Second) {
		t.Fatalf("grandchild %d survived timeout", pid)
	}
	if n := registrySize(); n != 0 {
		t.Fatalf("registry holds %d entries", n)
	}
}

func TestCancellationKillsDescendantsAndIsNotATimeout(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "gc.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30 & echo $! > \"$1\"; wait", "sh", pidFile)
	ConfigureProcessGroup(cmd)
	started, err := StartChild("lifecycle_test", cmd)
	if err != nil {
		t.Fatal(err)
	}
	pid := readPIDFile(t, pidFile)
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	begin := time.Now()
	err = WaitChild("lifecycle_test", cmd, started, ctx, nil, nil)
	if time.Since(begin) > 5*time.Second {
		t.Fatal("cancellation was not enforced promptly")
	}
	if err == nil {
		t.Fatal("canceled child reported success")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("explicit cancellation was reported as a timeout: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("explicit cancellation is not distinguishable: %v", err)
	}
	if !waitProcessGone(pid, 2*time.Second) {
		t.Fatalf("grandchild %d survived cancellation", pid)
	}
}

func TestChildIgnoringTermIsStillKilled(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "gc.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "trap '' TERM INT HUP; sleep 30 & echo $! > \"$1\"; while :; do sleep 1; done", "sh", pidFile)
	ConfigureProcessGroup(cmd)
	started, err := StartChild("lifecycle_test", cmd)
	if err != nil {
		t.Fatal(err)
	}
	pid := readPIDFile(t, pidFile)
	begin := time.Now()
	_ = WaitChild("lifecycle_test", cmd, started, ctx, nil, nil)
	if time.Since(begin) > 5*time.Second {
		t.Fatal("a child that ignores SIGTERM outlived the timeout")
	}
	if !waitProcessGone(pid, 2*time.Second) {
		t.Fatalf("signal-ignoring descendant %d survived", pid)
	}
}

func TestGrandchildHoldingOutputPipeDoesNotDelayOrFailSuccessfulChild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "gc.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The background sleep inherits stdout/stderr, so the capture pipes stay
	// open after the shell exits 0.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30 & echo $! > \"$1\"; exit 0", "sh", pidFile)
	ConfigureProcessGroup(cmd)
	stdout, stderr := NewCappedBuffer(1024, 0, nil), NewCappedBuffer(1024, 0, nil)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	started, err := StartChild("lifecycle_test", cmd)
	if err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	err = WaitChild("lifecycle_test", cmd, started, ctx, stdout, stderr)
	elapsed := time.Since(begin)
	pid := readPIDFile(t, pidFile)
	if err != nil {
		t.Fatalf("successful command was reported as failed: %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("reaping a pipe-holding grandchild took %s", elapsed)
	}
	if !waitProcessGone(pid, 2*time.Second) {
		t.Fatalf("pipe-holding grandchild %d survived", pid)
	}
}

func TestLargeStdoutAndStderrStreamsAreBoundedAndKilled(t *testing.T) {
	if _, err := exec.LookPath("yes"); err != nil {
		t.Skip("yes(1) not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "yes stdout-flood & yes stderr-flood >&2 & wait")
	ConfigureProcessGroup(cmd)
	const hard = 1 << 20
	stdout := NewCappedBuffer(2048, hard, cancel)
	stderr := NewCappedBuffer(2048, hard, cancel)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	started, err := StartChild("lifecycle_test", cmd)
	if err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	err = WaitChild("lifecycle_test", cmd, started, ctx, stdout, stderr)
	if time.Since(begin) > 10*time.Second {
		t.Fatal("runaway output was not terminated by the hard cap")
	}
	if err == nil {
		t.Fatal("killed flood reported success")
	}
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("output-cap termination is not distinguishable: %v", err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("output-cap termination has the wrong classification: %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("output-cap kill was reported as a timeout: %v", err)
	}
	if len(stdout.String()) > 2048 || len(stderr.String()) > 2048 {
		t.Fatalf("retained output exceeds limit: %d/%d", len(stdout.String()), len(stderr.String()))
	}
	if stdout.Total() <= hard && stderr.Total() <= hard {
		t.Fatalf("neither stream passed the hard cap: %d/%d", stdout.Total(), stderr.Total())
	}
	if n := registrySize(); n != 0 {
		t.Fatalf("registry holds %d entries", n)
	}
}

func TestRepeatedStartWaitCancelDoesNotLeak(t *testing.T) {
	for i := range 20 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		script := "exit 0"
		if i%2 == 1 {
			script = "sleep 30 & wait"
		}
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
		ConfigureProcessGroup(cmd)
		started, err := StartChild("lifecycle_test", cmd)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if i%2 == 1 {
			go func() {
				time.Sleep(20 * time.Millisecond)
				cancel()
			}()
		}
		_ = WaitChild("lifecycle_test", cmd, started, ctx, nil, nil)
		cancel()
	}
	if n := registrySize(); n != 0 {
		t.Fatalf("registry leaked %d entries", n)
	}
}

func TestKillAllChildrenOnlyTargetsRegisteredGroups(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30")
	ConfigureProcessGroup(cmd)
	started, err := StartChild("lifecycle_test", cmd)
	if err != nil {
		t.Fatal(err)
	}
	// The test process itself is in a different group and must survive.
	if registeredProcessGroup(cmd.Process.Pid) == syscall.Getpgrp() {
		t.Fatal("child shares the parent's process group")
	}
	KillAllChildren()
	err = WaitChild("lifecycle_test", cmd, started, ctx, nil, nil)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected the child to be killed, got %v", err)
	}
}

func TestSSHRollbackHardOutputCapKillsChild(t *testing.T) {
	if _, err := exec.LookPath("yes"); err != nil {
		t.Skip("yes(1) not available")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nexec yes flood\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("HOME", t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	begin := time.Now()
	err := runSSHDirectStdin(ctx, "user", "host.example", "22", "true", nil)
	if elapsed := time.Since(begin); elapsed > 6*time.Second {
		t.Fatalf("runaway ssh output was not killed at the hard cap (took %s, err=%v)", elapsed, err)
	}
	if err == nil {
		t.Fatal("killed ssh reported success")
	}
	if n := registrySize(); n != 0 {
		t.Fatalf("registry holds %d entries", n)
	}
}
