package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBwrapProbeArgsMatchProductionSandboxArgs(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	want := append(bwrapArgs(homeDir(), cwd, nil), "sh", "-c", "cat /proc/self/attr/current")
	if got := bwrapProbeArgs(homeDir(), cwd); !reflect.DeepEqual(got, want) {
		t.Fatalf("probe args do not match production bwrap args\ngot:  %#v\nwant: %#v", got, want)
	}
}

func fakeBwrap(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bwrap")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return dir
}

func TestProbeBwrapCapturesLabelAndBoundsStderr(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "args")
	fakeBwrap(t, "printf '%s\\0' \"$@\" > "+marker+"\nprintf 'unconfined\\n'\nprintf '%05000d' 0 >&2\n")

	probe, err := ProbeBwrap(time.Second)
	if err != nil {
		t.Fatalf("ProbeBwrap() error = %v", err)
	}
	if probe.Path == "" || probe.ExitStatus != 0 || probe.AppArmor != "unconfined" {
		t.Fatalf("unexpected probe result: %+v", probe)
	}
	if len(probe.Stderr) > 4096 {
		t.Fatalf("stderr exceeded cap: %d bytes", len(probe.Stderr))
	}
	args, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	gotArgs := strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")
	cwd, _ := os.Getwd()
	wantArgs := bwrapProbeArgs(homeDir(), cwd)
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("probe invocation differs from production args\ngot:  %#v\nwant: %#v", gotArgs, wantArgs)
	}
}

func TestProbeBwrapTimeoutKillsProcessGroup(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	fakeBwrap(t, "/bin/sleep 30 &\necho $! > "+pidFile+"\nwait\n")

	start := time.Now()
	probe, err := ProbeBwrap(100 * time.Millisecond)
	if !errors.Is(err, ErrBwrapBlocked) || !probe.TimedOut {
		t.Fatalf("expected bounded timeout, probe=%+v err=%v", probe, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("probe did not honor timeout: %s", time.Since(start))
	}
	pidBytes, readErr := os.ReadFile(pidFile)
	if readErr == nil {
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		for range 30 {
			if err := syscall.Kill(pid, 0); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("probe left child process %d alive", pid)
	}
}

func TestProbeBwrapMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	probe, err := ProbeBwrap(time.Second)
	if !errors.Is(err, ErrBwrapNotFound) || probe.Path != "" {
		t.Fatalf("expected missing-bwrap result, got probe=%+v err=%v", probe, err)
	}
}
