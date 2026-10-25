package transport

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installFakeSSH(t *testing.T, script string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOME", t.TempDir())
}

const fakeSSHScript = `last=""
for arg do last="$arg"; done
case "$last" in
  *OS_RELEASE_ID*)
    printf 'OS_RELEASE_ID=linux\nPATH=/usr/bin:/bin\nHOME=/home/test user\nUID=1000\nGID=1000\nUSER=test\n'
    if [ "${FAKE_BWRAP_PRESENT:-1}" = 1 ]; then echo 'BIN:bwrap=1'; else echo 'BIN:bwrap=0'; fi
    echo 'BIN:python3=1'
    exit 0
    ;;
  *bwrap\ --ro-bind*)
    [ "${FAKE_BWRAP_FAIL:-}" != 1 ] || exit 42
    exit 0
    ;;
  *sleep-test*) sleep 10; exit 0 ;;
esac
exit 0
`

func TestSSHPreflightFailsWhenBubblewrapMissing(t *testing.T) {
	installFakeSSH(t, fakeSSHScript)
	t.Setenv("FAKE_BWRAP_PRESENT", "0")
	e, err := NewSSHExecutor("tester@example.com", "run", "/home/test user")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("Preflight error = %v, want missing bwrap", err)
	}
	if _, err := e.RunReadOnly(context.Background(), "id", "", time.Second); err == nil {
		t.Fatal("protected command ran without remote sandbox")
	}
}

func TestSSHPreflightFailsWhenCapabilityProbeFails(t *testing.T) {
	installFakeSSH(t, fakeSSHScript)
	t.Setenv("FAKE_BWRAP_FAIL", "1")
	e, _ := NewSSHExecutor("tester@example.com", "run", "")
	if err := e.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "capability probe failed") {
		t.Fatalf("Preflight error = %v, want capability probe failure", err)
	}
	if e.RemoteFingerprint() == nil || e.RemoteFingerprint().HasBwrap {
		t.Fatal("failed capability probe was recorded as available")
	}
}

func TestSSHPreflightAndCommandConstructionAreSandboxed(t *testing.T) {
	installFakeSSH(t, fakeSSHScript)
	e, _ := NewSSHExecutor("tester@example.com", "run", "")
	if err := e.Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !e.RemoteFingerprint().HasBwrap {
		t.Fatal("successful probe was not recorded")
	}
	command, err := e.buildRemoteCommand("printf '%s'; touch /tmp/a; $(id)", "/home/test user/work dir", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"--unshare-user", "--unshare-net", "--unshare-pid", "--cap-drop", "--clearenv", "--tmpfs", "--chdir", "touch /tmp/a"} {
		if !strings.Contains(command, required) {
			t.Errorf("sandbox command missing %q: %s", required, command)
		}
	}
	if strings.HasPrefix(command, "sh -c") || !strings.Contains(command, shellQuote("printf '%s'; touch /tmp/a; $(id)")) {
		t.Fatalf("unexpected fallback or unsafe shell argument quoting: %s", command)
	}
}

func TestSSHCommandRefusesWithoutSuccessfulPreflight(t *testing.T) {
	e, _ := NewSSHExecutor("tester@example.com", "run", "")
	if _, err := e.buildRemoteCommand("true", "/tmp", nil); err == nil {
		t.Fatal("buildRemoteCommand accepted an unprobed executor")
	}
}

func TestRunSystemSSHCancellationStopsProcess(t *testing.T) {
	installFakeSSH(t, fakeSSHScript)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := runSystemSSH(ctx, "tester", "example.com", "22", "sleep-test", nil, time.Second)
	if err == nil {
		t.Fatal("expected timeout/cancellation error")
	}
}

func TestRemoteScopedWriteFailsClosed(t *testing.T) {
	e, _ := NewSSHExecutor("tester@example.com", "run", "")
	if _, err := e.WriteFile(context.Background(), "/tmp/file", []byte("x"), 0o644, []string{"/tmp/*"}, nil); err == nil {
		t.Fatal("remote write succeeded without a secure writer")
	}
}
