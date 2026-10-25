// Package sandbox tests for Landlock fallback when bwrap is unavailable or blocked.
package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLandlockProbe checks if Landlock is available on the current kernel.
func TestLandlockProbe(t *testing.T) {
	err := LandlockProbe()
	if err != nil {
		t.Logf("Landlock not available: %v", err)
		// Don't fail - Landlock requires kernel 5.13+
	} else {
		t.Log("Landlock probe: OK")
	}
}

// TestLandlockBlocksHostWrites verifies that when bwrap is unavailable,
// the Landlock fallback prevents writes to host filesystem.
func TestLandlockBlocksHostWrites(t *testing.T) {
	// Skip if Landlock not available
	if err := LandlockProbe(); err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}

	home := sandboxTempDir(t)
	t.Setenv("HOME", home)
	testFile := filepath.Join(home, ".lnta-landlock-write-test")
	defer os.Remove(testFile)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := runLandlock(ctx, `echo data > "$HOME/.lnta-landlock-write-test"`, home, 15*time.Second)

	if err == nil && res.ExitCode == 0 {
		t.Fatalf("expected write to $HOME to be blocked; got exit=%d out=%q", res.ExitCode, res.Stdout)
	}
	if _, statErr := os.Stat(testFile); !os.IsNotExist(statErr) {
		t.Fatalf("file was written to host $HOME despite Landlock: %v", statErr)
	}
	t.Logf("Landlock write blocked: exit=%d err=%v stderr=%q", res.ExitCode, err, res.Stderr)
}

// TestLandlockBlocksHostTmp verifies the Landlock fallback /tmp is isolated.
func TestLandlockBlocksHostTmp(t *testing.T) {
	if err := LandlockProbe(); err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}

	home := sandboxTempDir(t)
	t.Setenv("HOME", home)
	hostTmp := filepath.Join(t.TempDir(), "outside-write")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := runLandlock(ctx, "echo data > "+shellQuote(hostTmp), home, 15*time.Second)
	if err == nil && res.ExitCode == 0 {
		t.Fatalf("expected write outside the sandbox tmp directory to be blocked: exit=%d", res.ExitCode)
	}
	if _, statErr := os.Stat(hostTmp); !os.IsNotExist(statErr) {
		t.Fatalf("Landlock wrote outside its private tmp directory: %v", statErr)
	}
}

// TestLandlockMasksSSH verifies $HOME/.ssh is blocked by Landlock.
func TestLandlockMasksSSH(t *testing.T) {
	if err := LandlockProbe(); err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}

	home := sandboxTempDir(t)
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("setup .ssh dir: %v", err)
	}
	secret := filepath.Join(sshDir, ".lnta-landlock-secret")
	if err := os.WriteFile(secret, []byte("super-secret-lnta-value"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := runLandlock(ctx, `cat "$HOME/.ssh/.lnta-landlock-secret"`, home, 15*time.Second)

	// Landlock should block access to ~/.ssh with EACCES
	if err == nil && res.ExitCode == 0 && contains(res.Stdout, "super-secret-lnta-value") {
		t.Fatalf("Landlock leaked $HOME/.ssh content: %q", res.Stdout)
	}
	t.Logf("Landlock SSH blocked: exit=%d err=%v stderr=%q", res.ExitCode, err, res.Stderr)
}

// TestLandlockAllowsReadSystemDirs verifies Landlock allows reading /usr, /etc, etc.
func TestLandlockAllowsReadSystemDirs(t *testing.T) {
	if err := LandlockProbe(); err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}
	home := sandboxTempDir(t)
	t.Setenv("HOME", home)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Should be able to read /etc/passwd
	res, err := runLandlock(ctx, `cat /etc/passwd | head -1`, home, 15*time.Second)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("expected read of /etc/passwd to succeed: exit=%d err=%v stderr=%q", res.ExitCode, err, res.Stderr)
	}
	if !contains(res.Stdout, "root:") {
		t.Fatalf("expected /etc/passwd content, got %q", res.Stdout)
	}
	t.Logf("Landlock read /etc/passwd: OK")
}

// TestLandlockAllowsTmpWrite verifies Landlock allows writing to /tmp.
func TestLandlockAllowsTmpWrite(t *testing.T) {
	if err := LandlockProbe(); err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}
	home := sandboxTempDir(t)
	t.Setenv("HOME", home)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := runLandlock(ctx, `echo "test" > "$TMPDIR/landlock-test" && cat "$TMPDIR/landlock-test"`, home, 15*time.Second)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("expected write to /tmp to succeed: exit=%d err=%v stderr=%q", res.ExitCode, err, res.Stderr)
	}
	if !contains(res.Stdout, "test") {
		t.Fatalf("expected 'test' in output, got %q", res.Stdout)
	}
	t.Logf("Landlock write /tmp: OK")
}

// TestRunReadOnlyUsesOperationalBackend exercises automatic backend selection
// where at least one complete sandbox path is operational.
func TestRunReadOnlyUsesOperationalBackend(t *testing.T) {
	home := sandboxTempDir(t)
	t.Setenv("HOME", home)
	if bwrapErr := probeBwrap(); bwrapErr != nil {
		if err := ProbeLandlockExecution(3 * time.Second); err != nil {
			t.Skipf("no operational sandbox backend: Bubblewrap: %v; Landlock: %v", bwrapErr, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := RunReadOnly(ctx, `echo "fallback test"`, home, 15*time.Second)
	if err != nil {
		t.Fatalf("expected an operational backend: exit=%d err=%v stderr=%q", res.ExitCode, err, res.Stderr)
	}
	if res.ExitCode != 0 {
		t.Fatalf("RunReadOnly failed: exit=%d err=%v stderr=%q", res.ExitCode, err, res.Stderr)
	}
	t.Logf("RunReadOnly: exit=%d backend=%v", res.ExitCode, err)
}

// contains checks if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
