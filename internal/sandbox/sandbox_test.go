package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireBwrap(t *testing.T) {
	t.Helper()
	if err := SandboxAvailable(); err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
}

// TestRunReadOnlyBlocksHostWrites verifies the sandbox root is read-only:
// writing to $HOME fails inside the sandbox and nothing lands on the host.
func TestRunReadOnlyBlocksHostWrites(t *testing.T) {
	requireBwrap(t)
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sm-me"
	}
	testFile := filepath.Join(home, ".lnta-ro-write-test")
	defer os.Remove(testFile)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := RunReadOnly(ctx, `echo data > "$HOME/.lnta-ro-write-test"`, home, 15*time.Second)

	if err == nil && res.ExitCode == 0 {
		t.Fatalf("expected write to $HOME to be blocked; got exit=%d out=%q", res.ExitCode, res.Stdout)
	}
	if _, statErr := os.Stat(testFile); !os.IsNotExist(statErr) {
		t.Fatalf("file was written to host $HOME despite read-only sandbox: %v", statErr)
	}
	t.Logf("sandbox write blocked: exit=%d err=%v stderr=%q", res.ExitCode, err, res.Stderr)
}

// TestRunReadOnlyBlocksHostTmp verifies the sandbox /tmp is a private tmpfs:
// a file written to /tmp inside the sandbox never appears on the host /tmp.
func TestRunReadOnlyBlocksHostTmp(t *testing.T) {
	requireBwrap(t)
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sm-me"
	}
	hostTmp := filepath.Join(os.TempDir(), ".lnta-ro-tmp-test")
	defer os.Remove(hostTmp)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, _ := RunReadOnly(ctx, `echo data > /tmp/.lnta-ro-tmp-test`, home, 15*time.Second)
	if res.ExitCode != 0 {
		t.Fatalf("expected sandboxed write to /tmp to succeed (private tmpfs), got exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}

	if _, statErr := os.Stat(hostTmp); !os.IsNotExist(statErr) {
		t.Fatalf("sandbox /tmp write leaked to host /tmp: %v", statErr)
	}
}

// TestRunReadOnlyMasksSSH verifies $HOME/.ssh is masked inside the sandbox so
// credentials cannot be exfiltrated by a prompt-injected command.
func TestRunReadOnlyMasksSSH(t *testing.T) {
	requireBwrap(t)
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sm-me"
	}
	sshDir := filepath.Join(home, ".ssh")
	sshExisted := true
	if _, statErr := os.Stat(sshDir); os.IsNotExist(statErr) {
		if err := os.MkdirAll(sshDir, 0o700); err != nil {
			t.Fatalf("setup .ssh dir: %v", err)
		}
		sshExisted = false
	}
	secret := filepath.Join(sshDir, ".lnta-ro-secret")
	_ = os.WriteFile(secret, []byte("super-secret-lnta-value"), 0o600)
	defer func() {
		_ = os.Remove(secret)
		if !sshExisted {
			_ = os.Remove(sshDir)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := RunReadOnly(ctx, `cat "$HOME/.ssh/.lnta-ro-secret"`, home, 15*time.Second)

	if err == nil && res.ExitCode == 0 && strings.Contains(res.Stdout, "super-secret-lnta-value") {
		t.Fatalf("sandbox leaked $HOME/.ssh content: %q", res.Stdout)
	}
	t.Logf("ssh masked: exit=%d err=%v stderr=%q", res.ExitCode, err, res.Stderr)
}

// TestScopedWriteFileBlocksPathTraversal verifies that relative path traversal
// and symlink escapes are rejected with ScopeViolationError.
func TestScopedWriteFileBlocksPathTraversal(t *testing.T) {
	dir := t.TempDir()
	allowed := []string{filepath.Join(dir, "*")}

	// Relative traversal escapes the allowed tree.
	_, err := ScopedWriteFile("run-traversal", filepath.Join(dir, "..", "escape.txt"), []byte("bad"), allowed)
	var sve *ScopeViolationError
	if !errors.As(err, &sve) {
		t.Fatalf("expected ScopeViolationError for traversal, got %v", err)
	}

	// Symlink escape: dir/link -> / (or another dir outside), then write through it.
	outside := t.TempDir()
	linkDir := filepath.Join(dir, "linkdir")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Fatalf("setup symlink: %v", err)
	}
	target := filepath.Join(linkDir, "evil.txt")
	_, err = ScopedWriteFile("run-traversal", target, []byte("bad"), allowed)
	if !errors.As(err, &sve) {
		t.Fatalf("expected ScopeViolationError for symlink escape, got %v", err)
	}
}

// TestScopedWriteFileModifyAndRollback verifies snapshot creation and
// byte-for-byte restoration by RollbackRun.
func TestScopedWriteFileModifyAndRollback(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.toml")
	original := []byte("key = \"old\"\n")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	allowed := []string{filepath.Join(dir, "*")}
	runID := "run-rollback-modify"
	defer os.RemoveAll(snapshotDir(runID))

	diff, err := ScopedWriteFile(runID, target, []byte("key = \"new\"\n"), allowed)
	if err != nil {
		t.Fatalf("ScopedWriteFile: %v", err)
	}
	if diff.Created {
		t.Fatalf("expected created=false for existing file")
	}
	if diff.OldSHA256 == "" || diff.NewSHA256 == "" {
		t.Fatalf("expected sha256 hashes; old=%q new=%q", diff.OldSHA256, diff.NewSHA256)
	}
	if !strings.Contains(diff.Diff, "-key = \"old\"") || !strings.Contains(diff.Diff, "+key = \"new\"") {
		t.Fatalf("expected unified diff with removals/additions; got %q", diff.Diff)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read after write: %v", err)
	}
	if !bytes.Equal(got, []byte("key = \"new\"\n")) {
		t.Fatalf("expected new content, got %q", got)
	}

	// Snapshot must exist with a manifest recording path + root.
	man, err := os.ReadFile(manifestPath(runID))
	if err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	if !strings.Contains(string(man), filepath.Base(target)) {
		t.Fatalf("manifest does not record target path: %s", man)
	}
	if !strings.Contains(string(man), filepath.Dir(target)) {
		t.Fatalf("manifest does not record target root: %s", man)
	}

	if err := RollbackRun(runID); err != nil {
		t.Fatalf("RollbackRun: %v", err)
	}

	got2, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read after rollback: %v", err)
	}
	if !bytes.Equal(got2, original) {
		t.Fatalf("rollback did not restore original byte-for-byte: got %q want %q", got2, original)
	}
}

// TestScopedWriteFileNewFileAndRollback verifies created:true recording and
// deletion of newly created files by RollbackRun.
func TestScopedWriteFileNewFileAndRollback(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "newfile.txt")
	allowed := []string{filepath.Join(dir, "*")}
	runID := "run-rollback-newfile"
	defer os.RemoveAll(snapshotDir(runID))

	diff, err := ScopedWriteFile(runID, target, []byte("hello\n"), allowed)
	if err != nil {
		t.Fatalf("ScopedWriteFile: %v", err)
	}
	if !diff.Created {
		t.Fatalf("expected created=true for new file")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected new file to exist: %v", err)
	}

	if err := RollbackRun(runID); err != nil {
		t.Fatalf("RollbackRun: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("expected new file to be deleted after rollback, stat=%v", err)
	}
}
