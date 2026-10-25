package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestScopedWriteRejectsEmptyAllowlistAndSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if _, err := ScopedWriteFile("run-empty-scope", target, []byte("x"), nil); err == nil {
		t.Fatal("empty write allowlist unexpectedly permitted a write")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}
	_, err := ScopedWriteFile("run-symlink-target", target, []byte("replace"), []string{filepath.Join(dir, "*")})
	if err == nil {
		t.Fatal("symlink target unexpectedly permitted a write")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "keep" {
		t.Fatalf("outside target changed: content=%q error=%v", got, err)
	}
}

func TestScopedWriteRejectsParentSymlinkEscapeAndHardLinks(t *testing.T) {
	base := t.TempDir()
	inside := filepath.Join(base, "inside")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "parent")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(snapshotDir("run-parent-link"))
	_, err := ScopedWriteFile("run-parent-link", filepath.Join(link, "file"), []byte("x"), []string{filepath.Join(inside, "*")})
	if err != nil {
		t.Fatalf("canonical in-scope parent symlink should resolve safely: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	_, err = ScopedWriteFile("run-parent-escape", filepath.Join(link, "escape"), []byte("x"), []string{filepath.Join(inside, "*")})
	if err == nil {
		t.Fatal("parent symlink escaping the allowed root was accepted")
	}

	target := filepath.Join(inside, "linked")
	alias := filepath.Join(inside, "alias")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, alias); err != nil {
		t.Fatal(err)
	}
	_, err = ScopedWriteFile("run-hardlink", target, []byte("replacement"), []string{filepath.Join(inside, "*")})
	if err == nil || !strings.Contains(err.Error(), "multiple hard links") {
		t.Fatalf("hard-linked target was not rejected: %v", err)
	}
}

func TestScopedWriteApprovalPreviewDetectsConcurrentMutation(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config")
	if err := os.WriteFile(target, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	allowed := []string{filepath.Join(dir, "*")}
	preview, err := PreviewScopedWrite(target, []byte("approved"), allowed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("external change"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, err = ScopedWriteFileApproved("run-preview-race", target, []byte("approved"), allowed, &preview)
	if err == nil || !strings.Contains(err.Error(), "changed after approval") {
		t.Fatalf("stale approval was not rejected: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "external change" {
		t.Fatalf("concurrent content was overwritten: %q", got)
	}
}

func TestScopedWriteUsesRequestedCreateModeAndRollbackRejectsConflict(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "new")
	allowed := []string{filepath.Join(dir, "*")}
	runID := "run-mode-conflict"
	defer os.RemoveAll(snapshotDir(runID))
	diff, err := ScopedWriteFileApprovedMode(runID, target, []byte("created"), 0o600, allowed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Mode.Perm() != 0o600 {
		t.Fatalf("reported mode = %o, want 600", diff.Mode.Perm())
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("created mode = %v, error=%v", info, err)
	}
	if err := os.WriteFile(target, []byte("external"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RollbackRun(runID); err == nil || !strings.Contains(err.Error(), "concurrent modification") {
		t.Fatalf("rollback conflict was not surfaced: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "external" {
		t.Fatalf("rollback overwrote external content: %q, %v", got, err)
	}
}

func TestScopedWriteConcurrentWritersLeaveCompleteContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "shared")
	allowed := []string{filepath.Join(dir, "*")}
	const workers = 8
	for i := 0; i < workers; i++ {
		defer os.RemoveAll(snapshotDir(fmt.Sprintf("run-concurrent-%d", i)))
	}
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := ScopedWriteFile(fmt.Sprintf("run-concurrent-%d", i), target, []byte(strings.Repeat(string(rune('a'+i)), 10000)), allowed)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write failed: %v", err)
		}
	}
	got, err := os.ReadFile(target)
	if err != nil || len(got) != 10000 {
		t.Fatalf("concurrent write left partial content: size=%d error=%v", len(got), err)
	}
	for _, b := range got {
		if b != got[0] {
			t.Fatal("concurrent write left mixed content")
		}
	}
}

func TestLandlockRequiresCompleteNetworkConfinementABI(t *testing.T) {
	if err := checkLandlockABI(minLandlockABI - 1); !errors.Is(err, ErrLandlockUnavailable) {
		t.Fatalf("ABI below minimum accepted: %v", err)
	}
	if err := checkLandlockABI(minLandlockABI); err != nil {
		t.Fatalf("minimum supported ABI rejected: %v", err)
	}
}

func TestLandlockFallbackDoesNotExposeHostProcfs(t *testing.T) {
	cwd := t.TempDir()
	cfg, err := buildLandlockConfig(cwd, t.TempDir(), t.TempDir(), "true", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range cfg.RODirs {
		if dir == "/proc" {
			t.Fatal("Landlock fallback exposes host procfs")
		}
	}
}

func TestScopedWriteRejectsUnboundedDiffInput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "large")
	_, err := PreviewScopedWrite(target, bytes.Repeat([]byte{'x'}, maxScopedFileBytes+1), []string{filepath.Join(dir, "*")})
	if err == nil || !strings.Contains(err.Error(), "limited") {
		t.Fatalf("oversized write preview was not rejected: %v", err)
	}
}
