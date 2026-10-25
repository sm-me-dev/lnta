// Package sandbox provides a transactional, scope-checked file writer with an
// undo log, plus bwrap-based read-only sandboxed execution.
//
// See AGENTS.md "Architectural Non-Negotiables".
package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sm-me-dev/lnta/internal/audit"
)

// dataRoot returns ~/.local/share/lnta (sandbox-local mirror of audit's helper).
func dataRoot() string {
	if h := os.Getenv("HOME"); h != "" {
		return filepath.Join(h, ".local", "share", "lnta")
	}
	if u, err := os.UserHomeDir(); err == nil {
		return filepath.Join(u, ".local", "share", "lnta")
	}
	return filepath.Join(".local", "share", "lnta")
}

// snapshotRoot returns ~/.local/share/lnta/snapshots.
func snapshotRoot() string {
	return filepath.Join(dataRoot(), "snapshots")
}

// snapshotDir returns the snapshot directory for a run id.
func snapshotDir(runID string) string {
	return filepath.Join(snapshotRoot(), runID)
}

// manifestPath returns the manifest file for a run id.
func manifestPath(runID string) string {
	return filepath.Join(snapshotDir(runID), "manifest.json")
}

// FileDiff describes the result of a ScopedWriteFile operation: what changed,
// the old/new content hashes, and a unified diff of old vs. new.
type FileDiff struct {
	Status     string      `json:"status"`
	TargetPath string      `json:"target_path"`
	Created    bool        `json:"created"`
	Mode       os.FileMode `json:"mode"` // new file permission bits
	OldMode    os.FileMode `json:"old_mode,omitempty"`
	OldSHA256  string      `json:"old_sha256,omitempty"`
	NewSHA256  string      `json:"new_sha256"`
	SizeOld    int64       `json:"size_old,omitempty"`
	SizeNew    int64       `json:"size_new"`
	Diff       string      `json:"diff,omitempty"`
}

// ScopeViolationError is returned when a target path resolves outside the
// active pack's allowed_paths. The caller must escalate to mutate_system for
// human approval rather than retrying automatically.
type ScopeViolationError struct {
	TargetPath   string
	Resolved     string
	AllowedGlobs []string
}

const (
	maxScopedFileBytes  = 1 << 20
	maxUnifiedDiffLines = 2000
)

// CheckDiffLimits keeps the LCS-based preview bounded for both trusted files
// and model-provided content. Oversized changes fail closed instead of
// producing a misleading partial diff or exhausting memory.
func CheckDiffLimits(oldContent, newContent []byte) error {
	if len(oldContent) > maxScopedFileBytes || len(newContent) > maxScopedFileBytes {
		return fmt.Errorf("scoped files are limited to %d bytes", maxScopedFileBytes)
	}
	lines := func(data []byte) int {
		if len(data) == 0 {
			return 0
		}
		count := bytes.Count(data, []byte{'\n'})
		if data[len(data)-1] != '\n' {
			count++
		}
		return count
	}
	if lines(oldContent)+lines(newContent) > maxUnifiedDiffLines {
		return fmt.Errorf("scoped file diff is limited to %d combined lines", maxUnifiedDiffLines)
	}
	return nil
}

func (e *ScopeViolationError) Error() string {
	return fmt.Sprintf(
		"scope violation: %q resolves to %q which does not match any allowed path %v (escalate to mutate_system)",
		e.TargetPath, e.Resolved, e.AllowedGlobs,
	)
}

// manifestEntry is one row in a run's manifest.json.
// Path is stored relative to Root; Root is the directory that must be opened
// with os.OpenRoot before operating on Path. This confines rollback to a
// single directory and rejects absolute path escapes (C4).
type manifestEntry struct {
	Path       string `json:"path"`                  // relative to Root
	Root       string `json:"root"`                  // directory opened as the rollback root
	Created    bool   `json:"created"`               // true if the file was newly created
	Mode       string `json:"mode,omitempty"`        // octal permission string of the original
	SHA256     string `json:"sha256,omitempty"`      // hash of the original content
	PostSHA256 string `json:"post_sha256,omitempty"` // hash of the content written by LNTA
	Backup     string `json:"backup,omitempty"`      // backup blob file name within the snapshot dir
}

// manifestMu synchronizes manifest read-modify-write operations in-process.
var manifestMu sync.Mutex

var scopedWriteLocks sync.Map // map[canonical target path]*sync.Mutex

// manifest is the undo log for a single run.
type manifest struct {
	RunID   string          `json:"run_id"`
	Entries []manifestEntry `json:"entries"`
}

// splitLines splits content into lines, dropping a single trailing empty
// element produced by a final newline.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// edit is a single line operation produced by the line diff.
type edit struct {
	kind   rune // ' ' context, '-' delete, '+' insert
	oldIdx int  // 1-based index in old (context/delete), 0 for insert
	newIdx int  // 1-based index in new (context/insert), 0 for delete
	line   string
}

// diffLines computes an edit script transforming old into new using an LCS
// dynamic-programming table. Correct but O(m*n); fine for small config files.
func diffLines(old, new []string) []edit {
	m, n := len(old), len(new)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if old[i-1] == new[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	var rev []edit
	i, j := m, n
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && old[i-1] == new[j-1] {
			rev = append(rev, edit{' ', i, j, old[i-1]})
			i--
			j--
		} else if j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]) {
			rev = append(rev, edit{'+', 0, j, new[j-1]})
			j--
		} else {
			rev = append(rev, edit{'-', i, 0, old[i-1]})
			i--
		}
	}
	for a, z := 0, len(rev)-1; a < z; a, z = a+1, z-1 {
		rev[a], rev[z] = rev[z], rev[a]
	}
	return rev
}

// unifiedDiff returns a standard unified diff comparing oldContent vs
// newContent, labeled with oldPath/newPath.
func unifiedDiff(oldPath, newPath string, oldContent, newContent []byte) string {
	oldLines := splitLines(string(oldContent))
	newLines := splitLines(string(newContent))
	ops := diffLines(oldLines, newLines)

	const context = 3
	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n", oldPath)
	fmt.Fprintf(&b, "+++ b/%s\n", newPath)

	n := len(ops)
	i := 0
	for i < n {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		// Start of a change run.
		runStart := i
		for i < n && ops[i].kind != ' ' {
			i++
		}
		runEnd := i

		hStart := runStart - context
		if hStart < 0 {
			hStart = 0
		}
		hEnd := runEnd + context
		if hEnd > n {
			hEnd = n
		}
		hunk := ops[hStart:hEnd]

		oldStart, oldCount := hunkRange(hunk, true)
		newStart, newCount := hunkRange(hunk, false)
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
		for _, e := range hunk {
			b.WriteRune(e.kind)
			b.WriteString(e.line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// hunkRange computes the starting line number and count of old (or new) lines
// covered by a hunk. old=true counts context/delete lines; false counts
// context/insert lines.
func hunkRange(hunk []edit, old bool) (start, count int) {
	for _, e := range hunk {
		if old && (e.kind == ' ' || e.kind == '-') {
			if count == 0 {
				start = e.oldIdx
			}
			count++
		} else if !old && (e.kind == ' ' || e.kind == '+') {
			if count == 0 {
				start = e.newIdx
			}
			count++
		}
	}
	if old && count == 0 {
		// Pure insertion: convention starts at 0.
		start = 0
	}
	if !old && count == 0 {
		start = 0
	}
	return start, count
}

// resolveTarget cleans the target path, expands ~, resolves symlinks on the
// parent directory (defending against symlink-based path traversal), and
// returns the fully resolved path.
func resolveTarget(targetPath string) (string, error) {
	p := expandPath(targetPath)
	p, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("resolve target path: %w", err)
	}
	parent := filepath.Dir(p)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("resolve parent directory %q: %w", parent, err)
	}
	resolved := filepath.Join(resolvedParent, filepath.Base(p))
	return resolved, nil
}

// pathAllowed reports whether resolved matches at least one glob pattern.
func pathAllowed(resolved string, allowedGlobs []string) bool {
	for _, g := range allowedGlobs {
		matched, err := filepath.Match(g, resolved)
		if err != nil {
			// Malformed glob: ignore rather than crash.
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// PathAllowed is the exported wrapper of pathAllowed, used by the transport
// package to check a resolved target against the pack's allowed_paths.
func PathAllowed(resolved string, allowedGlobs []string) bool {
	return pathAllowed(resolved, allowedGlobs)
}

// appendManifestEntry reads (or creates) the run manifest, appends entry, and
// rewrites it atomically with locking and fsync.
func appendManifestEntry(runID string, entry manifestEntry) error {
	manifestMu.Lock()
	defer manifestMu.Unlock()

	snapDir := snapshotDir(runID)
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		return err
	}

	lockPath := filepath.Join(snapDir, ".lock")
	snapRoot, err := os.OpenRoot(snapDir)
	if err != nil {
		return fmt.Errorf("open snapshot directory: %w", err)
	}
	defer snapRoot.Close()
	lockFile, err := snapRoot.OpenFile(filepath.Base(lockPath), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open snapshot lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return fmt.Errorf("lock snapshot manifest: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
	}()

	m := manifest{RunID: runID}
	data, err := readRootFile(snapRoot, "manifest.json")
	if err == nil {
		if jerr := json.Unmarshal(data, &m); jerr != nil {
			return jerr
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read snapshot manifest: %w", err)
	}
	m.Entries = append(m.Entries, entry)
	return writeManifest(snapDir, m)
}

// writeManifest writes the manifest atomically via temp file + fsync + rename.
func writeManifest(snapDir string, m manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(snapDir)
	if err != nil {
		return fmt.Errorf("open snapshot directory: %w", err)
	}
	defer root.Close()
	tmp := fmt.Sprintf(".manifest.tmp-%d-%d", os.Getpid(), time.Now().UnixNano())
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmp, "manifest.json"); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	if dir, err := root.Open("."); err == nil {
		defer dir.Close()
		if err := dir.Sync(); err != nil {
			return fmt.Errorf("sync snapshot directory: %w", err)
		}
	}
	return nil
}

func writeSnapshotBlob(snapDir, blobName string, content []byte) error {
	root, err := os.OpenRoot(snapDir)
	if err != nil {
		return fmt.Errorf("open snapshot directory: %w", err)
	}
	defer root.Close()
	if info, err := root.Lstat(blobName); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("snapshot backup %q is not a regular file", blobName)
		}
		existing, err := readRootFile(root, blobName)
		if err != nil {
			return fmt.Errorf("read existing snapshot backup: %w", err)
		}
		if !bytes.Equal(existing, content) {
			return fmt.Errorf("snapshot backup name collision for %q", blobName)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect snapshot backup: %w", err)
	}
	f, err := root.OpenFile(blobName, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create snapshot backup: %w", err)
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		_ = root.Remove(blobName)
		return fmt.Errorf("write snapshot backup: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = root.Remove(blobName)
		return fmt.Errorf("sync snapshot backup: %w", err)
	}
	return f.Close()
}

// ScopedWriteFile atomically writes content to targetPath under the scope
// checks of the active instruction pack:
//
//   - ~ is expanded and the parent directory's symlinks are resolved
//     (filepath.EvalSymlinks) to defeat path traversal (../../etc/passwd).
//   - The resolved path must match at least one glob in allowedGlobs;
//     otherwise a ScopeViolationError is returned.
//   - If the file exists it is copied (content + mode + SHA-256) into the run
//     snapshot dir as a backup blob before being overwritten; a new file is
//     recorded with created: true so lnta undo <run_id> can delete it.
//   - A unified diff (FileDiff) is generated comparing old vs. new content.
//   - The write is atomic: temp file in the same directory + os.Rename.
//
// The manifest at ~/.local/share/lnta/snapshots/<run_id>/manifest.json is
// updated so RollbackRun can restore exact byte-for-byte state.
func ScopedWriteFile(runID string, targetPath string, content []byte, allowedGlobs []string) (FileDiff, error) {
	return ScopedWriteFileApproved(runID, targetPath, content, allowedGlobs, nil)
}

// ScopedWriteFileApproved additionally requires the current file state to
// match the diff shown during approval. A mismatch aborts before any write.
func ScopedWriteFileApproved(runID string, targetPath string, content []byte, allowedGlobs []string, expected *FileDiff) (FileDiff, error) {
	return ScopedWriteFileApprovedMode(runID, targetPath, content, 0o644, allowedGlobs, expected)
}

// ScopedWriteFileApprovedMode preserves an existing file's permission bits
// and applies requestedMode to newly created files.
func ScopedWriteFileApprovedMode(runID string, targetPath string, content []byte, requestedMode os.FileMode, allowedGlobs []string, expected *FileDiff) (FileDiff, error) {
	var diff FileDiff
	diff.Status = "FAILED"
	diff.TargetPath = targetPath
	if err := CheckDiffLimits(nil, content); err != nil {
		return diff, err
	}

	resolved, err := resolveTarget(targetPath)
	if err != nil {
		return diff, err
	}
	diff.TargetPath = resolved

	if !pathAllowed(resolved, allowedGlobs) {
		return diff, &ScopeViolationError{
			TargetPath:   targetPath,
			Resolved:     resolved,
			AllowedGlobs: allowedGlobs,
		}
	}
	if !runIDRE.MatchString(runID) || strings.Contains(runID, "..") {
		return diff, fmt.Errorf("invalid run id %q", runID)
	}
	lockValue, _ := scopedWriteLocks.LoadOrStore(resolved, &sync.Mutex{})
	pathLock := lockValue.(*sync.Mutex)
	pathLock.Lock()
	defer pathLock.Unlock()

	parentPath := filepath.Dir(resolved)
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return diff, fmt.Errorf("open target parent %q: %w", parentPath, err)
	}
	defer root.Close()
	// Re-resolve after opening the directory. If the parent was replaced by a
	// symlink between validation and open, reject instead of following it.
	resolvedAgain, err := filepath.EvalSymlinks(parentPath)
	if err != nil || filepath.Clean(resolvedAgain) != filepath.Clean(parentPath) {
		return diff, fmt.Errorf("target parent changed during validation")
	}
	parentFD, err := root.Open(".")
	if err != nil {
		return diff, fmt.Errorf("open target parent descriptor: %w", err)
	}
	defer parentFD.Close()
	openedParentInfo, err := root.Stat(".")
	if err != nil {
		return diff, fmt.Errorf("stat opened target parent: %w", err)
	}
	currentParentInfo, err := os.Stat(parentPath)
	if err != nil || !os.SameFile(openedParentInfo, currentParentInfo) {
		return diff, fmt.Errorf("target parent changed during validation")
	}
	if err := syscall.Flock(int(parentFD.Fd()), syscall.LOCK_EX); err != nil {
		return diff, fmt.Errorf("lock target parent: %w", err)
	}
	defer syscall.Flock(int(parentFD.Fd()), syscall.LOCK_UN)
	base := filepath.Base(resolved)

	snapDir := snapshotDir(runID)
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		return diff, err
	}

	fi, statErr := root.Lstat(base)
	if statErr != nil && !os.IsNotExist(statErr) {
		return diff, fmt.Errorf("inspect target %q: %w", resolved, statErr)
	}
	if statErr == nil && fi.Mode()&os.ModeSymlink != 0 {
		return diff, fmt.Errorf("target %q is a symlink; refusing to write", resolved)
	}
	exists := statErr == nil
	var oldContent []byte
	var oldMode os.FileMode = 0o644

	sum := sha256.Sum256(content)
	diff.NewSHA256 = hex.EncodeToString(sum[:])
	diff.SizeNew = int64(len(content))

	if exists {
		if !fi.Mode().IsRegular() {
			return diff, fmt.Errorf("target %q is not a regular file", resolved)
		}
		// Read backup with O_NOFOLLOW to avoid symlink races
		f, rerr := root.OpenFile(base, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if rerr != nil {
			return diff, fmt.Errorf("open target for backup %q: %w", resolved, rerr)
		}
		openedInfo, serr := f.Stat()
		if serr != nil || !os.SameFile(fi, openedInfo) {
			_ = f.Close()
			return diff, fmt.Errorf("target %q changed during validation", resolved)
		}
		oldContent, err = io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return diff, err
		}
		oldMode = fi.Mode().Perm()
		diff.Mode = oldMode
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
			return diff, fmt.Errorf("target %q has multiple hard links; refusing to replace it", resolved)
		}
		diff.OldMode = oldMode
		oldSum := sha256.Sum256(oldContent)
		diff.OldSHA256 = hex.EncodeToString(oldSum[:])
		if expected != nil && (expected.Created != diff.Created || expected.OldSHA256 != diff.OldSHA256 || expected.NewSHA256 != diff.NewSHA256 || expected.OldMode.Perm() != diff.OldMode.Perm() || expected.Mode.Perm() != diff.Mode.Perm() || expected.TargetPath != resolved) {
			return diff, fmt.Errorf("target changed after approval preview; no write was performed")
		}

		diff.SizeOld = int64(len(oldContent))
		if err := CheckDiffLimits(oldContent, content); err != nil {
			return diff, err
		}
		// Backup blob: original content, mode, hash recorded in manifest.
		blobName := fmt.Sprintf("backup-%x.bin", oldSum[:8])
		if err := writeSnapshotBlob(snapDir, blobName, oldContent); err != nil {
			return diff, err
		}
		if err := appendManifestEntry(runID, manifestEntry{
			Path:       filepath.Base(resolved),
			Root:       filepath.Dir(resolved),
			Created:    false,
			Mode:       fmt.Sprintf("%04o", oldMode),
			SHA256:     diff.OldSHA256,
			PostSHA256: diff.NewSHA256,
			Backup:     blobName,
		}); err != nil {
			return diff, err
		}
		diff.Status = "PREPARED"
	} else {
		diff.Created = true
		diff.Mode = requestedMode.Perm()
		if diff.Mode == 0 {
			diff.Mode = 0o644
		}
		if expected != nil && (expected.Created != diff.Created || expected.OldSHA256 != diff.OldSHA256 || expected.NewSHA256 != diff.NewSHA256 || expected.Mode.Perm() != diff.Mode.Perm() || expected.TargetPath != resolved) {
			return diff, fmt.Errorf("target changed after approval preview; no write was performed")
		}
		if err := appendManifestEntry(runID, manifestEntry{
			Path:       filepath.Base(resolved),
			Root:       filepath.Dir(resolved),
			Created:    true,
			PostSHA256: diff.NewSHA256,
		}); err != nil {
			return diff, err
		}
		diff.Status = "PREPARED"
	}

	diff.Diff = unifiedDiff(resolved, resolved, oldContent, content)

	// Atomic write: temp file in same directory, fsync, then rename.
	newMode := oldMode.Perm()
	if !exists {
		newMode = requestedMode.Perm()
		if newMode == 0 {
			newMode = 0o644
		}
	}
	tmpName := fmt.Sprintf(".lnta-tmp-%d-%d", os.Getpid(), time.Now().UnixNano())
	tf, err := root.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, newMode)
	if err != nil {
		return diff, err
	}
	if _, err := tf.Write(content); err != nil {
		_ = tf.Close()
		_ = root.Remove(tmpName)
		return diff, err
	}
	if err := tf.Chmod(newMode); err != nil {
		_ = tf.Close()
		_ = root.Remove(tmpName)
		return diff, fmt.Errorf("set target permissions: %w", err)
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		_ = root.Remove(tmpName)
		return diff, err
	}
	if err := tf.Close(); err != nil {
		_ = root.Remove(tmpName)
		return diff, err
	}
	if err := root.Rename(tmpName, base); err != nil {
		_ = root.Remove(tmpName)
		return diff, err
	}
	diff.Status = "INCOMPLETE"
	if err := parentFD.Sync(); err != nil {
		return diff, fmt.Errorf("sync target parent: %w", err)
	}
	verify, err := root.OpenFile(base, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return diff, fmt.Errorf("verify written target: %w", err)
	}
	written, err := io.ReadAll(verify)
	_ = verify.Close()
	if err != nil {
		return diff, fmt.Errorf("read back written target: %w", err)
	}
	writtenHash := sha256.Sum256(written)
	if hex.EncodeToString(writtenHash[:]) != diff.NewSHA256 {
		return diff, fmt.Errorf("written target verification failed: content hash mismatch")
	}
	diff.Mode = newMode
	diff.Status = "COMMITTED"

	audit.Log("fs.scoped_write", "", map[string]string{
		"path":    resolved,
		"created": fmt.Sprintf("%v", diff.Created),
		"sha256":  diff.NewSHA256,
		"run_id":  runID,
	})
	return diff, nil
}

// PreviewScopedWrite validates the target against allowedGlobs and computes the
// unified diff between the existing content and the proposed content, without
// writing anything to disk. It is used by the --dry-run CLI mode to show what
// would be written without persisting any change. A non-existent target is
// reported with Created: true.
func PreviewScopedWrite(targetPath string, content []byte, allowedGlobs []string) (FileDiff, error) {
	return PreviewScopedWriteMode(targetPath, content, 0o644, allowedGlobs)
}

// PreviewScopedWriteMode previews the permission mode that the atomic writer
// will apply to a newly created file.
func PreviewScopedWriteMode(targetPath string, content []byte, requestedMode os.FileMode, allowedGlobs []string) (FileDiff, error) {
	var diff FileDiff
	diff.TargetPath = targetPath
	if err := CheckDiffLimits(nil, content); err != nil {
		return diff, err
	}

	resolved, err := resolveTarget(targetPath)
	if err != nil {
		return diff, err
	}
	diff.TargetPath = resolved

	if !pathAllowed(resolved, allowedGlobs) {
		return diff, &ScopeViolationError{
			TargetPath:   targetPath,
			Resolved:     resolved,
			AllowedGlobs: allowedGlobs,
		}
	}

	fi, statErr := os.Lstat(resolved)
	exists := statErr == nil
	if exists && fi.Mode()&os.ModeSymlink != 0 {
		return diff, fmt.Errorf("target %q is a symlink; refusing to preview", resolved)
	}
	var oldContent []byte
	var oldMode os.FileMode = 0o644

	if exists {
		if !fi.Mode().IsRegular() {
			return diff, fmt.Errorf("target %q is not a regular file", resolved)
		}
		oldContent, err = os.ReadFile(resolved)
		if err != nil {
			return diff, err
		}
		if err := CheckDiffLimits(oldContent, content); err != nil {
			return diff, err
		}
		oldMode = fi.Mode().Perm()
		diff.OldMode = oldMode
		sum := sha256.Sum256(oldContent)
		diff.OldSHA256 = hex.EncodeToString(sum[:])
		diff.SizeOld = int64(len(oldContent))
	} else {
		diff.Created = true
	}

	sum := sha256.Sum256(content)
	diff.NewSHA256 = hex.EncodeToString(sum[:])
	diff.SizeNew = int64(len(content))
	diff.Diff = unifiedDiff(resolved, resolved, oldContent, content)

	// Mode reporting only; no write occurs.
	newMode := oldMode.Perm()
	if !exists {
		newMode = requestedMode.Perm()
		if newMode == 0 {
			newMode = 0o644
		}
	}
	diff.Mode = newMode
	return diff, nil
}

var runIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// RollbackRun restores every modified file from its backup blob and deletes
// every file recorded as created, using the manifest at
// ~/.local/share/lnta/snapshots/<run_id>/manifest.json. Entries are processed
// in reverse order; the snapshot directory is removed afterward. Wired to the
// `lnta undo <run_id>` CLI command.
//
// The manifest and run id are treated as hostile input: the run id is
// validated against a strict regex, every manifest path must be local
// (filepath.IsLocal), and no symlink is followed on restore. All snapshot
// reads are confined to an opened root directory (os.OpenRoot).
func RollbackRun(runID string) error {
	if !runIDRE.MatchString(runID) || strings.Contains(runID, "..") {
		return fmt.Errorf("invalid run id %q", runID)
	}
	snapDir := snapshotDir(runID)

	snapRoot, err := os.OpenRoot(snapDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No snapshot for this run, nothing to undo
		}
		return fmt.Errorf("open snapshot root %q: %w", snapDir, err)
	}
	defer snapRoot.Close()

	// 1. Process local manifest
	if err := rollbackLocalManifest(snapRoot, runID); err != nil {
		return err
	}

	// 2. Scan for remote manifests
	entries, err := os.ReadDir(snapDir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read snapshot dir %q: %w", snapDir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "remote_") {
			// Found remote manifest directory
			remoteDir := filepath.Join(snapDir, name)
			if err := rollbackRemoteManifest(runID, remoteDir, name); err != nil {
				return err
			}
		}
	}

	// Remove the snapshot directory after attempting all restores.
	if rerr := os.RemoveAll(snapDir); rerr != nil {
		return fmt.Errorf("remove snapshot dir %q: %w", snapDir, rerr)
	}

	audit.Log("fs.rollback", "", map[string]string{
		"run_id": runID,
	})
	return nil
}

// rollbackLocalManifest processes the local manifest.json, confined to snapRoot.
// Each entry's Path is relative to its Root; we open Root with os.OpenRoot and
// operate on Path relative to it, rejecting symlinks and .. escapes (C4).
func rollbackLocalManifest(snapRoot *os.Root, runID string) error {
	data, err := os.ReadFile(manifestPath(runID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No local manifest, that's OK
		}
		return fmt.Errorf("read manifest for run %q: %w", runID, err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse manifest for run %q: %w", runID, err)
	}

	// Restore in reverse order so later writes are undone first.
	for i := len(m.Entries) - 1; i >= 0; i-- {
		e := m.Entries[i]
		// Confine every path: Path must be local (no .. escape). Backup is
		// empty for newly created files, so skip it when empty.
		if !filepath.IsLocal(e.Path) || (e.Backup != "" && !filepath.IsLocal(e.Backup)) {
			return fmt.Errorf("manifest entry escapes root: %q / %q", e.Path, e.Backup)
		}
		if e.Root == "" {
			return fmt.Errorf("manifest entry %q has no root directory", e.Path)
		}
		targetRoot, err := os.OpenRoot(e.Root)
		if err != nil {
			return fmt.Errorf("open target root %q: %w", e.Root, err)
		}

		if e.Created {
			// A missing file means a previous rollback or interrupted operation
			// already removed it. Any other content change is a conflict.
			curBytes, rerr := readRootFile(targetRoot, e.Path)
			if os.IsNotExist(rerr) {
				targetRoot.Close()
				continue
			}
			if rerr != nil {
				targetRoot.Close()
				return fmt.Errorf("read created target %q: %w", e.Path, rerr)
			}
			curSum := sha256.Sum256(curBytes)
			if e.PostSHA256 != "" && hex.EncodeToString(curSum[:]) != e.PostSHA256 {
				targetRoot.Close()
				return fmt.Errorf("concurrent modification detected on %q: content changed since run %s", e.Path, runID)
			}
			fi, lerr := targetRoot.Lstat(e.Path)
			if lerr != nil || !fi.Mode().IsRegular() {
				targetRoot.Close()
				return fmt.Errorf("refusing to remove non-regular created target %q", e.Path)
			}
			if err := targetRoot.Remove(e.Path); err != nil && !os.IsNotExist(err) {
				targetRoot.Close()
				return fmt.Errorf("remove created file %q: %w", e.Path, err)
			}
			if _, err := targetRoot.Lstat(e.Path); !os.IsNotExist(err) {
				targetRoot.Close()
				return fmt.Errorf("verify removed created file %q: %v", e.Path, err)
			}
			targetRoot.Close()
			continue
		}
		// Modified file: restore backup blob with original mode.
		if e.Backup == "" {
			targetRoot.Close()
			continue
		}
		// M5: check if file was modified concurrently after run
		curBytes, rerr := readRootFile(targetRoot, e.Path)
		if rerr != nil {
			targetRoot.Close()
			return fmt.Errorf("cannot verify current target %q before rollback: %w", e.Path, rerr)
		}
		curSum := sha256.Sum256(curBytes)
		curHash := hex.EncodeToString(curSum[:])
		if e.SHA256 != "" && curHash == e.SHA256 {
			// Already restored, or the write-ahead entry was persisted before
			// the original write reached its atomic rename.
			targetRoot.Close()
			continue
		}
		if e.PostSHA256 != "" && curHash != e.PostSHA256 {
			targetRoot.Close()
			return fmt.Errorf("concurrent modification detected on %q: content changed since run %s", e.Path, runID)
		}
		// Read the backup through the opened snapshot root (no path escape).
		blob, rerr := readRootFile(snapRoot, e.Backup)
		if rerr != nil {
			targetRoot.Close()
			return fmt.Errorf("read backup blob %q: %w", e.Backup, rerr)
		}
		mode := os.FileMode(0o644)
		if e.Mode != "" {
			if v, perr := strconv.ParseUint(e.Mode, 8, 32); perr == nil {
				mode = os.FileMode(v)
			}
		}
		// Lstat the target through targetRoot: refuse to restore through a symlink.
		fi, lerr := targetRoot.Lstat(e.Path)
		if lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			targetRoot.Close()
			return fmt.Errorf("refusing to restore through symlink %q", e.Path)
		}
		// Write temp file in the same directory, then rename (atomic within root).
		dir := filepath.Dir(e.Path)
		tmp := filepath.Join(dir, fmt.Sprintf(".lnta-rollback-%d-%d", os.Getpid(), time.Now().UnixNano()))
		tf, werr := targetRoot.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
		if werr != nil {
			targetRoot.Close()
			return fmt.Errorf("write restore temp for %q: %w", e.Path, werr)
		}
		if _, werr := tf.Write(blob); werr != nil {
			tf.Close()
			targetRoot.Close()
			return fmt.Errorf("write restore temp for %q: %w", e.Path, werr)
		}
		if werr := tf.Chmod(mode.Perm()); werr != nil {
			tf.Close()
			targetRoot.Close()
			return fmt.Errorf("set restored permissions for %q: %w", e.Path, werr)
		}
		if werr := tf.Sync(); werr != nil {
			tf.Close()
			targetRoot.Close()
			return fmt.Errorf("sync restore temp for %q: %w", e.Path, werr)
		}
		tf.Close()
		if rerr := targetRoot.Rename(tmp, e.Path); rerr != nil {
			_ = targetRoot.Remove(tmp)
			targetRoot.Close()
			return fmt.Errorf("restore %q: %w", e.Path, rerr)
		}
		restored, verr := readRootFile(targetRoot, e.Path)
		if verr != nil {
			targetRoot.Close()
			return fmt.Errorf("verify restored target %q: %w", e.Path, verr)
		}
		restoredHash := sha256.Sum256(restored)
		if e.SHA256 != "" && hex.EncodeToString(restoredHash[:]) != e.SHA256 {
			targetRoot.Close()
			return fmt.Errorf("verify restored target %q: hash mismatch", e.Path)
		}
		restoredInfo, verr := targetRoot.Stat(e.Path)
		if verr != nil || restoredInfo.Mode().Perm() != mode.Perm() {
			targetRoot.Close()
			return fmt.Errorf("verify restored target %q: permission mode mismatch", e.Path)
		}
		targetRoot.Close()
	}
	return nil
}

// readRootFile reads a file relative to an opened root directory, confined to
// that root (no symlink or .. escape).
func readRootFile(root *os.Root, name string) ([]byte, error) {
	fd, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	return io.ReadAll(fd)
}

// rollbackRemoteManifest processes a remote manifest and restores files via SSH
// Uses direct SSH commands to avoid circular dependency with transport package.
func rollbackRemoteManifest(runID, remoteDir, dirName string) error {
	// Parse remote host from directory name: remote_user@host:port
	_ = strings.TrimPrefix(dirName, "remote_")
	manifestPath := filepath.Join(remoteDir, "manifest.json")

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read remote manifest %q: %w", manifestPath, err)
	}

	var m remoteManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse remote manifest %q: %w", manifestPath, err)
	}

	// Parse remote host string (user@host:port)
	parts := strings.Split(m.RemoteHost, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid remote host format: %s", m.RemoteHost)
	}
	user := parts[0]
	hostPort := parts[1]
	hostParts := strings.Split(hostPort, ":")
	host := hostParts[0]
	port := "22"
	if len(hostParts) > 1 {
		port = hostParts[1]
	}

	ctx := context.Background()

	// Process entries in reverse order
	for i := len(m.Entries) - 1; i >= 0; i-- {
		e := m.Entries[i]
		if e.Created {
			// Newly created file: delete it via SSH
			cmd := fmt.Sprintf("rm -f %s", shellQuote(e.Path))
			if err := runSSHDirect(ctx, user, host, port, cmd); err != nil {
				// Log but continue
				fmt.Fprintf(os.Stderr, "Warning: failed to delete remote file %q: %v\n", e.Path, err)
			}
			continue
		}
		// Modified file: restore backup blob
		if e.Backup == "" {
			continue
		}
		blobPath := filepath.Join(remoteDir, e.Backup)
		blob, rerr := os.ReadFile(blobPath)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to read backup blob %q: %v\n", e.Backup, rerr)
			continue
		}
		// Write blob back via SSH. Stream bytes over stdin; no heredoc parser
		// to confuse, so a backup blob containing "LNTA_EOF" cannot execute code.
		writeScript := fmt.Sprintf("cat > %s", shellQuote(e.Path))
		if err := runSSHDirectStdin(ctx, user, host, port, writeScript, bytes.NewReader(blob)); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to restore remote file %q: %v\n", e.Path, err)
		}
	}

	return nil
}

// runSSHDirect executes a command on a remote host via direct SSH call.
func runSSHDirect(ctx context.Context, user, host, port, cmd string) error {
	return runSSHDirectStdin(ctx, user, host, port, cmd, nil)
}

// runSSHDirectStdin executes a command on a remote host via direct SSH call,
// streaming stdin to the remote command's stdin (binary-safe, no heredoc).
// Validates the target to prevent option injection (C3) through manifest data.
func runSSHDirectStdin(ctx context.Context, user, host, port, cmd string, stdin io.Reader) error {
	if !sshUserRE.MatchString(user) || !sshHostRE.MatchString(host) || strings.HasPrefix(host, "-") {
		return fmt.Errorf("invalid ssh target %s@%s:%s", user, host, port)
	}
	if strings.Contains(host, "%") {
		return fmt.Errorf("ssh host %q contains %% (ControlPath token expansion)", host)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil || portInt < 1 || portInt > 65535 {
		return fmt.Errorf("invalid ssh port %q", port)
	}

	home, _ := os.UserHomeDir()
	controlDir := filepath.Join(home, ".cache", "lnta")
	if err := os.MkdirAll(controlDir, 0o700); err != nil {
		return fmt.Errorf("create ssh control dir %q: %w", controlDir, err)
	}
	if fi, err := os.Lstat(controlDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("ssh control dir %q is a symlink", controlDir)
		}
		if fi.Mode().Perm() != 0o700 {
			_ = os.Chmod(controlDir, 0o700)
		}
	}

	sshCmd := exec.CommandContext(ctx, "ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ControlMaster=no",
		"-o", fmt.Sprintf("ControlPath=%s/ssh-%%r@%%h:%%p", controlDir),
		"-p", strconv.Itoa(portInt),
		"--", user+"@"+host,
		cmd,
	)
	sshCmd.Stdin = stdin
	ConfigureProcessGroup(sshCmd)
	out := NewCappedBuffer(16*1024, 8<<20, nil)
	errOut := NewCappedBuffer(16*1024, 8<<20, nil)
	sshCmd.Stdout = out
	sshCmd.Stderr = errOut
	sshCmd.WaitDelay = 5 * time.Second

	started, err := StartChild("ssh_rollback", sshCmd)
	if err != nil {
		return err
	}
	return WaitChild("ssh_rollback", sshCmd, started, ctx, out, errOut)
}

// remoteManifest represents the undo log for remote files.
type remoteManifest struct {
	RunID      string                `json:"run_id"`
	RemoteHost string                `json:"remote_host"`
	Entries    []remoteManifestEntry `json:"entries"`
}

type remoteManifestEntry struct {
	Path    string `json:"path"`
	Created bool   `json:"created"`
	Mode    string `json:"mode,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Backup  string `json:"backup,omitempty"`
}

// shellQuote safely quotes a string for use in a shell command.
func shellQuote(s string) string {
	// Use single quotes, escaping any embedded single quotes
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

var (
	sshUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	sshHostRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

// SnapshotRoot returns the snapshot root directory (~/.local/share/lnta/snapshots).
// Exported for use by transport package.
func SnapshotRoot() string {
	return snapshotRoot()
}

// ComputeSHA256 computes the SHA-256 hash of data.
// Exported for use by transport package.
func ComputeSHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}
