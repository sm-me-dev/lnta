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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sm-me/lnta/internal/audit"
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

func (e *ScopeViolationError) Error() string {
	return fmt.Sprintf(
		"scope violation: %q resolves to %q which does not match any allowed path %v (escalate to mutate_system)",
		e.TargetPath, e.Resolved, e.AllowedGlobs,
	)
}

// manifestEntry is one row in a run's manifest.json.
type manifestEntry struct {
	Path    string `json:"path"`
	Created bool   `json:"created"`
	Mode    string `json:"mode,omitempty"`   // octal permission string of the original
	SHA256  string `json:"sha256,omitempty"` // hash of the original content
	Backup  string `json:"backup,omitempty"` // backup blob file name within the snapshot dir
}

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
	b.WriteString(fmt.Sprintf("--- a/%s\n", oldPath))
	b.WriteString(fmt.Sprintf("+++ b/%s\n", newPath))

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
	p = filepath.Clean(p)
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

// appendManifestEntry reads (or creates) the run manifest, appends entry, and
// rewrites it atomically.
func appendManifestEntry(runID string, entry manifestEntry) error {
	snapDir := snapshotDir(runID)
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		return err
	}
	m := manifest{RunID: runID}
	data, err := os.ReadFile(manifestPath(runID))
	if err == nil {
		if jerr := json.Unmarshal(data, &m); jerr != nil {
			return jerr
		}
	}
	m.Entries = append(m.Entries, entry)
	return writeManifest(snapDir, m)
}

// writeManifest writes the manifest atomically via temp file + rename.
func writeManifest(snapDir string, m manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(snapDir, ".manifest.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(snapDir, "manifest.json"))
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
	var diff FileDiff
	diff.TargetPath = targetPath

	resolved, err := resolveTarget(targetPath)
	if err != nil {
		return diff, err
	}

	if !pathAllowed(resolved, allowedGlobs) {
		return diff, &ScopeViolationError{
			TargetPath:   targetPath,
			Resolved:     resolved,
			AllowedGlobs: allowedGlobs,
		}
	}

	snapDir := snapshotDir(runID)
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		return diff, err
	}

	fi, statErr := os.Stat(resolved)
	exists := statErr == nil
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
		oldMode = fi.Mode().Perm()
		diff.OldMode = oldMode
		sum := sha256.Sum256(oldContent)
		diff.OldSHA256 = hex.EncodeToString(sum[:])

		// Backup blob: original content, mode, hash recorded in manifest.
		blobName := fmt.Sprintf("backup-%x.bin", sum[:8])
		if werr := os.WriteFile(filepath.Join(snapDir, blobName), oldContent, 0o600); werr != nil {
			return diff, werr
		}
		diff.SizeOld = int64(len(oldContent))
		if err := appendManifestEntry(runID, manifestEntry{
			Path:    resolved,
			Created: false,
			Mode:    fmt.Sprintf("%04o", oldMode),
			SHA256:  diff.OldSHA256,
			Backup:  blobName,
		}); err != nil {
			return diff, err
		}
	} else {
		diff.Created = true
		if err := appendManifestEntry(runID, manifestEntry{
			Path:    resolved,
			Created: true,
		}); err != nil {
			return diff, err
		}
	}

	sum := sha256.Sum256(content)
	diff.NewSHA256 = hex.EncodeToString(sum[:])
	diff.SizeNew = int64(len(content))
	diff.Diff = unifiedDiff(resolved, resolved, oldContent, content)

	// Atomic write: temp file in same directory, then rename.
	newMode := oldMode
	if !exists || newMode == 0 {
		newMode = 0o644
	}
	tmpName := filepath.Join(filepath.Dir(resolved),
		fmt.Sprintf(".lnta-tmp-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.WriteFile(tmpName, content, newMode); err != nil {
		return diff, err
	}
	if err := os.Rename(tmpName, resolved); err != nil {
		_ = os.Remove(tmpName)
		return diff, err
	}
	diff.Mode = newMode

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
	var diff FileDiff
	diff.TargetPath = targetPath

	resolved, err := resolveTarget(targetPath)
	if err != nil {
		return diff, err
	}

	if !pathAllowed(resolved, allowedGlobs) {
		return diff, &ScopeViolationError{
			TargetPath:   targetPath,
			Resolved:     resolved,
			AllowedGlobs: allowedGlobs,
		}
	}

	fi, statErr := os.Stat(resolved)
	exists := statErr == nil
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
	newMode := oldMode
	if !exists || newMode == 0 {
		newMode = 0o644
	}
	diff.Mode = newMode
	return diff, nil
}

// RollbackRun restores every modified file from its backup blob and deletes
// every file recorded as created, using the manifest at
// ~/.local/share/lnta/snapshots/<run_id>/manifest.json. Entries are processed
// in reverse order; the snapshot directory is removed afterward. Wired to the
// `lnta undo <run_id>` CLI command.
//
// Also processes remote manifests in remote_*/manifest.json subdirectories
// for SSH-based remote file operations.
func RollbackRun(runID string) error {
	snapDir := snapshotDir(runID)

	// 1. Process local manifest
	if err := rollbackLocalManifest(runID, snapDir); err != nil {
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

// rollbackLocalManifest processes the local manifest.json
func rollbackLocalManifest(runID, snapDir string) error {
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
		if e.Created {
			// Newly created file: delete it.
			if err := os.Remove(e.Path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove created file %q: %w", e.Path, err)
			}
			continue
		}
		// Modified file: restore backup blob with original mode.
		if e.Backup == "" {
			continue
		}
		blob, rerr := os.ReadFile(filepath.Join(snapDir, e.Backup))
		if rerr != nil {
			return fmt.Errorf("read backup blob %q: %w", e.Backup, rerr)
		}
		mode := os.FileMode(0o644)
		if e.Mode != "" {
			if v, perr := strconv.ParseUint(e.Mode, 8, 32); perr == nil {
				mode = os.FileMode(v)
			}
		}
		dir := filepath.Dir(e.Path)
		tmp := filepath.Join(dir, fmt.Sprintf(".lnta-rollback-%d-%d", os.Getpid(), time.Now().UnixNano()))
		if werr := os.WriteFile(tmp, blob, mode); werr != nil {
			return fmt.Errorf("write restore temp for %q: %w", e.Path, werr)
		}
		if rerr := os.Rename(tmp, e.Path); rerr != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("restore %q: %w", e.Path, rerr)
		}
	}
	return nil
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
		// Write blob back via SSH
		writeCmd := fmt.Sprintf("cat > %s <<'LNTA_EOF'\n%s\nLNTA_EOF", shellQuote(e.Path), string(blob))
		if err := runSSHDirect(ctx, user, host, port, writeCmd); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to restore remote file %q: %v\n", e.Path, err)
		}
	}

	return nil
}

// runSSHDirect executes a command on a remote host via direct SSH call.
func runSSHDirect(ctx context.Context, user, host, port, cmd string) error {
	sshCmd := exec.CommandContext(ctx, "ssh",
		"-o", "BatchMode=yes",
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=~/.cache/lnta/ssh-%r@%h:%p",
		"-o", "ControlPersist=60s",
		"-o", "StrictHostKeyChecking=accept-new",
		"-p", port,
		fmt.Sprintf("%s@%s", user, host),
		cmd,
	)
	sshCmd.Stdin = nil
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	return sshCmd.Run()
}

// remoteManifest represents the undo log for remote files.
type remoteManifest struct {
	RunID      string                  `json:"run_id"`
	RemoteHost string                  `json:"remote_host"`
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

var _ = bytes.MinRead