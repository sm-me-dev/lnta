// Package transport provides the SSHExecutor implementation of TargetExecutor
// for remote command execution over system ssh command.
package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sm-me/lnta/internal/sandbox"
)

// SSHExecutor executes commands and file operations on a remote host via system ssh command.
type SSHExecutor struct {
	user       string
	host       string
	port       int
	runID      string
	cwd        string
	connMux    sync.Mutex
	fingerprint *RemoteFingerprint
}

// NewSSHExecutor creates a new SSHExecutor for the given target.
// Target format: user@host[:port] (port defaults to 22).
func NewSSHExecutor(target, runID, cwd string) (*SSHExecutor, error) {
	userHostPort := target
	user := ""
	host := ""
	port := 22

	// Parse user@host:port
	if at := strings.LastIndex(userHostPort, "@"); at != -1 {
		user = userHostPort[:at]
		userHostPort = userHostPort[at+1:]
	}
	if colon := strings.LastIndex(userHostPort, ":"); colon != -1 {
		host = userHostPort[:colon]
		if p, err := strconv.Atoi(userHostPort[colon+1:]); err == nil {
			port = p
		}
	} else {
		host = userHostPort
	}

	if user == "" || host == "" {
		return nil, fmt.Errorf("invalid SSH target %q: expected user@host[:port]", target)
	}

	return &SSHExecutor{
		user:        user,
		host:        host,
		port:        port,
		runID:       runID,
		cwd:         cwd,
	}, nil
}

// Preflight performs one-time remote fingerprinting and connection validation.
func (e *SSHExecutor) Preflight(ctx context.Context) error {
	// Since we use system ssh, just parse available info
	// We'll set a basic fingerprint from the SSH connection attempt
	if e.fingerprint != nil {
		return nil
	}

	// Try to execute the fingerprint command via system ssh
	fpCmd := `source /etc/os-release 2>/dev/null; echo "OS_RELEASE_ID=$ID"; echo "PATH=$PATH"; echo "UID=$(id -u)"; echo "GID=$(id -g)"; echo "USER=$(whoami)"; for b in bwrap systemctl desktop-file-validate ss ufw git; do command -v "$b" >/dev/null && echo "BIN:$b=1" || echo "BIN:$b=0"; done`

	result, err := runSystemSSH(ctx, e.user, e.host, strconv.Itoa(e.port), fpCmd, 15*time.Second)
	if err != nil {
		e.fingerprint = nil
		return fmt.Errorf("preflight failed: could not fingerprint remote host: %w", err)
	}

	fp := &RemoteFingerprint{
		Host:            fmt.Sprintf("%s@%s:%d", e.user, e.host, e.port),
		OSRelease:       make(map[string]string),
		Path:            "",
		UID:             0,
		GID:             0,
		Username:        "",
		Binaries:        make(map[string]bool),
		HasBwrap:        false,
		FingerprintedAt: time.Now(),
	}

	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "OS_RELEASE_ID=") {
			fp.OSRelease["ID"] = strings.TrimPrefix(line, "OS_RELEASE_ID=")
		} else if strings.HasPrefix(line, "PATH=") {
			fp.Path = strings.TrimPrefix(line, "PATH=")
		} else if strings.HasPrefix(line, "UID=") {
			if u, err := strconv.Atoi(strings.TrimPrefix(line, "UID=")); err == nil {
				fp.UID = u
			}
		} else if strings.HasPrefix(line, "GID=") {
			if g, err := strconv.Atoi(strings.TrimPrefix(line, "GID=")); err == nil {
				fp.GID = g
			}
		} else if strings.HasPrefix(line, "USER=") {
			fp.Username = strings.TrimPrefix(line, "USER=")
		} else if strings.HasPrefix(line, "BIN:") {
			parts := strings.SplitN(strings.TrimPrefix(line, "BIN:"), "=", 2)
			if len(parts) == 2 {
				fp.Binaries[parts[0]] = parts[1] == "1"
				if parts[0] == "bwrap" && parts[1] == "1" {
					fp.HasBwrap = true
				}
			}
		}
	}

	e.fingerprint = fp
	if e.fingerprint == nil {
		return fmt.Errorf("preflight failed: could not fingerprint remote host")
	}
	return nil
}

// RunReadOnly executes a read-only command on the remote host.
func (e *SSHExecutor) RunReadOnly(ctx context.Context, cmdStr string, cwd string, timeout time.Duration) (sandbox.CommandResult, error) {
	remoteCmd := e.buildRemoteCommand(cmdStr)
	result, err := runSystemSSH(ctx, e.user, e.host, strconv.Itoa(e.port), remoteCmd, timeout)
	if err != nil {
		return sandbox.CommandResult{}, err
	}

	return sandbox.CommandResult{
		Stdout:    result.Stdout,
		Stderr:    result.Stderr,
		ExitCode:  result.ExitCode,
		Duration:  result.Duration,
		Truncated: result.Truncated,
	}, nil
}

// buildRemoteCommand wraps the command for remote execution with sandboxing if bwrap available.
func (e *SSHExecutor) buildRemoteCommand(cmdStr string) string {
	if e.fingerprint != nil && e.fingerprint.HasBwrap {
		// Use bwrap for sandboxed execution on remote
		return fmt.Sprintf("bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --unshare-net --unshare-ipc --unshare-pid --new-session --die-with-parent -- sh -c %s", shellQuote(cmdStr))
	}
	// Fallback: strict non-interactive shell
	return fmt.Sprintf("sh -c %s", shellQuote(cmdStr))
}

// shellQuote safely quotes a string for use in a shell command.
func shellQuote(s string) string {
	// Use single quotes, escaping any embedded single quotes
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// runSystemSSH executes a command on the remote host via system ssh.
func runSystemSSH(ctx context.Context, user, host, port, cmdStr string, timeout time.Duration) (sshResult, error) {
	sshCmd := exec.CommandContext(ctx, "ssh",
		"-o", "BatchMode=yes",
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=~/.cache/lnta/ssh-%r@%h:%p",
		"-o", "ControlPersist=60s",
		"-o", "StrictHostKeyChecking=accept-new",
		"-p", port,
		fmt.Sprintf("%s@%s", user, host),
		cmdStr,
	)
	sshCmd.Stdin = nil

	var stdout, stderr bytes.Buffer
	sshCmd.Stdout = &stdout
	sshCmd.Stderr = &stderr

	start := time.Now()
	err := sshCmd.Run()
	duration := time.Since(start)

	var exitCode int
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 126
		}
	}

	const maxOutputBytes = 16 * 1024
	out := truncateOutput(stdout.String(), maxOutputBytes)
	errOut := truncateOutput(stderr.String(), maxOutputBytes)
	truncated := len(out) < len(stdout.String()) || len(errOut) < len(stderr.String())

	return sshResult{
		Stdout:    out,
		Stderr:    errOut,
		ExitCode:  exitCode,
		Duration:  duration,
		Truncated: truncated,
	}, nil
}

// truncateOutput caps output at maxBytes.
func truncateOutput(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	marker := fmt.Sprintf("\n\n[OUTPUT TRUNCATED: %d total bytes]\n", len(s))
	keep := maxBytes - len(marker)
	if keep < 0 {
		keep = 0
	}
	return s[:keep] + marker
}

// CommandResult mirrors sandbox.CommandResult for transport package.
type CommandResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Truncated bool
}

// sshResult holds the result of an SSH command execution.
type sshResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Truncated bool
}

// ReadFile reads a file from the remote host using system ssh.
func (e *SSHExecutor) ReadFile(ctx context.Context, path string) ([]byte, os.FileInfo, error) {
	cmd := fmt.Sprintf("cat %s; echo '---LNTA-STAT---'; stat -c '%%a %%U %%G %%s %%Y %%n' %s", shellQuote(path), shellQuote(path))
	result, err := runSystemSSH(ctx, e.user, e.host, strconv.Itoa(e.port), cmd, 30*time.Second)
	if err != nil {
		return nil, nil, err
	}

	parts := strings.Split(result.Stdout, "---LNTA-STAT---")
	if len(parts) < 2 {
		return []byte(strings.TrimSpace(parts[0])), nil, nil
	}

	content := []byte(strings.TrimSuffix(parts[0], "\n"))
	statLine := strings.TrimSpace(parts[1])

	statParts := strings.Fields(statLine)
	if len(statParts) < 5 {
		return content, nil, nil
	}

	mode, _ := strconv.ParseUint(statParts[0], 8, 32)
	size, _ := strconv.ParseInt(statParts[3], 10, 64)
	mtime, _ := strconv.ParseInt(statParts[4], 10, 64)

	return content, &remoteFileInfo{
		name:    filepath.Base(path),
		size:    size,
		mode:    os.FileMode(mode),
		modTime: time.Unix(mtime, 0),
		isDir:   false,
	}, nil
}

// remoteFileInfo implements os.FileInfo for remote files.
type remoteFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
}

func (r *remoteFileInfo) Name() string       { return r.name }
func (r *remoteFileInfo) Size() int64        { return r.size }
func (r *remoteFileInfo) Mode() os.FileMode  { return r.mode }
func (r *remoteFileInfo) ModTime() time.Time { return r.modTime }
func (r *remoteFileInfo) IsDir() bool        { return r.isDir }
func (r *remoteFileInfo) Sys() interface{}   { return nil }

// WriteFile writes a file to the remote host, creating a local snapshot first.
func (e *SSHExecutor) WriteFile(ctx context.Context, path string, content []byte, mode os.FileMode) (string, os.FileInfo, error) {
	// 1. Read original file for snapshot (if exists)
	var originalContent []byte
	var originalMode os.FileMode = 0o644
	var existed bool

	if _, err := e.StatFile(ctx, path); err == nil {
		existed = true
		origContent, info, err := e.ReadFile(ctx, path)
		if err == nil {
			originalContent = origContent
			originalMode = info.Mode()
		}
	}

	// 2. Save snapshot LOCALLY
	if err := e.saveRemoteSnapshot(path, originalContent, originalMode, existed); err != nil {
		return "", nil, fmt.Errorf("save remote snapshot: %w", err)
	}

	// 3. Write new content via SSH
	writeCmd := fmt.Sprintf("cat > %s <<'LNTA_EOF'\n%s\nLNTA_EOF\nchmod %o %s",
		shellQuote(path), string(content), mode.Perm(), shellQuote(path))
	_, err := runSystemSSH(ctx, e.user, e.host, strconv.Itoa(e.port), writeCmd, 30*time.Second)
	if err != nil {
		return "", nil, fmt.Errorf("write remote file: %w", err)
	}

	// 4. Get updated file info
	info, err := e.StatFile(ctx, path)
	if err != nil {
		return "", nil, err
	}

	// Return resolved path (expand ~)
	resolved := path
	if len(resolved) > 0 && resolved[0] == '~' {
		home, _ := os.UserHomeDir()
		resolved = filepath.Join(home, resolved[1:])
	}
	resolved = filepath.Clean(resolved)

	return resolved, info, nil
}

// StatFile stats a file on the remote host.
func (e *SSHExecutor) StatFile(ctx context.Context, path string) (os.FileInfo, error) {
	cmd := fmt.Sprintf("stat -c '%%a %%U %%G %%s %%Y %%n' %s", shellQuote(path))
	result, err := runSystemSSH(ctx, e.user, e.host, strconv.Itoa(e.port), cmd, 10*time.Second)
	if err != nil {
		return nil, err
	}

	statLine := strings.TrimSpace(result.Stdout)
	statParts := strings.Fields(statLine)
	if len(statParts) < 5 {
		return nil, fmt.Errorf("invalid stat output: %s", statLine)
	}

	mode, _ := strconv.ParseUint(statParts[0], 8, 32)
	size, _ := strconv.ParseInt(statParts[3], 10, 64)
	mtime, _ := strconv.ParseInt(statParts[4], 10, 64)

	return &remoteFileInfo{
		name:    filepath.Base(path),
		size:    size,
		mode:    os.FileMode(mode),
		modTime: time.Unix(mtime, 0),
		isDir:   false,
	}, nil
}

// saveRemoteSnapshot saves a backup of a remote file locally before modification.
func (e *SSHExecutor) saveRemoteSnapshot(path string, content []byte, mode os.FileMode, existed bool) error {
	// Get snapshot root
	home, _ := os.UserHomeDir()
	snapRoot := filepath.Join(home, ".local", "share", "lnta", "snapshots")
	snapDir := filepath.Join(snapRoot, e.runID)

	// Remote-specific subdirectory: remote_user@host:port
	remoteDirName := fmt.Sprintf("remote_%s@%s:%d", e.user, e.host, e.port)
	remoteDir := filepath.Join(snapDir, remoteDirName)
	if err := os.MkdirAll(remoteDir, 0o700); err != nil {
		return err
	}

	// Generate backup blob name
	var shaHex string
	if len(content) > 0 {
		sum := sha256.Sum256(content)
		shaHex = hex.EncodeToString(sum[:8])
	} else {
		// For new files, generate random suffix
		b := make([]byte, 4)
		rand.Read(b)
		shaHex = hex.EncodeToString(b)
	}

	blobName := fmt.Sprintf("backup-%s.bin", shaHex)
	blobPath := filepath.Join(remoteDir, blobName)

	if existed && len(content) > 0 {
		if err := os.WriteFile(blobPath, content, 0o600); err != nil {
			return err
		}
	}

	// Update remote manifest
	manifestPath := filepath.Join(remoteDir, "manifest.json")
	var manifest remoteManifest
	if data, err := os.ReadFile(manifestPath); err == nil {
		if err := json.Unmarshal(data, &manifest); err != nil {
			manifest = remoteManifest{
				RunID:      e.runID,
				RemoteHost: fmt.Sprintf("%s@%s:%d", e.user, e.host, e.port),
				Entries:    []remoteManifestEntry{},
			}
		}
	} else {
		manifest = remoteManifest{
			RunID:      e.runID,
			RemoteHost: fmt.Sprintf("%s@%s:%d", e.user, e.host, e.port),
			Entries:    []remoteManifestEntry{},
		}
	}

	entry := remoteManifestEntry{
		Path:    path,
		Created: !existed,
		Mode:    fmt.Sprintf("%04o", mode),
		SHA256:  shaHex,
		Backup:  blobName,
	}
	manifest.Entries = append(manifest.Entries, entry)

	// Write manifest atomically
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(remoteDir, ".manifest.tmp")
	if err := os.WriteFile(tmp, manifestData, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, manifestPath)
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

// Close closes the SSH connection (no persistent connection for system ssh).
func (e *SSHExecutor) Close() error {
	// No persistent connection for system ssh command
	return nil
}

// TargetID returns the SSH target identifier.
func (e *SSHExecutor) TargetID() string {
	return fmt.Sprintf("%s@%s:%d", e.user, e.host, e.port)
}

// IsRemote returns true for SSH executor.
func (e *SSHExecutor) IsRemote() bool {
	return true
}

// RemoteFingerprint returns the cached fingerprint.
func (e *SSHExecutor) RemoteFingerprint() *RemoteFingerprint {
	return e.fingerprint
}