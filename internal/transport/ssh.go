// Package transport provides the SSHExecutor implementation of TargetExecutor
// for remote command execution over system ssh command.
package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sm-me-dev/lnta/internal/sandbox"
)

// SSHExecutor executes commands and file operations on a remote host via system ssh command.
type SSHExecutor struct {
	user        string
	host        string
	port        int
	runID       string
	cwd         string
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

	if err := validateSSHTarget(user, host, port); err != nil {
		return nil, err
	}

	return &SSHExecutor{
		user:  user,
		host:  host,
		port:  port,
		runID: runID,
		cwd:   cwd,
	}, nil
}

// Preflight performs one-time remote fingerprinting and connection validation.
func (e *SSHExecutor) Preflight(ctx context.Context) error {
	if e.fingerprint != nil {
		if !e.fingerprint.HasBwrap {
			return fmt.Errorf("remote sandbox unavailable: %s", e.fingerprint.SandboxError)
		}
		return nil
	}

	// Try to execute the fingerprint command via system ssh
	fpCmd := `(. /etc/os-release 2>/dev/null || true); printf 'OS_RELEASE_ID=%s\nPATH=%s\nHOME=%s\nUID=%s\nGID=%s\nUSER=%s\n' "${ID:-}" "$PATH" "$HOME" "$(id -u)" "$(id -g)" "$(id -un)"; for b in bwrap python3 systemctl desktop-file-validate ss ufw git; do command -v "$b" >/dev/null 2>&1 && echo "BIN:$b=1" || echo "BIN:$b=0"; done`

	result, err := runSystemSSH(ctx, e.user, e.host, strconv.Itoa(e.port), fpCmd, nil, 15*time.Second)
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
		} else if strings.HasPrefix(line, "HOME=") {
			fp.Home = strings.TrimPrefix(line, "HOME=")
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
			}
		}
	}

	// Presence is not capability. Execute the required isolation profile and
	// fail closed if user namespaces, networking isolation, or mounts cannot
	// be established on the remote host.
	if !fp.Binaries["bwrap"] {
		fp.SandboxError = "bubblewrap is not installed"
	} else if !filepath.IsAbs(fp.Home) || filepath.Clean(fp.Home) != fp.Home {
		fp.SandboxError = "remote home directory is missing or invalid"
	} else {
		probe := `bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /var/tmp --tmpfs /run --unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts --cap-drop ALL --new-session --die-with-parent --clearenv --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin -- /bin/sh -c 'test -r /etc/os-release'`
		if _, probeErr := runSystemSSH(ctx, e.user, e.host, strconv.Itoa(e.port), probe, nil, 15*time.Second); probeErr != nil {
			fp.SandboxError = "bubblewrap capability probe failed (required namespaces or mounts unavailable)"
		} else {
			fp.HasBwrap = true
		}
	}

	e.fingerprint = fp
	if !fp.HasBwrap {
		return fmt.Errorf("remote sandbox unavailable: %s", fp.SandboxError)
	}
	return nil
}

// RunReadOnly executes a read-only command on the remote host.
func (e *SSHExecutor) RunReadOnly(ctx context.Context, cmdStr string, projectRoot, cwd string, timeout time.Duration) (sandbox.CommandResult, error) {
	return e.RunReadOnlyEnv(ctx, cmdStr, projectRoot, cwd, timeout, nil)
}

func (e *SSHExecutor) RunReadOnlyEnv(ctx context.Context, cmdStr string, projectRoot, cwd string, timeout time.Duration, extraEnv []string) (sandbox.CommandResult, error) {
	_ = projectRoot // project paths are local; remote execution is rooted by its remote CWD.
	if e.fingerprint == nil || !e.fingerprint.HasBwrap {
		return sandbox.CommandResult{}, fmt.Errorf("remote sandbox unavailable: run successful Preflight first")
	}
	remoteCmd, err := e.buildRemoteCommand(cmdStr, cwd, extraEnv)
	if err != nil {
		return sandbox.CommandResult{}, err
	}
	result, err := runSystemSSH(ctx, e.user, e.host, strconv.Itoa(e.port), remoteCmd, nil, timeout)
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
func (e *SSHExecutor) buildRemoteCommand(cmdStr, cwd string, extraEnv []string) (string, error) {
	if e.fingerprint == nil || !e.fingerprint.HasBwrap {
		return "", fmt.Errorf("remote sandbox unavailable: protected command refused")
	}
	if cwd == "" {
		cwd = e.cwd
	}
	if cwd == "" {
		cwd = e.fingerprint.Home
	}
	if !filepath.IsAbs(cwd) || filepath.Clean(cwd) != cwd {
		return "", fmt.Errorf("invalid remote working directory")
	}
	args := []string{"bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/var/tmp", "--tmpfs", "/run", "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL", "--new-session", "--die-with-parent", "--clearenv", "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "--setenv", "HOME", "/tmp/lnta-home", "--chdir", cwd}
	args = append(args, "--dir", "/tmp/lnta-home")
	for _, item := range extraEnv {
		key, value, ok := strings.Cut(item, "=")
		if !ok || !validSandboxEnvKey(key) || strings.ContainsRune(value, 0) {
			return "", fmt.Errorf("invalid sandbox environment entry")
		}
		args = append(args, "--setenv", key, value)
	}
	for _, secret := range []string{".ssh", ".gnupg", ".aws", ".kube", ".config/lnta", ".config/gcloud", ".azure"} {
		args = append(args, "--tmpfs", filepath.Join(e.fingerprint.Home, secret))
	}
	// Mask common credential/config files at the remote working directory.
	// --ro-bind-try makes absent paths harmless while overlaying existing files
	// with /dev/null inside the sandbox.
	for _, secret := range []string{".env", ".env.local", ".env.production", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".gitconfig", ".bashrc", ".bash_profile", ".zshrc", ".zprofile"} {
		args = append(args, "--ro-bind-try", "/dev/null", filepath.Join(cwd, secret))
	}
	args = append(args, "--", "/bin/sh", "-c", cmdStr)
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuote(arg)
	}
	return strings.Join(quoted, " "), nil
}

func validSandboxEnvKey(key string) bool {
	if key == "" || strings.ContainsAny(key, "=\x00") || key == "PATH" || key == "HOME" || key == "LD_PRELOAD" || key == "BASH_ENV" || key == "ENV" {
		return false
	}
	for i, r := range key {
		valid := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_' || (i > 0 && r >= '0' && r <= '9')
		if !valid {
			return false
		}
	}
	return true
}

// shellQuote safely quotes a string for use in a shell command.
func shellQuote(s string) string {
	// Use single quotes, escaping any embedded single quotes
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

var (
	// userRE matches a POSIX portable username (no leading dash, no metachars).
	userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// hostRE matches a DNS hostname or IPv4 literal (no leading dash, no %).
	hostRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

// validateSSHTarget rejects option-injection (user starting with -o), path
// traversal, and ControlPath token-expansion hosts (%).
func validateSSHTarget(user, host string, port int) error {
	if !userRE.MatchString(user) {
		return fmt.Errorf("invalid ssh user %q", user)
	}
	if !hostRE.MatchString(host) || strings.HasPrefix(host, "-") {
		return fmt.Errorf("invalid ssh host %q", host)
	}
	if strings.Contains(host, "%") {
		return fmt.Errorf("ssh host %q contains %% (ControlPath token expansion)", host)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid ssh port %d", port)
	}
	return nil
}

// runSystemSSH executes a command on the remote host via system ssh.
// stdin is streamed to the remote command's stdin (binary-safe; no heredoc).
// The timeout is enforced via context; output is capped; the error is returned
// so callers can distinguish transport failure from a non-zero exit code.
func runSystemSSH(ctx context.Context, user, host, port, cmdStr string, stdin io.Reader, timeout time.Duration) (sshResult, error) {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return sshResult{}, fmt.Errorf("invalid ssh port %q: %w", port, err)
	}

	if err := validateSSHTarget(user, host, portInt); err != nil {
		return sshResult{}, err
	}

	// Harden the SSH control socket directory: 0700, not a symlink, absolute.
	home, _ := os.UserHomeDir()
	controlDir := filepath.Join(home, ".cache", "lnta")
	if err := os.MkdirAll(controlDir, 0o700); err != nil {
		return sshResult{}, fmt.Errorf("create ssh control dir %q: %w", controlDir, err)
	}
	if fi, err := os.Lstat(controlDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return sshResult{}, fmt.Errorf("ssh control dir %q is a symlink", controlDir)
		}
		if fi.Mode().Perm() != 0o700 {
			if err := os.Chmod(controlDir, 0o700); err != nil {
				return sshResult{}, fmt.Errorf("chmod ssh control dir %q: %w", controlDir, err)
			}
		}
	}

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ControlMaster=no",
		"-o", "ForwardAgent=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "RequestTTY=no",
		"-o", "PermitLocalCommand=no",
		"-o", fmt.Sprintf("ControlPath=%s/ssh-%%r@%%h:%%p", controlDir),
		"-p", strconv.Itoa(portInt),
		"--", user + "@" + host,
		cmdStr,
	}
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = stdin
	sandbox.ConfigureProcessGroup(cmd)

	out := sandbox.NewCappedBuffer(16*1024, 8<<20, cancel)
	errOut := sandbox.NewCappedBuffer(16*1024, 8<<20, cancel)
	cmd.Stdout = out
	cmd.Stderr = errOut
	cmd.WaitDelay = 5 * time.Second

	start, startErr := sandbox.StartChild("ssh", cmd)
	if startErr != nil {
		return sshResult{}, fmt.Errorf("start ssh: %w", startErr)
	}
	err = sandbox.WaitChild("ssh", cmd, start, ctx, out, errOut)
	duration := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		return sshResult{ExitCode: 124, Stderr: "ssh timed out", Duration: duration, Truncated: out.Truncated() || errOut.Truncated()}, ctx.Err()
	}
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 126
		}
		return sshResult{
			ExitCode:  exitCode,
			Stdout:    out.Render(),
			Stderr:    errOut.Render(),
			Duration:  duration,
			Truncated: out.Truncated() || errOut.Truncated(),
		}, err
	}
	return sshResult{
		ExitCode:  exitCode,
		Stdout:    out.Render(),
		Stderr:    errOut.Render(),
		Duration:  duration,
		Truncated: out.Truncated() || errOut.Truncated(),
	}, nil
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
// SSH stdout is binary-safe; we do not wrap content in text sentinels (which
// could be spoofed by content containing the delimiter). Files over the
// snapshot limit are rejected rather than silently truncated (H4).
func (e *SSHExecutor) ReadFile(ctx context.Context, path string) ([]byte, os.FileInfo, error) {
	const maxSnapshotBytes = 16 * 1024
	cmd := fmt.Sprintf("cat -- %s", shellQuote(path))
	result, err := runSystemSSH(ctx, e.user, e.host, strconv.Itoa(e.port), cmd, nil, 30*time.Second)
	if err != nil {
		return nil, nil, err
	}
	if len(result.Stdout) > maxSnapshotBytes {
		return nil, nil, fmt.Errorf("remote file %q is %d bytes; limit is %d; use sftp",
			path, len(result.Stdout), maxSnapshotBytes)
	}
	info, err := e.StatFile(ctx, path)
	if err != nil || info == nil {
		return nil, nil, fmt.Errorf("stat %q after read: %w", path, err)
	}
	return []byte(result.Stdout), info, nil
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
func (e *SSHExecutor) WriteFile(ctx context.Context, path string, content []byte, mode os.FileMode, allowedGlobs []string, expected *sandbox.FileDiff) (sandbox.FileDiff, error) {
	// The previous implementation used `cat > path`, which followed symlinks,
	// ignored the pack allowlist and could leave partial writes. Refuse remote
	// writes until a descriptor-relative remote writer is available.
	return sandbox.FileDiff{}, fmt.Errorf("remote scoped writes are unavailable: secure atomic remote writer is not configured")
}

// StatFile stats a file on the remote host.
func (e *SSHExecutor) StatFile(ctx context.Context, path string) (os.FileInfo, error) {
	cmd := fmt.Sprintf("stat -c '%%a %%U %%G %%s %%Y %%n' %s", shellQuote(path))
	result, err := runSystemSSH(ctx, e.user, e.host, strconv.Itoa(e.port), cmd, nil, 10*time.Second)
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
