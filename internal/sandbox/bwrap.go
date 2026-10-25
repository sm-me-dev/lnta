// Package sandbox provides bwrap-based sandboxed, read-only command execution
// and a transactional, auditable file writer with undo support.
//
// See AGENTS.md "Architectural Non-Negotiables" for the design constraints.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sm-me-dev/lnta/internal/audit"
)

// defaultTimeout is the execution timeout applied when the caller passes 0.
const defaultTimeout = 15 * time.Second

// maxOutputBytes caps captured stdout/stderr so huge logs never blow up the
// LLM context window. Output beyond this is replaced with a marker.
const maxOutputBytes = 16 * 1024

// ErrBwrapNotFound is returned when bwrap is not installed on the host.
var ErrBwrapNotFound = errors.New("bwrap not found on host; cannot run sandboxed command")

// ErrBwrapBlocked is returned when bwrap exists but cannot create its
// namespaces (AppArmor userns restriction, EPERM, missing userns support...).
var ErrBwrapBlocked = errors.New("bwrap blocked by AppArmor userns restriction; try 'lnta doctor --generate-apparmor'")

// CommandResult captures the outcome of a sandboxed command execution.
type CommandResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Truncated bool
}

// SandboxBackend identifies which sandbox backend was used.
type SandboxBackend string

const (
	BackendBwrap    SandboxBackend = "bwrap"
	BackendLandlock SandboxBackend = "landlock"
)

// probeBwrap runs a fast pre-flight check to see if bwrap can create the same
// namespaces the real run needs. It FAILS CLOSED: any failure (not just exit
// codes 126/127, which bwrap never uses for EPERM) is reported as
// ErrBwrapBlocked together with bwrap's stderr, so the caller falls back to
// Landlock instead of "trying anyway".
func probeBwrap() error {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return ErrBwrapNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bwrap,
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-net",
		"--unshare-uts", "--unshare-cgroup-try", "--new-session", "--die-with-parent",
		"--cap-drop", "ALL", "--clearenv", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
		"--tmpfs", "/tmp", "--tmpfs", "/var/tmp", "--tmpfs", "/run", "--", "true")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = &stderr
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	ConfigureProcessGroup(cmd)
	RegisterChild(cmd)
	defer UnregisterChild(cmd)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %v: %s", ErrBwrapBlocked, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// SandboxAvailable checks if bwrap sandboxing is available and working.
// Returns nil if available, or an error explaining why not.
// Use in tests to skip when sandboxing is not available.
func SandboxAvailable() error {
	return probeBwrap()
}

// secretMaskDirs lists host directories masked over (empty tmpfs) inside the
// sandbox so a prompt-injected command cannot exfiltrate credentials.
func secretMaskDirs(home string) []string {
	rel := []string{
		".ssh", ".gnupg", ".aws", ".kube", ".azure", ".docker", ".oci", ".terraform.d",
		".password-store", ".mozilla", ".thunderbird", ".vault",
		filepath.Join(".config", "lnta"),
		filepath.Join(".config", "gh"),
		filepath.Join(".config", "gcloud"),
		filepath.Join(".config", "rclone"),
		filepath.Join(".config", "op"),
		filepath.Join(".config", "helm"),
		filepath.Join(".config", "git-credential-manager"),
		filepath.Join(".config", "google-chrome"),
		filepath.Join(".config", "chromium"),
		filepath.Join(".config", "BraveSoftware"),
		filepath.Join(".config", "Bitwarden"),
		filepath.Join(".local", "share", "keyrings"),
		filepath.Join(".local", "share", "lnta"),
		filepath.Join(".cache", "lnta"),
		filepath.Join(".gem"),
	}
	out := make([]string, 0, len(rel))
	for _, r := range rel {
		out = append(out, filepath.Join(home, r))
	}
	return out
}

// secretMaskFiles lists individual credential/history files bound over with
// /dev/null inside the sandbox.
func secretMaskFiles(home string) []string {
	rel := []string{
		".git-credentials", ".netrc", ".npmrc", ".pypirc", ".vault-token",
		".bash_history", ".zsh_history", ".python_history", ".psql_history",
		".mysql_history", ".lesshst", ".viminfo", ".node_repl_history", ".sqlite_history",
		".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zlogin", ".pam_environment",
		filepath.Join(".config", "git", "credentials"),
		filepath.Join(".cargo", "credentials.toml"),
		filepath.Join(".cargo", "credentials"),
		filepath.Join(".m2", "settings.xml"),
		filepath.Join(".config", "claude", "settings.json"),
		filepath.Join(".config", "claude", "settings.local.json"),
	}
	out := make([]string, 0, len(rel))
	for _, r := range rel {
		out = append(out, filepath.Join(home, r))
	}
	return out
}

// projectSecretFile reports whether a file found under the working directory
// looks like a credential file that must be masked.
func projectSecretFile(name string) bool {
	switch name {
	case ".netrc", ".npmrc", ".pypirc", ".git-credentials", "terraform.tfvars", "credentials.json", "service-account.json":
		return true
	}
	return strings.HasPrefix(name, ".env")
}

// maskProjectSecrets walks cwd (bounded) and returns the credential files to
// mask. Depth and entry count are capped so a huge tree cannot stall startup.
func maskProjectSecrets(cwd string) []string {
	const maxDepth, maxEntries = 4, 5000
	var out []string
	seen := 0
	base := strings.Count(filepath.Clean(cwd), string(filepath.Separator))
	_ = filepath.WalkDir(cwd, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if seen++; seen > maxEntries {
			return filepath.SkipAll
		}
		if d.IsDir() {
			if p != cwd && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			if strings.Count(p, string(filepath.Separator))-base >= maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && projectSecretFile(d.Name()) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func under(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}

// resolveCWD returns an absolute, existing directory for the sandbox cwd.
func resolveCWD(cwd string) (string, error) {
	if cwd == "" {
		cwd = "."
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("cwd: %w", err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("cwd %s is not a directory", abs)
	}
	return abs, nil
}

// bwrapArgs builds the bubblewrap argument vector (without the executable and
// without the trailing command). Pure function of (home, cwd, extraEnv) plus
// the on-disk existence of the paths to mask.
func bwrapArgs(home, cwd string, extraEnv []string) []string {
	args := []string{
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-net",
		"--unshare-uts", "--unshare-cgroup-try",
		"--new-session", "--die-with-parent",
		"--cap-drop", "ALL",
		"--clearenv",
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--tmpfs", "/var/tmp",
		// /run holds the user session bus, docker.sock, ssh/gpg-agent and
		// podman sockets. Pathname Unix sockets are NOT blocked by
		// --unshare-net, so hide all of it and re-expose only inert data.
		"--tmpfs", "/run",
		"--ro-bind-try", "/run/udev", "/run/udev",
		"--ro-bind-try", "/run/utmp", "/run/utmp",
		"--ro-bind-try", "/run/log", "/run/log",
	}

	// Mask secret-bearing directories (empty tmpfs) and files (/dev/null).
	// H7: use os.Lstat and resolve symlinks so symlink targets are also
	// masked, defeating symlink bypasses and dangling link exposures.
	for _, d := range secretMaskDirs(home) {
		if st, err := os.Lstat(d); err == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				if target, rerr := filepath.EvalSymlinks(d); rerr == nil {
					if tst, terr := os.Stat(target); terr == nil && tst.IsDir() {
						args = append(args, "--tmpfs", target)
					}
				}
			}
			if st.IsDir() {
				args = append(args, "--tmpfs", d)
			}
		}
	}
	for _, f := range secretMaskFiles(home) {
		if st, err := os.Lstat(f); err == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				if target, rerr := filepath.EvalSymlinks(f); rerr == nil {
					if tst, terr := os.Stat(target); terr == nil && tst.Mode().IsRegular() {
						args = append(args, "--ro-bind", "/dev/null", target)
					}
				}
			}
			if st.Mode().IsRegular() {
				args = append(args, "--ro-bind", "/dev/null", f)
			}
		}
	}
	// Credential files inside the project tree (.env, .netrc, ...), recursive and bounded.
	for _, f := range maskProjectSecrets(cwd) {
		args = append(args, "--ro-bind", "/dev/null", f)
	}

	for _, kv := range envList(sandboxEnvMap(home, ""), extraEnv) {
		i := strings.IndexByte(kv, '=')
		args = append(args, "--setenv", kv[:i], kv[i+1:])
	}
	return append(args, "--chdir", cwd, "--")
}

// exitCodeOf converts a Wait error into a shell-style exit code.
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ex *exec.ExitError
	if errors.As(err, &ex) {
		if ws, ok := ex.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ex.ExitCode()
	}
	return 126
}

// runBwrapEnv is runBwrap with extra KEY=VALUE environment entries (used to
// pass verify_cmd arguments as data, never as shell text).
func runBwrapEnv(ctx context.Context, cmdStr string, cwd string, timeout time.Duration, extraEnv []string) (CommandResult, error) {
	var res CommandResult
	start := time.Now()

	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return res, ErrBwrapNotFound
	}
	absCwd, err := resolveCWD(cwd)
	if err != nil {
		return res, err
	}
	home := homeDir()

	args := append(bwrapArgs(home, absCwd, extraEnv), "sh", "-c", cmdStr)

	cmd := exec.CommandContext(ctx, bwrap, args...)
	cmd.Stdin = nil                                         // /dev/null
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"} // bwrap itself: nothing from the host
	ConfigureProcessGroup(cmd)

	stdout := NewCappedBuffer(maxOutputBytes, hardOutputBytes, cancel)
	stderr := NewCappedBuffer(maxOutputBytes, hardOutputBytes, cancel)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	RegisterChild(cmd)
	defer UnregisterChild(cmd)
	err = cmd.Run()
	res.Duration = time.Since(start)
	res.Stdout = stdout.Render()
	res.Stderr = stderr.Render()
	res.Truncated = stdout.Truncated() || stderr.Truncated()

	if err != nil {
		res.ExitCode = exitCodeOf(err)
		var ex *exec.ExitError
		if !errors.As(err, &ex) {
			res.Stderr = err.Error() + "\n" + res.Stderr
		}
	}

	// Best-effort audit log of the sandboxed execution.
	audit.Log("sandbox.run", "", map[string]string{
		"cmd":      cmdStr,
		"cwd":      absCwd,
		"backend":  "bwrap",
		"exit":     fmt.Sprintf("%d", res.ExitCode),
		"duration": res.Duration.String(),
	})

	return res, err
}

// RunReadOnly executes sh -c cmdStr inside a sandbox with the entire
// root filesystem mounted read-only. See RunReadOnlyEnv.
func RunReadOnly(ctx context.Context, cmdStr string, cwd string, timeout time.Duration) (CommandResult, error) {
	return RunReadOnlyEnv(ctx, cmdStr, cwd, timeout, nil)
}

// RunReadOnlyEnv is RunReadOnly plus extra KEY=VALUE environment entries that
// are made visible to the command. Callers use it to hand untrusted values
// (verify_cmd arguments) to the shell as DATA, never as shell source.
//
// It automatically selects the best available backend:
//
//  1. Tier 1 (bwrap): if bwrap can create its namespaces and required mounts.
//  2. Tier 2 (Landlock): if bwrap is missing or blocked (AppArmor userns
//     restriction), via self-re-exec; requires Landlock ABI >= 10 plus
//     network-denying seccomp or it refuses to run (fail closed).
//
// The sandbox:
//   - read-only root; private tmpfs /tmp, /var/tmp, /run (no host sockets)
//   - masks credential directories and files (bwrap) / omits them (Landlock)
//   - masks .env* and similar credential files under the working directory
//   - no network, no inherited environment (explicit allowlist only)
//   - runs in its own process group; timeout and output caps kill the group
//   - output truncated at 16KB with a marker; 8MB hard cap kills the command
func RunReadOnlyEnv(ctx context.Context, cmdStr string, cwd string, timeout time.Duration, extraEnv []string) (CommandResult, error) {
	probeErr := probeBwrap()
	if probeErr == nil {
		return runBwrapEnv(ctx, cmdStr, cwd, timeout, extraEnv)
	}

	landlockErr := LandlockProbe()
	if landlockErr == nil {
		return runLandlockEnv(ctx, cmdStr, cwd, timeout, extraEnv)
	}

	if errors.Is(probeErr, ErrBwrapNotFound) {
		return CommandResult{}, fmt.Errorf("%w; Landlock also unavailable: %v", ErrBwrapNotFound, landlockErr)
	}
	return CommandResult{}, fmt.Errorf("%w; Landlock also unavailable: %v", probeErr, landlockErr)
}

// expandPath replaces a leading ~ with the HOME directory.
func expandPath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home := homeDir(); home != "" {
			p = home + p[1:]
		}
	}
	return p
}

// homeDir returns the user's home directory, falling back gracefully.
func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if u, err := os.UserHomeDir(); err == nil {
		return u
	}
	return ""
}

// truncateOutput caps s at maxOutputBytes, appending a clear marker when cut.
func truncateOutput(s string) string {
	if len(s) <= maxOutputBytes {
		return s
	}
	marker := fmt.Sprintf("\n\n[OUTPUT TRUNCATED: %d total bytes]\n", len(s))
	keep := maxOutputBytes - len(marker)
	if keep < 0 {
		keep = 0
	}
	return s[:keep] + marker
}
