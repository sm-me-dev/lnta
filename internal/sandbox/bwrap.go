// Package sandbox provides bwrap-based sandboxed, read-only command execution
// and a transactional, auditable file writer with undo support.
//
// See AGENTS.md "Architectural Non-Negotiables" for the design constraints.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sm-me-dev/lnta/internal/audit"
)

// defaultTimeout is the execution timeout applied when the caller passes 0.
const defaultTimeout = 15 * time.Second

// maxOutputBytes caps captured stdout/stderr so huge logs never blow up the
// LLM context window. Output beyond this is replaced with a marker.
const maxOutputBytes = 16 * 1024

const (
	maxProjectScanEntries     = 500_000
	maxProjectScanDepth       = 32
	maxProjectSecretPaths     = 4_096
	maxProjectSecretPathBytes = 1 << 20
)

// ErrBwrapNotFound is returned when bwrap is not installed on the host.
var ErrBwrapNotFound = errors.New("bwrap not found on host; cannot run sandboxed command")

// ErrBwrapBlocked is returned when bwrap exists but cannot create the
// namespaces and mounts required by LNTA.
var ErrBwrapBlocked = errors.New("bwrap cannot create LNTA's required sandbox")

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

// BwrapProbe contains bounded, non-sensitive results from an actual sandbox
// initialization attempt.
type BwrapProbe struct {
	Path       string
	ExitStatus int
	Stderr     string
	Duration   time.Duration
	AppArmor   string
	TimedOut   bool
}

// ProbeBwrap runs the same namespace and mount setup as LNTA's read-only
// executor. It captures bounded stderr and the AppArmor label observed by a
// process inside the sandbox. Failures remain closed to the caller.
func ProbeBwrap(timeout time.Duration) (BwrapProbe, error) {
	result := BwrapProbe{ExitStatus: -1}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return result, ErrBwrapNotFound
	}
	result.Path = bwrap

	if timeout <= 0 || timeout > 5*time.Second {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cwd, err := os.Getwd()
	if err != nil {
		return result, fmt.Errorf("get current directory: %w", err)
	}
	home := homeDir()
	args, err := bwrapProbeArgs(home, cwd)
	if err != nil {
		return result, err
	}
	cmd := exec.CommandContext(ctx, bwrap, args...)
	cmd.Stdin = nil
	stdout := NewCappedBuffer(1024, 0, nil)
	stderr := NewCappedBuffer(4096, 0, nil)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	ConfigureProcessGroup(cmd)
	start, err := StartChild("bwrap_probe", cmd)
	if err != nil {
		result.Duration = time.Since(start)
		result.Stderr = strings.TrimSpace(stderr.String())
		return result, fmt.Errorf("start bwrap probe: %w", err)
	}
	err = WaitChild("bwrap_probe", cmd, start, ctx, stdout, stderr)
	result.Duration = time.Since(start)
	result.Stderr = strings.TrimSpace(stderr.String())
	if state := cmd.ProcessState; state != nil {
		result.ExitStatus = state.ExitCode()
	}
	result.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	result.AppArmor = strings.TrimSpace(stdout.String())
	if err != nil {
		return result, fmt.Errorf("%w: %v: %s", ErrBwrapBlocked, err, result.Stderr)
	}
	return result, nil
}

func bwrapProbeArgs(home, cwd string) ([]string, error) {
	root, err := ResolveProjectRoot(cwd)
	if err != nil {
		return nil, err
	}
	args, err := bwrapArgs(home, root, cwd, nil)
	if err != nil {
		return nil, err
	}
	return append(args, "sh", "-c", "cat /proc/self/attr/current"), nil
}

func probeBwrap() error {
	_, err := ProbeBwrap(3 * time.Second)
	return err
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

// maskProjectSecrets walks cwd without following links and returns credential
// files to mask. A scan that cannot prove completeness is rejected.
var ErrSecretScanIncomplete = errors.New("project credential scan incomplete; sandbox refused")

func maskProjectSecrets(cwd string) ([]string, error) {
	return scanProjectSecrets(cwd, maxProjectScanDepth, maxProjectScanEntries, maxProjectSecretPaths, maxProjectSecretPathBytes)
}

func scanProjectSecrets(cwd string, maxDepth, maxEntries, maxSecrets, maxPathBytes int) ([]string, error) {
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve project root: %v", ErrSecretScanIncomplete, err)
	}
	fd, err := openAbsoluteDirNoFollow(abs)
	if err != nil {
		return nil, fmt.Errorf("%w: open project root %q without following links: %v", ErrSecretScanIncomplete, abs, err)
	}
	defer unix.Close(fd)
	var out []string
	budget := projectSecretScanBudget{maxDepth: maxDepth, maxEntries: maxEntries, maxSecrets: maxSecrets, maxPathBytes: maxPathBytes}
	err = scanProjectSecretDir(fd, filepath.Clean(abs), 0, &budget, &out)
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

type projectSecretScanBudget struct {
	entries      int
	secrets      int
	pathBytes    int
	maxDepth     int
	maxEntries   int
	maxSecrets   int
	maxPathBytes int
}

func (budget *projectSecretScanBudget) addEntry() error {
	if budget.entries >= budget.maxEntries {
		return fmt.Errorf("%w: entry limit %d exceeded", ErrSecretScanIncomplete, budget.maxEntries)
	}
	budget.entries++
	return nil
}

func scanProjectSecretDir(dirFD int, dir string, depth int, budget *projectSecretScanBudget, secrets *[]string) error {
	var before unix.Stat_t
	if err := unix.Fstat(dirFD, &before); err != nil {
		return fmt.Errorf("%w: inspect project directory %q: %v", ErrSecretScanIncomplete, dir, err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: project path %q is not a directory", ErrSecretScanIncomplete, dir)
	}
	err := readDirAt(dirFD, func(entry os.DirEntry) error {
		if err := budget.addEntry(); err != nil {
			return err
		}
		name := entry.Name()
		path := filepath.Join(dir, name)
		stat, err := statAtNoFollow(dirFD, name)
		if err != nil {
			return fmt.Errorf("%w: inspect project entry %q: %v", ErrSecretScanIncomplete, path, err)
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			return fmt.Errorf("%w: symlink in project tree at %q", ErrSecretScanIncomplete, path)
		case unix.S_IFDIR:
			if projectSecretFile(name) {
				return fmt.Errorf("%w: credential-named directory at %q", ErrSecretScanIncomplete, path)
			}
			if depth+1 > budget.maxDepth {
				return fmt.Errorf("%w: depth limit %d exceeded at %q", ErrSecretScanIncomplete, budget.maxDepth, path)
			}
			childFD, _, err := openChildDirNoFollow(dirFD, name, &stat)
			if err != nil {
				return fmt.Errorf("%w: project directory changed at %q: %v", ErrSecretScanIncomplete, path, err)
			}
			err = scanProjectSecretDir(childFD, path, depth+1, budget, secrets)
			_ = unix.Close(childFD)
			if err != nil {
				return err
			}
			current, err := statAtNoFollow(dirFD, name)
			if err != nil || !sameTreeStat(stat, current) {
				return fmt.Errorf("%w: project directory changed during scan at %q", ErrSecretScanIncomplete, path)
			}
		case unix.S_IFREG:
			fd, err := unix.Openat(dirFD, name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return fmt.Errorf("%w: open project file %q without following links: %v", ErrSecretScanIncomplete, path, err)
			}
			var opened unix.Stat_t
			statErr := unix.Fstat(fd, &opened)
			_ = unix.Close(fd)
			if statErr != nil || !sameTreeStat(stat, opened) {
				return fmt.Errorf("%w: project file changed during scan at %q", ErrSecretScanIncomplete, path)
			}
			if projectSecretFile(name) {
				budget.secrets++
				if budget.secrets > budget.maxSecrets {
					return fmt.Errorf("%w: secret path limit %d exceeded", ErrSecretScanIncomplete, budget.maxSecrets)
				}
				budget.pathBytes += len(path)
				if budget.pathBytes > budget.maxPathBytes {
					return fmt.Errorf("%w: secret path byte limit %d exceeded", ErrSecretScanIncomplete, budget.maxPathBytes)
				}
				*secrets = append(*secrets, path)
			}
		default:
			return fmt.Errorf("%w: unsupported project entry type at %q", ErrSecretScanIncomplete, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: read project directory %q: %v", ErrSecretScanIncomplete, dir, err)
	}
	if err := verifyDirUnchanged(dirFD, before); err != nil {
		return fmt.Errorf("%w: project directory changed during scan at %q", ErrSecretScanIncomplete, dir)
	}
	return nil
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
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve cwd symlinks: %w", err)
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

// ResolveProjectRoot selects the nearest Git worktree/repository root above
// launchDir. A launch outside a repository is its own project root.
func ResolveProjectRoot(launchDir string) (string, error) {
	launch, err := resolveCWD(launchDir)
	if err != nil {
		return "", err
	}
	for dir := launch; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect git root %q: %w", dir, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return launch, nil
		}
	}
}

func resolveProjectAndCWD(projectRoot, cwd string) (string, string, error) {
	root, err := resolveCWD(projectRoot)
	if err != nil {
		return "", "", fmt.Errorf("resolve project root: %w", err)
	}
	work, err := resolveCWD(cwd)
	if err != nil {
		return "", "", err
	}
	rel, err := filepath.Rel(root, work)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("working directory %q is outside project root %q", work, root)
	}
	return root, work, nil
}

// bwrapArgs builds the bubblewrap argument vector (without the executable and
// without the trailing command). Project credential masking is rooted at
// projectRoot; cwd remains the command's working directory.
func bwrapArgs(home, projectRoot, cwd string, extraEnv []string) ([]string, error) {
	var projectSecrets []string
	if projectRoot != "" {
		var err error
		projectSecrets, err = maskProjectSecrets(projectRoot)
		if err != nil {
			return nil, err
		}
	}
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
	for _, f := range projectSecrets {
		args = append(args, "--ro-bind", "/dev/null", f)
	}

	for _, kv := range envList(sandboxEnvMap(home, ""), extraEnv) {
		i := strings.IndexByte(kv, '=')
		args = append(args, "--setenv", kv[:i], kv[i+1:])
	}
	return append(args, "--chdir", cwd, "--"), nil
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
func runBwrapEnv(ctx context.Context, cmdStr string, projectRoot, cwd string, timeout time.Duration, extraEnv []string) (CommandResult, error) {
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
	var absRoot, absCwd string
	if projectRoot == "" {
		absCwd, err = resolveCWD(cwd)
	} else {
		absRoot, absCwd, err = resolveProjectAndCWD(projectRoot, cwd)
	}
	if err != nil {
		return res, err
	}
	home := homeDir()

	seccompFile, err := newNetworkSeccompFile()
	if err != nil {
		return res, fmt.Errorf("required network seccomp filter unavailable: %w", err)
	}
	defer seccompFile.Close()
	baseArgs, err := bwrapArgs(home, absRoot, absCwd, extraEnv)
	if err != nil {
		return res, err
	}
	args, err := bwrapCommandArgs(baseArgs, cmdStr)
	if err != nil {
		return res, err
	}

	cmd := exec.CommandContext(ctx, bwrap, args...)
	cmd.Stdin = nil                                         // /dev/null
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"} // bwrap itself: nothing from the host
	cmd.ExtraFiles = []*os.File{seccompFile}
	ConfigureProcessGroup(cmd)

	stdout := NewCappedBuffer(maxOutputBytes, hardOutputBytes, cancel)
	stderr := NewCappedBuffer(maxOutputBytes, hardOutputBytes, cancel)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	validatedArgs, err := bwrapArgs(home, absRoot, absCwd, extraEnv)
	if err != nil {
		return res, err
	}
	if !equalStringSlices(baseArgs, validatedArgs) {
		return res, fmt.Errorf("project or credential paths changed during pre-launch validation")
	}

	childStarted, startErr := StartChild("bwrap", cmd)
	if startErr != nil {
		return res, fmt.Errorf("start sandbox: %w", startErr)
	}
	err = WaitChild("bwrap", cmd, childStarted, ctx, stdout, stderr)
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

func bwrapCommandArgs(baseArgs []string, command string) ([]string, error) {
	return bwrapCommandArgsWithSeccomp(baseArgs, command, 3)
}

func bwrapCommandArgsWithSeccomp(baseArgs []string, command string, seccompFD int) ([]string, error) {
	if len(baseArgs) == 0 || baseArgs[len(baseArgs)-1] != "--" {
		return nil, fmt.Errorf("bubblewrap arguments are missing the command delimiter")
	}
	args := append([]string(nil), baseArgs[:len(baseArgs)-1]...)
	args = append(args, "--seccomp", fmt.Sprintf("%d", seccompFD), "--", "sh", "-c", command)
	return args, nil
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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
//     restriction), via self-re-exec; requires Landlock ABI >= 8 plus
//     network-denying seccomp or it refuses to run (fail closed).
//
// The sandbox:
//   - read-only root; private tmpfs /tmp, /var/tmp, /run (no host sockets)
//   - masks credential directories and files (bwrap) / omits them (Landlock)
//   - masks .env* and similar credential files under the project root
//   - no network, no inherited environment (explicit allowlist only)
//   - runs in its own process group; timeout and output caps kill the group
//   - output truncated at 16KB with a marker; 8MB hard cap kills the command
func RunReadOnlyEnv(ctx context.Context, cmdStr string, cwd string, timeout time.Duration, extraEnv []string) (CommandResult, error) {
	root, err := ResolveProjectRoot(cwd)
	if err != nil {
		return CommandResult{}, err
	}
	return RunReadOnlyProjectEnv(ctx, cmdStr, root, cwd, timeout, extraEnv)
}

// RunReadOnlyProjectEnv runs with a fixed project boundary independent of the
// requested working directory. Credential scanning always covers projectRoot.
func RunReadOnlyProjectEnv(ctx context.Context, cmdStr, projectRoot, cwd string, timeout time.Duration, extraEnv []string) (CommandResult, error) {
	probeErr := probeBwrap()
	if probeErr == nil {
		return runBwrapEnv(ctx, cmdStr, projectRoot, cwd, timeout, extraEnv)
	}

	landlockErr := LandlockProbe()
	if landlockErr == nil {
		return runLandlockProjectEnv(ctx, cmdStr, projectRoot, cwd, timeout, extraEnv)
	}

	if errors.Is(probeErr, ErrBwrapNotFound) {
		return CommandResult{}, fmt.Errorf("%w; Landlock also unavailable: %v", ErrBwrapNotFound, landlockErr)
	}
	return CommandResult{}, fmt.Errorf("%w; Landlock also unavailable: %v", probeErr, landlockErr)
}

// RunReadOnlyHost runs a targeted host command in the read-only sandbox without
// invoking the project credential scanner. Host commands still inherit the
// standard home secret masks, network isolation, and output/time limits.
func RunReadOnlyHost(ctx context.Context, cmdStr, cwd string, timeout time.Duration) (CommandResult, error) {
	probeErr := probeBwrap()
	if probeErr == nil {
		return runBwrapEnv(ctx, cmdStr, "", cwd, timeout, nil)
	}
	landlockErr := LandlockProbe()
	if landlockErr == nil {
		return runLandlockProjectEnv(ctx, cmdStr, "", cwd, timeout, nil)
	}
	if errors.Is(probeErr, ErrBwrapNotFound) {
		return CommandResult{}, fmt.Errorf("%w; Landlock also unavailable: %v; no command was run", ErrBwrapNotFound, landlockErr)
	}
	return CommandResult{}, fmt.Errorf("%w; Landlock also unavailable: %v; no command was run", probeErr, landlockErr)
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
