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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sm-me/lnta/internal/audit"
)

// defaultTimeout is the execution timeout applied when the caller passes 0.
const defaultTimeout = 15 * time.Second

// maxOutputBytes caps captured stdout/stderr so huge logs never blow up the
// LLM context window. Output beyond this is replaced with a marker.
const maxOutputBytes = 16 * 1024

// ErrBwrapNotFound is returned when bwrap is not installed on the host.
var ErrBwrapNotFound = errors.New("bwrap not found on host; cannot run sandboxed command")

// ErrBwrapBlocked is returned when bwrap exists but is blocked by AppArmor
// (EACCES/EPERM on namespace creation).
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
	BackendBwrap   SandboxBackend = "bwrap"
	BackendLandlock SandboxBackend = "landlock"
)

// probeBwrap runs a fast pre-flight check to see if bwrap can create
// a user namespace. Returns nil if successful, ErrBwrapNotFound if bwrap
// is not installed, ErrBwrapBlocked if blocked by AppArmor, or other error.
func probeBwrap() error {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return ErrBwrapNotFound
	}

	// Fast probe: try to create a minimal user namespace
	// --ro-bind / / -- true  (mounts root read-only, runs true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bwrap, "--ro-bind", "/", "/", "--", "true")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	err = cmd.Run()
	if err == nil {
		return nil // success
	}

	// Check if it's a permission error (AppArmor blocking userns)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// Exit code 126 or 127 often means permission denied on namespace creation
		// Check stderr for clues, but on Ubuntu 24.04+ it's typically silent EACCES
		if exitErr.ExitCode() == 126 || exitErr.ExitCode() == 127 {
			return ErrBwrapBlocked
		}
	}

	// Context timeout or other error
	return err
}

// runBwrap executes the command inside a bwrap sandbox (the original implementation).
func runBwrap(ctx context.Context, cmdStr string, cwd string, timeout time.Duration) (CommandResult, error) {
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

	home := os.Getenv("HOME")
	if home == "" {
		home = homeDir()
	}

	args := []string{
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--die-with-parent",
	}

	// Mask secret-bearing directories so they appear empty inside the sandbox.
	for _, d := range secretMaskDirs(home) {
		if _, statErr := os.Stat(d); statErr == nil {
			args = append(args, "--tmpfs", d)
		}
	}

	// Mask any .env files in cwd so credentials cannot be read/exfiltrated.
	if entries, rdErr := os.ReadDir(cwd); rdErr == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasPrefix(e.Name(), ".env") {
				args = append(args, "--ro-bind", "/dev/null", filepath.Join(cwd, e.Name()))
			}
		}
	}

	args = append(args, "--chdir", cwd, "--", "sh", "-c", cmdStr)

	cmd := exec.CommandContext(ctx, bwrap, args...)
	cmd.Stdin = nil // reads from /dev/null
	env := os.Environ()
	env = append(env, "DEBIAN_FRONTEND=noninteractive", "GIT_TERMINAL_PROMPT=0")
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	res.Duration = time.Since(start)

	if ex, ok := err.(*exec.ExitError); ok {
		res.ExitCode = ex.ExitCode()
	} else if err != nil {
		// Context deadline, bwrap failure to start, etc.
		res.ExitCode = 126
		res.Stderr = err.Error() + "\n" + stderr.String()
	}

	out := truncateOutput(stdout.String())
	errOut := truncateOutput(stderr.String())
	res.Stdout = out
	res.Stderr = errOut
	res.Truncated = len(out) < len(stdout.String()) || len(errOut) < len(stderr.String())

	// Best-effort audit log of the sandboxed execution.
	audit.Log("sandbox.run", "", map[string]string{
		"cwd":      cwd,
		"backend":  "bwrap",
		"exit":     fmt.Sprintf("%d", res.ExitCode),
		"duration": res.Duration.String(),
	})

	return res, err
}

// RunReadOnly executes sh -c cmdStr inside a sandbox with the entire
// root filesystem mounted read-only. It automatically selects the best
// available backend:
//
//  1. Tier 1 (bwrap): Runs a fast pre-flight probe. If bwrap can create
//     a user namespace, uses bwrap for full isolation.
//  2. Tier 2 (Landlock): If bwrap is not installed or blocked by AppArmor
//     (kernel.apparmor_restrict_unprivileged_userns=1), falls back to
//     native Linux Landlock LSM via self-re-exec.
//
// The sandbox:
//   - Provides read-only access to system directories (/usr, /bin, /lib, /etc, /proc, /sys)
//   - Provides private, non-persistent /tmp via tmpfs
//   - Masks secret directories (~/.ssh, ~/.gnupg, ~/.aws, ~/.kube, ~/.config/lnta)
//     so they appear empty (bwrap) or return EACCES (Landlock)
//   - Masks .env files in cwd to /dev/null
//   - chdirs to cwd and dies with the parent
//   - Stdin bound to /dev/null, noninteractive env vars set
//   - Output truncated at 16KB with [OUTPUT TRUNCATED] marker
//
// Returns CommandResult with Stdout, Stderr, ExitCode, Duration.
// Returns error if both backends fail.
func RunReadOnly(ctx context.Context, cmdStr string, cwd string, timeout time.Duration) (CommandResult, error) {
	// Tier 1: Try bwrap first
	probeErr := probeBwrap()
	if probeErr == nil {
		return runBwrap(ctx, cmdStr, cwd, timeout)
	} else if !errors.Is(probeErr, ErrBwrapNotFound) && !errors.Is(probeErr, ErrBwrapBlocked) {
		// Unexpected error from probe (e.g., timeout), try bwrap anyway
		return runBwrap(ctx, cmdStr, cwd, timeout)
	}

	// Tier 2: Fall back to Landlock LSM
	landlockErr := LandlockProbe()
	if landlockErr == nil {
		return runLandlock(ctx, cmdStr, cwd, timeout)
	}

	// Both backends unavailable
	if errors.Is(probeErr, ErrBwrapNotFound) {
		return CommandResult{}, fmt.Errorf("%w; Landlock also unavailable: %v", ErrBwrapNotFound, landlockErr)
	}
	return CommandResult{}, fmt.Errorf("%w; Landlock also unavailable: %v", ErrBwrapBlocked, landlockErr)
}

// secretMaskDirs lists host directories masked over inside the sandbox so a
// prompt-injected command cannot exfiltrate credentials.
func secretMaskDirs(home string) []string {
	return []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".config", "lnta"),
	}
}

// expandPath replaces a leading ~ with the HOME directory.
func expandPath(p string) string {
	if strings.HasPrefix(p, "~") {
		home := os.Getenv("HOME")
		if home == "" {
			if u, err := os.UserHomeDir(); err == nil {
				home = u
			}
		}
		if home != "" {
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

// compile-time check that CommandResult is used meaningfully.
var _ = fmt.Sprintf("%v", CommandResult{})