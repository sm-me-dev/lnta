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
	"io"
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

// CommandResult captures the outcome of a sandboxed command execution.
type CommandResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Truncated bool
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

// RunReadOnly executes sh -c cmdStr inside a bwrap sandbox with the entire
// root filesystem bind-mounted read-only. When bwrap is absent it returns
// ErrBwrapNotFound.
//
// The sandbox:
//   - bind-mounts / read-only (--ro-bind / /)
//   - provides minimal /dev and /proc
//   - gives a private, non-persistent /tmp via tmpfs
//   - masks $HOME/.ssh, .gnupg, .aws, .kube, .config/lnta and any .env files
//     in cwd over empty/ /dev/null mounts
//   - chdirs to cwd and dies with the parent
//
// Stdin is bound to /dev/null. DEBIAN_FRONTEND=noninteractive and
// GIT_TERMINAL_PROMPT=0 are set in the environment. A context timeout is
// enforced (default 15s).
//
// Stdout, Stderr, ExitCode and Duration are captured; output is truncated at
// 16KB with a clear [OUTPUT TRUNCATED] marker.
func RunReadOnly(ctx context.Context, cmdStr string, cwd string, timeout time.Duration) (CommandResult, error) {
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
	cmd.Stdout = io.Writer(&stdout)
	cmd.Stderr = io.Writer(&stderr)

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
		"exit":     fmt.Sprintf("%d", res.ExitCode),
		"duration": res.Duration.String(),
	})

	return res, err
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
