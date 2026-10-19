// Package sandbox provides Landlock LSM fallback for read-only sandboxed execution
// when bwrap is unavailable or blocked by AppArmor userns restrictions.
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

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/sm-me/lnta/internal/audit"
)

const (
	// landlockHiddenCmd is the hidden subcommand that re-execs under Landlock.
	landlockHiddenCmd = "__sandbox_exec"
)

// landlockHiddenCmdEnv is the environment variable that signals we're in the
// Landlock child process (not the parent probing bwrap).
const landlockHiddenCmdEnv = "LNTA_LANDLOCK_CHILD"

// ErrLandlockUnavailable is returned when Landlock is not supported by the kernel
// or the go-landlock library cannot apply rules.
var ErrLandlockUnavailable = errors.New("Landlock LSM not available on this kernel")

// ErrLandlockNotRootless is returned when Landlock rules cannot be applied
// because the process lacks the necessary ambient capabilities.
var ErrLandlockNotRootless = errors.New("Landlock requires rootless/container environment")

// landlockExePath is the path to the lnta binary for self-re-exec.
// Can be overridden in tests.
var landlockExePath string

// runLandlock executes a command under Landlock LSM restrictions by
// re-executing the current binary with the hidden __sandbox_exec subcommand.
func runLandlock(ctx context.Context, cmdStr string, cwd string, timeout time.Duration) (CommandResult, error) {
	var res CommandResult
	start := time.Now()

	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Get the executable path for self-re-exec.
	exe := landlockExePath
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return res, fmt.Errorf("get executable path: %w", err)
		}
	}

	home := os.Getenv("HOME")
	if home == "" {
		home = homeDir()
	}

	// Build the Landlock ruleset as a config string passed via env.
	// This avoids complex serialization - we rebuild rules in the child.
	// RO dirs: system directories + working directory (if not under home)
	// NOTE: home directory is INTENTIONALLY OMITTED to block access to
	// ~/.ssh, ~/.gnupg, ~/.aws, ~/.config/lnta etc.
	roDirs := []string{
		"/usr", "/bin", "/lib", "/lib64",
		"/etc", "/proc", "/sys",
	}
	// Add working directory to RO only if it's not under home directory
	// to avoid exposing secret directories like ~/.ssh, ~/.gnupg, etc.
	if cwd != "" && home != "" {
		cleanCwd := filepath.Clean(cwd)
		cleanHome := filepath.Clean(home)
		if !strings.HasPrefix(cleanCwd, cleanHome+string(filepath.Separator)) && cleanCwd != cleanHome {
			roDirs = append(roDirs, cwd)
		}
	} else if cwd != "" {
		roDirs = append(roDirs, cwd)
	}

	rwDirs := []string{"/tmp"}
	rwFiles := []string{"/dev/null"}

	// Prepare environment for child process
	env := os.Environ()
	env = append(env,
		"DEBIAN_FRONTEND=noninteractive",
		"GIT_TERMINAL_PROMPT=0",
		landlockHiddenCmdEnv+"=1",
		"LNTA_LANDLOCK_RO_DIRS="+joinPaths(roDirs),
		"LNTA_LANDLOCK_RW_DIRS="+joinPaths(rwDirs),
		"LNTA_LANDLOCK_RW_FILES="+joinPaths(rwFiles),
		"LNTA_LANDLOCK_CWD="+cwd,
		"LNTA_LANDLOCK_CMD="+cmdStr,
		"LNTA_LANDLOCK_HOME="+home,
	)

	// Execute the hidden command which will apply Landlock and exec the target
	cmd := exec.CommandContext(ctx, exe, landlockHiddenCmd)
	cmd.Stdin = nil // reads from /dev/null
	cmd.Env = env
	cmd.Dir = cwd

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	res.Duration = time.Since(start)

	if ex, ok := runErr.(*exec.ExitError); ok {
		res.ExitCode = ex.ExitCode()
	} else if runErr != nil {
		res.ExitCode = 126
		res.Stderr = runErr.Error() + "\n" + stderr.String()
	}

	out := truncateOutput(stdout.String())
	errOut := truncateOutput(stderr.String())
	res.Stdout = out
	res.Stderr = errOut
	res.Truncated = len(out) < len(stdout.String()) || len(errOut) < len(stderr.String())

	// Best-effort audit log
	audit.Log("sandbox.run", "", map[string]string{
		"cwd":      cwd,
		"backend":  "landlock",
		"exit":     fmt.Sprintf("%d", res.ExitCode),
		"duration": res.Duration.String(),
	})

	return res, runErr
}

// joinPaths joins paths with : separator, skipping empty ones.
func joinPaths(paths []string) string {
	var out []string
	for _, p := range paths {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ":")
}

// applyLandlock applies Landlock restrictions in the child process.
// This is called from the __sandbox_exec hidden command.
func applyLandlock() error {
	// Check Landlock availability
	cfg := landlock.V10.BestEffort()
	// BestEffort() may return a zero-value Config on unsupported kernels

	// Parse rules from environment
	roDirs := parsePaths(os.Getenv("LNTA_LANDLOCK_RO_DIRS"))
	rwDirs := parsePaths(os.Getenv("LNTA_LANDLOCK_RW_DIRS"))
	rwFiles := parsePaths(os.Getenv("LNTA_LANDLOCK_RW_FILES"))
	_ = os.Getenv("LNTA_LANDLOCK_CWD") // cwd - used by LandlockExecCommand
	home := os.Getenv("LNTA_LANDLOCK_HOME")

	// Build Landlock rules
	var rules []landlock.Rule

	// Add read-only directories
	for _, dir := range roDirs {
		if dir == "" {
			continue
		}
		// Skip secret directories - they are INTENTIONALLY OMITTED
		if isSecretDir(dir, home) {
			continue
		}
		rules = append(rules, landlock.RODirs(dir).IgnoreIfMissing())
	}

	// Add read-write directories
	for _, dir := range rwDirs {
		if dir == "" {
			continue
		}
		rules = append(rules, landlock.RWDirs(dir).IgnoreIfMissing())
	}

	// Add read-write files
	for _, file := range rwFiles {
		if file == "" {
			continue
		}
		rules = append(rules, landlock.RWFiles(file).IgnoreIfMissing())
	}

	// Apply the ruleset - this restricts the current thread and all future threads
	if err := cfg.RestrictPaths(rules...); err != nil {
		return fmt.Errorf("apply Landlock rules: %w", err)
	}

	return nil
}

// parsePaths splits a colon-separated path string.
func parsePaths(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range splitColon(s) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitColon splits on ':' but handles empty elements.
func splitColon(s string) []string {
	// Simple split - paths shouldn't contain ':'
	return splitString(s, ':')
}

// splitString splits a string by a separator rune.
func splitString(s string, sep rune) []string {
	var out []string
	var current []rune
	for _, r := range s {
		if r == sep {
			out = append(out, string(current))
			current = nil
		} else {
			current = append(current, r)
		}
	}
	out = append(out, string(current))
	return out
}

// isSecretDir checks if a directory is one of the secret directories
// that should be OMITTED from Landlock read rules.
func isSecretDir(dir, home string) bool {
	if home == "" {
		return false
	}
	secretDirs := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".config", "lnta"),
	}
	for _, sd := range secretDirs {
		if dir == sd {
			return true
		}
	}
	return false
}

// LandlockExecCommand is the entry point for the __sandbox_exec hidden command.
// It applies Landlock restrictions and then executes the target command.
func LandlockExecCommand() error {
	// Apply Landlock restrictions first
	if err := applyLandlock(); err != nil {
		return fmt.Errorf("Landlock apply: %w", err)
	}

	// Get the command to execute
	cmdStr := os.Getenv("LNTA_LANDLOCK_CMD")
	if cmdStr == "" {
		return errors.New("LNTA_LANDLOCK_CMD not set")
	}

	cwd := os.Getenv("LNTA_LANDLOCK_CWD")
	if cwd == "" {
		cwd = "."
	}

	// Execute the command under Landlock restrictions
	// We use exec.Command to run sh -c cmdStr
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Dir = cwd
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"GIT_TERMINAL_PROMPT=0",
	)

	return cmd.Run()
}

// LandlockProbe checks if Landlock is available on the current kernel.
// Returns nil if available, error otherwise.
// Does NOT apply any rules to the current process.
func LandlockProbe() error {
	cfg := landlock.V10.BestEffort()
	// BestEffort() returns a config with HandledAccessFS set to the maximum
	// available on the current kernel. If Landlock is not supported at all,
	// HandledAccessFS will be 0.
	if cfg.HandledAccessFS == 0 {
		return ErrLandlockUnavailable
	}
	return nil
}