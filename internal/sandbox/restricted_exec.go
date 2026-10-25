package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	restrictedExecHiddenCmd    = "__restricted_exec"
	restrictedExecHiddenCmdEnv = "LNTA_RESTRICTED_CHILD"
	restrictedExecConfigLimit  = 8 << 20
	restrictedExecCommandLimit = 1 << 20
	restrictedExecEnvLimit     = 128 << 10
)

type restrictedExecConfig struct {
	Command string   `json:"command"`
	CWD     string   `json:"cwd"`
	Env     []string `json:"env"`
}

// RunRestrictedCommand executes an approved mutating command through a hidden
// launcher that denies session/group changes before replacing itself with sh.
// The child and its descendants remain in the process group managed here.
func RunRestrictedCommand(ctx context.Context, command, cwd string, env []string, timeout time.Duration) (CommandResult, error) {
	var res CommandResult
	if command == "" || len(command) > restrictedExecCommandLimit || !filepath.IsAbs(cwd) || len(cwd) > 4096 || len(env) > 128 {
		return res, fmt.Errorf("restricted command inputs exceed limits")
	}
	envBytes := 0
	for _, entry := range env {
		if strings.IndexByte(entry, 0) >= 0 || len(entry) > 16<<10 {
			return res, fmt.Errorf("restricted command environment is invalid")
		}
		envBytes += len(entry)
		if envBytes > restrictedExecEnvLimit {
			return res, fmt.Errorf("restricted command environment exceeds limit")
		}
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	childCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	exe, err := os.Executable()
	if err != nil {
		return res, fmt.Errorf("get restricted launcher path: %w", err)
	}
	cfg, err := json.Marshal(restrictedExecConfig{Command: command, CWD: cwd, Env: env})
	if err != nil {
		return res, fmt.Errorf("encode restricted command configuration: %w", err)
	}
	if len(cfg) > restrictedExecConfigLimit {
		return res, fmt.Errorf("restricted command configuration exceeds limit")
	}

	startedAt := time.Now()
	cmd := exec.CommandContext(childCtx, exe, restrictedExecHiddenCmd)
	cmd.Stdin = bytes.NewReader(cfg)
	cmd.Env = []string{restrictedExecHiddenCmdEnv + "=1", "PATH=/usr/local/bin:/usr/bin:/bin"}
	cmd.Dir = "/"
	ConfigureProcessGroup(cmd)
	stdout := NewCappedBuffer(maxOutputBytes, hardOutputBytes, cancel)
	stderr := NewCappedBuffer(maxOutputBytes, hardOutputBytes, cancel)
	cmd.Stdout, cmd.Stderr = stdout, stderr

	childStarted, err := StartChild("mutate_system", cmd)
	if err != nil {
		return res, fmt.Errorf("start restricted command: %w", err)
	}
	err = WaitChild("mutate_system", cmd, childStarted, childCtx, stdout, stderr)
	res.Duration = time.Since(startedAt)
	res.Stdout, res.Stderr = stdout.Render(), stderr.Render()
	res.Truncated = stdout.Truncated() || stderr.Truncated()
	if err != nil {
		res.ExitCode = exitCodeOf(err)
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			res.Stderr = err.Error() + "\n" + res.Stderr
		}
	}
	return res, err
}

// RestrictedExecMain is the hidden launcher entry point for approved
// mutations. It refuses execution if its marker, bounded config, or seccomp
// filter is unavailable; it never falls back to an unrestricted shell.
func RestrictedExecMain() int {
	if os.Getenv(restrictedExecHiddenCmdEnv) != "1" {
		fmt.Fprintln(os.Stderr, "__restricted_exec is internal and must not be invoked directly")
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, restrictedExecConfigLimit+1))
	if err != nil || len(raw) > restrictedExecConfigLimit {
		fmt.Fprintln(os.Stderr, "restricted command configuration unavailable")
		return 2
	}
	var cfg restrictedExecConfig
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg.Command == "" || len(cfg.Command) > restrictedExecCommandLimit || !filepath.IsAbs(cfg.CWD) || len(cfg.CWD) > 4096 || len(cfg.Env) > 128 {
		fmt.Fprintln(os.Stderr, "restricted command configuration invalid")
		return 2
	}
	envBytes := 0
	for _, entry := range cfg.Env {
		if strings.IndexByte(entry, 0) >= 0 || len(entry) > 16<<10 {
			fmt.Fprintln(os.Stderr, "restricted command configuration invalid")
			return 2
		}
		envBytes += len(entry)
		if envBytes > restrictedExecEnvLimit {
			fmt.Fprintln(os.Stderr, "restricted command configuration invalid")
			return 2
		}
	}
	if err := denySessionGroupSyscalls(); err != nil {
		fmt.Fprintln(os.Stderr, "required process-group restriction unavailable")
		return 126
	}
	if err := os.Chdir(cfg.CWD); err != nil {
		fmt.Fprintln(os.Stderr, "restricted command working directory unavailable")
		return 126
	}
	if err := syscall.Exec("/bin/sh", []string{"sh", "-c", cfg.Command}, cfg.Env); err != nil {
		fmt.Fprintln(os.Stderr, "restricted command exec failed")
		return 126
	}
	return 126
}
