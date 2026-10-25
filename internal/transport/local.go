// Package transport provides the LocalExecutor implementation of TargetExecutor.
package transport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sm-me-dev/lnta/internal/sandbox"
)

// LocalExecutor wraps the local sandbox and file transaction operations.
// `allowed` is the pack's allowed_paths; it is owned by the caller/pack, never
// derived from the target path. An empty list denies all writes (fail closed).
type LocalExecutor struct {
	runID       string
	cwd         string
	projectRoot string
	allowed     []string
}

// NewLocalExecutor creates a new LocalExecutor for the given run ID, working
// directory, and allowed paths. Pass an empty/nil slice to deny all writes.
func NewLocalExecutor(runID, cwd string, allowed []string, projectRoot ...string) *LocalExecutor {
	root := ""
	if len(projectRoot) > 0 {
		root = projectRoot[0]
	}
	if root == "" {
		if resolved, err := sandbox.ResolveProjectRoot(cwd); err == nil {
			root = resolved
		} else {
			root = cwd
		}
	}
	return &LocalExecutor{
		runID:       runID,
		cwd:         cwd,
		projectRoot: root,
		allowed:     allowed,
	}
}

// RunReadOnly executes a read-only command locally using the sandbox.
func (e *LocalExecutor) RunReadOnly(ctx context.Context, cmdStr string, projectRoot, cwd string, timeout time.Duration) (sandbox.CommandResult, error) {
	return e.RunReadOnlyEnv(ctx, cmdStr, projectRoot, cwd, timeout, nil)
}

func (e *LocalExecutor) RunReadOnlyEnv(ctx context.Context, cmdStr string, projectRoot, cwd string, timeout time.Duration, extraEnv []string) (sandbox.CommandResult, error) {
	if projectRoot != "" && projectRoot != e.projectRoot {
		return sandbox.CommandResult{}, fmt.Errorf("requested project root %q does not match launch-time root %q", projectRoot, e.projectRoot)
	}
	if cwd == "" {
		cwd = e.cwd
	}
	return sandbox.RunReadOnlyProjectEnv(ctx, cmdStr, e.projectRoot, cwd, timeout, extraEnv)
}

// ReadFile reads a file from the local filesystem.
func (e *LocalExecutor) ReadFile(ctx context.Context, path string) ([]byte, os.FileInfo, error) {
	resolved, err := e.resolvePath(path)
	if err != nil {
		return nil, nil, err
	}

	content, err := os.ReadFile(resolved)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, nil, err
	}
	return content, info, nil
}

// WriteFile writes a file locally using the sandbox's scoped write with snapshot support.
// Scope is checked against e.allowed (pack-owned), never against the target itself.
func (e *LocalExecutor) WriteFile(ctx context.Context, path string, content []byte, mode os.FileMode, allowedGlobs []string, expected *sandbox.FileDiff) (sandbox.FileDiff, error) {
	if err := ctx.Err(); err != nil {
		return sandbox.FileDiff{}, fmt.Errorf("write_scoped_file cancelled before write: %w", err)
	}
	resolved, err := e.resolvePath(path)
	if err != nil {
		return sandbox.FileDiff{}, err
	}

	// Scope must be owned by the executor/pack, never derived from the target.
	// Fail closed: no allowed paths means no writes.
	if len(e.allowed) == 0 || len(allowedGlobs) == 0 {
		return sandbox.FileDiff{}, fmt.Errorf("write_scoped_file: %q is outside allowed_paths (no allowed_paths configured)", resolved)
	}
	if !sandbox.PathAllowed(resolved, e.allowed) || !sandbox.PathAllowed(resolved, allowedGlobs) {
		return sandbox.FileDiff{}, fmt.Errorf("write_scoped_file: %q is outside allowed_paths", resolved)
	}

	diff, err := sandbox.ScopedWriteFileApprovedMode(e.runID, resolved, content, mode, allowedGlobs, expected)
	if err != nil {
		return diff, err
	}
	return diff, nil
}

func (e *LocalExecutor) resolvePath(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	if !filepath.IsAbs(path) {
		cwd := e.cwd
		if cwd == "" {
			cwd, _ = os.Getwd()
		}
		path = filepath.Join(cwd, path)
	}
	return filepath.Abs(filepath.Clean(path))
}

// StatFile stats a file on the local filesystem.
func (e *LocalExecutor) StatFile(ctx context.Context, path string) (os.FileInfo, error) {
	resolved := path
	if filepath.IsAbs(path) {
		// Already absolute
	} else {
		resolved = filepath.Join(e.cwd, path)
	}
	// Expand ~
	if len(resolved) > 0 && resolved[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			resolved = filepath.Join(home, resolved[1:])
		}
	}
	resolved = filepath.Clean(resolved)

	return os.Stat(resolved)
}

// Close is a no-op for local executor (no persistent connections).
func (e *LocalExecutor) Close() error {
	return nil
}

// TargetID returns "local" for the local executor.
func (e *LocalExecutor) TargetID() string {
	return "local"
}

// IsRemote returns false for the local executor.
func (e *LocalExecutor) IsRemote() bool {
	return false
}

// RemoteFingerprint returns nil for the local executor.
func (e *LocalExecutor) RemoteFingerprint() *RemoteFingerprint {
	return nil
}

// Preflight is a no-op for the local executor (always ready).
func (e *LocalExecutor) Preflight(ctx context.Context) error {
	return nil
}
