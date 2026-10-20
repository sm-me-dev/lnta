// Package transport provides the LocalExecutor implementation of TargetExecutor.
package transport

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/sm-me/lnta/internal/sandbox"
)

// LocalExecutor wraps the local sandbox and file transaction operations.
type LocalExecutor struct {
	runID string
	cwd   string
}

// NewLocalExecutor creates a new LocalExecutor for the given run ID and working directory.
func NewLocalExecutor(runID, cwd string) *LocalExecutor {
	return &LocalExecutor{
		runID: runID,
		cwd:   cwd,
	}
}

// RunReadOnly executes a read-only command locally using the sandbox.
func (e *LocalExecutor) RunReadOnly(ctx context.Context, cmdStr string, cwd string, timeout time.Duration) (sandbox.CommandResult, error) {
	if cwd == "" {
		cwd = e.cwd
	}
	return sandbox.RunReadOnly(ctx, cmdStr, cwd, timeout)
}

// ReadFile reads a file from the local filesystem.
func (e *LocalExecutor) ReadFile(ctx context.Context, path string) ([]byte, os.FileInfo, error) {
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
func (e *LocalExecutor) WriteFile(ctx context.Context, path string, content []byte, mode os.FileMode) (string, os.FileInfo, error) {
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

	// Use the sandbox's ScopedWriteFile for snapshot support
	// We need to determine allowed paths - for local executor we use a broad pattern
	// The actual scope checking happens in the tool layer
	allowedGlobs := []string{resolved} // Allow this specific path
	diff, err := sandbox.ScopedWriteFile(e.runID, resolved, content, allowedGlobs)
	if err != nil {
		return "", nil, err
	}

	// Get file info after write
	info, err := os.Stat(diff.TargetPath)
	if err != nil {
		return "", nil, err
	}
	return diff.TargetPath, info, nil
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