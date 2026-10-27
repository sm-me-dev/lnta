// Package transport provides the TargetExecutor interface and implementations
// for local and remote (SSH) command execution and file operations.
package transport

import (
	"context"
	"os"
	"time"

	"github.com/sm-me-dev/lnta/internal/sandbox"
)

// TargetExecutor abstracts command execution and file operations
// over a local or remote target.
type TargetExecutor interface {
	// RunReadOnly executes a read-only command on the target.
	// projectRoot is the immutable launch-time boundary; cwd is the selected
	// command directory and must remain inside it for local execution.
	RunReadOnly(ctx context.Context, cmdStr string, projectRoot, cwd string, timeout time.Duration) (sandbox.CommandResult, error)
	RunReadOnlyEnv(ctx context.Context, cmdStr string, projectRoot, cwd string, timeout time.Duration, extraEnv []string) (sandbox.CommandResult, error)

	// ReadFile reads a file from the target and returns its content.
	ReadFile(ctx context.Context, path string) ([]byte, os.FileInfo, error)

	// WriteFile writes a file within the supplied allowlist and returns the
	// accurate transactional diff. Parent directories are never created.
	WriteFile(ctx context.Context, path string, content []byte, mode os.FileMode, allowedGlobs []string, expected *sandbox.FileDiff) (sandbox.FileDiff, error)

	// StatFile stats a file on the target.
	StatFile(ctx context.Context, path string) (os.FileInfo, error)

	// Close releases any persistent connections (e.g., SSH multiplexing).
	Close() error

	// TargetID returns a unique identifier for this target (e.g., "local" or "user@host:port").
	TargetID() string

	// IsRemote returns true if this executor targets a remote host.
	IsRemote() bool

	// RemoteFingerprint returns the remote system fingerprint (os-release, PATH, UID, binaries).
	// Only valid after Preflight() succeeds.
	RemoteFingerprint() *RemoteFingerprint

	// Preflight performs one-time remote fingerprinting and connection validation.
	// Called before any RunReadOnly/ReadFile/WriteFile.
	Preflight(ctx context.Context) error
}

// HostCommandExecutor is implemented by targets that can run a targeted host
// command in a read-only sandbox without using the local project boundary.
type HostCommandExecutor interface {
	RunReadOnlyHost(ctx context.Context, cmdStr, cwd string, timeout time.Duration) (sandbox.CommandResult, error)
}

// RemoteFingerprint captures remote host identity for display/validation.
type RemoteFingerprint struct {
	Host            string            // user@host:port
	OSRelease       map[string]string // /etc/os-release key/value
	Path            string            // $PATH
	Home            string            // remote home directory
	UID             int               // remote uid
	GID             int               // remote gid
	Username        string            // remote username
	Binaries        map[string]bool   // binary availability
	HasBwrap        bool              // bwrap was found and the required isolation probe passed
	SandboxError    string            // probe failure diagnostic
	FingerprintedAt time.Time
}
