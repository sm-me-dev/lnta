// Package transport provides the TargetExecutor interface and implementations
// for local and remote (SSH) command execution and file operations.
package transport

import (
	"context"
	"os"
	"time"

	"github.com/sm-me/lnta/internal/sandbox"
)

// TargetExecutor abstracts command execution and file operations
// over a local or remote target.
type TargetExecutor interface {
	// RunReadOnly executes a read-only command on the target.
	// Mirrors sandbox.RunReadOnly signature.
	RunReadOnly(ctx context.Context, cmdStr string, cwd string, timeout time.Duration) (sandbox.CommandResult, error)

	// ReadFile reads a file from the target and returns its content.
	ReadFile(ctx context.Context, path string) ([]byte, os.FileInfo, error)

	// WriteFile writes a file to the target, creating parent dirs as needed.
	// Returns the resolved path and file info of the written file.
	WriteFile(ctx context.Context, path string, content []byte, mode os.FileMode) (string, os.FileInfo, error)

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

// RemoteFingerprint captures remote host identity for display/validation.
type RemoteFingerprint struct {
	Host           string            // user@host:port
	OSRelease      map[string]string // /etc/os-release key/value
	Path           string            // $PATH
	UID            int               // remote uid
	GID            int               // remote gid
	Username       string            // remote username
	Binaries       map[string]bool   // binary availability
	HasBwrap       bool              // whether bwrap is available on remote
	FingerprintedAt time.Time
}