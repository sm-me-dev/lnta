package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// DefaultGCKeepLast is the default number of run snapshots to keep.
	DefaultGCKeepLast = 100
	// DefaultGCMaxBytes is the default max cumulative snapshot storage (100MB).
	DefaultGCMaxBytes = 100 * 1024 * 1024
	// DefaultMaxLogBytes is the default threshold for audit.jsonl log rotation (10MB).
	DefaultMaxLogBytes = 10 * 1024 * 1024
)

// GCOptions configures the garbage collection run.
type GCOptions struct {
	SnapshotsDir string // Defaults to snapshotRoot() (~/.local/share/lnta/snapshots)
	LogsDir      string // Defaults to logsDir() (~/.local/share/lnta/logs)
	KeepLast     int    // Keep up to this many most recent runs (0 uses DefaultGCKeepLast)
	MaxBytes     int64  // Max allowed snapshot disk usage in bytes (0 uses DefaultGCMaxBytes)
	MaxLogBytes  int64  // Size threshold to rotate audit.jsonl (0 uses DefaultMaxLogBytes)
}

// GCResult reports the outcome of a garbage collection operation.
type GCResult struct {
	SnapshotsRemoved int   `json:"snapshots_removed"`
	BytesFreed       int64 `json:"bytes_freed"`
	LogRotated       bool  `json:"log_rotated"`
	OldLogSize       int64 `json:"old_log_size,omitempty"`
	TotalRunsAfter   int   `json:"total_runs_after"`
	TotalBytesAfter  int64 `json:"total_bytes_after"`
}

type snapshotItem struct {
	name    string
	path    string
	modTime time.Time
	size    int64
}

// RunGC executes snapshot pruning and audit log rotation according to opts.
func RunGC(opts GCOptions) (*GCResult, error) {
	if opts.SnapshotsDir == "" {
		opts.SnapshotsDir = snapshotRoot()
	}
	if opts.LogsDir == "" {
		opts.LogsDir = filepath.Join(dataRoot(), "logs")
	}
	if opts.KeepLast <= 0 {
		opts.KeepLast = DefaultGCKeepLast
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultGCMaxBytes
	}
	if opts.MaxLogBytes <= 0 {
		opts.MaxLogBytes = DefaultMaxLogBytes
	}

	res := &GCResult{}

	// 1. Snapshot pruning
	entries, err := os.ReadDir(opts.SnapshotsDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read snapshots dir %s: %w", opts.SnapshotsDir, err)
	}

	var items []snapshotItem
	var totalInitialBytes int64

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		itemPath := filepath.Join(opts.SnapshotsDir, e.Name())
		fi, err := e.Info()
		if err != nil {
			continue
		}
		sz, _ := dirSize(itemPath)
		items = append(items, snapshotItem{
			name:    e.Name(),
			path:    itemPath,
			modTime: fi.ModTime(),
			size:    sz,
		})
		totalInitialBytes += sz
	}

	// Sort newest first.
	// Run directory names are formatted as "run-20060102T150405", so lexicographical
	// sort on name matches chronological sort; fallback to ModTime.
	sort.Slice(items, func(i, j int) bool {
		if items[i].name != items[j].name {
			return items[i].name > items[j].name
		}
		return items[i].modTime.After(items[j].modTime)
	})

	toDelete := make(map[string]bool)

	// Prune beyond KeepLast limit
	if len(items) > opts.KeepLast {
		for i := opts.KeepLast; i < len(items); i++ {
			toDelete[items[i].path] = true
		}
	}

	// Prune beyond MaxBytes limit (scanning from newest to oldest)
	var cumulativeBytes int64
	for i, item := range items {
		if toDelete[item.path] {
			continue
		}
		if cumulativeBytes+item.size > opts.MaxBytes && i > 0 {
			// Mark this and all remaining older items for deletion
			for j := i; j < len(items); j++ {
				toDelete[items[j].path] = true
			}
			break
		}
		cumulativeBytes += item.size
	}

	// Perform deletions
	for _, item := range items {
		if toDelete[item.path] {
			if rerr := os.RemoveAll(item.path); rerr == nil {
				res.SnapshotsRemoved++
				res.BytesFreed += item.size
			}
		}
	}

	res.TotalRunsAfter = len(items) - res.SnapshotsRemoved
	res.TotalBytesAfter = totalInitialBytes - res.BytesFreed
	if res.TotalBytesAfter < 0 {
		res.TotalBytesAfter = 0
	}

	// 2. Audit log rotation
	logPath := filepath.Join(opts.LogsDir, "audit.jsonl")
	if fi, err := os.Stat(logPath); err == nil {
		if fi.Size() > opts.MaxLogBytes {
			rotatedPath := logPath + ".1"
			_ = os.Remove(rotatedPath)
			if renErr := os.Rename(logPath, rotatedPath); renErr == nil {
				res.LogRotated = true
				res.OldLogSize = fi.Size()
				// Create a new empty audit.jsonl with strict 0600 permissions
				if f, cerr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); cerr == nil {
					_ = f.Close()
				}
			}
		}
	}

	return res, nil
}

// AutoGC runs a lightweight background prune using config limits (or defaults).
func AutoGC(keepLast int, maxMB int) {
	if keepLast <= 0 {
		keepLast = DefaultGCKeepLast
	}
	maxBytes := int64(DefaultGCMaxBytes)
	if maxMB > 0 {
		maxBytes = int64(maxMB) * 1024 * 1024
	}
	_, _ = RunGC(GCOptions{
		KeepLast: keepLast,
		MaxBytes: maxBytes,
	})
}

// dirSize computes the cumulative size in bytes of all non-directory files within path.
func dirSize(path string) (int64, error) {
	var total int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

// FormatGCResult returns a user-friendly string summarizing the GC operation.
func FormatGCResult(res *GCResult) string {
	var sb strings.Builder
	mbFreed := float64(res.BytesFreed) / (1024 * 1024)
	if res.SnapshotsRemoved > 0 {
		sb.WriteString(fmt.Sprintf("Cleaned %d old snapshot(s) (freed %.1f MB).\n", res.SnapshotsRemoved, mbFreed))
	} else {
		sb.WriteString("No snapshots needed cleaning.\n")
	}

	if res.LogRotated {
		oldMB := float64(res.OldLogSize) / (1024 * 1024)
		sb.WriteString(fmt.Sprintf("Audit log rotated (was %.1f MB).\n", oldMB))
	}

	totalMB := float64(res.TotalBytesAfter) / (1024 * 1024)
	sb.WriteString(fmt.Sprintf("Active storage: %d snapshot(s) using %.1f MB.", res.TotalRunsAfter, totalMB))
	return sb.String()
}
