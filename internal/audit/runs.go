// Package audit implements structured JSONL audit logging with automatic
// redaction of secrets (bearer tokens, sk-... keys, private keys, password
// assignments) and run metadata persistence for the time-machine TUI.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// RunStatus represents the status of a run.
type RunStatus string

const (
	RunStatusVerified    RunStatus = "VERIFIED"
	RunStatusNotRequired RunStatus = "NOT_REQUIRED"
	RunStatusFailed      RunStatus = "FAILED"
	RunStatusRolledBack  RunStatus = "ROLLED_BACK"
)

// CommandRecord represents a command executed during a run.
type CommandRecord struct {
	Command   string    `json:"command"`
	ExitCode  int       `json:"exit_code,omitempty"`
	Stdout    string    `json:"stdout,omitempty"`
	Stderr    string    `json:"stderr,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"` // "inspect_system", "mutate_system", "verify_cmd"
	Truncated bool      `json:"truncated,omitempty"`
}

// TokenUsage represents token consumption for a run.
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// VerificationRecord represents a verification command result.
type VerificationRecord struct {
	Command   string    `json:"command"`
	ExitCode  int       `json:"exit_code"`
	Output    string    `json:"output,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Passed    bool      `json:"passed"`
	Status    string    `json:"status"`
}

const (
	VerificationPassed      = "PASSED"
	VerificationFailed      = "FAILED"
	VerificationUnavailable = "UNAVAILABLE"
	VerificationNotRequired = "NOT_REQUIRED"
)

// FileDiffInfo captures the essential diff information without importing
// sandbox.FileDiff directly (to avoid import cycles with bwrap.go).
type FileDiffInfo struct {
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	TargetPath string `json:"target_path"`
	Created    bool   `json:"created"`
	OldMode    string `json:"old_mode,omitempty"`
	NewMode    string `json:"new_mode,omitempty"`
	OldSHA256  string `json:"old_sha256,omitempty"`
	NewSHA256  string `json:"new_sha256"`
	SizeOld    int64  `json:"size_old,omitempty"`
	SizeNew    int64  `json:"size_new"`
	Diff       string `json:"diff,omitempty"`
}

// RunSummary captures all metadata for a single lnta run.
type RunSummary struct {
	RunID               string               `json:"run_id"`
	Timestamp           time.Time            `json:"timestamp"`
	Prompt              string               `json:"prompt"`
	SelectedPack        string               `json:"selected_pack"`
	CWD                 string               `json:"cwd"`
	Status              RunStatus            `json:"status"`
	FilesChanged        []FileDiffInfo       `json:"files_changed"`
	CommandsExecuted    []CommandRecord      `json:"commands_executed"`
	TokensUsed          TokenUsage           `json:"tokens_used"`
	VerificationReceipt []VerificationRecord `json:"verification_receipt"`
	Error               string               `json:"error,omitempty"`
	Plan                string               `json:"plan,omitempty"`
	ExitCode            int                  `json:"exit_code"`
}

// summaryPath returns the summary.json path for a run id.
func summaryPath(runID string) string {
	return filepath.Join(snapshotDir(runID), "summary.json")
}

// snapshotRoot returns ~/.local/share/lnta/snapshots.
func snapshotRoot() string {
	if h := os.Getenv("HOME"); h != "" {
		return filepath.Join(h, ".local", "share", "lnta/snapshots")
	}
	if u, err := os.UserHomeDir(); err == nil {
		return filepath.Join(u, ".local", "share", "lnta/snapshots")
	}
	return filepath.Join(".local", "share", "lnta/snapshots")
}

// snapshotDir returns the snapshot directory for a run id.
func snapshotDir(runID string) string {
	return filepath.Join(snapshotRoot(), runID)
}

// SaveRunSummary writes the run summary to the snapshot directory.
func SaveRunSummary(runID string, summary *RunSummary) error {
	snapDir := snapshotDir(runID)
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		return err
	}

	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}

	tmp := filepath.Join(snapDir, ".summary.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, summaryPath(runID))
}

// LoadRunSummary reads the run summary from the snapshot directory.
func LoadRunSummary(runID string) (*RunSummary, error) {
	data, err := os.ReadFile(summaryPath(runID))
	if err != nil {
		return nil, fmt.Errorf("read summary for run %q: %w", runID, err)
	}
	var summary RunSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		return nil, fmt.Errorf("parse summary for run %q: %w", runID, err)
	}
	return &summary, nil
}

// ListRunSummaries returns all run summaries sorted by timestamp (newest first).
func ListRunSummaries() ([]*RunSummary, error) {
	root := snapshotRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return []*RunSummary{}, nil
		}
		return nil, err
	}

	var summaries []*RunSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		runID := e.Name()
		summary, err := LoadRunSummary(runID)
		if err != nil {
			// Skip corrupted summaries but log the error
			continue
		}
		summaries = append(summaries, summary)
	}

	// Sort by timestamp descending (newest first)
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Timestamp.After(summaries[j].Timestamp)
	})

	return summaries, nil
}

// UpdateRunStatus updates the status field of a run summary.
func UpdateRunStatus(runID string, status RunStatus) error {
	summary, err := LoadRunSummary(runID)
	if err != nil {
		return err
	}
	summary.Status = status
	return SaveRunSummary(runID, summary)
}

// --- Run summary collection during execution ---

// RunSummaryCollector holds the in-progress run summary.
type RunSummaryCollector struct {
	mu           sync.Mutex
	summary      *RunSummary
	budgetTokens *TokenUsage
}

// NewRunSummaryCollector creates a collector for a new run.
func NewRunSummaryCollector(runID, prompt, pack, cwd string) *RunSummaryCollector {
	return &RunSummaryCollector{
		summary: &RunSummary{
			RunID:               runID,
			Timestamp:           time.Now().UTC(),
			Prompt:              prompt,
			SelectedPack:        pack,
			CWD:                 cwd,
			Status:              RunStatusFailed, // Default to FAILED; updated on success
			FilesChanged:        []FileDiffInfo{},
			CommandsExecuted:    []CommandRecord{},
			TokensUsed:          TokenUsage{},
			VerificationReceipt: []VerificationRecord{},
		},
		budgetTokens: &TokenUsage{},
	}
}

// RecordFileDiff adds a file diff to the summary.
func (c *RunSummaryCollector) RecordFileDiff(diff FileDiffInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summary.FilesChanged = append(c.summary.FilesChanged, diff)
}

// RecordCommand adds a command execution record.
func (c *RunSummaryCollector) RecordCommand(cmd CommandRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summary.CommandsExecuted = append(c.summary.CommandsExecuted, cmd)
}

// RecordTokens updates token usage.
func (c *RunSummaryCollector) RecordTokens(prompt, completion int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.budgetTokens.PromptTokens += prompt
	c.budgetTokens.CompletionTokens += completion
	c.budgetTokens.TotalTokens = c.budgetTokens.PromptTokens + c.budgetTokens.CompletionTokens
	c.summary.TokensUsed = *c.budgetTokens
}

// RecordVerification adds a verification record.
func (c *RunSummaryCollector) RecordVerification(vr VerificationRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summary.VerificationReceipt = append(c.summary.VerificationReceipt, vr)
}

// SetStatus updates the run status.
func (c *RunSummaryCollector) SetStatus(status RunStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summary.Status = status
}

// SetError records an error message.
func (c *RunSummaryCollector) SetError(err string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summary.Error = err
}

// SetPlan records the execution plan.
func (c *RunSummaryCollector) SetPlan(plan string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summary.Plan = plan
}

// SetExitCode records the exit code.
func (c *RunSummaryCollector) SetExitCode(code int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summary.ExitCode = code
}

// Snapshot returns a copy of the current summary.
func (c *RunSummaryCollector) Snapshot() *RunSummary {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Deep copy
	files := make([]FileDiffInfo, len(c.summary.FilesChanged))
	copy(files, c.summary.FilesChanged)
	cmds := make([]CommandRecord, len(c.summary.CommandsExecuted))
	copy(cmds, c.summary.CommandsExecuted)
	vrs := make([]VerificationRecord, len(c.summary.VerificationReceipt))
	copy(vrs, c.summary.VerificationReceipt)

	return &RunSummary{
		RunID:               c.summary.RunID,
		Timestamp:           c.summary.Timestamp,
		Prompt:              c.summary.Prompt,
		SelectedPack:        c.summary.SelectedPack,
		CWD:                 c.summary.CWD,
		Status:              c.summary.Status,
		FilesChanged:        files,
		CommandsExecuted:    cmds,
		TokensUsed:          c.summary.TokensUsed,
		VerificationReceipt: vrs,
		Error:               c.summary.Error,
		Plan:                c.summary.Plan,
		ExitCode:            c.summary.ExitCode,
	}
}

// Save persists the summary to disk.
func (c *RunSummaryCollector) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SaveRunSummary(c.summary.RunID, c.summary)
}
