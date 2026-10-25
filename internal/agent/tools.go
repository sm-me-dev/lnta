// Package agent provides the LLM agent tool registry. The four core tools are
// strictly typed with JSON schemas and map onto the sandbox primitives from
// AGENTS.md.
//
//   - inspect_system: read-only sandboxed command execution.
//   - write_scoped_file: scope-checked atomic file write.
//   - mutate_system: host mutation gated behind interactive user approval.
//   - complete_task: harness-enforced verification gate.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sashabaranov/go-openai"
	"github.com/sm-me-dev/lnta/internal/audit"
	"github.com/sm-me-dev/lnta/internal/packs"
	"github.com/sm-me-dev/lnta/internal/sandbox"
	"github.com/sm-me-dev/lnta/internal/transport"
)

// Tool is a strictly typed, JSON-schema-validated tool the LLM may call.
type Tool struct {
	Name        string
	Description string
	Parameters  json.RawMessage // strict JSON schema
	Func        ToolFunc
}

// ToolFunc executes a single tool call. deps carries the orchestrator-supplied
// dependencies (active pack, approval callback, run id, cwd).
type ToolFunc func(ctx context.Context, args json.RawMessage, deps ToolDeps) (result string, err error)

// ToolDeps are the dependencies injected into every tool call.
type ToolDeps struct {
	RunID         string
	Pack          *packs.Pack       // active instruction pack (may be nil)
	Approve       ApproveFunc       // mutate_system approval callback
	CWD           string            // working directory for sandboxed commands
	DryRun        bool              // when true, writes are diff-only previews and mutations are blocked
	RunCollector  *audit.RunSummaryCollector // for recording run metadata
	Executor      transport.TargetExecutor // for command execution (local or SSH)
}

// ApproveFunc is consulted before executing a mutate_system command. It should
// display a high-visibility warning and block on interactive user confirmation.
type ApproveFunc func(command, cwd, riskLevel, reason string) (approved bool)

// DefaultApprove is the safe default: it denies every mutation. Callers (the
// TUI/CLI layer) replace this with a huh.Confirm-backed implementation.
func DefaultApprove(command, cwd, riskLevel, reason string) bool {
	return false
}

// jsonSchema builds a strict JSON schema raw message from a compact JSON
// string, validating it at build time.
func jsonSchema(s string) json.RawMessage {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		panic(fmt.Sprintf("invalid tool schema: %v", err))
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return json.RawMessage(b)
}

// CoreTools returns the four registered tools with strict JSON schemas.
func CoreTools() []Tool {
	return []Tool{
		{
			Name:        "inspect_system",
			Description: "Execute a read-only shell command inside a bwrap sandbox. The entire root filesystem is bind-mounted read-only; /tmp is a private tmpfs; secret dirs (.ssh, .gnupg, .aws, .kube, .config/lnta) are masked. Stdin is /dev/null. Use this for system inspection only — it cannot modify the host.",
			Parameters: jsonSchema(`{
				"type": "object",
				"properties": {
					"command": {"type": "string", "description": "The shell command to execute (read-only), run via sh -c inside the sandbox."},
					"cwd": {"type": "string", "description": "Working directory for the command."},
					"reason": {"type": "string", "description": "Why this inspection is needed."}
				},
				"required": ["command", "cwd", "reason"],
				"additionalProperties": false
			}`),
			Func: inspectSystem,
		},
		{
			Name:        "write_scoped_file",
			Description: "Atomically write a file whose path must match the active instruction pack's allowed_paths. Backs up the previous content to the run snapshot and returns a unified diff. If the path is outside the allowed scope, returns a SCOPE_VIOLATION directing you to mutate_system instead.",
			Parameters: jsonSchema(`{
				"type": "object",
				"properties": {
					"path": {"type": "string", "description": "Target file path. ~ is expanded and must match at least one glob in the pack's allowed_paths."},
					"content": {"type": "string", "description": "Full file content to write."},
					"mode": {"type": "string", "description": "Octal file mode, e.g. \"0644\". Defaults to 0644."},
					"reason": {"type": "string", "description": "Why this file is being written."}
				},
				"required": ["path", "content", "reason"],
				"additionalProperties": false
			}`),
			Func: writeScopedFile,
		},
		{
			Name:        "mutate_system",
			Description: "Execute a shell command on the host (not sandboxed). Requires interactive user approval first; the orchestrator shows a high-visibility warning with the exact command, cwd, and risk level and blocks on [y/N]. Only use this when write_scoped_file is out of scope or a system mutation is genuinely required.",
			Parameters: jsonSchema(`{
				"type": "object",
				"properties": {
					"command": {"type": "string", "description": "The shell command to execute on the host, run via sh -c."},
					"cwd": {"type": "string", "description": "Working directory for the command."},
					"risk_level": {"type": "string", "enum": ["low", "medium", "high"], "description": "Risk level of the mutation."},
					"reason": {"type": "string", "description": "Why this mutation is needed."}
				},
				"required": ["command", "cwd", "risk_level", "reason"],
				"additionalProperties": false
			}`),
			Func: mutateSystem,
		},
		{
			Name:        "complete_task",
			Description: "Signal task completion. Triggers the harness-enforced verification gate: the active pack's verify_cmd is executed inside the sandbox, and for linux-desktop-entries a native Go check confirms the desktop entry exists, desktop-file-validate passes, and the Exec= binary resolves. On failure returns HARNESS_VERIFICATION_FAILED and the loop continues.",
			Parameters: jsonSchema(`{
				"type": "object",
				"properties": {
					"summary": {"type": "string", "description": "Human-readable summary of what was accomplished."},
					"target_artifacts": {"type": "string", "description": "Comma-separated target artifact paths to verify (e.g. the .desktop file path)."},
					"verification_notes": {"type": "string", "description": "Notes on how verification was performed."}
				},
				"required": ["summary", "target_artifacts"],
				"additionalProperties": false
			}`),
			Func: completeTask,
		},
	}
}

// toolByName maps tool name to tool for fast lookup during dispatch.
func toolByName(tools []Tool) map[string]Tool {
	m := make(map[string]Tool, len(tools))
	for _, t := range tools {
		m[t.Name] = t
	}
	return m
}

// --- Tool implementations ---------------------------------------------------

type inspectInput struct {
	Command string `json:"command"`
	Cmd     string `json:"cmd"` // common alias produced by some LLMs
	CWD     string `json:"cwd"`
	Reason  string `json:"reason"`
}

func inspectSystem(ctx context.Context, args json.RawMessage, deps ToolDeps) (string, error) {
	var in inspectInput
	if err := json.Unmarshal(args, &in); err != nil {
		return "", fmt.Errorf("inspect_system: invalid args: %w", err)
	}
	if in.Command == "" && in.Cmd != "" {
		in.Command = in.Cmd
	}
	if in.CWD == "" {
		in.CWD = deps.CWD
	}
	res, err := deps.Executor.RunReadOnly(ctx, in.Command, in.CWD, 0)
	if err != nil {
		return fmt.Sprintf("inspect_system error: %v\nstderr: %s", err, res.Stderr), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "exit_code=%d duration=%s\n", res.ExitCode, res.Duration)
	if res.Truncated {
		b.WriteString("[OUTPUT TRUNCATED]\n")
	}
	b.WriteString("--- stdout ---\n")
	b.WriteString(res.Stdout)
	if res.Stderr != "" {
		b.WriteString("--- stderr ---\n")
		b.WriteString(res.Stderr)
	}

	// Record command for time-machine TUI
	if deps.RunCollector != nil {
		deps.RunCollector.RecordCommand(audit.CommandRecord{
			Command:   in.Command,
			ExitCode:  res.ExitCode,
			Stdout:    res.Stdout,
			Stderr:    res.Stderr,
			Timestamp: time.Now().UTC(),
			Source:    "inspect_system",
			Truncated: res.Truncated,
		})
	}

	return b.String(), nil
}

type writeInput struct {
	Path   string `json:"path"`
	Content string `json:"content"`
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
}

func writeScopedFile(ctx context.Context, args json.RawMessage, deps ToolDeps) (string, error) {
	var in writeInput
	if err := json.Unmarshal(args, &in); err != nil {
		return "", fmt.Errorf("write_scoped_file: invalid args: %w", err)
	}
	if in.Mode != "" {
		if _, perr := strconv.ParseUint(in.Mode, 8, 32); perr != nil {
			return "", fmt.Errorf("write_scoped_file: invalid mode %q: %w", in.Mode, perr)
		}
	}

	// Fail closed: no pack or no allowed_paths means no writes. This prevents
	// LocalExecutor.WriteFile from being reached with a vacuous scope (C1) and
	// a nil-pack dereference (M1).
	if deps.Pack == nil || len(deps.Pack.AllowedPaths) == 0 {
		return "SCOPE_VIOLATION: active pack has no allowed_paths; writing is not permitted.", nil
	}

	allowed := deps.Pack.AllowedPaths
	if len(allowed) == 0 {
		return "SCOPE_VIOLATION: active pack has no allowed_paths; writing is not permitted.", nil
	}

	// Dry-run mode: validate scope and show the proposed diff without
	// persisting anything to disk.
	if deps.DryRun {
		diff, perr := previewScopedWrite(in.Path, []byte(in.Content), allowed)
		if perr != nil {
			var sve *sandbox.ScopeViolationError
			if errors.As(perr, &sve) {
				return fmt.Sprintf(
					"SCOPE_VIOLATION: %s. Escalate to mutate_system (risk_level=high) to write outside allowed paths %v.",
					sve.Error(), allowed), nil
			}
			return "", fmt.Errorf("write_scoped_file (dry-run): %w", perr)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "[dry-run] would write %q (created=%v, mode=%o, size_old=%d, size_new=%d)\n",
			diff.TargetPath, diff.Created, diff.Mode, diff.SizeOld, diff.SizeNew)
		if diff.Diff != "" {
			b.WriteString("--- proposed unified diff ---\n")
			b.WriteString(diff.Diff)
		}
		return b.String(), nil
	}

	// Determine file mode (default 0644)
	fileMode := os.FileMode(0o644)
	if in.Mode != "" {
		if m, err := strconv.ParseUint(in.Mode, 8, 32); err == nil && m != 0 {
			fileMode = os.FileMode(m)
		}
	}

	// Use the executor's WriteFile for remote-aware writing
	writtenPath, writtenInfo, err := deps.Executor.WriteFile(ctx, in.Path, []byte(in.Content), fileMode)
	if err != nil {
		var sve *sandbox.ScopeViolationError
		if errors.As(err, &sve) {
			return fmt.Sprintf(
				"SCOPE_VIOLATION: %s. Escalate to mutate_system (risk_level=high) to write outside allowed paths %v.",
				sve.Error(), allowed), nil
		}
		return "", fmt.Errorf("write_scoped_file: %w", err)
	}

	// Record file diff for time-machine TUI
	if deps.RunCollector != nil {
		newModeStr := fmt.Sprintf("%04o", fileMode)
		var newSize int64
		if writtenInfo != nil {
			newModeStr = fmt.Sprintf("%04o", writtenInfo.Mode())
			newSize = writtenInfo.Size()
		}
		deps.RunCollector.RecordFileDiff(audit.FileDiffInfo{
			TargetPath: writtenPath,
			Created:    false,
			OldMode:    fmt.Sprintf("%04o", 0o644),
			NewMode:    newModeStr,
			OldSHA256:  "",
			NewSHA256:  "",
			SizeOld:    0,
			SizeNew:    newSize,
			Diff:       "",
		})
	}

	return fmt.Sprintf("wrote %q (mode=%o, size=%d)\n", writtenPath, writtenInfo.Mode(), writtenInfo.Size()), nil
}

type mutateInput struct {
	Command       string `json:"command"`
	Cmd           string `json:"cmd"` // common alias produced by some LLMs
	CWD           string `json:"cwd"`
	RiskLevel     string `json:"risk_level"`      // Deprecated: kept for backwards compatibility
	Reason        string `json:"reason"`
	ChallengeCode string `json:"challenge_code"`  // User-provided challenge code for CRITICAL_DESTRUCTIVE
}

func mutateSystem(ctx context.Context, args json.RawMessage, deps ToolDeps) (string, error) {
	var in mutateInput
	if err := json.Unmarshal(args, &in); err != nil {
		return "", fmt.Errorf("mutate_system: invalid args: %w", err)
	}
	if in.Command == "" && in.Cmd != "" {
		in.Command = in.Cmd
	}
	if in.CWD == "" {
		in.CWD = deps.CWD
	}

	// Dry-run mode: block all host mutations.
	if deps.DryRun {
		return "[dry-run] mutate_system blocked: host mutations are not permitted in dry-run mode.", nil
	}

	// Classify the risk level of the command using the semantic blast-radius classifier.
	classification := sandbox.ClassifyRisk(in.Command)

	// Override risk_level from input if provided (backwards compat), but
	// the classifier's decision is authoritative for CRITICAL_DESTRUCTIVE.
	riskLevel := classification.Level.String()
	if in.RiskLevel != "" && classification.Level != sandbox.RiskCriticalDestructive {
		riskLevel = in.RiskLevel
	}

	// H1: never echo the challenge code to the LLM (the tool result is fed back
	// to the model, which would just echo it on the next call). The human
	// approval dialog gates execution through deps.Approve, where
	// CRITICAL_DESTRUCTIVE requires typing an anti-fatigue challenge.

	// C7: mutate_system never runs on a remote target. If the active executor
	// is remote (e.g. --ssh), fail closed: the command would otherwise run on
	// the operator's workstation instead of the intended host.
	if deps.Executor != nil && deps.Executor.IsRemote() {
		return "MUTATE_UNSUPPORTED: mutate_system is not implemented for remote targets; " +
			"refusing to run this command on the local machine. Run it manually on " +
			deps.Executor.TargetID() + " or use a remote-execution pack.", nil
	}

	// Check approval - for CRITICAL_DESTRUCTIVE, the approval callback should
	// present the challenge code requirement and not accept --yes flags.
	approved := false
	if deps.Approve != nil {
		approved = deps.Approve(in.Command, in.CWD, riskLevel, in.Reason)
	}
	if !approved {
		return fmt.Sprintf(
			"MUTATE_BLOCKED: user did not approve mutate_system (risk: %s). The command was NOT executed.\nReason: %s",
			riskLevel, classification.Reason), nil
	}

	// C9: explicit minimal environment allowlist. Never inherit LD_PRELOAD,
	// BASH_ENV, ENV, PROMPT_COMMAND, GIT_SSH_COMMAND, SSH_AUTH_SOCK, or any
	// *_KEY/*_SECRET/*_TOKEN variables. Mirror the sandbox allowlist.
	homeDir, _ := os.UserHomeDir()
	mutateEnv := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + homeDir,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"TERM=dumb",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"NO_COLOR=1",
	}

	// C9/C2/H2/H13: finite timeout, own process group, capped output.
	mctx, mcancel := context.WithTimeout(ctx, 10*time.Minute)
	defer mcancel()

	cmd := exec.CommandContext(mctx, "sh", "-c", in.Command)
	cmd.Dir = in.CWD
	cmd.Stdin = nil
	cmd.Env = mutateEnv
	sandbox.ConfigureProcessGroup(cmd)

	out := sandbox.NewCappedBuffer(16*1024, 8<<20, mcancel)
	errOut := sandbox.NewCappedBuffer(16*1024, 8<<20, mcancel)
	cmd.Stdout = out
	cmd.Stderr = errOut
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Start(); err != nil {
		return fmt.Sprintf("mutate_system failed to start: %v", err), nil
	}
	sandbox.RegisterChild(cmd)
	defer sandbox.UnregisterChild(cmd)

	defer func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // negative PID = whole process group
		}
	}()

	err := cmd.Wait()
	var exitCode int
	if ex, ok := err.(*exec.ExitError); ok {
		exitCode = ex.ExitCode()
	} else if err != nil {
		exitCode = -1
	}

	// Record command for time-machine TUI using capped/rendered output.
	if deps.RunCollector != nil {
		deps.RunCollector.RecordCommand(audit.CommandRecord{
			Command:   in.Command,
			ExitCode:  exitCode,
			Stdout:    out.Render(),
			Stderr:    errOut.Render(),
			Timestamp: time.Now().UTC(),
			Source:    "mutate_system",
		})
	}

	if ex, ok := err.(*exec.ExitError); ok {
		return fmt.Sprintf("exit_code=%d\n--- stdout ---\n%s\n--- stderr ---\n%s",
			ex.ExitCode(), out.Render(), errOut.Render()), nil
	}
	if err != nil {
		return fmt.Sprintf("mutate_system failed to start: %v\nstderr: %s", err, errOut.Render()), nil
	}
	return fmt.Sprintf("exit_code=0\n--- stdout ---\n%s", out.Render()), nil
}

type completeInput struct {
	Summary           string `json:"summary"`
	TargetArtifacts   string `json:"target_artifacts"`
	Targets           string `json:"targets"`           // alias
	Artifact          string `json:"artifact"`          // alias
	VerificationNotes string `json:"verification_notes"`
}

func completeTask(ctx context.Context, args json.RawMessage, deps ToolDeps) (string, error) {
	var in completeInput
	if err := json.Unmarshal(args, &in); err != nil {
		return "", fmt.Errorf("complete_task: invalid args: %w", err)
	}
	if in.TargetArtifacts == "" {
		if in.Targets != "" {
			in.TargetArtifacts = in.Targets
		} else if in.Artifact != "" {
			in.TargetArtifacts = in.Artifact
		}
	}

	// --- Verification Gate ---
	// Fail closed: no pack or no verify_cmd means we cannot certify. The
	// target is passed out-of-band as LNTA_TARGET (single-quoted env
	// assignment, data never shell text) so it cannot rewrite the command.
	if deps.Pack == nil || strings.TrimSpace(deps.Pack.VerifyCmd) == "" {
		return "", errors.New("complete_task: no verify_cmd for the active pack; refusing to certify")
	}

	// Native Go check for linux-desktop-entries: file exists,
	// desktop-file-validate returns 0, Exec= binary resolves via LookPath.
	if deps.Pack.ID == "linux-desktop-entries" {
		if err := nativeDesktopEntryVerify(in.TargetArtifacts, deps.Pack.AllowedPaths); err != nil {
			return fmt.Sprintf("HARNESS_VERIFICATION_FAILED: %s. Fix the issue and verify again.", err), nil
		}
	}

	// export LNTA_TARGET makes the target available as data for the entire
	// verify_cmd. Packs must reference $LNTA_TARGET literally and must not
	// interpolate target_artifacts into shell text.
	verifyCmd := "export LNTA_TARGET=" + shellQuoteTarget(in.TargetArtifacts) + "; " + deps.Pack.VerifyCmd

	// Execute verify_cmd inside the sandbox with a finite timeout.
	cwd := deps.CWD
	if cwd == "" {
		cwd = "/"
	}
	res, err := deps.Executor.RunReadOnly(ctx, verifyCmd, cwd, 2*time.Minute)
	if err != nil {
		// Record failed verification
		if deps.RunCollector != nil {
			deps.RunCollector.RecordVerification(audit.VerificationRecord{
				Command:   verifyCmd,
				ExitCode:  -1,
				Output:    res.Stderr,
				Timestamp: time.Now().UTC(),
				Passed:    false,
			})
		}
		return fmt.Sprintf("HARNESS_VERIFICATION_FAILED: verify_cmd failed to run: %v. stderr: %s. Fix the issue and verify again.",
			err, res.Stderr), nil
	}
	if res.ExitCode != 0 {
		stderr := res.Stderr
		// Record failed verification
		if deps.RunCollector != nil {
			deps.RunCollector.RecordVerification(audit.VerificationRecord{
				Command:   verifyCmd,
				ExitCode:  res.ExitCode,
				Output:    stderr,
				Timestamp: time.Now().UTC(),
				Passed:    false,
			})
		}
		return fmt.Sprintf("HARNESS_VERIFICATION_FAILED: verify_cmd exited %d. stderr: %s. Fix the issue and verify again.",
			res.ExitCode, stderr), nil
	}

	// Record successful verification
	if deps.RunCollector != nil {
		deps.RunCollector.RecordVerification(audit.VerificationRecord{
			Command:   verifyCmd,
			ExitCode:  res.ExitCode,
			Output:    res.Stdout,
			Timestamp: time.Now().UTC(),
			Passed:    true,
		})
	}

	var b strings.Builder
	fmt.Fprintf(&b, "TASK_COMPLETE: %s\n", in.Summary)
	fmt.Fprintf(&b, "verified_targets: %s\n", in.TargetArtifacts)
	if in.VerificationNotes != "" {
		fmt.Fprintf(&b, "verification_notes: %s\n", in.VerificationNotes)
	}
	return b.String(), nil
}

// shellQuoteTarget single-quotes s for shell use so it is data, never code.
func shellQuoteTarget(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// nativeDesktopEntryVerify performs the native Go verification for the
// linux-desktop-entries pack: the target desktop entry file exists,
// desktop-file-validate returns 0 (if installed), and the binary referenced by
// Exec= resolves via exec.LookPath.
func nativeDesktopEntryVerify(target string, allowedPaths []string) error {
	resolved := target
	if !filepath.IsAbs(target) {
		if abs, err := filepath.Abs(target); err == nil {
			resolved = abs
		}
	}
	if len(allowedPaths) > 0 && !sandbox.PathAllowed(resolved, allowedPaths) {
		return fmt.Errorf("target desktop entry %q is outside allowed_paths %v", target, allowedPaths)
	}

	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("desktop entry %q does not exist: %v", target, err)
	}

	if validatePath, err := exec.LookPath("desktop-file-validate"); err == nil {
		cmd := exec.Command(validatePath, target)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("desktop-file-validate %q failed: %v\n%s", target, err, string(out))
		}
	}

	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("read %q: %v", target, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Exec=") {
			continue
		}
		execVal := strings.TrimPrefix(line, "Exec=")
		execVal = stripDesktopFieldCodes(execVal)
		fields := strings.Fields(execVal)
		if len(fields) == 0 {
			continue
		}
		bin := fields[0]
		if strings.Contains(bin, "/") {
			if _, err := os.Stat(bin); err != nil {
				return fmt.Errorf("exec binary %q does not exist: %v", bin, err)
			}
			continue
		}
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("exec binary %q not found in PATH: %v", bin, err)
		}
	}
	return nil
}

// stripDesktopFieldCodes removes desktop entry field codes (%f, %u, %F, %U,
// %i, %c, %k, ...) from an Exec value so the binary name can be resolved.
func stripDesktopFieldCodes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+1 < len(s) {
			c := s[i+1]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				i++ // skip the field-code letter
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// --- local dry-run preview helpers -----------------------------------------

// previewScopedWrite validates targetPath against allowedGlobs and computes
// the unified diff between existing and proposed content without persisting
// anything to disk. It mirrors sandbox.ScopedWriteFile's scope checks but
// performs no write, so it is safe to use in --dry-run mode.
func previewScopedWrite(targetPath string, content []byte, allowedGlobs []string) (sandbox.FileDiff, error) {
	var diff sandbox.FileDiff
	diff.TargetPath = targetPath

	resolved, err := previewResolveTarget(targetPath)
	if err != nil {
		return diff, err
	}
	if !previewPathAllowed(resolved, allowedGlobs) {
		return diff, &sandbox.ScopeViolationError{
			TargetPath:   targetPath,
			Resolved:     resolved,
			AllowedGlobs: allowedGlobs,
		}
	}

	fi, statErr := os.Stat(resolved)
	exists := statErr == nil
	var oldContent []byte
	var oldMode os.FileMode = 0o644

	if exists {
		if !fi.Mode().IsRegular() {
			return diff, fmt.Errorf("target %q is not a regular file", resolved)
		}
		oldContent, err = os.ReadFile(resolved)
		if err != nil {
			return diff, err
		}
		oldMode = fi.Mode().Perm()
		diff.OldMode = oldMode
		sum := sha256.Sum256(oldContent)
		diff.OldSHA256 = hex.EncodeToString(sum[:])
		diff.SizeOld = int64(len(oldContent))
	} else {
		diff.Created = true
	}

	sum := sha256.Sum256(content)
	diff.NewSHA256 = hex.EncodeToString(sum[:])
	diff.SizeNew = int64(len(content))
	diff.Diff = previewUnifiedDiff(resolved, resolved, oldContent, content)

	newMode := oldMode
	if !exists || newMode == 0 {
		newMode = 0o644
	}
	diff.Mode = newMode
	return diff, nil
}

// previewResolveTarget expands ~ and resolves symlinks on the parent directory.
func previewResolveTarget(targetPath string) (string, error) {
	p := previewExpandPath(targetPath)
	p = filepath.Clean(p)
	parent := filepath.Dir(p)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("resolve parent directory %q: %w", parent, err)
	}
	return filepath.Join(resolvedParent, filepath.Base(p)), nil
}

// previewExpandPath replaces a leading ~ with the HOME directory.
func previewExpandPath(p string) string {
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

// previewPathAllowed reports whether resolved matches at least one glob.
func previewPathAllowed(resolved string, allowedGlobs []string) bool {
	for _, g := range allowedGlobs {
		matched, err := filepath.Match(g, resolved)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// previewSplitLines splits content into lines, dropping a trailing empty element.
func previewSplitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// previewEdit is a single line operation produced by the local line diff.
type previewEdit struct {
	kind   rune
	oldIdx int
	newIdx int
	line   string
}

// previewDiffLines computes an edit script transforming old into new (LCS DP).
func previewDiffLines(old, new []string) []previewEdit {
	m, n := len(old), len(new)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if old[i-1] == new[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	var rev []previewEdit
	i, j := m, n
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && old[i-1] == new[j-1] {
			rev = append(rev, previewEdit{' ', i, j, old[i-1]})
			i--
			j--
		} else if j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]) {
			rev = append(rev, previewEdit{'+', 0, j, new[j-1]})
			j--
		} else {
			rev = append(rev, previewEdit{'-', i, 0, old[i-1]})
			i--
		}
	}
	for a, z := 0, len(rev)-1; a < z; a, z = a+1, z-1 {
		rev[a], rev[z] = rev[z], rev[a]
	}
	return rev
}

// previewUnifiedDiff returns a standard unified diff comparing oldContent vs newContent.
func previewUnifiedDiff(oldPath, newPath string, oldContent, newContent []byte) string {
	oldLines := previewSplitLines(string(oldContent))
	newLines := previewSplitLines(string(newContent))
	ops := previewDiffLines(oldLines, newLines)

	const context = 3
	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n", oldPath)
	fmt.Fprintf(&b, "+++ b/%s\n", newPath)

	n := len(ops)
	i := 0
	for i < n {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		runStart := i
		for i < n && ops[i].kind != ' ' {
			i++
		}
		runEnd := i
		hStart := runStart - context
		if hStart < 0 {
			hStart = 0
		}
		hEnd := runEnd + context
		if hEnd > n {
			hEnd = n
		}
		hunk := ops[hStart:hEnd]
		oldStart, oldCount := previewHunkRange(hunk, true)
		newStart, newCount := previewHunkRange(hunk, false)
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
		for _, e := range hunk {
			b.WriteRune(e.kind)
			b.WriteString(e.line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// previewHunkRange computes the starting line number and count for a hunk.
func previewHunkRange(hunk []previewEdit, old bool) (start, count int) {
	for _, e := range hunk {
		if old && (e.kind == ' ' || e.kind == '-') {
			if count == 0 {
				start = e.oldIdx
			}
			count++
		} else if !old && (e.kind == ' ' || e.kind == '+') {
			if count == 0 {
				start = e.newIdx
			}
			count++
		}
	}
	if old && count == 0 {
		start = 0
	}
	if !old && count == 0 {
		start = 0
	}
	return start, count
}

// --- OpenAI tool definition conversion -------------------------------------

// openaiTools converts the registered tools into go-openai FunctionDefinition
// values suitable for a chat completion request.
func openaiTools(tools []Tool) []openai.Tool {
	out := make([]openai.Tool, 0, len(tools))
	for _, t := range tools {
		out = append(out, openai.Tool{
			Type: openai.ToolTypeFunction,
			Function: &openai.FunctionDefinition{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			},
		})
	}
	return out
}