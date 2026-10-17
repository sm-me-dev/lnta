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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sashabaranov/go-openai"
	"github.com/sm-me/lnta/internal/packs"
	"github.com/sm-me/lnta/internal/sandbox"
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
	RunID    string
	Pack     *packs.Pack   // active instruction pack (may be nil)
	Approve  ApproveFunc   // mutate_system approval callback
	CWD      string        // working directory for sandboxed commands
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
	CWD     string `json:"cwd"`
	Reason  string `json:"reason"`
}

func inspectSystem(ctx context.Context, args json.RawMessage, deps ToolDeps) (string, error) {
	var in inspectInput
	if err := json.Unmarshal(args, &in); err != nil {
		return "", fmt.Errorf("inspect_system: invalid args: %w", err)
	}
	if in.CWD == "" {
		in.CWD = deps.CWD
	}
	res, err := sandbox.RunReadOnly(ctx, in.Command, in.CWD, 0)
	if err != nil {
		return fmt.Sprintf("inspect_system error: %v\nstderr: %s", err, res.Stderr), nil
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("exit_code=%d duration=%s\n", res.ExitCode, res.Duration))
	if res.Truncated {
		b.WriteString("[OUTPUT TRUNCATED]\n")
	}
	b.WriteString("--- stdout ---\n")
	b.WriteString(res.Stdout)
	if res.Stderr != "" {
		b.WriteString("--- stderr ---\n")
		b.WriteString(res.Stderr)
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

	allowed := deps.Pack.AllowedPaths
	if len(allowed) == 0 {
		return "SCOPE_VIOLATION: active pack has no allowed_paths; writing is not permitted.", nil
	}

	diff, err := sandbox.ScopedWriteFile(deps.RunID, in.Path, []byte(in.Content), allowed)
	if err != nil {
		var sve *sandbox.ScopeViolationError
		if errors.As(err, &sve) {
			return fmt.Sprintf(
				"SCOPE_VIOLATION: %s. Escalate to mutate_system (risk_level=high) to write outside allowed paths %v.",
				sve.Error(), allowed), nil
		}
		return "", fmt.Errorf("write_scoped_file: %w", err)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("wrote %q (created=%v, mode=%o, size_old=%d, size_new=%d)\n",
		diff.TargetPath, diff.Created, diff.Mode, diff.SizeOld, diff.SizeNew))
	if diff.Diff != "" {
		b.WriteString("--- unified diff ---\n")
		b.WriteString(diff.Diff)
	}
	return b.String(), nil
}

type mutateInput struct {
	Command   string `json:"command"`
	CWD       string `json:"cwd"`
	RiskLevel string `json:"risk_level"`
	Reason    string `json:"reason"`
}

func mutateSystem(ctx context.Context, args json.RawMessage, deps ToolDeps) (string, error) {
	var in mutateInput
	if err := json.Unmarshal(args, &in); err != nil {
		return "", fmt.Errorf("mutate_system: invalid args: %w", err)
	}
	if in.CWD == "" {
		in.CWD = deps.CWD
	}

	if deps.Approve == nil || !deps.Approve(in.Command, in.CWD, in.RiskLevel, in.Reason) {
		return "MUTATE_BLOCKED: user did not approve mutate_system. The command was NOT executed.", nil
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", in.Command)
	cmd.Dir = in.CWD
	cmd.Stdin = nil
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ex, ok := err.(*exec.ExitError); ok {
		return fmt.Sprintf("exit_code=%d\n--- stdout ---\n%s\n--- stderr ---\n%s",
			ex.ExitCode(), stdout.String(), stderr.String()), nil
	}
	if err != nil {
		return fmt.Sprintf("mutate_system failed to start: %v\nstderr: %s", err, stderr.String()), nil
	}
	return fmt.Sprintf("exit_code=0\n--- stdout ---\n%s", stdout.String()), nil
}

type completeInput struct {
	Summary           string `json:"summary"`
	TargetArtifacts   string `json:"target_artifacts"`
	VerificationNotes string `json:"verification_notes"`
}

func completeTask(ctx context.Context, args json.RawMessage, deps ToolDeps) (string, error) {
	var in completeInput
	if err := json.Unmarshal(args, &in); err != nil {
		return "", fmt.Errorf("complete_task: invalid args: %w", err)
	}

	// --- Verification Gate ---
	if deps.Pack != nil && deps.Pack.VerifyCmd != "" {
		vars := map[string]string{"target": in.TargetArtifacts}
		verifyCmd := packs.RenderVerifyCmd(deps.Pack.VerifyCmd, vars)

		// Native Go check for linux-desktop-entries: file exists,
		// desktop-file-validate returns 0, Exec= binary resolves via LookPath.
		if deps.Pack.ID == "linux-desktop-entries" {
			if err := nativeDesktopEntryVerify(in.TargetArtifacts); err != nil {
				return fmt.Sprintf("HARNESS_VERIFICATION_FAILED: %s. Fix the issue and verify again.", err), nil
			}
		}

		// Execute verify_cmd inside the sandbox.
		cwd := deps.CWD
		if cwd == "" {
			cwd = "/"
		}
		res, err := sandbox.RunReadOnly(ctx, verifyCmd, cwd, 0)
		if err != nil {
			return fmt.Sprintf("HARNESS_VERIFICATION_FAILED: verify_cmd failed to run: %v. stderr: %s. Fix the issue and verify again.",
				err, res.Stderr), nil
		}
		if res.ExitCode != 0 {
			return fmt.Sprintf("HARNESS_VERIFICATION_FAILED: verify_cmd exited %d. stderr: %s. Fix the issue and verify again.",
				res.ExitCode, res.Stderr), nil
		}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("TASK_COMPLETE: %s\n", in.Summary))
	b.WriteString(fmt.Sprintf("verified_targets: %s\n", in.TargetArtifacts))
	if in.VerificationNotes != "" {
		b.WriteString(fmt.Sprintf("verification_notes: %s\n", in.VerificationNotes))
	}
	return b.String(), nil
}

// nativeDesktopEntryVerify performs the native Go verification for the
// linux-desktop-entries pack: the target desktop entry file exists,
// desktop-file-validate returns 0 (if installed), and the binary referenced by
// Exec= resolves via exec.LookPath.
func nativeDesktopEntryVerify(target string) error {
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
				return fmt.Errorf("Exec binary %q does not exist: %v", bin, err)
			}
			continue
		}
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("Exec binary %q not found in PATH: %v", bin, err)
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

// compile-time check that time is used (needed for a potential deadline).
var _ = time.Second
