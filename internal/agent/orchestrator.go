// Package agent provides the LLM agent orchestration pipeline: single-turn
// pre-flight (fingerprint → route → context_cmd) followed by a multi-step
// streaming tool-calling loop with cancellation support.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sashabaranov/go-openai"
	"github.com/sm-me-dev/lnta/internal/audit"
	"github.com/sm-me-dev/lnta/internal/fingerprint"
	"github.com/sm-me-dev/lnta/internal/packs"
	"github.com/sm-me-dev/lnta/internal/sandbox"
	"github.com/sm-me-dev/lnta/internal/transport"
)

// LLMClient is the abstraction over the chat completions API. It is kept as an
// interface so the orchestrator can be tested with a mock client and so any
// OpenAI-compatible backend (OpenAI, OpenRouter, Ollama, Anthropic proxy,
// Gemini) can be used.
type LLMClient interface {
	// ChatCompletionStream streams a chat completion. It returns a stream
	// reader and an error. The caller drains the stream via Recv() until
	// io.EOF, then closes it.
	ChatCompletionStream(ctx context.Context, req openai.ChatCompletionRequest) (ChatStream, error)
}

// ChatStream is the small subset of *openai.ChatCompletionStream needed by the
// orchestrator. It is an interface (rather than the concrete type) so tests and
// external callers can provide a fake stream; the real *openai.ChatCompletionStream
// satisfies it.
type ChatStream interface {
	Recv() (openai.ChatCompletionStreamResponse, error)
	Close() error
}

// openaiClient wraps sashabaranov/go-openai's Client to satisfy LLMClient.
type openaiClient struct {
	client *openai.Client
}

func (c *openaiClient) ChatCompletionStream(ctx context.Context, req openai.ChatCompletionRequest) (ChatStream, error) {
	return c.client.CreateChatCompletionStream(ctx, req)
}

// Orchestrator runs the agent loop for a single user prompt.
type Orchestrator struct {
	client  LLMClient
	router  *packs.Router
	tools   map[string]Tool
	config  *Config

	runID    string
	cwd      string
	approve  ApproveFunc
	maxTurns int
	dryRun   bool

	sysCtx fingerprint.SystemContext

	// Executor for command execution (local or SSH)
	executor transport.TargetExecutor

	// Budget tracking for runaway loop and token budget circuit breaker.
	budgetTracker *BudgetTracker

	// Run summary collection for time-machine TUI.
	runCollector *audit.RunSummaryCollector
}

// Option configures an Orchestrator.
type Option func(*Orchestrator)

// WithRunID sets the run identifier used for snapshots and audit logs.
func WithRunID(id string) Option {
	return func(o *Orchestrator) { o.runID = id }
}

// WithCWD sets the working directory for sandboxed commands.
func WithCWD(dir string) Option {
	return func(o *Orchestrator) { o.cwd = dir }
}

// WithApprove sets the mutate_system approval callback.
func WithApprove(fn ApproveFunc) Option {
	return func(o *Orchestrator) { o.approve = fn }
}

// WithMaxTurns sets the maximum number of tool-calling turns.
func WithMaxTurns(n int) Option {
	return func(o *Orchestrator) { o.maxTurns = n }
}

// WithConfig sets the LLM config (model, temperature, ...).
func WithConfig(cfg *Config) Option {
	return func(o *Orchestrator) { o.config = cfg }
}

// RunID returns the active run identifier.
func (o *Orchestrator) RunID() string {
	return o.runID
}

// RunSummary returns the current snapshot of the run summary if available.
func (o *Orchestrator) RunSummary() *audit.RunSummary {
	if o.runCollector != nil {
		return o.runCollector.Snapshot()
	}
	return nil
}

// NewOpenAIClient builds an LLMClient backed by sashabaranov/go-openai using the
// given config. It supports any OpenAI-compatible endpoint (OpenAI, OpenRouter,
// Ollama, Anthropic proxy, Gemini).
func NewOpenAIClient(cfg *Config) (LLMClient, error) {
	cliCfg := openai.DefaultConfig(cfg.APIKey)
	cliCfg.BaseURL = cfg.BaseURL
	client := openai.NewClientWithConfig(cliCfg)
	return &openaiClient{client: client}, nil
}

// NewOllamaClient builds an LLMClient pointed at a local Ollama server's
// OpenAI-compatible endpoint (http://127.0.0.1:11434/v1). No API key is
// required — Ollama does not authenticate local calls. This enables 100%
// offline execution for airgapped sysadmin tasks.
func NewOllamaClient(model string) (LLMClient, error) {
	cliCfg := openai.DefaultConfig("")
	cliCfg.BaseURL = ollamaBaseURL
	client := openai.NewClientWithConfig(cliCfg)
	// Override the default model so callers can use WithConfig(Model=model).
	return &openaiClient{client: client}, nil
}

// WithDryRun enables dry-run mode: file writes become diff-only previews and
// host mutations are blocked.
func WithDryRun(dry bool) Option {
	return func(o *Orchestrator) { o.dryRun = dry }
}

// WithAllowedTools restricts the registered tools to the given names (used by
// --explain mode, which removes write_scoped_file and mutate_system).
func WithAllowedTools(names []string) Option {
	return func(o *Orchestrator) {
		allowed := make(map[string]bool, len(names))
		for _, n := range names {
			allowed[n] = true
		}
		filtered := make(map[string]Tool)
		for _, t := range toolByName(CoreTools()) {
			if allowed[t.Name] {
				filtered[t.Name] = t
			}
		}
		o.tools = filtered
	}
}

// WithExecutor sets the target executor (local or SSH).
func WithExecutor(exec transport.TargetExecutor) Option {
	return func(o *Orchestrator) { o.executor = exec }
}

// New constructs an Orchestrator with the four core tools registered.
func New(client LLMClient, router *packs.Router, opts ...Option) *Orchestrator {
	o := &Orchestrator{
		client:        client,
		router:        router,
		tools:         toolByName(CoreTools()),
		maxTurns:      8,
		runID:         "run-" + time.Now().UTC().Format("20060102T150405"),
		cwd:           ".",
		approve:       DefaultApprove,
		budgetTracker: NewBudgetTracker(),
	}
	for _, opt := range opts {
		opt(o)
	}
	// Default to local executor if not set. Allowed paths are unknown at
	// construction time (the pack arrives per-tool-call via deps.Pass), so an
	// empty list fails closed: direct executor writes are denied unless a
	// caller configures allowed paths. WithExecutor is always used in practice.
	if o.executor == nil {
		o.executor = transport.NewLocalExecutor(o.runID, o.cwd, nil)
	}
	return o
}

// Run executes the full pipeline:
//
//	Step 1: collect SystemContext (<5ms)
//	Step 2: route prompt to best InstructionPack (<2ms)
//	Step 3: run the pack's context_cmd inside RunReadOnly
//	Step 4: construct the slim System Prompt
//	Step 5: streaming tool-calling loop with cancellation support
//
// It returns a human-readable summary of the outcome. If the context is
// cancelled (SIGINT / Ctrl+C), it returns immediately with a cancellation
// error.
func (o *Orchestrator) Run(ctx context.Context, prompt string, pipeContext string, commandOnly bool) (string, error) {
	// Step 1: Collect SystemContext (<5ms).
	start := time.Now()
	sysCtx, err := fingerprint.Fingerprint()
	if err != nil {
		return "", fmt.Errorf("fingerprint: %w", err)
	}
	o.sysCtx = sysCtx
	if elapsed := time.Since(start); elapsed > 5*time.Millisecond {
		// Log but do not fail; this is a soft SLO.
		fmt.Fprintf(os.Stderr, "[warn] fingerprint took %v (>5ms)\n", elapsed)
	}

	// Step 2: Route prompt to best InstructionPack (<2ms).
	routeStart := time.Now()
	selected, err := o.router.SelectPacks(prompt, sysCtx)
	if err != nil {
		return "", fmt.Errorf("route: %w", err)
	}
	pack := selected[0]
	if elapsed := time.Since(routeStart); elapsed > 2*time.Millisecond {
		fmt.Fprintf(os.Stderr, "[warn] routing took %v (>2ms)\n", elapsed)
	}

	// Initialize run summary collector for time-machine TUI.
	o.runCollector = audit.NewRunSummaryCollector(o.runID, prompt, pack.ID, o.cwd)

	// Step 3: Run the pack's context_cmd inside RunReadOnly so the LLM starts
	// Turn 1 already knowing the ground truth.
	var contextOutput string
	if pack.ContextCmd != "" && pack.ContextCmd != "true" {
		res, rerr := o.executor.RunReadOnly(ctx, pack.ContextCmd, o.cwd, 0)
		if rerr != nil || res.ExitCode != 0 {
			contextOutput = fmt.Sprintf("[context_cmd produced no output: %v] %s", rerr, res.Stderr)
		} else {
			contextOutput = strings.TrimSpace(res.Stdout)
		}
		// Record context_cmd as a command execution
		o.runCollector.RecordCommand(audit.CommandRecord{
			Command:   pack.ContextCmd,
			ExitCode:  res.ExitCode,
			Stdout:    res.Stdout,
			Stderr:    res.Stderr,
			Timestamp: time.Now().UTC(),
			Source:    "verify_cmd",
			Truncated: res.Truncated,
		})
	}

	// Step 4: Construct the slim System Prompt.
	systemPrompt := buildSystemPrompt(sysCtx, pack, contextOutput, pipeContext, commandOnly)

	// Step 5: Streaming tool-calling loop with cancellation support.
	return o.runLoop(ctx, systemPrompt, prompt, pack)
}

// runLoop executes the multi-turn streaming tool-calling loop.
func (o *Orchestrator) runLoop(ctx context.Context, systemPrompt, userPrompt string, pack packs.Pack) (string, error) {
	toolDefs := openaiTools(values(o.tools))

	messages := []openai.ChatCompletionMessage{
		{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
		{Role: openai.ChatMessageRoleUser, Content: userPrompt},
	}

	// Attach budget tracker to context for tool access
	ctx = WithBudgetTracker(ctx, o.budgetTracker)

	for turn := 0; turn < o.maxTurns; turn++ {
		// Check circuit breaker before each turn
		if o.budgetTracker.IsCircuitBreakerTriggered() {
			return "", fmt.Errorf("circuit breaker triggered: %s", o.budgetTracker.CircuitBreakerReason())
		}

		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("cancelled: %w", err)
		}

		req := openai.ChatCompletionRequest{
			Model:       o.model(),
			Messages:    messages,
			Tools:       toolDefs,
			ToolChoice:  "required",
			Temperature:         o.temperature(),
			MaxCompletionTokens: o.maxTokens(),
			Stream:              true,
		}
		// Convert tool params to string for token estimation
		_ = toolDefs

		stream, err := o.client.ChatCompletionStream(ctx, req)
		if err != nil {
			return "", fmt.Errorf("create stream: %w", err)
		}

		var assistantContent strings.Builder
		// pending accumulates in-call tool calls keyed by stream index.
		pending := make(map[int]*streamingToolCall)
		var order []int

		// Track tokens from this request (approximate)
		promptTokens := estimatePromptTokens(messages, toolDefs)
		o.budgetTracker.RecordPromptTokens(promptTokens)

		for {
			if err := ctx.Err(); err != nil {
				stream.Close()
				return "", fmt.Errorf("cancelled during stream: %w", err)
			}
			sr, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				stream.Close()
				return "", fmt.Errorf("stream recv: %w", err)
			}
			if len(sr.Choices) == 0 {
				continue
			}
			delta := sr.Choices[0].Delta
			assistantContent.WriteString(delta.Content)
			for _, tc := range delta.ToolCalls {
				if tc.Index == nil {
					continue
				}
				idx := *tc.Index
				p, exists := pending[idx]
				if !exists {
					p = &streamingToolCall{index: idx}
					pending[idx] = p
					order = append(order, idx)
				}
				if tc.ID != "" {
					p.id = tc.ID
				}
				p.typ = string(tc.Type)
				if tc.Function.Name != "" {
					p.name = tc.Function.Name
				}
				p.args += tc.Function.Arguments
			}
		}
		stream.Close()

		// Estimate completion tokens
		completionTokens := estimateCompletionTokens(assistantContent.String())
		o.budgetTracker.RecordCompletionTokens(completionTokens)

		// Record tokens for time-machine TUI
		if o.runCollector != nil {
			o.runCollector.RecordTokens(promptTokens, completionTokens)
		}

		assistantMsg := openai.ChatCompletionMessage{
			Role: openai.ChatMessageRoleAssistant,
		}
		if assistantContent.Len() > 0 {
			assistantMsg.Content = assistantContent.String()
		}
		if len(order) > 0 {
			assistantMsg.ToolCalls = make([]openai.ToolCall, 0, len(order))
			for _, idx := range order {
				p := pending[idx]
				assistantMsg.ToolCalls = append(assistantMsg.ToolCalls, openai.ToolCall{
					ID:   p.id,
					Type: openai.ToolType(p.typ),
					Function: openai.FunctionCall{
						Name:      p.name,
						Arguments: p.args,
					},
				})
			}
		}
		messages = append(messages, assistantMsg)

		if len(order) == 0 {
			// No tool calls: surface the assistant text and stop.
			return assistantContent.String(), nil
		}

		// Execute each tool call in order.
		var toolResults []openai.ChatCompletionMessage
		completed := false
		for _, idx := range order {
			p := pending[idx]
			tool, ok := o.tools[p.name]
			if !ok {
				toolResults = append(toolResults, toolResultMessage(p.id, "", fmt.Errorf("unknown tool %q", p.name)))
				continue
			}
			deps := ToolDeps{
				RunID:        o.runID,
				Pack:         &pack,
				Approve:      o.approve,
				CWD:          o.cwd,
				DryRun:       o.dryRun,
				RunCollector: o.runCollector,
				Executor:     o.executor,
			}
			// Parse args to json.RawMessage for budget tracking
			var argsJSON json.RawMessage
			if p.args != "" {
				argsJSON = json.RawMessage(p.args)
			} else {
				argsJSON = json.RawMessage("{}")
			}

			result, err := tool.Func(ctx, argsJSON, deps)

			// Record tool call for circuit breaker detection
			shouldBlock, hint := o.budgetTracker.RecordToolCall(p.name, argsJSON, err == nil && !strings.HasPrefix(result, "TOOL_ERROR:"), err)
			if shouldBlock {
				// Circuit breaker triggered - inject hint and stop
			if o.runCollector != nil {
				o.runCollector.SetStatus(audit.RunStatusFailed)
				o.runCollector.SetError("circuit breaker triggered: " + hint)
				_ = o.runCollector.Save()
			}
			return fmt.Sprintf("CIRCUIT_BREAKER_TRIGGERED: %s", hint), nil
			}

			if err != nil {
				toolResults = append(toolResults, toolResultMessage(p.id, "", err))
				continue
			}
			if strings.HasPrefix(result, "TASK_COMPLETE:") {
				completed = true
			}
			toolResults = append(toolResults, toolResultMessage(p.id, result, nil))
		}
		messages = append(messages, toolResults...)

		if completed {
			// The last complete_task result is the final outcome. Return the
			// last TASK_COMPLETE (or HARNESS_VERIFICATION_FAILED) message.
			last := toolResults[len(toolResults)-1]

			// Save run summary on completion
			if o.runCollector != nil {
				if strings.Contains(last.Content, "TASK_COMPLETE:") {
					o.runCollector.SetStatus(audit.RunStatusVerified)
				} else if strings.Contains(last.Content, "HARNESS_VERIFICATION_FAILED:") {
					o.runCollector.SetStatus(audit.RunStatusFailed)
				}
				_ = o.runCollector.Save()
			}

			return last.Content, nil
		}
		// Otherwise the loop continues, giving the LLM the tool results and
		// another turn to self-correct or call complete_task again.
	}

	// Save run summary on max_turns reached
	if o.runCollector != nil {
		o.runCollector.SetStatus(audit.RunStatusFailed)
		o.runCollector.SetError("max_turns reached without successful task completion")
		_ = o.runCollector.Save()
	}

	return "", fmt.Errorf("max_turns (%d) reached without successful task completion", o.maxTurns)
}

// streamingToolCall accumulates one in-flight tool call from stream deltas.
type streamingToolCall struct {
	index int
	id    string
	typ   string
	name  string
	args  string
}

func toolResultMessage(id, content string, err error) openai.ChatCompletionMessage {
	if err != nil {
		content = fmt.Sprintf("TOOL_ERROR: %v", err)
	}
	return openai.ChatCompletionMessage{
		Role:      openai.ChatMessageRoleTool,
		Content:   content,
		ToolCallID: id,
	}
}

func values(m map[string]Tool) []Tool {
	out := make([]Tool, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func (o *Orchestrator) model() string {
	if o.config != nil && o.config.Model != "" {
		return o.config.Model
	}
	return defaultModel
}

func (o *Orchestrator) temperature() float32 {
	if o.config != nil {
		return o.config.Temperature
	}
	return defaultTemperature
}

func (o *Orchestrator) maxTokens() int {
	if o.config != nil {
		return o.config.MaxTokens
	}
	return defaultMaxTokens
}

// buildSystemPrompt constructs the slim, focused system prompt: Base Safety
// Policy + SystemContext + Selected Pack Markdown + Pre-flight context_cmd
// output + Pipe Context (if any).
func buildSystemPrompt(sysCtx fingerprint.SystemContext, pack packs.Pack, contextOutput string, pipeContext string, commandOnly bool) string {
	var b strings.Builder
	b.WriteString(baseSafetyPolicy())
	b.WriteString("\n")
	b.WriteString("## System Context\n")
	b.WriteString(sysCtx.String())
	b.WriteString("\n")
	b.WriteString("## Selected Instruction Pack\n")
	fmt.Fprintf(&b, "id: %s\nname: %s\n", pack.ID, pack.Name)
	if len(pack.RequiredBins) > 0 {
		fmt.Fprintf(&b, "required_bins: %v\n", pack.RequiredBins)
	}
	if pack.ContextCmd != "" {
		fmt.Fprintf(&b, "context_cmd: %s\n", pack.ContextCmd)
	}
	if pack.VerifyCmd != "" {
		fmt.Fprintf(&b, "verify_cmd: %s\n", pack.VerifyCmd)
	}
	b.WriteString("allowed_paths:\n")
	for _, ap := range pack.AllowedPaths {
		fmt.Fprintf(&b, "  - %s\n", ap)
	}
	b.WriteString("\n## Pack Guidance\n")
	b.WriteString(pack.Body)
	b.WriteString("\n")
	if contextOutput != "" {
		b.WriteString("## Pre-flight Context (context_cmd output)\n")
		b.WriteString(contextOutput)
		b.WriteString("\n")
	}
	if pipeContext != "" {
		b.WriteString("## Piped Stdin Context\n")
		b.WriteString(pipeContext)
		b.WriteString("\n")
	}
	if commandOnly {
		b.WriteString("## Output Mode: Command Only\n")
		b.WriteString("Output ONLY the verified shell command. No explanations, no markdown, no extra text.\n")
		b.WriteString("The command must be a single line, executable as-is in the target shell.\n")
		b.WriteString("\n")
	}
	b.WriteString("## Tool Rules\n")
	b.WriteString("- Never run raw bash. Use inspect_system for read-only inspection.\n")
	b.WriteString("- Use write_scoped_file for any file write within allowed_paths.\n")
	b.WriteString("- Use mutate_system only for out-of-scope writes or host mutations, and only after user approval.\n")
	b.WriteString("- Always end by calling complete_task with summary and target_artifacts.\n")
	b.WriteString("- If complete_task returns HARNESS_VERIFICATION_FAILED, fix the issue and call complete_task again.\n")
	return b.String()
}

func baseSafetyPolicy() string {
	return `## Base Safety Policy

You are LNTA, a Linux Natural-Language Terminal Assistant. You never receive a
raw, unrestricted shell. All actions go through four strictly typed tools:

1. inspect_system — read-only sandboxed command execution (bwrap, read-only
   root, masked secret dirs).
2. write_scoped_file — atomic, scope-checked file writes (allowed_paths only).
3. mutate_system — host mutations, gated behind explicit user approval.
4. complete_task — task completion; the harness enforces verification before
   the task is considered done.

Prefer read-only inspection. Do not attempt to read or exfiltrate secrets.
Do not write outside allowed_paths without mutate_system approval. Confirm
task completion only after verification passes.`
}

// WithSignalCancellation returns a context cancelled on SIGINT / SIGTERM,
// suitable for passing to Orchestrator.Run so Ctrl+C cleanly cancels active
// child processes and triggers process group termination.
func WithSignalCancellation() (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	wrappedCancel := func() {
		cancel()
		sandbox.KillAllChildren()
	}
	go func() {
		<-ctx.Done()
		sandbox.KillAllChildren()
	}()
	return ctx, wrappedCancel
}

// estimatePromptTokens roughly estimates the number of tokens in the prompt.
// This is a heuristic since we don't have access to the tokenizer.
// Roughly: 1 token ≈ 4 characters for English text.
func estimatePromptTokens(messages []openai.ChatCompletionMessage, tools []openai.Tool) int {
	var totalChars int
	for _, msg := range messages {
		totalChars += len(msg.Content)
	}
	// Add estimate for tool definitions
	for _, tool := range tools {
		totalChars += len(tool.Function.Description)
		if tool.Function.Parameters != nil {
			// Parameters is any type, need to marshal to JSON for length
			if b, err := json.Marshal(tool.Function.Parameters); err == nil {
				totalChars += len(b)
			}
		}
	}
	// Add overhead for message formatting
	totalChars += len(messages) * 50
	// 1 token ≈ 4 chars
	return totalChars / 4
}

// estimateCompletionTokens roughly estimates the number of tokens in the completion.
func estimateCompletionTokens(content string) int {
	// 1 token ≈ 4 chars
	return len(content) / 4
}
