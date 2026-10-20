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
	"time"

	"github.com/sashabaranov/go-openai"
	"github.com/sm-me/lnta/internal/fingerprint"
	"github.com/sm-me/lnta/internal/packs"
	"github.com/sm-me/lnta/internal/sandbox"
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

	// Budget tracking for runaway loop and token budget circuit breaker.
	budgetTracker *BudgetTracker
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

// NewOpenAIClient builds an LLMClient backed by sashabaranov/go-openai using the
// given config. It supports any OpenAI-compatible endpoint (OpenAI, OpenRouter,
// Ollama, Anthropic proxy, Gemini).
func NewOpenAIClient(cfg *Config) (LLMClient, error) {
	cliCfg := openai.DefaultConfig(cfg.APIKey)
	cliCfg.BaseURL = cfg.BaseURL
	client := openai.NewClientWithConfig(cliCfg)
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

	// Step 3: Run the pack's context_cmd inside RunReadOnly so the LLM starts
	// Turn 1 already knowing the ground truth.
	var contextOutput string
	if pack.ContextCmd != "" && pack.ContextCmd != "true" {
		res, rerr := sandbox.RunReadOnly(ctx, pack.ContextCmd, o.cwd, 0)
		if rerr != nil || res.ExitCode != 0 {
			contextOutput = fmt.Sprintf("[context_cmd produced no output: %v] %s", rerr, res.Stderr)
		} else {
			contextOutput = strings.TrimSpace(res.Stdout)
		}
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
			Temperature: o.temperature(),
			MaxTokens:   o.maxTokens(),
			Stream:      true,
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
				RunID:   o.runID,
				Pack:    &pack,
				Approve: o.approve,
				CWD:     o.cwd,
				DryRun:  o.dryRun,
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
			return last.Content, nil
		}
		// Otherwise the loop continues, giving the LLM the tool results and
		// another turn to self-correct or call complete_task again.
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
	b.WriteString(fmt.Sprintf("id: %s\nname: %s\n", pack.ID, pack.Name))
	if len(pack.RequiredBins) > 0 {
		b.WriteString(fmt.Sprintf("required_bins: %v\n", pack.RequiredBins))
	}
	if pack.ContextCmd != "" {
		b.WriteString(fmt.Sprintf("context_cmd: %s\n", pack.ContextCmd))
	}
	if pack.VerifyCmd != "" {
		b.WriteString(fmt.Sprintf("verify_cmd: %s\n", pack.VerifyCmd))
	}
	b.WriteString("allowed_paths:\n")
	for _, ap := range pack.AllowedPaths {
		b.WriteString(fmt.Sprintf("  - %s\n", ap))
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
// child processes.
func WithSignalCancellation() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
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
