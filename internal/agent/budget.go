// Package agent provides token budget tracking and runaway loop circuit breaker.
// This implements the Runaway Loop & Token Budget Circuit Breaker for Phase 9.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// BudgetConfig holds configuration for the token budget and circuit breaker.
type BudgetConfig struct {
	// MaxTokensPerTask is the maximum cumulative tokens (prompt + completion)
	// allowed per task invocation. Default: 32000.
	MaxTokensPerTask int

	// MaxIdenticalToolCalls is the maximum number of identical failing tool
	// calls allowed before the circuit breaker triggers. Default: 2 (block on 3rd).
	MaxIdenticalToolCalls int
}

// DefaultBudgetConfig returns the default budget configuration.
func DefaultBudgetConfig() BudgetConfig {
	return BudgetConfig{
		MaxTokensPerTask:       32000,
		MaxIdenticalToolCalls:  2,
	}
}

// ToolCallRecord tracks a single tool call for circuit breaker detection.
type ToolCallRecord struct {
	ToolName    string
	ArgsHash    string
	Success     bool
	Timestamp   time.Time
	Error       string
}

// BudgetTracker tracks token usage and tool call patterns per task invocation.
type BudgetTracker struct {
	mu                      sync.Mutex
	config                  BudgetConfig
	totalPromptTokens       int
	totalCompletionTokens   int
	toolCallHistory         []ToolCallRecord
	identicalFailureCounts  map[string]int // argsHash -> consecutive failure count
	circuitBreakerTriggered bool
	circuitBreakerReason    string
}

// NewBudgetTracker creates a new budget tracker with default config.
func NewBudgetTracker() *BudgetTracker {
	return NewBudgetTrackerWithConfig(DefaultBudgetConfig())
}

// NewBudgetTrackerWithConfig creates a new budget tracker with custom config.
func NewBudgetTrackerWithConfig(config BudgetConfig) *BudgetTracker {
	return &BudgetTracker{
		config:                 config,
		toolCallHistory:        make([]ToolCallRecord, 0),
		identicalFailureCounts: make(map[string]int),
	}
}

// RecordPromptTokens adds prompt tokens to the budget.
func (bt *BudgetTracker) RecordPromptTokens(tokens int) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	bt.totalPromptTokens += tokens
}

// RecordCompletionTokens adds completion tokens to the budget.
func (bt *BudgetTracker) RecordCompletionTokens(tokens int) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	bt.totalCompletionTokens += tokens
}

// TotalTokens returns the cumulative tokens used.
func (bt *BudgetTracker) TotalTokens() int {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	return bt.totalPromptTokens + bt.totalCompletionTokens
}

// RemainingTokens returns the remaining token budget.
func (bt *BudgetTracker) RemainingTokens() int {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	used := bt.totalPromptTokens + bt.totalCompletionTokens
	remaining := bt.config.MaxTokensPerTask - used
	if remaining < 0 {
		return 0
	}
	return remaining
}

// IsBudgetExceeded returns true if the token budget has been exceeded.
func (bt *BudgetTracker) IsBudgetExceeded() bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	return (bt.totalPromptTokens + bt.totalCompletionTokens) > bt.config.MaxTokensPerTask
}

// hashArgs creates a deterministic hash of tool arguments for comparison.
func hashArgs(args json.RawMessage) string {
	sum := sha256.Sum256(args)
	return hex.EncodeToString(sum[:])
}

// RecordToolCall records a tool call and checks for runaway loop patterns.
// Returns (shouldBlock, hintMessage). If shouldBlock is true, the caller
// should not execute the tool and instead return the hint message to the LLM.
func (bt *BudgetTracker) RecordToolCall(toolName string, args json.RawMessage, success bool, err error) (bool, string) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	argsHash := hashArgs(args)
	record := ToolCallRecord{
		ToolName:  toolName,
		ArgsHash:  argsHash,
		Success:   success,
		Timestamp: time.Now(),
	}
	if err != nil {
		record.Error = err.Error()
	}
	bt.toolCallHistory = append(bt.toolCallHistory, record)

	// Check for identical consecutive failures
	key := toolName + ":" + argsHash
	if !success {
		bt.identicalFailureCounts[key]++
		count := bt.identicalFailureCounts[key]
		if count >= bt.config.MaxIdenticalToolCalls {
			bt.circuitBreakerTriggered = true
			bt.circuitBreakerReason = fmt.Sprintf(
				"identical failing %s call repeated %d times (args hash: %s)",
				toolName, count, argsHash[:16])
			return true, fmt.Sprintf(
				"CIRCUIT_BREAKER: The same %s call with identical arguments has failed %d times. "+
					"Try a different diagnostic approach (e.g., use different flags, check different paths, or examine logs). "+
					"Circuit breaker reason: %s",
				toolName, count, bt.circuitBreakerReason)
		}
	} else {
		// Reset failure count on success
		bt.identicalFailureCounts[key] = 0
	}

	// Check token budget (inline to avoid deadlock)
	if (bt.totalPromptTokens + bt.totalCompletionTokens) > bt.config.MaxTokensPerTask {
		bt.circuitBreakerTriggered = true
		bt.circuitBreakerReason = fmt.Sprintf(
			"token budget exceeded: %d/%d tokens used",
			bt.totalPromptTokens+bt.totalCompletionTokens, bt.config.MaxTokensPerTask)
		return true, fmt.Sprintf(
			"CIRCUIT_BREAKER: Token budget exceeded (%d/%d). Task terminated to prevent runaway loop.",
			bt.totalPromptTokens+bt.totalCompletionTokens, bt.config.MaxTokensPerTask)
	}

	return false, ""
}

// IsCircuitBreakerTriggered returns true if the circuit breaker has been triggered.
func (bt *BudgetTracker) IsCircuitBreakerTriggered() bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	return bt.circuitBreakerTriggered
}

// CircuitBreakerReason returns the reason the circuit breaker was triggered.
func (bt *BudgetTracker) CircuitBreakerReason() string {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	return bt.circuitBreakerReason
}

// Reset clears the tracker for a new task.
func (bt *BudgetTracker) Reset() {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	bt.totalPromptTokens = 0
	bt.totalCompletionTokens = 0
	bt.toolCallHistory = bt.toolCallHistory[:0]
	bt.identicalFailureCounts = make(map[string]int)
	bt.circuitBreakerTriggered = false
	bt.circuitBreakerReason = ""
}

// GetStats returns current budget statistics.
func (bt *BudgetTracker) GetStats() map[string]any {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	used := bt.totalPromptTokens + bt.totalCompletionTokens
	remaining := bt.config.MaxTokensPerTask - used
	if remaining < 0 {
		remaining = 0
	}
	return map[string]any{
		"total_prompt_tokens":       bt.totalPromptTokens,
		"total_completion_tokens":   bt.totalCompletionTokens,
		"total_tokens":              used,
		"max_tokens":                bt.config.MaxTokensPerTask,
		"remaining_tokens":          remaining,
		"tool_calls_count":          len(bt.toolCallHistory),
		"circuit_breaker_triggered": bt.circuitBreakerTriggered,
		"circuit_breaker_reason":    bt.circuitBreakerReason,
	}
}

// BudgetTrackerKey is the context key for storing BudgetTracker in context.
type BudgetTrackerKey struct{}

// WithBudgetTracker returns a new context with the budget tracker attached.
func WithBudgetTracker(ctx context.Context, tracker *BudgetTracker) context.Context {
	return context.WithValue(ctx, BudgetTrackerKey{}, tracker)
}

// GetBudgetTracker retrieves the budget tracker from context.
func GetBudgetTracker(ctx context.Context) *BudgetTracker {
	if tracker, ok := ctx.Value(BudgetTrackerKey{}).(*BudgetTracker); ok {
		return tracker
	}
	return nil
}

// EnsureBudgetTracker returns the budget tracker from context, creating a new
// one with default config if none exists.
func EnsureBudgetTracker(ctx context.Context) *BudgetTracker {
	if tracker := GetBudgetTracker(ctx); tracker != nil {
		return tracker
	}
	tracker := NewBudgetTracker()
	return tracker
}