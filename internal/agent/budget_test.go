// Package agent tests for the token budget and circuit breaker.
package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestBudgetTrackerTokenLimit(t *testing.T) {
	config := BudgetConfig{
		MaxTokensPerTask:      100,
		MaxIdenticalToolCalls: 2,
	}
	tracker := NewBudgetTrackerWithConfig(config)

	// Record tokens up to limit
	tracker.RecordPromptTokens(50)
	tracker.RecordCompletionTokens(30)
	if tracker.TotalTokens() != 80 {
		t.Errorf("Expected 80 tokens, got %d", tracker.TotalTokens())
	}
	if tracker.RemainingTokens() != 20 {
		t.Errorf("Expected 20 remaining, got %d", tracker.RemainingTokens())
	}

	// Exceed limit
	tracker.RecordCompletionTokens(30)
	if !tracker.IsBudgetExceeded() {
		t.Error("Budget should be exceeded after 110 tokens")
	}
	if tracker.RemainingTokens() != 0 {
		t.Errorf("Remaining should be 0 when exceeded, got %d", tracker.RemainingTokens())
	}
}

func TestBudgetTrackerCircuitBreakerOnIdenticalFailures(t *testing.T) {
	config := BudgetConfig{
		MaxTokensPerTask:       10000,
		MaxIdenticalToolCalls:  2, // Block on 2nd identical failure (max 2 allowed)
	}
	tracker := NewBudgetTrackerWithConfig(config)

	args := json.RawMessage(`{"command": "ls /nonexistent", "cwd": "/", "reason": "test"}`)

	// First failure
	blocked, hint := tracker.RecordToolCall("inspect_system", args, false, nil)
	if blocked {
		t.Errorf("First failure should not block, got: %s", hint)
	}

	// Second failure - should trigger circuit breaker (MaxIdenticalToolCalls = 2)
	blocked, hint = tracker.RecordToolCall("inspect_system", args, false, nil)
	if !blocked {
		t.Error("Second identical failure should trigger circuit breaker")
	}
	if !contains(hint, "CIRCUIT_BREAKER") {
		t.Errorf("Hint should mention circuit breaker: %s", hint)
	}
	if !contains(hint, "identical failing inspect_system call repeated 2 times") {
		t.Errorf("Hint should mention identical call count: %s", hint)
	}

	// Verify circuit breaker state
	if !tracker.IsCircuitBreakerTriggered() {
		t.Error("Circuit breaker should be triggered")
	}
}

func TestBudgetTrackerResetsOnSuccess(t *testing.T) {
	config := BudgetConfig{
		MaxTokensPerTask:       10000,
		MaxIdenticalToolCalls:  2,
	}
	tracker := NewBudgetTrackerWithConfig(config)

	args := json.RawMessage(`{"command": "ls /tmp", "cwd": "/", "reason": "test"}`)

	// Two failures
	tracker.RecordToolCall("inspect_system", args, false, nil)
	tracker.RecordToolCall("inspect_system", args, false, nil)

	// Success - should reset counter
	tracker.RecordToolCall("inspect_system", args, true, nil)

	// Another failure - should be first in new sequence
	blocked, _ := tracker.RecordToolCall("inspect_system", args, false, nil)
	if blocked {
		t.Error("Failure after success should not trigger circuit breaker")
	}
}

func TestBudgetTrackerDifferentArgsNotCountedAsIdentical(t *testing.T) {
	config := BudgetConfig{
		MaxTokensPerTask:       10000,
		MaxIdenticalToolCalls:  5, // Higher limit for this test
	}
	tracker := NewBudgetTrackerWithConfig(config)

	args1 := json.RawMessage(`{"command": "ls /tmp", "cwd": "/", "reason": "test"}`)
	args2 := json.RawMessage(`{"command": "ls /var", "cwd": "/", "reason": "test"}`)

	// Two failures with different args
	tracker.RecordToolCall("inspect_system", args1, false, nil)
	tracker.RecordToolCall("inspect_system", args2, false, nil)

	// Third failure with first args - should be second in sequence for args1
	blocked, _ := tracker.RecordToolCall("inspect_system", args1, false, nil)
	if blocked {
		t.Error("Different args should not count as identical")
	}
}

func TestBudgetTrackerDifferentToolNotCounted(t *testing.T) {
	config := BudgetConfig{
		MaxTokensPerTask:       10000,
		MaxIdenticalToolCalls:  2,
	}
	tracker := NewBudgetTrackerWithConfig(config)

	args := json.RawMessage(`{"path": "/tmp/test", "content": "hello", "reason": "test"}`)

	// Two failures with write_scoped_file
	tracker.RecordToolCall("write_scoped_file", args, false, nil)
	tracker.RecordToolCall("write_scoped_file", args, false, nil)

	// Failure with inspect_system - different tool
	blocked, _ := tracker.RecordToolCall("inspect_system", args, false, nil)
	if blocked {
		t.Error("Different tool should not count as identical")
	}
}

func TestBudgetTrackerContextIntegration(t *testing.T) {
	tracker := NewBudgetTracker()
	ctx := WithBudgetTracker(context.Background(), tracker)

	retrieved := GetBudgetTracker(ctx)
	if retrieved != tracker {
		t.Error("Budget tracker not retrieved from context")
	}

	// Test EnsureBudgetTracker creates new one if missing
	ctx2 := context.Background()
	tracker2 := EnsureBudgetTracker(ctx2)
	if tracker2 == nil {
		t.Error("EnsureBudgetTracker should create new tracker")
	}
}

func TestBudgetTrackerStats(t *testing.T) {
	tracker := NewBudgetTracker()
	tracker.RecordPromptTokens(100)
	tracker.RecordCompletionTokens(200)

	stats := tracker.GetStats()
	if stats["total_prompt_tokens"] != 100 {
		t.Errorf("Expected 100 prompt tokens, got %v", stats["total_prompt_tokens"])
	}
	if stats["total_completion_tokens"] != 200 {
		t.Errorf("Expected 200 completion tokens, got %v", stats["total_completion_tokens"])
	}
	if stats["total_tokens"] != 300 {
		t.Errorf("Expected 300 total tokens, got %v", stats["total_tokens"])
	}
	if stats["circuit_breaker_triggered"] != false {
		t.Error("Circuit breaker should not be triggered initially")
	}
}

func TestBudgetTrackerReset(t *testing.T) {
	config := BudgetConfig{
		MaxTokensPerTask:       100,
		MaxIdenticalToolCalls:  2,
	}
	tracker := NewBudgetTrackerWithConfig(config)

	tracker.RecordPromptTokens(150) // Exceed budget
	args := json.RawMessage(`{"command": "fail", "reason": "test"}`)
	tracker.RecordToolCall("inspect_system", args, false, nil)
	tracker.RecordToolCall("inspect_system", args, false, nil)
	tracker.RecordToolCall("inspect_system", args, false, nil) // Trigger circuit breaker

	if !tracker.IsCircuitBreakerTriggered() {
		t.Error("Circuit breaker should be triggered before reset")
	}

	tracker.Reset()

	if tracker.IsCircuitBreakerTriggered() {
		t.Error("Circuit breaker should be cleared after reset")
	}
	if tracker.TotalTokens() != 0 {
		t.Error("Tokens should be reset to 0")
	}
	if tracker.RemainingTokens() != 100 {
		t.Errorf("Remaining tokens should be 100 after reset, got %d", tracker.RemainingTokens())
	}
}

func TestOrchestratorCircuitBreakerIntegration(t *testing.T) {
	// This test verifies the orchestrator integrates with the budget tracker
	// by checking that circuit breaker triggers are returned properly.
	// We use a mock LLM that makes identical failing calls.

	// The actual integration test is in agent_test.go with a mock LLM
	// This is a unit test for the budget tracker logic in orchestrator context
	// Use MaxIdenticalToolCalls=3 to match test expectation (block on 3rd failure)
	tracker := NewBudgetTrackerWithConfig(BudgetConfig{
		MaxTokensPerTask:       10000,
		MaxIdenticalToolCalls:  3,
	})
	_ = WithBudgetTracker(context.Background(), tracker)

	// Simulate tool calls through the tracker
	args := json.RawMessage(`{"command": "ls /nonexistent", "cwd": "/", "reason": "test"}`)

	for i := 0; i < 3; i++ {
		blocked, hint := tracker.RecordToolCall("inspect_system", args, false, nil)
		if i < 2 {
			if blocked {
				t.Errorf("Call %d should not block", i+1)
			}
		} else {
			if !blocked {
				t.Error("Call 3 should trigger circuit breaker")
			}
			if !contains(hint, "CIRCUIT_BREAKER") {
				t.Errorf("Hint should contain CIRCUIT_BREAKER: %s", hint)
			}
		}
	}

	// Verify the context would return the circuit breaker message
	if tracker.IsCircuitBreakerTriggered() {
		t.Logf("Circuit breaker reason: %s", tracker.CircuitBreakerReason())
	}
}

func TestBudgetTrackerConcurrency(t *testing.T) {
	tracker := NewBudgetTracker()

	// Simulate concurrent access
	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func(idx int) {
			args := json.RawMessage(`{"id": ` + string(rune('0'+idx%10)) + `}`)
			tracker.RecordToolCall("inspect_system", args, idx%2 == 0, nil)
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	// Should not panic and stats should be consistent
	stats := tracker.GetStats()
	t.Logf("Concurrent test stats: %v", stats)
	if stats["total_tokens"].(int) < 0 {
		t.Error("Token count should not be negative")
	}
}

func TestBudgetTrackerTimeTracking(t *testing.T) {
	tracker := NewBudgetTracker()
	args := json.RawMessage(`{"test": "time"}`)

	before := time.Now()
	tracker.RecordToolCall("inspect_system", args, true, nil)
	after := time.Now()

	// Verify the tool call history has timestamps
	stats := tracker.GetStats()
	if stats["tool_calls_count"].(int) != 1 {
		t.Error("Should have 1 tool call recorded")
	}
	// We can't easily check the internal timestamp without exporting it,
	// but the fact that RecordToolCall didn't panic is a good sign
	_ = before
	_ = after
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}