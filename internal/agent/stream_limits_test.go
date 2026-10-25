package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sashabaranov/go-openai"
	"github.com/sm-me-dev/lnta/internal/packs"
)

func streamedResponse(delta openai.ChatCompletionStreamChoiceDelta) openai.ChatCompletionStreamResponse {
	return openai.ChatCompletionStreamResponse{Choices: []openai.ChatCompletionStreamChoice{{Delta: delta}}}
}

func TestCollectStreamedCompletionAllowsAssistantTextAtLimit(t *testing.T) {
	stream := &mockStream{responses: []openai.ChatCompletionStreamResponse{
		streamedResponse(openai.ChatCompletionStreamChoiceDelta{Content: strings.Repeat("x", maxStreamedAssistantText)}),
	}}
	content, order, pending, _, err := collectStreamedCompletion(context.Background(), stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != maxStreamedAssistantText || len(order) != 0 || len(pending) != 0 {
		t.Fatalf("unexpected completion result: content=%d calls=%d pending=%d", len(content), len(order), len(pending))
	}
	if stream.closeCount != 1 {
		t.Fatalf("stream close count=%d, want 1", stream.closeCount)
	}
}

func TestCollectStreamedCompletionJoinsFragmentedCallFields(t *testing.T) {
	idx := 0
	first := streamedResponse(openai.ChatCompletionStreamChoiceDelta{ToolCalls: []openai.ToolCall{{
		Index: &idx,
		ID:    "call-",
		Type:  openai.ToolTypeFunction,
		Function: openai.FunctionCall{
			Name:      "inspect_",
			Arguments: `{"command":`,
		},
	}}})
	second := streamedResponse(openai.ChatCompletionStreamChoiceDelta{ToolCalls: []openai.ToolCall{{
		Index: &idx,
		ID:    "1",
		Function: openai.FunctionCall{
			Name:      "system",
			Arguments: `"true"}`,
		},
	}}})
	second.Choices[0].FinishReason = openai.FinishReasonToolCalls
	stream := &mockStream{responses: []openai.ChatCompletionStreamResponse{first, second}}
	_, order, pending, _, err := collectStreamedCompletion(context.Background(), stream)
	if err != nil {
		t.Fatal(err)
	}
	call := pending[order[0]]
	if call.id != "call-1" || call.typ != string(openai.ToolTypeFunction) || call.name != "inspect_system" || call.args != `{"command":"true"}` {
		t.Fatalf("fragmented call fields were not joined: %#v", call)
	}
}

func TestCollectStreamedCompletionRejectsOversizedTextBeforeAppend(t *testing.T) {
	stream := &mockStream{responses: []openai.ChatCompletionStreamResponse{
		streamedResponse(openai.ChatCompletionStreamChoiceDelta{Content: strings.Repeat("x", maxStreamedAssistantText+1)}),
	}}
	content, order, pending, _, err := collectStreamedCompletion(context.Background(), stream)
	if err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatalf("expected text limit error, got %v", err)
	}
	if content != "" || order != nil || pending != nil {
		t.Fatalf("rejected completion leaked partial result: %d bytes, %v, %v", len(content), order, pending)
	}
	if stream.closeCount != 1 {
		t.Fatalf("stream close count=%d, want 1", stream.closeCount)
	}
}

func TestCollectStreamedCompletionRejectsOversizedArgument(t *testing.T) {
	idx := 0
	stream := &mockStream{responses: []openai.ChatCompletionStreamResponse{
		streamedResponse(openai.ChatCompletionStreamChoiceDelta{ToolCalls: []openai.ToolCall{{
			Index:    &idx,
			Function: openai.FunctionCall{Arguments: strings.Repeat("x", maxStreamedToolArgument+1)},
		}}}),
	}}
	_, order, pending, _, err := collectStreamedCompletion(context.Background(), stream)
	if err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("expected argument limit error, got %v", err)
	}
	if order != nil || pending != nil || stream.closeCount != 1 {
		t.Fatalf("rejected argument retained state or left stream open: order=%v pending=%v closes=%d", order, pending, stream.closeCount)
	}
}

func TestCollectStreamedCompletionRejectsMoreThan64Calls(t *testing.T) {
	calls := make([]openai.ToolCall, 0, maxStreamedToolCalls+1)
	for i := 0; i <= maxStreamedToolCalls; i++ {
		idx := i
		calls = append(calls, openai.ToolCall{Index: &idx})
	}
	stream := &mockStream{responses: []openai.ChatCompletionStreamResponse{
		streamedResponse(openai.ChatCompletionStreamChoiceDelta{ToolCalls: calls}),
	}}
	_, order, pending, _, err := collectStreamedCompletion(context.Background(), stream)
	if err == nil || !strings.Contains(err.Error(), "64 tool call") {
		t.Fatalf("expected call count limit error, got %v", err)
	}
	if order != nil || pending != nil || stream.closeCount != 1 {
		t.Fatalf("rejected response retained calls or left stream open: order=%v pending=%v closes=%d", order, pending, stream.closeCount)
	}
}

func TestCollectStreamedCompletionEnforcesAggregateLimit(t *testing.T) {
	const argumentSize = 1 << 20
	calls := make([]openai.ToolCall, 0, 9)
	for i := 0; i < 9; i++ {
		idx := i
		calls = append(calls, openai.ToolCall{
			Index: &idx,
			ID:    "id",
			Type:  openai.ToolTypeFunction,
			Function: openai.FunctionCall{
				Name:      "inspect_system",
				Arguments: strings.Repeat("x", argumentSize),
			},
		})
	}
	stream := &mockStream{responses: []openai.ChatCompletionStreamResponse{
		streamedResponse(openai.ChatCompletionStreamChoiceDelta{ToolCalls: calls}),
	}}
	_, order, pending, _, err := collectStreamedCompletion(context.Background(), stream)
	if err == nil || !strings.Contains(err.Error(), "8 MiB") {
		t.Fatalf("expected aggregate limit error, got %v", err)
	}
	if order != nil || pending != nil || stream.closeCount != 1 {
		t.Fatalf("rejected response retained calls or left stream open: order=%v pending=%v closes=%d", order, pending, stream.closeCount)
	}
}

func TestCollectStreamedCompletionAggregateIncludesCallIDsAndNames(t *testing.T) {
	idx := 0
	stream := &mockStream{responses: []openai.ChatCompletionStreamResponse{
		streamedResponse(openai.ChatCompletionStreamChoiceDelta{ToolCalls: []openai.ToolCall{{
			Index: &idx,
			ID:    strings.Repeat("i", 4<<20),
			Type:  openai.ToolTypeFunction,
			Function: openai.FunctionCall{
				Name: strings.Repeat("n", 4<<20),
			},
		}}}),
	}}
	_, order, pending, _, err := collectStreamedCompletion(context.Background(), stream)
	if err == nil || !strings.Contains(err.Error(), "8 MiB") {
		t.Fatalf("expected ID/name aggregate limit error, got %v", err)
	}
	if order != nil || pending != nil || stream.closeCount != 1 {
		t.Fatalf("rejected response retained calls or left stream open: order=%v pending=%v closes=%d", order, pending, stream.closeCount)
	}
}

func TestRunLoopDoesNotExecuteRejectedStreamedToolCall(t *testing.T) {
	idx := 0
	response := streamedResponse(openai.ChatCompletionStreamChoiceDelta{ToolCalls: []openai.ToolCall{{
		Index: &idx,
		ID:    "call-1",
		Type:  openai.ToolTypeFunction,
		Function: openai.FunctionCall{
			Name:      "inspect_system",
			Arguments: strings.Repeat("x", maxStreamedToolArgument+1),
		},
	}}})
	client := &mockLLM{scenarios: [][]openai.ChatCompletionStreamResponse{{response}}}
	orchestrator := New(client, nil)
	executions := 0
	orchestrator.tools = map[string]Tool{
		"inspect_system": {Name: "inspect_system", Func: func(context.Context, json.RawMessage, ToolDeps) (string, error) {
			executions++
			return "unexpected", nil
		}},
	}
	if _, err := orchestrator.runLoop(context.Background(), "system", "user", packs.Pack{}); err == nil {
		t.Fatal("oversized streamed response was accepted")
	}
	if executions != 0 {
		t.Fatalf("rejected provider tool call executed %d time(s)", executions)
	}
}
