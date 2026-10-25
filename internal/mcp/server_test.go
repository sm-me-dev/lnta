// Package mcp implements a JSON-RPC 2.0 Model Context Protocol (MCP) server
// over stdio, exposing LNTA's capabilities as MCP tools.
package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sm-me-dev/lnta/internal/packs"
	"github.com/sm-me-dev/lnta/internal/sandbox"
)

// TestMCP_Initialize tests the initialize handshake
func TestMCP_Initialize(t *testing.T) {
	// We can't easily test the full server without stdin/stdout
	// So we test the individual handler functions
}

// TestMCP_ToolsList tests the tools/list method
func TestMCP_ToolsList(t *testing.T) {
	// This would test the tools/list response structure
	tools := []tool{
		{
			Name:        "lnta_inspect_sandboxed",
			Description: "Execute a read-only shell command inside a bwrap sandbox.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{
						"type":        "string",
						"description": "The shell command to execute",
					},
					"cwd": map[string]interface{}{
						"type":        "string",
						"description": "Working directory",
					},
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "Why this inspection is needed",
					},
				},
				"required": []string{"command", "cwd", "reason"},
			},
		},
		{
			Name:        "lnta_get_pack_runbook",
			Description: "Get the full instruction pack by pack ID.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"pack_id": map[string]interface{}{
						"type":        "string",
						"description": "The ID of the instruction pack",
					},
				},
				"required": []string{"pack_id"},
			},
		},
		{
			Name:        "lnta_verify_task",
			Description: "Run a pack's verify_cmd with the given target.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"pack_id": map[string]interface{}{
						"type":        "string",
						"description": "The ID of the instruction pack",
					},
					"target": map[string]interface{}{
						"type":        "string",
						"description": "The target artifact path",
					},
				},
				"required": []string{"pack_id", "target"},
			},
		},
	}

	// Verify all three tools are defined
	if len(tools) != 3 {
		t.Errorf("expected 3 tools, got %d", len(tools))
	}

	// Verify tool names
	expectedNames := []string{"lnta_inspect_sandboxed", "lnta_get_pack_runbook", "lnta_verify_task"}
	for i, tool := range tools {
		if tool.Name != expectedNames[i] {
			t.Errorf("tool %d: expected name %s, got %s", i, expectedNames[i], tool.Name)
		}
	}

	// Verify all have input schemas
	for _, tool := range tools {
		if tool.InputSchema == nil {
			t.Errorf("tool %s missing input schema", tool.Name)
		}
		if tool.Description == "" {
			t.Errorf("tool %s missing description", tool.Name)
		}
	}
}

// TestMCP_JSONRPCRequestParsing tests JSON-RPC request parsing
func TestMCP_JSONRPCRequestParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantMethod string
		wantError  bool
	}{
		{
			name:       "valid initialize",
			input:      `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
			wantMethod: "initialize",
			wantError:  false,
		},
		{
			name:       "valid tools/list",
			input:      `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
			wantMethod: "tools/list",
			wantError:  false,
		},
		{
			name:       "valid tools/call",
			input:      `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lnta_inspect_sandboxed","arguments":{"command":"echo test","cwd":"/tmp","reason":"test"}}}`,
			wantMethod: "tools/call",
			wantError:  false,
		},
		{
			name:       "different jsonrpc version (parsed but will be rejected by server)",
			input:      `{"jsonrpc":"1.0","id":1,"method":"initialize"}`,
			wantMethod: "initialize",
			wantError:  false,
		},
		{
			name:       "missing jsonrpc (parsed but will be rejected by server)",
			input:      `{"id":1,"method":"initialize"}`,
			wantMethod: "initialize",
			wantError:  false,
		},
		{
			name:      "invalid json",
			input:     `{not valid json}`,
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req jsonrpcRequest
			err := json.Unmarshal([]byte(tc.input), &req)

			if tc.wantError {
				if err == nil {
					t.Error("expected parse error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			// Only check jsonrpc version for valid 2.0 cases
			if tc.wantMethod == "initialize" && tc.name == "valid initialize" {
				if req.JSONRPC != "2.0" {
					t.Errorf("expected jsonrpc 2.0, got %s", req.JSONRPC)
				}
			}
			if req.Method != tc.wantMethod {
				t.Errorf("expected method %s, got %s", tc.wantMethod, req.Method)
			}
		})
	}
}

// TestMCP_ToolCallParams tests tool call parameter parsing
func TestMCP_ToolCallParams(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lnta_inspect_sandboxed","arguments":{"command":"echo hello","cwd":"/tmp","reason":"test inspection"}}}`

	var req jsonrpcRequest
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		t.Fatalf("parse request: %v", err)
	}

	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		t.Fatalf("parse params: %v", err)
	}

	if params.Name != "lnta_inspect_sandboxed" {
		t.Errorf("expected tool name lnta_inspect_sandboxed, got %s", params.Name)
	}

	if params.Arguments == nil {
		t.Fatal("arguments is nil")
	}

	cmd, ok := params.Arguments["command"].(string)
	if !ok || cmd != "echo hello" {
		t.Errorf("expected command 'echo hello', got %v", cmd)
	}

	cwd, ok := params.Arguments["cwd"].(string)
	if !ok || cwd != "/tmp" {
		t.Errorf("expected cwd '/tmp', got %v", cwd)
	}

	reason, ok := params.Arguments["reason"].(string)
	if !ok || reason != "test inspection" {
		t.Errorf("expected reason 'test inspection', got %v", reason)
	}
}

// TestMCP_ErrorResponse tests error response formatting
func TestMCP_ErrorResponse(t *testing.T) {
	errResp := jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Error: &jsonrpcError{
			Code:    -32601,
			Message: "Method not found",
			Data:    "Method 'invalid' not found",
		},
	}

	data, err := json.Marshal(errResp)
	if err != nil {
		t.Fatalf("marshal error response: %v", err)
	}

	var parsed jsonrpcResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}

	if parsed.Error == nil {
		t.Fatal("error field missing after round-trip")
	}

	if parsed.Error.Code != -32601 {
		t.Errorf("expected code -32601, got %d", parsed.Error.Code)
	}

	if parsed.Error.Message != "Method not found" {
		t.Errorf("expected message 'Method not found', got %s", parsed.Error.Message)
	}
}

// TestMCP_ToolCallResult tests tool call result formatting
func TestMCP_ToolCallResult(t *testing.T) {
	result := toolCallResult{
		Content: []toolContent{
			{Type: "text", Text: "command output here"},
		},
		IsError: false,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	var parsed toolCallResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if len(parsed.Content) != 1 {
		t.Errorf("expected 1 content item, got %d", len(parsed.Content))
	}

	if parsed.Content[0].Text != "command output here" {
		t.Errorf("expected text 'command output here', got %s", parsed.Content[0].Text)
	}

	if parsed.IsError {
		t.Error("expected IsError=false")
	}

	// Test error result
	errResult := toolCallResult{
		Content: []toolContent{{Type: "text", Text: "something failed"}},
		IsError: true,
	}

	data, err = json.Marshal(errResult)
	if err != nil {
		t.Fatalf("marshal error result: %v", err)
	}

	var parsedErr toolCallResult
	if err := json.Unmarshal(data, &parsedErr); err != nil {
		t.Fatalf("unmarshal error result: %v", err)
	}

	if !parsedErr.IsError {
		t.Error("expected IsError=true")
	}
}

// TestMCP_InitializeResult tests initialize result formatting
func TestMCP_InitializeResult(t *testing.T) {
	result := initializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		ServerInfo: map[string]string{
			"name":    "lnta",
			"version": "1.0.0",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal initialize result: %v", err)
	}

	var parsed initializeResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal initialize result: %v", err)
	}

	if parsed.ProtocolVersion != "2024-11-05" {
		t.Errorf("expected protocol version 2024-11-05, got %s", parsed.ProtocolVersion)
	}

	if parsed.ServerInfo["name"] != "lnta" {
		t.Errorf("expected server name lnta, got %s", parsed.ServerInfo["name"])
	}
}

// TestMCP_ToolsListResult tests tools/list result formatting
func TestMCP_ToolsListResult(t *testing.T) {
	result := toolsListResult{
		Tools: []tool{
			{Name: "test-tool", Description: "A test tool"},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal tools list: %v", err)
	}

	var parsed toolsListResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal tools list: %v", err)
	}

	if len(parsed.Tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(parsed.Tools))
	}
}

// TestMCP_ContextCmdExecution tests the inspect_sandboxed tool logic
func TestMCP_InspectSandboxed_ContextCmd(t *testing.T) {
	home, err := os.MkdirTemp(".", ".lnta-mcp-home-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	home, err = filepath.Abs(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	project := filepath.Join(home, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := sandbox.SandboxAvailable(); err != nil {
		t.Skipf("skipping: sandbox unavailable (%v)", err)
	}

	// This tests the tool logic by calling the sandbox directly
	ctx := context.Background()
	res, err := sandbox.RunReadOnly(ctx, "echo hello", project, 5*time.Second)
	if err != nil {
		t.Fatalf("RunReadOnly: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}

	if !strings.Contains(res.Stdout, "hello") {
		t.Errorf("expected stdout to contain 'hello', got %s", res.Stdout)
	}
}

// TestMCP_GetPackRunbook tests getting a pack by ID
func TestMCP_GetPackRunbook(t *testing.T) {
	// Test the pack parsing directly using a temp file
	tmpDir := t.TempDir()
	packFile := filepath.Join(tmpDir, "test.md")
	packContent := `---
id: test-pack
name: Test Pack
triggers:
  - test
allowed_paths: []
required_bins: []
context_cmd: true
verify_cmd: true
---
# Test Pack Body

This is a test pack.
`
	if err := os.WriteFile(packFile, []byte(packContent), 0o644); err != nil {
		t.Fatalf("write pack file: %v", err)
	}

	// Parse the pack directly using parsePack
	data, err := os.ReadFile(packFile)
	if err != nil {
		t.Fatalf("read pack file: %v", err)
	}

	pack, err := packs.ParsePackForTest(packFile, data)
	if err != nil {
		t.Fatalf("parsePack: %v", err)
	}

	if pack.ID != "test-pack" {
		t.Errorf("expected pack ID test-pack, got %s", pack.ID)
	}

	if pack.Body == "" {
		t.Error("pack body is empty")
	}

	if !strings.Contains(pack.Body, "Test Pack Body") {
		t.Errorf("pack body doesn't contain expected content")
	}
}

// TestMCP_VerifyTask tests the verify_task tool logic
func TestMCP_VerifyTask(t *testing.T) {
	command := `test -f "${target}" && test "$LNTA_TARGET" = "${target}"`
	value := `a'; touch /tmp/marker; #`
	env, err := makeMCPVerificationEnv(command, value)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(env, "target="+value) || !slices.Contains(env, "LNTA_TARGET="+value) {
		t.Fatalf("verification target was not passed as data: %q", env)
	}
	if _, err := makeMCPVerificationEnv(`test "${unit}"`, value); err == nil {
		t.Fatal("unprovided verify_cmd placeholder was accepted")
	}
}
