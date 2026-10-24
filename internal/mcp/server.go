// Package mcp implements a JSON-RPC 2.0 Model Context Protocol (MCP) server
// over stdio, exposing LNTA's capabilities as MCP tools.
package mcp

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/sm-me-dev/lnta/internal/packs"
	"github.com/sm-me-dev/lnta/internal/sandbox"
)

// JSON-RPC 2.0 types
type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCP types
type initializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      map[string]string      `json:"clientInfo"`
}

type initializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      map[string]string      `json:"serverInfo"`
}

type tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type toolsListResult struct {
	Tools []tool `json:"tools"`
}

type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type toolCallResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Server holds the MCP server state.
type Server struct {
	stdin  *bufio.Reader
	stdout *bufio.Writer
	router *packs.Router
}

// NewServer creates a new MCP server.
func NewServer(userConfigDir string, embeddedPacks embed.FS) (*Server, error) {
	router, err := packs.NewRouter(embeddedPacks, "packs/*.md", userConfigDir)
	if err != nil {
		return nil, fmt.Errorf("load packs: %w", err)
	}
	packs.SetDefaultRouter(router)

	return &Server{
		stdin:  bufio.NewReader(os.Stdin),
		stdout: bufio.NewWriter(os.Stdout),
		router: router,
	}, nil
}

// Run starts the MCP server loop.
func (s *Server) Run(ctx context.Context) error {
	// Handle shutdown signals
	sigCtx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	for {
		select {
		case <-sigCtx.Done():
			return sigCtx.Err()
		default:
			line, err := s.stdin.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return fmt.Errorf("read stdin: %w", err)
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			var req jsonrpcRequest
			if err := json.Unmarshal([]byte(line), &req); err != nil {
				s.writeError(nil, -32700, "Parse error", err.Error())
				continue
			}

			if req.JSONRPC != "2.0" {
				s.writeError(req.ID, -32600, "Invalid Request", "jsonrpc must be '2.0'")
				continue
			}

			s.handleRequest(sigCtx, &req)
		}
	}
}

func (s *Server) handleRequest(ctx context.Context, req *jsonrpcRequest) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "initialized":
		// Notification, no response needed
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolCall(ctx, req)
	default:
		s.writeError(req.ID, -32601, "Method not found", fmt.Sprintf("Method '%s' not found", req.Method))
	}
}

func (s *Server) handleInitialize(req *jsonrpcRequest) {
	var params initializeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.writeError(req.ID, -32602, "Invalid params", err.Error())
		return
	}

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
	s.writeResult(req.ID, result)
}

func (s *Server) handleToolsList(req *jsonrpcRequest) {
	tools := []tool{
		{
			Name:        "lnta_inspect_sandboxed",
			Description: "Execute a read-only shell command inside a bwrap sandbox. The entire root filesystem is bind-mounted read-only; /tmp is a private tmpfs; secret dirs (.ssh, .gnupg, .aws, .kube, .config/lnta) are masked. Stdin is /dev/null. Use this for system inspection only — it cannot modify the host.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{
						"type":        "string",
						"description": "The shell command to execute (read-only), run via sh -c inside the sandbox.",
					},
					"cwd": map[string]interface{}{
						"type":        "string",
						"description": "Working directory for the command.",
					},
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "Why this inspection is needed.",
					},
				},
				"required": []string{"command", "cwd", "reason"},
				"additionalProperties": false,
			},
		},
		{
			Name:        "lnta_get_pack_runbook",
			Description: "Get the full instruction pack (markdown body + frontmatter) by pack ID.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"pack_id": map[string]interface{}{
						"type":        "string",
						"description": "The ID of the instruction pack to retrieve.",
					},
				},
				"required": []string{"pack_id"},
				"additionalProperties": false,
			},
		},
		{
			Name:        "lnta_verify_task",
			Description: "Run a pack's verify_cmd with the given target artifact to verify task completion.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"pack_id": map[string]interface{}{
						"type":        "string",
						"description": "The ID of the instruction pack whose verify_cmd to run.",
					},
					"target": map[string]interface{}{
						"type":        "string",
						"description": "The target artifact path to verify (substituted for ${target} in verify_cmd).",
					},
				},
				"required": []string{"pack_id", "target"},
				"additionalProperties": false,
			},
		},
	}

	result := toolsListResult{Tools: tools}
	s.writeResult(req.ID, result)
}

func (s *Server) handleToolCall(ctx context.Context, req *jsonrpcRequest) {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.writeError(req.ID, -32602, "Invalid params", err.Error())
		return
	}

	var result toolCallResult
	var err error

	switch params.Name {
	case "lnta_inspect_sandboxed":
		result, err = s.toolInspectSandboxed(ctx, params.Arguments)
	case "lnta_get_pack_runbook":
		result, err = s.toolGetPackRunbook(params.Arguments)
	case "lnta_verify_task":
		result, err = s.toolVerifyTask(ctx, params.Arguments)
	default:
		s.writeError(req.ID, -32601, "Tool not found", fmt.Sprintf("Tool '%s' not found", params.Name))
		return
	}

	if err != nil {
		result = toolCallResult{
			Content: []toolContent{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		}
	}

	s.writeResult(req.ID, result)
}

func (s *Server) toolInspectSandboxed(ctx context.Context, args map[string]interface{}) (toolCallResult, error) {
	command, _ := args["command"].(string)
	cwd, _ := args["cwd"].(string)
	reason, _ := args["reason"].(string)

	if command == "" || cwd == "" || reason == "" {
		return toolCallResult{}, fmt.Errorf("missing required arguments: command, cwd, reason")
	}

	res, err := sandbox.RunReadOnly(ctx, command, cwd, 0)
	if err != nil {
		return toolCallResult{}, fmt.Errorf("sandbox execution failed: %w", err)
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

	return toolCallResult{
		Content: []toolContent{{Type: "text", Text: b.String()}},
		IsError: res.ExitCode != 0,
	}, nil
}

func (s *Server) toolGetPackRunbook(args map[string]interface{}) (toolCallResult, error) {
	packID, _ := args["pack_id"].(string)
	if packID == "" {
		return toolCallResult{}, fmt.Errorf("missing required argument: pack_id")
	}

	pack := s.router.PackByID(packID)
	if pack == nil {
		return toolCallResult{}, fmt.Errorf("pack not found: %s", packID)
	}

	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "id: %s\n", pack.ID)
	fmt.Fprintf(&b, "name: %s\n", pack.Name)
	fmt.Fprintf(&b, "triggers: %v\n", pack.Triggers)
	fmt.Fprintf(&b, "allowed_paths: %v\n", pack.AllowedPaths)
	fmt.Fprintf(&b, "required_bins: %v\n", pack.RequiredBins)
	fmt.Fprintf(&b, "context_cmd: %s\n", pack.ContextCmd)
	fmt.Fprintf(&b, "verify_cmd: %s\n", pack.VerifyCmd)
	b.WriteString("---\n")
	b.WriteString(pack.Body)

	return toolCallResult{
		Content: []toolContent{{Type: "text", Text: b.String()}},
	}, nil
}

func (s *Server) toolVerifyTask(ctx context.Context, args map[string]interface{}) (toolCallResult, error) {
	packID, _ := args["pack_id"].(string)
	target, _ := args["target"].(string)

	if packID == "" || target == "" {
		return toolCallResult{}, fmt.Errorf("missing required arguments: pack_id, target")
	}

	pack := s.router.PackByID(packID)
	if pack == nil {
		return toolCallResult{}, fmt.Errorf("pack not found: %s", packID)
	}

	if pack.VerifyCmd == "" {
		return toolCallResult{}, fmt.Errorf("pack %s has no verify_cmd", packID)
	}

	// Render verify_cmd with target passed out-of-band as LNTA_TARGET
	// (single-quoted env assignment, data never shell text). Packs must
	// reference $LNTA_TARGET literally and must not interpolate target.
	verifyCmd := "export LNTA_TARGET='" + strings.ReplaceAll(target, "'", "'\\''") + "'; " + pack.VerifyCmd

	cwd := "."
	res, err := sandbox.RunReadOnly(ctx, verifyCmd, cwd, 2*time.Minute)
	if err != nil {
		return toolCallResult{}, fmt.Errorf("verify_cmd execution failed: %w", err)
	}

	var b strings.Builder
	if res.ExitCode == 0 {
		b.WriteString("VERIFICATION PASSED\n")
		fmt.Fprintf(&b, "Command: %s\n", verifyCmd)
		fmt.Fprintf(&b, "Exit code: %d\n", res.ExitCode)
		if res.Stdout != "" {
			b.WriteString("--- stdout ---\n")
			b.WriteString(res.Stdout)
		}
	} else {
		b.WriteString("VERIFICATION FAILED\n")
		fmt.Fprintf(&b, "Command: %s\n", verifyCmd)
		fmt.Fprintf(&b, "Exit code: %d\n", res.ExitCode)
		if res.Stderr != "" {
			b.WriteString("--- stderr ---\n")
			b.WriteString(res.Stderr)
		}
		if res.Stdout != "" {
			b.WriteString("--- stdout ---\n")
			b.WriteString(res.Stdout)
		}
	}

	return toolCallResult{
		Content: []toolContent{{Type: "text", Text: b.String()}},
		IsError: res.ExitCode != 0,
	}, nil
}

func (s *Server) writeResult(id json.RawMessage, result interface{}) {
	resp := jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	s.writeResponse(resp)
}

func (s *Server) writeError(id json.RawMessage, code int, message string, data interface{}) {
	resp := jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &jsonrpcError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
	s.writeResponse(resp)
}

func (s *Server) writeResponse(resp jsonrpcResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		// Can't really handle this, just log to stderr
		fmt.Fprintf(os.Stderr, "mcp: marshal response: %v\n", err)
		return
	}
	s.stdout.Write(data)
	s.stdout.WriteString("\n")
	s.stdout.Flush()
}