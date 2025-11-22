package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// MCPRequest represents an incoming MCP request
type MCPRequest struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params"`
	ID     interface{}            `json:"id,omitempty"`
}

// MCPResponse represents an MCP response
type MCPResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  *MCPError   `json:"error,omitempty"`
	ID     interface{} `json:"id,omitempty"`
}

// MCPError represents an MCP error
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolHandler is a function that handles a tool call
type ToolHandler func(params map[string]interface{}) (interface{}, error)

// ToolDefinition describes a tool's metadata
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// Server handles MCP STDIO communication
type Server struct {
	reader  *bufio.Reader
	writer  io.Writer
	tools   map[string]ToolHandler
	toolDef map[string]ToolDefinition
}

// NewServer creates a new MCP server
func NewServer() *Server {
	return &Server{
		reader:  bufio.NewReader(os.Stdin),
		writer:  os.Stdout,
		tools:   make(map[string]ToolHandler),
		toolDef: make(map[string]ToolDefinition),
	}
}

// RegisterTool registers a tool handler with its definition
func (s *Server) RegisterTool(def ToolDefinition, handler ToolHandler) {
	s.tools[def.Name] = handler
	s.toolDef[def.Name] = def
}

// Start starts the MCP server (blocking)
func (s *Server) Start() error {
	for {
		// Read line from STDIN
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read from stdin: %w", err)
		}

		// Parse JSON-RPC request
		var req MCPRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.sendError(nil, -32700, fmt.Sprintf("Parse error: %v", err))
			continue
		}

		// Handle request
		s.handleRequest(&req)
	}
}

func (s *Server) handleRequest(req *MCPRequest) {
	switch req.Method {
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolCall(req)
	case "initialize":
		s.handleInitialize(req)
	default:
		s.sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func (s *Server) handleInitialize(req *MCPRequest) {
	// Return server capabilities
	s.sendResult(req.ID, map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "tmws-mcp-go",
			"version": "1.0.0",
		},
	})
}

func (s *Server) handleToolsList(req *MCPRequest) {
	tools := []ToolDefinition{}
	for _, def := range s.toolDef {
		tools = append(tools, def)
	}

	s.sendResult(req.ID, map[string]interface{}{
		"tools": tools,
	})
}

func (s *Server) handleToolCall(req *MCPRequest) {
	// Extract tool name
	toolName, ok := req.Params["name"].(string)
	if !ok {
		s.sendError(req.ID, -32602, "Invalid params: missing 'name'")
		return
	}

	// Find handler
	handler, ok := s.tools[toolName]
	if !ok {
		s.sendError(req.ID, -32601, fmt.Sprintf("Tool not found: %s", toolName))
		return
	}

	// Extract tool arguments
	args, _ := req.Params["arguments"].(map[string]interface{})

	// Call handler
	result, err := handler(args)
	if err != nil {
		s.sendError(req.ID, -32603, fmt.Sprintf("Tool execution failed: %v", err))
		return
	}

	// Wrap result in content array as per MCP spec
	s.sendResult(req.ID, map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("%v", result),
			},
		},
	})
}

func (s *Server) sendResult(id interface{}, result interface{}) {
	resp := MCPResponse{
		Result: result,
		ID:     id,
	}
	s.send(&resp)
}

func (s *Server) sendError(id interface{}, code int, message string) {
	resp := MCPResponse{
		Error: &MCPError{
			Code:    code,
			Message: message,
		},
		ID: id,
	}
	s.send(&resp)
}

func (s *Server) send(resp *MCPResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		// Fallback error response
		fallback := fmt.Sprintf(`{"error":{"code":-32603,"message":"Internal error: %v"},"id":%v}`, err, resp.ID)
		fmt.Fprintf(s.writer, "%s\n", fallback)
		return
	}
	fmt.Fprintf(s.writer, "%s\n", data)
}
