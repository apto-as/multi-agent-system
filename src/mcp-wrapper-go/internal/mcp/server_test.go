package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestServerToolRegistration(t *testing.T) {
	server := NewServer()

	server.RegisterTool(
		ToolDefinition{
			Name:        "test_tool",
			Description: "Test tool",
			InputSchema: map[string]interface{}{},
		},
		func(params map[string]interface{}) (interface{}, error) {
			return "ok", nil
		},
	)

	if len(server.tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(server.tools))
	}

	if len(server.toolDef) != 1 {
		t.Errorf("Expected 1 tool definition, got %d", len(server.toolDef))
	}

	if server.toolDef["test_tool"].Name != "test_tool" {
		t.Errorf("Expected tool name 'test_tool', got '%s'", server.toolDef["test_tool"].Name)
	}
}

func TestHandleToolsList(t *testing.T) {
	server := NewServer()

	// Register a test tool
	server.RegisterTool(
		ToolDefinition{
			Name:        "test_tool",
			Description: "Test tool description",
			InputSchema: map[string]interface{}{
				"type": "object",
			},
		},
		func(params map[string]interface{}) (interface{}, error) {
			return "ok", nil
		},
	)

	// Create a request
	req := &MCPRequest{
		Method: "tools/list",
		ID:     1,
	}

	// Capture output
	var buf bytes.Buffer
	server.writer = &buf

	// Handle request
	server.handleToolsList(req)

	// Parse response
	var resp MCPResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify response
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected result to be map[string]interface{}, got %T", resp.Result)
	}

	toolsInterface, ok := result["tools"].([]ToolDefinition)
	if !ok {
		// Try as []interface{} first
		toolsArray, ok2 := result["tools"].([]interface{})
		if !ok2 {
			t.Fatalf("Expected tools to be array, got %T", result["tools"])
		}
		if len(toolsArray) != 1 {
			t.Errorf("Expected 1 tool in response, got %d", len(toolsArray))
		}
	} else {
		if len(toolsInterface) != 1 {
			t.Errorf("Expected 1 tool in response, got %d", len(toolsInterface))
		}
		if toolsInterface[0].Name != "test_tool" {
			t.Errorf("Expected tool name 'test_tool', got '%s'", toolsInterface[0].Name)
		}
	}
}

func TestHandleInitialize(t *testing.T) {
	server := NewServer()

	req := &MCPRequest{
		Method: "initialize",
		ID:     0,
	}

	var buf bytes.Buffer
	server.writer = &buf

	server.handleInitialize(req)

	var resp MCPResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected result to be map[string]interface{}, got %T", resp.Result)
	}

	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("Expected protocolVersion '2024-11-05', got '%v'", result["protocolVersion"])
	}

	serverInfo, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected serverInfo to be map[string]interface{}")
	}

	if serverInfo["name"] != "tmws-mcp-go" {
		t.Errorf("Expected server name 'tmws-mcp-go', got '%v'", serverInfo["name"])
	}
}

func TestHandleToolCall(t *testing.T) {
	server := NewServer()

	// Register a test tool
	called := false
	server.RegisterTool(
		ToolDefinition{
			Name:        "echo",
			Description: "Echo tool",
			InputSchema: map[string]interface{}{},
		},
		func(params map[string]interface{}) (interface{}, error) {
			called = true
			return params["message"], nil
		},
	)

	// Create a request
	req := &MCPRequest{
		Method: "tools/call",
		ID:     2,
		Params: map[string]interface{}{
			"name": "echo",
			"arguments": map[string]interface{}{
				"message": "hello",
			},
		},
	}

	var buf bytes.Buffer
	server.writer = &buf

	server.handleToolCall(req)

	if !called {
		t.Error("Expected tool handler to be called")
	}

	var resp MCPResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("Expected no error, got: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected result to be map[string]interface{}")
	}

	content, ok := result["content"].([]interface{})
	if !ok {
		t.Fatalf("Expected content to be array")
	}

	if len(content) != 1 {
		t.Errorf("Expected 1 content item, got %d", len(content))
	}
}

func TestHandleToolCallNotFound(t *testing.T) {
	server := NewServer()

	req := &MCPRequest{
		Method: "tools/call",
		ID:     3,
		Params: map[string]interface{}{
			"name": "nonexistent",
		},
	}

	var buf bytes.Buffer
	server.writer = &buf

	server.handleToolCall(req)

	var resp MCPResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error == nil {
		t.Error("Expected error, got nil")
	}

	if resp.Error.Code != -32601 {
		t.Errorf("Expected error code -32601, got %d", resp.Error.Code)
	}

	if !strings.Contains(resp.Error.Message, "not found") {
		t.Errorf("Expected error message to contain 'not found', got '%s'", resp.Error.Message)
	}
}
