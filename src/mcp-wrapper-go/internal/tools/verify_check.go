// Package tools implements MCP tool handlers for TMWS verification operations.
package tools

import (
	"encoding/json"
	"fmt"

	"github.com/apto-as/tmws/mcp-wrapper-go/internal/api"
	"github.com/apto-as/tmws/mcp-wrapper-go/internal/mcp"
)

// VerifyCheckTool handles verification record detail retrieval
type VerifyCheckTool struct {
	apiClient *api.Client
}

// NewVerifyCheckTool creates a new VerifyCheckTool instance
func NewVerifyCheckTool(apiClient *api.Client) *VerifyCheckTool {
	return &VerifyCheckTool{
		apiClient: apiClient,
	}
}

// Definition returns the MCP tool definition for verify_check
func (t *VerifyCheckTool) Definition() mcp.ToolDefinition {
	return mcp.ToolDefinition{
		Name:        "verify_check",
		Description: "Check verification record details by ID. Retrieves the full verification record including claim content, verification result, accuracy status, and linked evidence memory ID.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"verification_id": map[string]interface{}{
					"type":        "string",
					"description": "UUID of the verification record to check (e.g., '550e8400-e29b-41d4-a716-446655440000')",
				},
			},
			"required": []string{"verification_id"},
		},
	}
}

// Handle processes the verify_check tool request
func (t *VerifyCheckTool) Handle(params map[string]interface{}) (interface{}, error) {
	// Extract verification_id (required parameter)
	verificationID, ok := params["verification_id"].(string)
	if !ok || verificationID == "" {
		return nil, fmt.Errorf("missing required parameter: verification_id")
	}

	// Call TMWS API to check verification record
	result, err := t.apiClient.VerifyCheck(verificationID)
	if err != nil {
		return nil, fmt.Errorf("failed to check verification: %w", err)
	}

	// Format response
	return t.formatResponse(result)
}

func (t *VerifyCheckTool) formatResponse(result *api.VerifyCheckResponse) (interface{}, error) {
	// Convert to JSON for pretty formatting
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to format response: %w", err)
	}

	return string(data), nil
}
