// Package tools implements MCP tool handlers for TMWS verification operations.
package tools

import (
	"encoding/json"
	"fmt"

	"github.com/apto-as/tmws/mcp-wrapper-go/internal/api"
	"github.com/apto-as/tmws/mcp-wrapper-go/internal/mcp"
)

// VerifyHistoryTool handles verification history retrieval with filtering
type VerifyHistoryTool struct {
	apiClient *api.Client
}

// NewVerifyHistoryTool creates a new VerifyHistoryTool instance
func NewVerifyHistoryTool(apiClient *api.Client) *VerifyHistoryTool {
	return &VerifyHistoryTool{
		apiClient: apiClient,
	}
}

// Definition returns the MCP tool definition for verify_history
func (t *VerifyHistoryTool) Definition() mcp.ToolDefinition {
	return mcp.ToolDefinition{
		Name:        "verify_history",
		Description: "Get verification history for an agent with optional filtering. Returns a list of verification records with claim content, verification results, accuracy status, and timestamps.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"agent_id": map[string]interface{}{
					"type":        "string",
					"description": "Agent identifier (e.g., 'artemis-optimizer')",
				},
				"claim_type": map[string]interface{}{
					"type":        "string",
					"description": "Optional claim type filter (e.g., 'test_result', 'performance_metric', 'security_finding', 'deployment_status')",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of records to return (default: 10, max: 100)",
					"default":     10,
					"minimum":     1,
					"maximum":     100,
				},
			},
			"required": []string{"agent_id"},
		},
	}
}

// Handle processes the verify_history tool request
func (t *VerifyHistoryTool) Handle(params map[string]interface{}) (interface{}, error) {
	// Extract agent_id (required parameter)
	agentID, ok := params["agent_id"].(string)
	if !ok || agentID == "" {
		return nil, fmt.Errorf("missing required parameter: agent_id")
	}

	// Extract optional parameters
	claimType, _ := params["claim_type"].(string)

	// Extract limit with default value
	limit := 10
	if l, ok := params["limit"].(float64); ok {
		limit = int(l)
	}

	// Validate limit range
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("limit must be between 1 and 100, got: %d", limit)
	}

	// Call TMWS API to get verification history
	result, err := t.apiClient.VerifyHistory(agentID, claimType, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get verification history: %w", err)
	}

	// Format response
	return t.formatResponse(result)
}

func (t *VerifyHistoryTool) formatResponse(result *api.VerifyHistoryResponse) (interface{}, error) {
	// Convert to JSON for pretty formatting
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to format response: %w", err)
	}

	return string(data), nil
}
