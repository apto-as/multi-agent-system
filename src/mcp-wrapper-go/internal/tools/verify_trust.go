// Package tools implements MCP tool handlers for TMWS verification operations.
package tools

import (
	"encoding/json"
	"fmt"

	"github.com/apto-as/tmws/mcp-wrapper-go/internal/api"
	"github.com/apto-as/tmws/mcp-wrapper-go/internal/mcp"
)

// VerifyTrustTool handles agent trust score and verification statistics retrieval
type VerifyTrustTool struct {
	apiClient *api.Client
}

// NewVerifyTrustTool creates a new VerifyTrustTool instance
func NewVerifyTrustTool(apiClient *api.Client) *VerifyTrustTool {
	return &VerifyTrustTool{
		apiClient: apiClient,
	}
}

// Definition returns the MCP tool definition for verify_trust
func (t *VerifyTrustTool) Definition() mcp.ToolDefinition {
	return mcp.ToolDefinition{
		Name:        "verify_trust",
		Description: "Get agent's trust score and verification statistics. Returns trust score (0.0-1.0), total verifications, accurate verifications, verification accuracy rate, and reliability flags.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"agent_id": map[string]interface{}{
					"type":        "string",
					"description": "Agent identifier (e.g., 'artemis-optimizer', 'hestia-auditor')",
				},
			},
			"required": []string{"agent_id"},
		},
	}
}

// Handle processes the verify_trust tool request
func (t *VerifyTrustTool) Handle(params map[string]interface{}) (interface{}, error) {
	// Extract agent_id (required parameter)
	agentID, ok := params["agent_id"].(string)
	if !ok || agentID == "" {
		return nil, fmt.Errorf("missing required parameter: agent_id")
	}

	// Call TMWS API to get trust score
	result, err := t.apiClient.VerifyTrust(agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get trust score: %w", err)
	}

	// Format response
	return t.formatResponse(result)
}

func (t *VerifyTrustTool) formatResponse(result *api.TrustScoreResponse) (interface{}, error) {
	// Convert to JSON for pretty formatting
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to format response: %w", err)
	}

	return string(data), nil
}
