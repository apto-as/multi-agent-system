package tools

import (
	"encoding/json"
	"fmt"

	"github.com/apto-as/tmws/mcp-wrapper-go/internal/api"
	"github.com/apto-as/tmws/mcp-wrapper-go/internal/mcp"
)

// VerifyListTool implements the verify_list MCP tool
type VerifyListTool struct {
	apiClient *api.Client
}

// NewVerifyListTool creates a new verify_list tool
func NewVerifyListTool(apiClient *api.Client) *VerifyListTool {
	return &VerifyListTool{
		apiClient: apiClient,
	}
}

// Definition returns the tool definition for MCP
func (t *VerifyListTool) Definition() mcp.ToolDefinition {
	return mcp.ToolDefinition{
		Name:        "verify_list",
		Description: "List recent verification history for an agent",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"agent_id": map[string]interface{}{
					"type":        "string",
					"description": "Agent identifier (e.g., 'artemis-optimizer'). Defaults to 'artemis-optimizer' if not provided.",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of records to return (default: 10, max: 100)",
					"minimum":     1,
					"maximum":     100,
					"default":     10,
				},
			},
		},
	}
}

// Handle executes the verify_list tool
func (t *VerifyListTool) Handle(params map[string]interface{}) (interface{}, error) {
	// Extract agent_id with default
	agentID := "artemis-optimizer"
	if id, ok := params["agent_id"].(string); ok && id != "" {
		agentID = id
	}

	// Extract limit with default
	limit := 10
	if l, ok := params["limit"].(float64); ok {
		limit = int(l)
		if limit < 1 {
			limit = 1
		} else if limit > 100 {
			limit = 100
		}
	}

	// Call TMWS API
	result, err := t.apiClient.VerifyList(agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch verification list: %w", err)
	}

	// Format response
	return t.formatResponse(result)
}

func (t *VerifyListTool) formatResponse(result *api.VerifyListResponse) (interface{}, error) {
	// Convert to JSON for pretty formatting
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to format response: %w", err)
	}

	return string(data), nil
}
