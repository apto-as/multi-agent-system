// Package tools implements MCP tool handlers for TMWS verification operations.
package tools

import (
	"encoding/json"
	"fmt"

	"github.com/apto-as/tmws/mcp-wrapper-go/internal/api"
	"github.com/apto-as/tmws/mcp-wrapper-go/internal/mcp"
)

// VerifyAndRecordTool handles verification execution, evidence recording, and trust score updates
type VerifyAndRecordTool struct {
	apiClient *api.Client
}

// NewVerifyAndRecordTool creates a new VerifyAndRecordTool instance
func NewVerifyAndRecordTool(apiClient *api.Client) *VerifyAndRecordTool {
	return &VerifyAndRecordTool{
		apiClient: apiClient,
	}
}

// Definition returns the MCP tool definition for verify_and_record
func (t *VerifyAndRecordTool) Definition() mcp.ToolDefinition {
	return mcp.ToolDefinition{
		Name: "verify_and_record",
		Description: `Verify a claim and record evidence

This tool executes a verification command to validate an agent's claim,
records the evidence in memory, and updates the agent's trust score.

Args:
    agent_id: Agent making the claim (e.g., "artemis-optimizer")
    claim_type: Type of claim - one of:
        - test_result: Test execution results
        - performance_metric: Performance measurements
        - code_quality: Code quality metrics
        - security_finding: Security audit findings
        - deployment_status: Deployment status
        - custom: Other claim types
    claim_content: The claim to verify as JSON, e.g.:
        {"return_code": 0, "output_contains": "100% PASSED"}
        {"metrics": {"coverage": 90.0}, "tolerance": 0.05}
    verification_command: Shell command to execute for verification
    verified_by_agent_id: Optional agent performing verification

Returns:
    Dictionary with verification result:
    {
        "claim": {...},  # Original claim
        "actual": {...},  # Actual result
        "accurate": true/false,
        "evidence_id": "uuid",  # Memory ID of evidence
        "verification_id": "uuid",
        "new_trust_score": 0.55
    }

Example:
    await verify_and_record(
        agent_id="artemis-optimizer",
        claim_type="test_result",
        claim_content={
            "return_code": 0,
            "output_contains": ["PASSED", "100%"]
        },
        verification_command="pytest tests/unit/ -v"
    )

Raises:
    AgentNotFoundError: If agent doesn't exist
    VerificationError: If verification command fails`,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"agent_id": map[string]interface{}{
					"type":        "string",
					"description": "Agent ID to verify claim for (e.g., 'artemis-optimizer', 'hestia-auditor')",
				},
				"claim_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of claim (test_result, performance_metric, code_quality, security_finding, deployment_status, custom)",
				},
				"claim_content": map[string]interface{}{
					"type":        "object",
					"description": "Claim content as JSON object (e.g., {\"return_code\": 0, \"output_contains\": \"PASSED\"})",
				},
				"verification_command": map[string]interface{}{
					"type":        "string",
					"description": "Shell command to execute for verification (whitelist: pytest, ruff, mypy, git, npm, echo, cat)",
				},
				"verified_by_agent_id": map[string]interface{}{
					"type":        "string",
					"description": "Optional: Agent ID performing verification (defaults to authenticated user)",
				},
			},
			"required": []string{"agent_id", "claim_type", "claim_content", "verification_command"},
		},
	}
}

// Handle processes the verify_and_record tool request
func (t *VerifyAndRecordTool) Handle(params map[string]interface{}) (interface{}, error) {
	// Extract required parameters
	agentID, ok := params["agent_id"].(string)
	if !ok || agentID == "" {
		return nil, fmt.Errorf("missing required parameter: agent_id")
	}

	claimType, ok := params["claim_type"].(string)
	if !ok || claimType == "" {
		return nil, fmt.Errorf("missing required parameter: claim_type")
	}

	claimContent, ok := params["claim_content"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing required parameter: claim_content (must be JSON object)")
	}

	verificationCommand, ok := params["verification_command"].(string)
	if !ok || verificationCommand == "" {
		return nil, fmt.Errorf("missing required parameter: verification_command")
	}

	// Extract optional parameter
	verifiedByAgentID, _ := params["verified_by_agent_id"].(string)

	// Call TMWS API to verify and record
	result, err := t.apiClient.VerifyAndRecord(
		agentID,
		claimType,
		claimContent,
		verificationCommand,
		verifiedByAgentID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and record: %w", err)
	}

	// Format response
	return t.formatResponse(result)
}

func (t *VerifyAndRecordTool) formatResponse(result *api.VerifyAndRecordResponse) (interface{}, error) {
	// Convert to JSON for pretty formatting
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to format response: %w", err)
	}

	return string(data), nil
}
