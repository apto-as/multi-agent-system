package api

import (
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
)

// Client handles HTTP communication with TMWS backend API
type Client struct {
	baseURL string
	client  *resty.Client
}

// NewClient creates a new API client
func NewClient(baseURL string) *Client {
	client := resty.New().
		SetBaseURL(baseURL).
		SetTimeout(10 * time.Second).
		SetHeader("Content-Type", "application/json").
		SetRetryCount(3).
		SetRetryWaitTime(100 * time.Millisecond).
		SetRetryMaxWaitTime(1 * time.Second)

	return &Client{
		baseURL: baseURL,
		client:  client,
	}
}

// VerificationRecord represents a verification record from the API
type VerificationRecord struct {
	ID               string                 `json:"id"`
	AgentID          string                 `json:"agent_id"`
	ClaimType        string                 `json:"claim_type"`
	ClaimContent     map[string]interface{} `json:"claim_content"`
	Accurate         bool                   `json:"accurate"`
	VerifiedAt       string                 `json:"verified_at"`
	VerifiedBy       string                 `json:"verified_by,omitempty"`
	EvidenceMemoryID string                 `json:"evidence_memory_id"`
}

// VerifyListResponse represents the response from verify_list API
type VerifyListResponse struct {
	Verifications []VerificationRecord `json:"verifications"`
	Total         int                  `json:"total"`
}

// VerifyList calls GET /api/v1/verification/list
func (c *Client) VerifyList(agentID string, limit int) (*VerifyListResponse, error) {
	var result VerifyListResponse

	resp, err := c.client.R().
		SetQueryParams(map[string]string{
			"agent_id": agentID,
			"limit":    fmt.Sprintf("%d", limit),
		}).
		SetResult(&result).
		Get("/api/v1/verification/list")

	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if resp.IsError() {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode(), resp.String())
	}

	return &result, nil
}

// VerifyCheckResponse represents the response from verify_check API
type VerifyCheckResponse struct {
	VerificationID string                 `json:"verification_id"`
	Accurate       bool                   `json:"accurate"`
	ClaimContent   map[string]interface{} `json:"claim_content"`
	ActualResult   map[string]interface{} `json:"actual_result"`
}

// VerifyCheck calls GET /api/v1/verification/{verification_id}
func (c *Client) VerifyCheck(verificationID string) (*VerifyCheckResponse, error) {
	var result VerifyCheckResponse

	resp, err := c.client.R().
		SetResult(&result).
		Get(fmt.Sprintf("/api/v1/verification/%s", verificationID))

	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if resp.IsError() {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode(), resp.String())
	}

	return &result, nil
}

// TrustScoreResponse represents the response from get_trust_score API
type TrustScoreResponse struct {
	AgentID               string  `json:"agent_id"`
	TrustScore            float64 `json:"trust_score"`
	TotalVerifications    int     `json:"total_verifications"`
	AccurateVerifications int     `json:"accurate_verifications"`
	VerificationAccuracy  float64 `json:"verification_accuracy"`
	RequiresVerification  bool    `json:"requires_verification"`
	IsReliable            bool    `json:"is_reliable"`
}

// GetTrustScore calls GET /api/v1/trust/{agent_id}
func (c *Client) GetTrustScore(agentID string) (*TrustScoreResponse, error) {
	var result TrustScoreResponse

	resp, err := c.client.R().
		SetResult(&result).
		Get(fmt.Sprintf("/api/v1/trust/%s", agentID))

	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if resp.IsError() {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode(), resp.String())
	}

	return &result, nil
}

// VerifyHistoryResponse represents the response from verify_history API
type VerifyHistoryResponse struct {
	History []VerificationRecord `json:"history"`
	Total   int                  `json:"total"`
}

// VerifyHistory calls GET /api/v1/verification/history
func (c *Client) VerifyHistory(agentID, claimType string, limit int) (*VerifyHistoryResponse, error) {
	var result VerifyHistoryResponse

	params := map[string]string{
		"agent_id": agentID,
		"limit":    fmt.Sprintf("%d", limit),
	}

	if claimType != "" {
		params["claim_type"] = claimType
	}

	resp, err := c.client.R().
		SetQueryParams(params).
		SetResult(&result).
		Get("/api/v1/verification/history")

	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if resp.IsError() {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode(), resp.String())
	}

	return &result, nil
}

// VerifyTrust calls GET /api/v1/verification/trust/{agent_id}
// This is an alias for GetTrustScore to maintain consistency with tool naming
func (c *Client) VerifyTrust(agentID string) (*TrustScoreResponse, error) {
	return c.GetTrustScore(agentID)
}

// VerifyAndRecordResponse represents the response from verify_and_record API
type VerifyAndRecordResponse struct {
	VerificationID string                 `json:"verification_id"`
	Accurate       bool                   `json:"accurate"`
	Claim          map[string]interface{} `json:"claim"`
	Actual         map[string]interface{} `json:"actual"`
	EvidenceID     string                 `json:"evidence_id"`
	NewTrustScore  *float64               `json:"new_trust_score,omitempty"`
	TrustDelta     *float64               `json:"trust_delta,omitempty"`
	PatternLinked  bool                   `json:"pattern_linked"`
}

// VerifyAndRecord calls POST /api/v1/verification/verify-and-record
func (c *Client) VerifyAndRecord(
	agentID string,
	claimType string,
	claimContent map[string]interface{},
	verificationCommand string,
	verifiedByAgentID string,
) (*VerifyAndRecordResponse, error) {
	var result VerifyAndRecordResponse

	// Build request body
	requestBody := map[string]interface{}{
		"agent_id":             agentID,
		"claim_type":           claimType,
		"claim_content":        claimContent,
		"verification_command": verificationCommand,
	}

	// Add optional parameter if provided
	if verifiedByAgentID != "" {
		requestBody["verified_by_agent_id"] = verifiedByAgentID
	}

	resp, err := c.client.R().
		SetBody(requestBody).
		SetResult(&result).
		Post("/api/v1/verification/verify-and-record")

	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if resp.IsError() {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode(), resp.String())
	}

	return &result, nil
}

// HealthCheckResponse represents the response from health check API
type HealthCheckResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// HealthCheck calls GET /health
func (c *Client) HealthCheck() (*HealthCheckResponse, error) {
	var result HealthCheckResponse

	resp, err := c.client.R().
		SetResult(&result).
		Get("/health")

	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if resp.IsError() {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode(), resp.String())
	}

	return &result, nil
}
