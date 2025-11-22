package main

import (
	"log"
	"os"

	"github.com/apto-as/tmws/mcp-wrapper-go/internal/api"
	"github.com/apto-as/tmws/mcp-wrapper-go/internal/mcp"
	"github.com/apto-as/tmws/mcp-wrapper-go/internal/tools"
)

func main() {
	// Initialize API client
	baseURL := os.Getenv("TMWS_API_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8000"
	}

	apiClient := api.NewClient(baseURL)

	// Verify backend connectivity (optional health check)
	if _, err := apiClient.HealthCheck(); err != nil {
		log.Printf("Warning: TMWS backend health check failed: %v", err)
		log.Printf("Continuing anyway, tools will fail if backend is unavailable")
	}

	// Initialize MCP server
	server := mcp.NewServer()

	// Register verification tools
	verifyListTool := tools.NewVerifyListTool(apiClient)
	server.RegisterTool(verifyListTool.Definition(), verifyListTool.Handle)

	verifyCheckTool := tools.NewVerifyCheckTool(apiClient)
	server.RegisterTool(verifyCheckTool.Definition(), verifyCheckTool.Handle)

	verifyTrustTool := tools.NewVerifyTrustTool(apiClient)
	server.RegisterTool(verifyTrustTool.Definition(), verifyTrustTool.Handle)

	verifyHistoryTool := tools.NewVerifyHistoryTool(apiClient)
	server.RegisterTool(verifyHistoryTool.Definition(), verifyHistoryTool.Handle)

	verifyAndRecordTool := tools.NewVerifyAndRecordTool(apiClient)
	server.RegisterTool(verifyAndRecordTool.Definition(), verifyAndRecordTool.Handle)

	// Start server (blocking)
	log.Println("TMWS MCP Server starting...")
	log.Printf("Backend URL: %s", baseURL)
	log.Println("Registered 5 verification tools: verify_list, verify_check, verify_trust, verify_history, verify_and_record")
	log.Println("Ready to accept MCP requests on STDIO")

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
