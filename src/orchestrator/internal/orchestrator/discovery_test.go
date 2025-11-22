package orchestrator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewDiscovery_Initialization(t *testing.T) {
	paths := []string{"/path/1", "/path/2"}
	discovery := NewDiscovery(paths)

	if discovery == nil {
		t.Fatal("Discovery is nil")
	}
	if len(discovery.paths) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(discovery.paths))
	}
	if discovery.cache == nil {
		t.Fatal("Cache not initialized")
	}
}

func TestDiscoveryScan_EmptyPaths(t *testing.T) {
	discovery := NewDiscovery([]string{})
	tools, err := discovery.Scan()

	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}
	if len(tools) != 0 {
		t.Errorf("Expected 0 tools, got %d", len(tools))
	}
}

func TestDiscoveryScan_CacheHit(t *testing.T) {
	// Create temporary test directory
	tmpDir := t.TempDir()

	// Create a valid tool.json
	toolDir := filepath.Join(tmpDir, "test-tool")
	if err := os.MkdirAll(toolDir, 0755); err != nil {
		t.Fatal(err)
	}

	toolJSON := `{
		"id": "test-tool-1",
		"name": "Test Tool",
		"version": "1.0.0",
		"category": "data_processing",
		"metadata": {}
	}`
	if err := os.WriteFile(filepath.Join(toolDir, "tool.json"), []byte(toolJSON), 0644); err != nil {
		t.Fatal(err)
	}

	discovery := NewDiscovery([]string{tmpDir})

	// First scan - should populate cache
	tools1, err := discovery.Scan()
	if err != nil {
		t.Fatalf("First scan failed: %v", err)
	}

	// Second scan - should hit cache
	tools2, err := discovery.Scan()
	if err != nil {
		t.Fatalf("Second scan failed: %v", err)
	}

	if len(tools1) != len(tools2) {
		t.Errorf("Cache hit returned different number of tools: %d vs %d", len(tools1), len(tools2))
	}
}

func TestValidateTool_ValidJSON(t *testing.T) {
	tool := &Tool{
		ID:         "test-tool-1",
		Name:       "Test Tool",
		Category:   "data_processing",
		SourcePath: "/usr/local/bin/tool",
		Version:    "1.0.0",
	}

	discovery := NewDiscovery([]string{})
	err := discovery.ValidateTool(tool)
	if err != nil {
		t.Errorf("ValidateTool failed: %v", err)
	}
}

func TestValidateTool_MissingID(t *testing.T) {
	tool := &Tool{
		Name:       "Test Tool",
		Category:   "data_processing",
		SourcePath: "/usr/local/bin/tool",
		Version:    "1.0.0",
	}

	discovery := NewDiscovery([]string{})
	err := discovery.ValidateTool(tool)
	if err == nil {
		t.Error("Expected validation error for missing ID")
	}
}

func TestValidateTool_InvalidCategory(t *testing.T) {
	tool := &Tool{
		ID:         "test-tool-2",
		Name:       "Invalid Tool",
		Category:   "invalid_category",
		SourcePath: "/usr/local/bin/tool",
		Version:    "1.0.0",
	}

	discovery := NewDiscovery([]string{})
	err := discovery.ValidateTool(tool)
	if err == nil {
		t.Error("Expected validation error for invalid category")
	}
}

func TestValidateTool_MissingVersion(t *testing.T) {
	tool := &Tool{
		ID:         "test-tool-3",
		Name:       "Test Tool",
		Category:   "security",
		SourcePath: "/usr/local/bin/tool",
	}

	discovery := NewDiscovery([]string{})
	err := discovery.ValidateTool(tool)
	if err == nil {
		t.Error("Expected validation error for missing version")
	}
}

func TestIsValidCategory_ValidCategories(t *testing.T) {
	validCategories := []string{
		"data_processing",
		"api_integration",
		"file_management",
		"security",
		"monitoring",
	}

	for _, category := range validCategories {
		if !isValidCategory(category) {
			t.Errorf("Category %s should be valid", category)
		}
	}
}

func TestIsValidCategory_InvalidCategory(t *testing.T) {
	invalidCategories := []string{
		"invalid",
		"unknown",
		"",
		"DATA_PROCESSING", // case sensitive
	}

	for _, category := range invalidCategories {
		if isValidCategory(category) {
			t.Errorf("Category %s should be invalid", category)
		}
	}
}

func TestScanWithValidation_FiltersInvalid(t *testing.T) {
	// Create temporary test directory
	tmpDir := t.TempDir()

	// Create valid tool
	validToolDir := filepath.Join(tmpDir, "valid-tool")
	if err := os.MkdirAll(validToolDir, 0755); err != nil {
		t.Fatal(err)
	}
	validToolJSON := `{
		"id": "valid-tool",
		"name": "Valid Tool",
		"version": "1.0.0",
		"category": "security",
		"metadata": {}
	}`
	if err := os.WriteFile(filepath.Join(validToolDir, "tool.json"), []byte(validToolJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Create invalid tool (missing category)
	invalidToolDir := filepath.Join(tmpDir, "invalid-tool")
	if err := os.MkdirAll(invalidToolDir, 0755); err != nil {
		t.Fatal(err)
	}
	invalidToolJSON := `{
		"id": "invalid-tool",
		"name": "Invalid Tool",
		"version": "1.0.0",
		"metadata": {}
	}`
	if err := os.WriteFile(filepath.Join(invalidToolDir, "tool.json"), []byte(invalidToolJSON), 0644); err != nil {
		t.Fatal(err)
	}

	discovery := NewDiscovery([]string{tmpDir})
	tools, err := discovery.ScanWithValidation()
	if err != nil {
		t.Fatalf("ScanWithValidation failed: %v", err)
	}

	// Should only return the valid tool
	if len(tools) != 1 {
		t.Errorf("Expected 1 valid tool, got %d", len(tools))
	}

	if len(tools) > 0 && tools[0].ID != "valid-tool" {
		t.Errorf("Expected valid-tool, got %s", tools[0].ID)
	}
}

func TestLoadToolManifest_ValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	toolDir := filepath.Join(tmpDir, "test-tool")
	if err := os.MkdirAll(toolDir, 0755); err != nil {
		t.Fatal(err)
	}

	toolJSON := `{
		"id": "test-tool-manifest",
		"name": "Test Tool Manifest",
		"version": "2.0.0",
		"category": "monitoring",
		"metadata": {"key": "value"}
	}`
	manifestPath := filepath.Join(toolDir, "tool.json")
	if err := os.WriteFile(manifestPath, []byte(toolJSON), 0644); err != nil {
		t.Fatal(err)
	}

	discovery := NewDiscovery([]string{})
	tool, err := discovery.loadToolManifest(manifestPath)
	if err != nil {
		t.Fatalf("loadToolManifest failed: %v", err)
	}

	if tool.ID != "test-tool-manifest" {
		t.Errorf("Expected ID 'test-tool-manifest', got '%s'", tool.ID)
	}
	if tool.Version != "2.0.0" {
		t.Errorf("Expected version '2.0.0', got '%s'", tool.Version)
	}
	if tool.SourcePath != toolDir {
		t.Errorf("Expected SourcePath '%s', got '%s'", toolDir, tool.SourcePath)
	}
}

func TestLoadToolManifest_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	toolDir := filepath.Join(tmpDir, "invalid-tool")
	if err := os.MkdirAll(toolDir, 0755); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(toolDir, "tool.json")
	if err := os.WriteFile(manifestPath, []byte("invalid json"), 0644); err != nil {
		t.Fatal(err)
	}

	discovery := NewDiscovery([]string{})
	_, err := discovery.loadToolManifest(manifestPath)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}
