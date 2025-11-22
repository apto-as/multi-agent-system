package orchestrator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestDiscovery_PathTraversal_SymlinkAttack verifies symlink outside base dir is rejected
func TestDiscovery_PathTraversal_SymlinkAttack(t *testing.T) {
	// Create temp directories
	baseDir := t.TempDir()
	toolsDir := filepath.Join(baseDir, "tools")
	maliciousDir := filepath.Join(toolsDir, "malicious")
	targetDir := t.TempDir() // Outside base directory

	if err := os.MkdirAll(maliciousDir, 0755); err != nil {
		t.Fatalf("Failed to create malicious dir: %v", err)
	}

	// Create a legitimate tool.json in target directory
	targetManifest := filepath.Join(targetDir, "tool.json")
	toolData := map[string]interface{}{
		"id":       "malicious-tool",
		"name":     "Malicious Tool",
		"version":  "1.0.0",
		"category": "security",
	}
	manifestBytes, _ := json.Marshal(toolData)
	if err := os.WriteFile(targetManifest, manifestBytes, 0644); err != nil {
		t.Fatalf("Failed to create target manifest: %v", err)
	}

	// Create symlink pointing outside base directory
	symlinkPath := filepath.Join(maliciousDir, "tool.json")
	if err := os.Symlink(targetManifest, symlinkPath); err != nil {
		t.Skipf("Symlink creation failed (may need elevated permissions): %v", err)
	}

	// Perform discovery scan
	discovery := NewDiscovery([]string{toolsDir})
	tools, err := discovery.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify: symlink outside base directory should be rejected
	for _, tool := range tools {
		if tool.ID == "malicious-tool" {
			t.Errorf("❌ SECURITY FAILURE: Path traversal attack succeeded - tool %s was loaded from symlink outside base directory", tool.ID)
		}
	}

	t.Log("✅ Path traversal attack prevented - symlink outside base dir was rejected")
}

// TestDiscovery_PathTraversal_ValidSymlink verifies symlink within base dir is allowed
func TestDiscovery_PathTraversal_ValidSymlink(t *testing.T) {
	// Create temp directories
	baseDir := t.TempDir()
	toolsDir := filepath.Join(baseDir, "tools")
	targetDir := filepath.Join(toolsDir, "target") // Inside base directory
	linkDir := filepath.Join(toolsDir, "link")

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("Failed to create target dir: %v", err)
	}
	if err := os.MkdirAll(linkDir, 0755); err != nil {
		t.Fatalf("Failed to create link dir: %v", err)
	}

	// Create valid tool.json in target directory
	targetManifest := filepath.Join(targetDir, "tool.json")
	toolData := map[string]interface{}{
		"id":       "valid-tool",
		"name":     "Valid Tool",
		"version":  "1.0.0",
		"category": "security",
	}
	manifestBytes, _ := json.Marshal(toolData)
	if err := os.WriteFile(targetManifest, manifestBytes, 0644); err != nil {
		t.Fatalf("Failed to create target manifest: %v", err)
	}

	// Create symlink pointing within base directory
	symlinkPath := filepath.Join(linkDir, "tool.json")
	if err := os.Symlink(targetManifest, symlinkPath); err != nil {
		t.Skipf("Symlink creation failed (may need elevated permissions): %v", err)
	}

	// Perform discovery scan
	discovery := NewDiscovery([]string{toolsDir})
	tools, err := discovery.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify: symlink within base directory should be allowed
	found := false
	for _, tool := range tools {
		if tool.ID == "valid-tool" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("❌ Valid symlink within base directory was incorrectly rejected")
	} else {
		t.Log("✅ Valid symlink within base directory was correctly allowed")
	}
}

// TestDiscovery_InvalidCategory verifies invalid category is rejected
func TestDiscovery_InvalidCategory(t *testing.T) {
	// Create temp directory
	baseDir := t.TempDir()
	toolDir := filepath.Join(baseDir, "invalid-tool")

	if err := os.MkdirAll(toolDir, 0755); err != nil {
		t.Fatalf("Failed to create tool dir: %v", err)
	}

	// Create tool.json with invalid category
	manifestPath := filepath.Join(toolDir, "tool.json")
	toolData := map[string]interface{}{
		"id":       "invalid-category-tool",
		"name":     "Invalid Category Tool",
		"version":  "1.0.0",
		"category": "hacking", // Invalid category
	}
	manifestBytes, _ := json.Marshal(toolData)
	if err := os.WriteFile(manifestPath, manifestBytes, 0644); err != nil {
		t.Fatalf("Failed to create manifest: %v", err)
	}

	// Perform discovery scan
	discovery := NewDiscovery([]string{baseDir})
	tools, err := discovery.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify: tool with invalid category should be rejected
	for _, tool := range tools {
		if tool.ID == "invalid-category-tool" {
			t.Errorf("❌ SECURITY FAILURE: Tool with invalid category 'hacking' was incorrectly accepted")
		}
	}

	t.Log("✅ Tool with invalid category was correctly rejected")
}

// TestDiscovery_ValidCategory verifies all 5 valid categories are accepted
func TestDiscovery_ValidCategory(t *testing.T) {
	// Test all 5 valid categories
	validCats := []string{
		"data_processing",
		"api_integration",
		"file_management",
		"security",
		"monitoring",
	}

	for _, category := range validCats {
		t.Run(category, func(t *testing.T) {
			// Create temp directory for this category
			baseDir := t.TempDir()
			toolDir := filepath.Join(baseDir, category+"-tool")

			if err := os.MkdirAll(toolDir, 0755); err != nil {
				t.Fatalf("Failed to create tool dir: %v", err)
			}

			// Create tool.json with valid category
			manifestPath := filepath.Join(toolDir, "tool.json")
			toolData := map[string]interface{}{
				"id":       category + "-tool",
				"name":     category + " Tool",
				"version":  "1.0.0",
				"category": category,
			}
			manifestBytes, _ := json.Marshal(toolData)
			if err := os.WriteFile(manifestPath, manifestBytes, 0644); err != nil {
				t.Fatalf("Failed to create manifest: %v", err)
			}

			// Perform discovery scan
			discovery := NewDiscovery([]string{baseDir})
			tools, err := discovery.Scan()
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			// Verify: tool with valid category should be accepted
			found := false
			for _, tool := range tools {
				if tool.ID == category+"-tool" {
					found = true
					if tool.Category != category {
						t.Errorf("❌ Category mismatch: expected %s, got %s", category, tool.Category)
					}
					break
				}
			}

			if !found {
				t.Errorf("❌ Tool with valid category '%s' was incorrectly rejected", category)
			} else {
				t.Logf("✅ Valid category '%s' was correctly accepted", category)
			}
		})
	}
}
