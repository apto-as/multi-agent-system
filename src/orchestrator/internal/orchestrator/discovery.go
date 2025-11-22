package orchestrator

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// validCategories defines the allowed tool categories
var validCategories = map[string]bool{
	"data_processing": true,
	"api_integration": true,
	"file_management": true,
	"security":        true,
	"monitoring":      true,
}

// getValidCategories returns a list of valid category names
func getValidCategories() []string {
	keys := make([]string, 0, len(validCategories))
	for k := range validCategories {
		keys = append(keys, k)
	}
	return keys
}

// Tool represents a discovered tool
type Tool struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Category   string            `json:"category"`
	SourcePath string            `json:"source_path"`
	Metadata   map[string]string `json:"metadata"`
}

// Discovery handles tool discovery with caching
type Discovery struct {
	paths       []string
	cache       map[string]*Tool
	cacheExpiry time.Time
	mu          sync.RWMutex
}

// NewDiscovery creates a new discovery engine
func NewDiscovery(paths []string) *Discovery {
	return &Discovery{
		paths: paths,
		cache: make(map[string]*Tool),
	}
}

// Scan scans configured paths for tools with caching
func (d *Discovery) Scan() ([]*Tool, error) {
	// Check cache first
	d.mu.RLock()
	if time.Now().Before(d.cacheExpiry) && len(d.cache) > 0 {
		// Return cached results
		tools := make([]*Tool, 0, len(d.cache))
		for _, tool := range d.cache {
			tools = append(tools, tool)
		}
		d.mu.RUnlock()
		log.Printf("✅ Discovery cache hit: %d tools", len(tools))
		return tools, nil
	}
	d.mu.RUnlock()

	// Cache miss - perform full scan
	log.Println("🔍 Discovery cache miss - scanning paths...")
	startTime := time.Now()

	var tools []*Tool
	for _, path := range d.paths {
		discovered, err := d.scanPath(path)
		if err != nil {
			log.Printf("Warning: scan path %s failed: %v", path, err)
			continue
		}
		tools = append(tools, discovered...)
	}

	// Update cache
	d.mu.Lock()
	d.cache = make(map[string]*Tool)
	for _, tool := range tools {
		d.cache[tool.ID] = tool
	}
	d.cacheExpiry = time.Now().Add(5 * time.Minute)
	d.mu.Unlock()

	scanTime := time.Since(startTime).Milliseconds()
	log.Printf("✅ Discovery scan complete: %d tools in %dms", len(tools), scanTime)

	return tools, nil
}

// scanPath scans a single path for tool manifests
func (d *Discovery) scanPath(path string) ([]*Tool, error) {
	var tools []*Tool

	// Get absolute base directory for path traversal validation
	// V-DISC-1 FIX: Resolve symlinks in base directory too for consistent comparison
	baseDir, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base directory: %w", err)
	}

	// Resolve symlinks in base directory path
	baseDir, err = filepath.EvalSymlinks(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base directory symlinks: %w", err)
	}

	// Walk directory tree
	err = filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Look for tool.json manifest files
		if !info.IsDir() && info.Name() == "tool.json" {
			// V-DISC-1 FIX: Symlink detection and path traversal prevention
			realPath, err := filepath.EvalSymlinks(filePath)
			if err != nil {
				fmt.Printf("Warning: Symlink resolution failed for %s: %v\n", filePath, err)
				return nil
			}

			// Validate that resolved path is within base directory
			if !strings.HasPrefix(realPath, baseDir) {
				fmt.Printf("Warning: Path traversal detected, rejecting %s (resolves to %s)\n", filePath, realPath)
				return nil
			}

			tool, err := d.loadToolManifest(realPath)
			if err != nil {
				// Log warning but continue
				fmt.Printf("Warning: Failed to load manifest %s: %v\n", filePath, err)
				return nil
			}
			tools = append(tools, tool)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return tools, nil
}

// loadToolManifest loads a tool manifest from JSON
func (d *Discovery) loadToolManifest(path string) (*Tool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var tool Tool
	if err := json.Unmarshal(data, &tool); err != nil {
		return nil, err
	}

	// Validate required fields
	if tool.ID == "" || tool.Name == "" || tool.Version == "" {
		return nil, fmt.Errorf("invalid manifest: missing required fields")
	}

	// V-DISC-3 FIX: Category validation
	if tool.Category != "" && !validCategories[tool.Category] {
		return nil, fmt.Errorf("invalid category: %s (allowed: %v)",
			tool.Category, getValidCategories())
	}

	// Set source path
	tool.SourcePath = filepath.Dir(path)

	return &tool, nil
}

// ValidateTool checks if a tool definition is valid
func (d *Discovery) ValidateTool(tool *Tool) error {
	if tool.ID == "" {
		return fmt.Errorf("tool_id is required")
	}
	if tool.Name == "" {
		return fmt.Errorf("name is required")
	}
	if tool.Category == "" {
		return fmt.Errorf("category is required")
	}
	if !isValidCategory(tool.Category) {
		return fmt.Errorf("invalid category: %s", tool.Category)
	}
	if tool.SourcePath == "" {
		return fmt.Errorf("source_path is required")
	}
	if tool.Version == "" {
		return fmt.Errorf("version is required")
	}
	return nil
}

// isValidCategory checks if a category is valid
func isValidCategory(category string) bool {
	return validCategories[category]
}

// ScanWithValidation discovers and validates tools
func (d *Discovery) ScanWithValidation() ([]*Tool, error) {
	tools, err := d.Scan()
	if err != nil {
		return nil, err
	}

	validTools := make([]*Tool, 0)
	for _, tool := range tools {
		if err := d.ValidateTool(tool); err != nil {
			log.Printf("⚠️  Invalid tool %s: %v", tool.ID, err)
			continue
		}
		validTools = append(validTools, tool)
	}

	if len(validTools) < len(tools) {
		log.Printf("⚠️  Filtered %d invalid tools, %d valid tools remaining",
			len(tools)-len(validTools), len(validTools))
	}

	return validTools, nil
}
