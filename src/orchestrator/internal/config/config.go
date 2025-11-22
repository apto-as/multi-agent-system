package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the orchestrator service configuration
type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Docker         DockerConfig         `yaml:"docker"`
	Discovery      DiscoveryConfig      `yaml:"discovery"`
	Performance    PerformanceConfig    `yaml:"performance"`
	Security       SecurityConfig       `yaml:"security"`
	Logging        LoggingConfig        `yaml:"logging"`
}

// ServerConfig defines gRPC server settings
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// DockerConfig defines Docker daemon settings
type DockerConfig struct {
	Endpoint    string `yaml:"endpoint"`
	APIVersion  string `yaml:"api_version"`
	TLSVerify   bool   `yaml:"tls_verify"`
	CertPath    string `yaml:"cert_path"`
}

// DiscoveryConfig defines tool discovery settings
type DiscoveryConfig struct {
	Paths           []string `yaml:"paths"`
	ScanIntervalSec int      `yaml:"scan_interval_sec"`
	VerifyTools     bool     `yaml:"verify_tools"`
}

// PerformanceConfig defines performance targets
type PerformanceConfig struct {
	// Target: <500ms startup
	StartupTimeoutMs int `yaml:"startup_timeout_ms"`

	// Target: <100ms discovery
	DiscoveryTimeoutMs int `yaml:"discovery_timeout_ms"`

	// Target: <20ms queries
	QueryTimeoutMs int `yaml:"query_timeout_ms"`

	// Max concurrent tool instances
	MaxConcurrentInstances int `yaml:"max_concurrent_instances"`
}

// SecurityConfig defines security settings
type SecurityConfig struct {
	// V-TOOL-1: Namespace isolation
	EnableNamespaceIsolation bool `yaml:"enable_namespace_isolation"`

	// Allowed tool categories
	AllowedCategories []string `yaml:"allowed_categories"`

	// Container resource limits
	MaxCPU    string `yaml:"max_cpu"`
	MaxMemory string `yaml:"max_memory"`
}

// LoggingConfig defines logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Load reads configuration from YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if cfg.Performance.StartupTimeoutMs == 0 {
		cfg.Performance.StartupTimeoutMs = 500
	}
	if cfg.Performance.DiscoveryTimeoutMs == 0 {
		cfg.Performance.DiscoveryTimeoutMs = 100
	}
	if cfg.Performance.QueryTimeoutMs == 0 {
		cfg.Performance.QueryTimeoutMs = 20
	}
	if cfg.Performance.MaxConcurrentInstances == 0 {
		cfg.Performance.MaxConcurrentInstances = 10
	}

	return &cfg, nil
}
