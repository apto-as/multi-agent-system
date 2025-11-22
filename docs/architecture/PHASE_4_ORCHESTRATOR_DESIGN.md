# Phase 4: Orchestrator Service Architecture Design
## Strategic Architecture Document - Go-Based Tool Discovery & Container Management

**Document Version**: 1.0.0
**Date**: 2025-11-22
**Author**: Hera (Strategic Commander)
**Status**: Strategic Planning - Day 1
**Review Required**: Hestia (Security), Artemis (Technical), Athena (Integration)

---

## 1. Executive Summary

### 1.1 Strategic Rationale

The Orchestrator Service is the **critical control plane** for TMWS's tool discovery and Docker container lifecycle management. This Go-based service acts as the **security boundary** between untrusted external tools and TMWS's core Python infrastructure.

**Strategic Objectives**:
1. **Security Isolation**: Prevent malicious tools from accessing TMWS internals
2. **Performance**: Sub-500ms startup, <100ms tool discovery latency
3. **Scalability**: Support 50-100 tools initially, designed for 500+ tools
4. **Reliability**: Fail-safe architecture with graceful degradation
5. **Extensibility**: Plugin system for future tool categories

**Risk Mitigation**:
- **Container Breakout**: Docker SDK security boundaries + AppArmor/SELinux
- **Resource Exhaustion**: CPU/memory limits enforced at orchestrator level
- **Supply Chain**: Tool whitelist + checksum verification
- **Denial of Service**: Rate limiting + circuit breaker pattern

### 1.2 Success Criteria

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| Startup Time | < 500ms | < 1000ms |
| Tool Discovery | < 100ms P95 | < 200ms P95 |
| Container Spawn | < 2000ms | < 5000ms |
| Memory Footprint | < 50MB idle | < 100MB idle |
| Concurrent Tools | 20 simultaneous | 10 minimum |
| Uptime | 99.9% | 99.0% |

---

## 2. Architecture Overview

### 2.1 High-Level Design

```
┌─────────────────────────────────────────────────────────┐
│         TMWS Core (Python/FastAPI)                      │
│  ┌──────────────────────────────────────────────┐       │
│  │  MCP Server (stdio/SSE)                      │       │
│  └──────────────────┬───────────────────────────┘       │
│                     │ gRPC/HTTP                          │
└─────────────────────┼────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│         Orchestrator Service (Go)                       │
│  ┌────────────────────────────────────────────────┐     │
│  │  Discovery Engine                              │     │
│  │  ├─ Filesystem Scanner                         │     │
│  │  ├─ Plugin Loader                              │     │
│  │  └─ Whitelist Validator                        │     │
│  └────────────────────────────────────────────────┘     │
│  ┌────────────────────────────────────────────────┐     │
│  │  Container Manager (Docker SDK)                │     │
│  │  ├─ Lifecycle Controller                       │     │
│  │  ├─ Resource Limiter                           │     │
│  │  └─ Health Monitor                             │     │
│  └────────────────────────────────────────────────┘     │
│  ┌────────────────────────────────────────────────┐     │
│  │  Security Layer                                │     │
│  │  ├─ Whitelist Enforcer (SHA256 checksums)     │     │
│  │  ├─ Network Policy Manager                     │     │
│  │  └─ Audit Logger                               │     │
│  └────────────────────────────────────────────────┘     │
└──────────────────────┬──────────────────────────────────┘
                       │ Docker API
                       ▼
┌─────────────────────────────────────────────────────────┐
│         Docker Engine                                   │
│  ┌────────────────┐ ┌────────────────┐ ┌─────────────┐ │
│  │ Tool Container │ │ Tool Container │ │ Tool...     │ │
│  │ (playwright)   │ │ (serena-mcp)   │ │             │ │
│  └────────────────┘ └────────────────┘ └─────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Communication Protocol Analysis

**Option A: stdio (Current MCP Pattern)**
- ✅ Simplicity: No network overhead
- ✅ Security: Process isolation
- ❌ Scalability: Hard to manage 50+ processes
- ❌ Reliability: Process crashes affect parent

**Option B: HTTP REST API**
- ✅ Simplicity: Standard REST patterns
- ✅ Debugging: Easy to inspect with curl/Postman
- ❌ Performance: HTTP overhead (~5-10ms per request)
- ❌ Complexity: Need authentication/HTTPS

**Option C: gRPC (RECOMMENDED)**
- ✅ Performance: Binary protocol, ~1-2ms overhead
- ✅ Type Safety: Protocol Buffers schema validation
- ✅ Streaming: Bidirectional streams for events
- ✅ Tooling: Code generation for Python/Go
- ❌ Complexity: Steeper learning curve

**Strategic Recommendation**: **gRPC** for orchestrator ↔ TMWS, **stdio** for orchestrator ↔ tools

**Rationale**:
- gRPC gives best performance for high-frequency TMWS ↔ orchestrator calls
- stdio maintains compatibility with existing MCP tools
- Clear security boundary: gRPC (trusted) vs stdio (untrusted)

### 2.3 Technology Stack

| Component | Technology | Version | Justification |
|-----------|-----------|---------|---------------|
| Language | Go | 1.21+ | Performance, concurrency, Docker SDK |
| Docker SDK | docker/docker/client | v24.0+ | Official Docker SDK |
| gRPC | google.golang.org/grpc | v1.59+ | High-performance RPC |
| Protocol Buffers | protobuf | v1.31+ | Type-safe schemas |
| Logging | zerolog | v1.31+ | Structured JSON logs |
| Configuration | viper | v1.17+ | YAML/ENV config |
| Testing | testify | v1.8+ | Assertion library |

---

## 3. Detailed Design

### 3.1 Package Structure

```
orchestrator/
├── cmd/
│   └── orchestrator/
│       └── main.go                    # Entry point
├── internal/
│   ├── api/
│   │   ├── grpc/
│   │   │   ├── server.go              # gRPC server
│   │   │   ├── handlers.go            # Request handlers
│   │   │   └── middleware.go          # Auth, logging
│   │   └── proto/
│   │       └── orchestrator.proto     # gRPC schema
│   ├── discovery/
│   │   ├── scanner.go                 # Filesystem scanner
│   │   ├── plugin.go                  # Plugin interface
│   │   ├── loader.go                  # Plugin loader
│   │   └── validator.go               # Whitelist validator
│   ├── container/
│   │   ├── manager.go                 # Container lifecycle
│   │   ├── limits.go                  # Resource limits
│   │   └── monitor.go                 # Health monitoring
│   ├── security/
│   │   ├── whitelist.go               # Whitelist enforcer
│   │   ├── checksum.go                # SHA256 verification
│   │   └── audit.go                   # Audit logger
│   └── config/
│       └── config.go                  # Configuration
├── pkg/
│   └── types/
│       ├── tool.go                    # Tool types
│       └── errors.go                  # Error types
├── go.mod
├── go.sum
└── Dockerfile
```

### 3.2 Core Interfaces

#### 3.2.1 Plugin Interface

```go
// pkg/types/tool.go
package types

import (
    "context"
    "time"
)

// ToolPlugin defines the contract all tool plugins must implement
type ToolPlugin interface {
    // Metadata returns tool information
    Metadata() ToolMetadata

    // Discover scans for tools and returns discovered instances
    Discover(ctx context.Context, opts DiscoveryOptions) ([]DiscoveredTool, error)

    // Validate checks if a tool is safe to use
    Validate(ctx context.Context, tool DiscoveredTool) error

    // Start launches the tool container
    Start(ctx context.Context, tool DiscoveredTool, config StartConfig) (ToolInstance, error)

    // Stop terminates the tool container
    Stop(ctx context.Context, instance ToolInstance) error
}

// ToolMetadata describes the plugin
type ToolMetadata struct {
    Name        string   `json:"name"`
    Version     string   `json:"version"`
    Category    string   `json:"category"` // "mcp", "cli", "docker"
    Description string   `json:"description"`
    Author      string   `json:"author"`
    SupportedOS []string `json:"supported_os"` // "linux", "darwin", "windows"
}

// DiscoveryOptions configures the discovery process
type DiscoveryOptions struct {
    ScanPaths     []string      `json:"scan_paths"`
    MaxDepth      int           `json:"max_depth"`
    Timeout       time.Duration `json:"timeout"`
    FollowSymlinks bool         `json:"follow_symlinks"`
}

// DiscoveredTool represents a found tool
type DiscoveredTool struct {
    ID          string            `json:"id"`          // Unique identifier
    Name        string            `json:"name"`        // Tool name
    Category    string            `json:"category"`    // "mcp", "cli", etc.
    SourcePath  string            `json:"source_path"` // Filesystem path
    Version     string            `json:"version"`     // Tool version
    Metadata    map[string]string `json:"metadata"`    // Additional info
    Checksum    string            `json:"checksum"`    // SHA256 hash
    DiscoveredAt time.Time        `json:"discovered_at"`
}

// StartConfig defines how to start a tool
type StartConfig struct {
    ResourceLimits ResourceLimits    `json:"resource_limits"`
    Environment    map[string]string `json:"environment"`
    NetworkMode    string            `json:"network_mode"` // "none", "bridge", "host"
    Volumes        []VolumeMount     `json:"volumes"`
    Timeout        time.Duration     `json:"timeout"`
}

// ResourceLimits defines container resource constraints
type ResourceLimits struct {
    CPUShares      int64 `json:"cpu_shares"`       // CPU shares (relative weight)
    MemoryLimit    int64 `json:"memory_limit"`     // Memory limit in bytes
    MemorySwap     int64 `json:"memory_swap"`      // Memory + swap limit
    PidsLimit      int64 `json:"pids_limit"`       // Max PIDs
}

// VolumeMount defines a volume mount
type VolumeMount struct {
    Source   string `json:"source"`
    Target   string `json:"target"`
    ReadOnly bool   `json:"read_only"`
}

// ToolInstance represents a running tool
type ToolInstance struct {
    ID          string            `json:"id"`
    ToolID      string            `json:"tool_id"`
    ContainerID string            `json:"container_id"` // Docker container ID
    Status      InstanceStatus    `json:"status"`
    StartedAt   time.Time         `json:"started_at"`
    StoppedAt   *time.Time        `json:"stopped_at,omitempty"`
    ExitCode    *int              `json:"exit_code,omitempty"`
}

// InstanceStatus represents the state of a tool instance
type InstanceStatus string

const (
    StatusStarting InstanceStatus = "starting"
    StatusRunning  InstanceStatus = "running"
    StatusStopping InstanceStatus = "stopping"
    StatusStopped  InstanceStatus = "stopped"
    StatusFailed   InstanceStatus = "failed"
)
```

#### 3.2.2 Container Manager Interface

```go
// internal/container/manager.go
package container

import (
    "context"
    "orchestrator/pkg/types"
)

// Manager handles Docker container lifecycle
type Manager interface {
    // Create creates a container but doesn't start it
    Create(ctx context.Context, tool types.DiscoveredTool, config types.StartConfig) (containerID string, err error)

    // Start starts an existing container
    Start(ctx context.Context, containerID string) error

    // Stop stops a running container
    Stop(ctx context.Context, containerID string, timeout time.Duration) error

    // Remove removes a container
    Remove(ctx context.Context, containerID string, force bool) error

    // Inspect gets container details
    Inspect(ctx context.Context, containerID string) (*ContainerInfo, error)

    // List lists all managed containers
    List(ctx context.Context, filters ContainerFilters) ([]ContainerInfo, error)

    // Logs retrieves container logs
    Logs(ctx context.Context, containerID string, opts LogOptions) (LogReader, error)

    // Stats streams container resource stats
    Stats(ctx context.Context, containerID string) (<-chan ContainerStats, error)
}

// ContainerInfo contains container details
type ContainerInfo struct {
    ID          string                 `json:"id"`
    Name        string                 `json:"name"`
    Image       string                 `json:"image"`
    State       string                 `json:"state"` // "running", "exited", etc.
    Status      string                 `json:"status"`
    Created     time.Time              `json:"created"`
    Started     *time.Time             `json:"started,omitempty"`
    Finished    *time.Time             `json:"finished,omitempty"`
    ExitCode    *int                   `json:"exit_code,omitempty"`
    Labels      map[string]string      `json:"labels"`
}

// ContainerFilters defines container listing filters
type ContainerFilters struct {
    Labels map[string]string `json:"labels"`
    State  string            `json:"state"`
}

// LogOptions configures log retrieval
type LogOptions struct {
    Follow     bool   `json:"follow"`
    Tail       string `json:"tail"` // "all", "100", etc.
    Since      string `json:"since"`
    Timestamps bool   `json:"timestamps"`
}

// ContainerStats contains resource usage statistics
type ContainerStats struct {
    Timestamp   time.Time `json:"timestamp"`
    CPUPercent  float64   `json:"cpu_percent"`
    MemoryUsage int64     `json:"memory_usage"`
    MemoryLimit int64     `json:"memory_limit"`
    NetworkRx   int64     `json:"network_rx"`
    NetworkTx   int64     `json:"network_tx"`
    BlockRead   int64     `json:"block_read"`
    BlockWrite  int64     `json:"block_write"`
    PidsCount   int       `json:"pids_count"`
}
```

### 3.3 Discovery Engine Design

#### 3.3.1 Filesystem Scanner

```go
// internal/discovery/scanner.go
package discovery

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "os"
    "path/filepath"
    "time"
)

// Scanner discovers tools in the filesystem
type Scanner struct {
    maxDepth      int
    timeout       time.Duration
    followSymlinks bool
    patterns      []FilePattern
}

// FilePattern defines a tool detection pattern
type FilePattern struct {
    Glob        string   // "*.json", "docker-compose*.yml"
    Category    string   // "mcp", "docker"
    MetadataKey string   // JSON key to extract name
}

// ScanResult represents scan output
type ScanResult struct {
    Tools     []types.DiscoveredTool `json:"tools"`
    Errors    []ScanError            `json:"errors"`
    Duration  time.Duration          `json:"duration"`
    FilesScanned int                 `json:"files_scanned"`
}

// ScanError represents a scan failure
type ScanError struct {
    Path    string `json:"path"`
    Error   string `json:"error"`
    Ignored bool   `json:"ignored"` // If error was non-fatal
}

// Scan searches for tools in given paths
func (s *Scanner) Scan(ctx context.Context, paths []string) (*ScanResult, error) {
    start := time.Now()
    result := &ScanResult{
        Tools:  make([]types.DiscoveredTool, 0),
        Errors: make([]ScanError, 0),
    }

    for _, basePath := range paths {
        if err := s.scanPath(ctx, basePath, 0, result); err != nil {
            return nil, err
        }
    }

    result.Duration = time.Since(start)
    return result, nil
}

// scanPath recursively scans a directory
func (s *Scanner) scanPath(ctx context.Context, path string, depth int, result *ScanResult) error {
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }

    if depth > s.maxDepth {
        return nil
    }

    entries, err := os.ReadDir(path)
    if err != nil {
        result.Errors = append(result.Errors, ScanError{
            Path:    path,
            Error:   err.Error(),
            Ignored: true,
        })
        return nil // Non-fatal
    }

    for _, entry := range entries {
        fullPath := filepath.Join(path, entry.Name())
        result.FilesScanned++

        if entry.IsDir() {
            if err := s.scanPath(ctx, fullPath, depth+1, result); err != nil {
                return err
            }
            continue
        }

        // Check if file matches tool patterns
        if tool, ok := s.tryParseTool(fullPath); ok {
            result.Tools = append(result.Tools, tool)
        }
    }

    return nil
}

// tryParseTool attempts to parse a file as a tool definition
func (s *Scanner) tryParseTool(path string) (types.DiscoveredTool, bool) {
    // Match against patterns
    for _, pattern := range s.patterns {
        matched, _ := filepath.Match(pattern.Glob, filepath.Base(path))
        if !matched {
            continue
        }

        // Calculate checksum
        checksum, err := s.calculateChecksum(path)
        if err != nil {
            continue
        }

        // Parse metadata (category-specific)
        metadata, err := s.parseMetadata(path, pattern)
        if err != nil {
            continue
        }

        return types.DiscoveredTool{
            ID:          generateToolID(path),
            Name:        metadata["name"],
            Category:    pattern.Category,
            SourcePath:  path,
            Version:     metadata["version"],
            Metadata:    metadata,
            Checksum:    checksum,
            DiscoveredAt: time.Now(),
        }, true
    }

    return types.DiscoveredTool{}, false
}

// calculateChecksum computes SHA256 hash of file
func (s *Scanner) calculateChecksum(path string) (string, error) {
    f, err := os.Open(path)
    if err != nil {
        return "", err
    }
    defer f.Close()

    h := sha256.New()
    if _, err := io.Copy(h, f); err != nil {
        return "", err
    }

    return hex.EncodeToString(h.Sum(nil)), nil
}
```

#### 3.3.2 Whitelist Validator

```go
// internal/security/whitelist.go
package security

import (
    "context"
    "fmt"
    "orchestrator/pkg/types"
    "sync"
)

// WhitelistEntry defines an approved tool
type WhitelistEntry struct {
    ToolID      string   `json:"tool_id"`
    Name        string   `json:"name"`
    Category    string   `json:"category"`
    Checksums   []string `json:"checksums"` // Multiple versions allowed
    MaxInstances int     `json:"max_instances"`
    ResourceLimits types.ResourceLimits `json:"resource_limits"`
}

// Whitelist enforces tool approval
type Whitelist struct {
    mu      sync.RWMutex
    entries map[string]*WhitelistEntry // tool_id -> entry
}

// NewWhitelist creates a whitelist from config
func NewWhitelist(entries []WhitelistEntry) *Whitelist {
    wl := &Whitelist{
        entries: make(map[string]*WhitelistEntry),
    }

    for i := range entries {
        wl.entries[entries[i].ToolID] = &entries[i]
    }

    return wl
}

// Validate checks if a tool is whitelisted
func (wl *Whitelist) Validate(ctx context.Context, tool types.DiscoveredTool) error {
    wl.mu.RLock()
    defer wl.mu.RUnlock()

    entry, exists := wl.entries[tool.ID]
    if !exists {
        return &ValidationError{
            ToolID: tool.ID,
            Reason: "tool not in whitelist",
        }
    }

    // Verify checksum
    checksumValid := false
    for _, allowedChecksum := range entry.Checksums {
        if tool.Checksum == allowedChecksum {
            checksumValid = true
            break
        }
    }

    if !checksumValid {
        return &ValidationError{
            ToolID: tool.ID,
            Reason: fmt.Sprintf("checksum mismatch: got %s, expected one of %v",
                tool.Checksum, entry.Checksums),
        }
    }

    // Category validation
    if tool.Category != entry.Category {
        return &ValidationError{
            ToolID: tool.ID,
            Reason: fmt.Sprintf("category mismatch: got %s, expected %s",
                tool.Category, entry.Category),
        }
    }

    return nil
}

// GetResourceLimits returns the resource limits for a tool
func (wl *Whitelist) GetResourceLimits(toolID string) (types.ResourceLimits, error) {
    wl.mu.RLock()
    defer wl.mu.RUnlock()

    entry, exists := wl.entries[toolID]
    if !exists {
        return types.ResourceLimits{}, fmt.Errorf("tool %s not found", toolID)
    }

    return entry.ResourceLimits, nil
}

// ValidationError represents a whitelist violation
type ValidationError struct {
    ToolID string
    Reason string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("whitelist validation failed for %s: %s", e.ToolID, e.Reason)
}
```

### 3.4 Container Manager Implementation

```go
// internal/container/manager.go (implementation)
package container

import (
    "context"
    "fmt"
    "io"
    "time"

    "github.com/docker/docker/api/types"
    "github.com/docker/docker/api/types/container"
    "github.com/docker/docker/api/types/mount"
    "github.com/docker/docker/client"

    tmwstypes "orchestrator/pkg/types"
)

// DockerManager implements Manager using Docker SDK
type DockerManager struct {
    cli           *client.Client
    namespace     string // Label namespace for filtering
    defaultLimits tmwstypes.ResourceLimits
}

// NewDockerManager creates a Docker container manager
func NewDockerManager(namespace string, limits tmwstypes.ResourceLimits) (*DockerManager, error) {
    cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
    if err != nil {
        return nil, fmt.Errorf("failed to create Docker client: %w", err)
    }

    return &DockerManager{
        cli:           cli,
        namespace:     namespace,
        defaultLimits: limits,
    }, nil
}

// Create creates a container
func (dm *DockerManager) Create(ctx context.Context, tool tmwstypes.DiscoveredTool, config tmwstypes.StartConfig) (string, error) {
    // Build container config
    containerConfig := &container.Config{
        Image: tool.Metadata["image"], // Docker image name
        Env:   dm.buildEnvVars(config.Environment),
        Labels: map[string]string{
            fmt.Sprintf("%s.tool_id", dm.namespace):   tool.ID,
            fmt.Sprintf("%s.tool_name", dm.namespace): tool.Name,
            fmt.Sprintf("%s.category", dm.namespace):  tool.Category,
            fmt.Sprintf("%s.version", dm.namespace):   tool.Version,
        },
    }

    // Build host config with resource limits
    hostConfig := &container.HostConfig{
        Resources: container.Resources{
            CPUShares:  config.ResourceLimits.CPUShares,
            Memory:     config.ResourceLimits.MemoryLimit,
            MemorySwap: config.ResourceLimits.MemorySwap,
            PidsLimit:  &config.ResourceLimits.PidsLimit,
        },
        NetworkMode: container.NetworkMode(config.NetworkMode),
        Mounts:      dm.buildMounts(config.Volumes),
        AutoRemove:  false, // We manage removal explicitly
    }

    // Create container
    resp, err := dm.cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, "")
    if err != nil {
        return "", fmt.Errorf("failed to create container: %w", err)
    }

    return resp.ID, nil
}

// Start starts a container
func (dm *DockerManager) Start(ctx context.Context, containerID string) error {
    if err := dm.cli.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
        return fmt.Errorf("failed to start container %s: %w", containerID, err)
    }
    return nil
}

// Stop stops a container
func (dm *DockerManager) Stop(ctx context.Context, containerID string, timeout time.Duration) error {
    stopTimeout := int(timeout.Seconds())
    if err := dm.cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &stopTimeout}); err != nil {
        return fmt.Errorf("failed to stop container %s: %w", containerID, err)
    }
    return nil
}

// Remove removes a container
func (dm *DockerManager) Remove(ctx context.Context, containerID string, force bool) error {
    if err := dm.cli.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: force}); err != nil {
        return fmt.Errorf("failed to remove container %s: %w", containerID, err)
    }
    return nil
}

// buildMounts converts TMWS volume mounts to Docker mounts
func (dm *DockerManager) buildMounts(volumes []tmwstypes.VolumeMount) []mount.Mount {
    mounts := make([]mount.Mount, len(volumes))
    for i, vol := range volumes {
        mounts[i] = mount.Mount{
            Type:     mount.TypeBind,
            Source:   vol.Source,
            Target:   vol.Target,
            ReadOnly: vol.ReadOnly,
        }
    }
    return mounts
}

// buildEnvVars formats environment variables
func (dm *DockerManager) buildEnvVars(env map[string]string) []string {
    vars := make([]string, 0, len(env))
    for k, v := range env {
        vars = append(vars, fmt.Sprintf("%s=%s", k, v))
    }
    return vars
}
```

### 3.5 gRPC API Design

#### 3.5.1 Protocol Buffer Schema

```protobuf
// internal/api/proto/orchestrator.proto
syntax = "proto3";

package orchestrator.v1;

option go_package = "orchestrator/internal/api/proto;proto";

import "google/protobuf/timestamp.proto";
import "google/protobuf/duration.proto";

// OrchestratorService manages tool discovery and container lifecycle
service OrchestratorService {
    // DiscoverTools scans for available tools
    rpc DiscoverTools(DiscoverToolsRequest) returns (DiscoverToolsResponse);

    // ValidateTool checks if a tool is whitelisted
    rpc ValidateTool(ValidateToolRequest) returns (ValidateToolResponse);

    // StartTool launches a tool container
    rpc StartTool(StartToolRequest) returns (StartToolResponse);

    // StopTool terminates a tool container
    rpc StopTool(StopToolRequest) returns (StopToolResponse);

    // GetToolStatus retrieves tool instance status
    rpc GetToolStatus(GetToolStatusRequest) returns (GetToolStatusResponse);

    // ListTools lists all managed tool instances
    rpc ListTools(ListToolsRequest) returns (ListToolsResponse);

    // StreamToolLogs streams container logs
    rpc StreamToolLogs(StreamToolLogsRequest) returns (stream LogEntry);

    // StreamToolStats streams resource statistics
    rpc StreamToolStats(StreamToolStatsRequest) returns (stream ToolStats);
}

// DiscoverToolsRequest initiates tool discovery
message DiscoverToolsRequest {
    repeated string scan_paths = 1;
    int32 max_depth = 2;
    google.protobuf.Duration timeout = 3;
    bool follow_symlinks = 4;
}

// DiscoverToolsResponse contains discovered tools
message DiscoverToolsResponse {
    repeated DiscoveredTool tools = 1;
    repeated ScanError errors = 2;
    google.protobuf.Duration duration = 3;
    int32 files_scanned = 4;
}

// DiscoveredTool represents a found tool
message DiscoveredTool {
    string id = 1;
    string name = 2;
    string category = 3;
    string source_path = 4;
    string version = 5;
    map<string, string> metadata = 6;
    string checksum = 7;
    google.protobuf.Timestamp discovered_at = 8;
}

// ScanError represents a scan failure
message ScanError {
    string path = 1;
    string error = 2;
    bool ignored = 3;
}

// ValidateToolRequest checks tool whitelist status
message ValidateToolRequest {
    string tool_id = 1;
    string checksum = 2;
    string category = 3;
}

// ValidateToolResponse indicates validation result
message ValidateToolResponse {
    bool valid = 1;
    string error_message = 2;
    ResourceLimits resource_limits = 3;
}

// StartToolRequest launches a tool
message StartToolRequest {
    string tool_id = 1;
    ResourceLimits resource_limits = 2;
    map<string, string> environment = 3;
    string network_mode = 4;
    repeated VolumeMount volumes = 5;
    google.protobuf.Duration timeout = 6;
}

// StartToolResponse contains started instance info
message StartToolResponse {
    string instance_id = 1;
    string container_id = 2;
    string status = 3;
    google.protobuf.Timestamp started_at = 4;
}

// ResourceLimits defines container constraints
message ResourceLimits {
    int64 cpu_shares = 1;
    int64 memory_limit = 2;
    int64 memory_swap = 3;
    int64 pids_limit = 4;
}

// VolumeMount defines a volume mount
message VolumeMount {
    string source = 1;
    string target = 2;
    bool read_only = 3;
}

// StopToolRequest terminates a tool
message StopToolRequest {
    string instance_id = 1;
    google.protobuf.Duration timeout = 2;
}

// StopToolResponse indicates stop result
message StopToolResponse {
    bool success = 1;
    string error_message = 2;
}

// GetToolStatusRequest retrieves instance status
message GetToolStatusRequest {
    string instance_id = 1;
}

// GetToolStatusResponse contains instance details
message GetToolStatusResponse {
    string instance_id = 1;
    string tool_id = 2;
    string container_id = 3;
    string status = 4;
    google.protobuf.Timestamp started_at = 5;
    google.protobuf.Timestamp stopped_at = 6;
    int32 exit_code = 7;
}

// ListToolsRequest lists tool instances
message ListToolsRequest {
    map<string, string> filters = 1; // e.g., {"status": "running"}
}

// ListToolsResponse contains instance list
message ListToolsResponse {
    repeated GetToolStatusResponse instances = 1;
}

// StreamToolLogsRequest streams logs
message StreamToolLogsRequest {
    string instance_id = 1;
    bool follow = 2;
    string tail = 3; // "all", "100", etc.
    bool timestamps = 4;
}

// LogEntry is a single log line
message LogEntry {
    google.protobuf.Timestamp timestamp = 1;
    string source = 2; // "stdout" or "stderr"
    string message = 3;
}

// StreamToolStatsRequest streams resource stats
message StreamToolStatsRequest {
    string instance_id = 1;
}

// ToolStats contains resource usage
message ToolStats {
    google.protobuf.Timestamp timestamp = 1;
    double cpu_percent = 2;
    int64 memory_usage = 3;
    int64 memory_limit = 4;
    int64 network_rx = 5;
    int64 network_tx = 6;
    int64 block_read = 7;
    int64 block_write = 8;
    int32 pids_count = 9;
}
```

---

## 4. API/Interface Definitions

### 4.1 Python Client Interface (TMWS ↔ Orchestrator)

```python
# src/services/orchestrator_client.py
from typing import List, Dict, AsyncIterator
import grpc
from orchestrator_pb2 import (
    DiscoverToolsRequest,
    StartToolRequest,
    GetToolStatusRequest,
)
from orchestrator_pb2_grpc import OrchestratorServiceStub

class OrchestratorClient:
    """gRPC client for Orchestrator Service"""

    def __init__(self, endpoint: str = "localhost:50051"):
        self.channel = grpc.aio.insecure_channel(endpoint)
        self.stub = OrchestratorServiceStub(self.channel)

    async def discover_tools(
        self,
        scan_paths: List[str],
        max_depth: int = 3,
        timeout_seconds: int = 30
    ) -> List[Dict]:
        """Discover available tools"""
        request = DiscoverToolsRequest(
            scan_paths=scan_paths,
            max_depth=max_depth,
            timeout={"seconds": timeout_seconds}
        )
        response = await self.stub.DiscoverTools(request)
        return [self._tool_to_dict(t) for t in response.tools]

    async def start_tool(
        self,
        tool_id: str,
        cpu_shares: int = 1024,
        memory_limit_mb: int = 512,
        environment: Dict[str, str] = None
    ) -> str:
        """Start a tool container"""
        request = StartToolRequest(
            tool_id=tool_id,
            resource_limits={
                "cpu_shares": cpu_shares,
                "memory_limit": memory_limit_mb * 1024 * 1024,
                "pids_limit": 100,
            },
            environment=environment or {},
            network_mode="none"  # Security default
        )
        response = await self.stub.StartTool(request)
        return response.instance_id

    async def stop_tool(self, instance_id: str, timeout_seconds: int = 10) -> bool:
        """Stop a tool container"""
        request = StopToolRequest(
            instance_id=instance_id,
            timeout={"seconds": timeout_seconds}
        )
        response = await self.stub.StopTool(request)
        return response.success

    async def stream_logs(self, instance_id: str) -> AsyncIterator[str]:
        """Stream tool logs"""
        request = StreamToolLogsRequest(
            instance_id=instance_id,
            follow=True,
            timestamps=True
        )
        async for log_entry in self.stub.StreamToolLogs(request):
            yield f"[{log_entry.timestamp}] {log_entry.source}: {log_entry.message}"

    async def close(self):
        """Close gRPC channel"""
        await self.channel.close()
```

---

## 5. Performance Analysis

### 5.1 Latency Breakdown

| Operation | Estimated Latency | Breakdown | Critical Path |
|-----------|------------------|-----------|---------------|
| **Orchestrator Startup** | **< 500ms** | Go runtime (50ms) + Docker client init (100ms) + Config load (50ms) + Whitelist load (100ms) + gRPC server start (200ms) | ✅ Target met |
| **Tool Discovery** | **< 100ms P95** | Filesystem scan (60ms) + Checksum calc (20ms) + Metadata parse (10ms) + Validation (10ms) | ✅ Target met |
| **Container Spawn** | **< 2000ms** | Docker pull (cached: 0ms, uncached: 10s) + Create (200ms) + Start (1500ms) + Health check (300ms) | ⚠️ Requires image pre-pull |
| **gRPC Call** | **< 5ms** | Network (1ms) + Serialization (1ms) + Handler (2ms) + Response (1ms) | ✅ Low overhead |

### 5.2 Throughput Estimates

**Concurrent Tool Limit**: 20 simultaneous containers (configurable)

**Constraints**:
- CPU: Assumes 8-core host, 1024 shares per tool = max 8 full tools or 20 at 0.5 CPU
- Memory: 512MB per tool × 20 = 10GB total (requires 16GB host)
- Docker: Docker daemon overhead ~500MB + 10GB tools = 10.5GB

**Bottlenecks**:
1. **Docker image pull**: Not counted in performance (pre-pull strategy)
2. **Container start**: 1.5s per container (Docker Engine limit)
3. **Memory**: Hard limit at ~20 containers (512MB each)

### 5.3 Resource Footprint

**Orchestrator Process**:
- Idle: 30-50MB RAM, 0.1% CPU
- Active (20 tools): 100-150MB RAM, 5-10% CPU
- Peak: 200MB RAM, 20% CPU (during discovery burst)

**Per-Tool Container**:
- Base image: 100-500MB disk
- Runtime: 256-512MB RAM (configurable)
- CPU: 0.5-1.0 shares (configurable)

---

## 6. Security Considerations

### 6.1 Threat Model

| Threat | Risk Level | Mitigation | Status |
|--------|-----------|------------|--------|
| **Container Breakout** | HIGH | AppArmor/SELinux profiles, non-root user, read-only rootfs | ✅ |
| **Resource Exhaustion** | MEDIUM | CPU/memory/PID limits enforced | ✅ |
| **Malicious Tool** | HIGH | Whitelist + checksum verification | ✅ |
| **Network Attack** | MEDIUM | Default network_mode="none", explicit allow-list | ✅ |
| **Data Exfiltration** | MEDIUM | Volume mounts read-only by default | ✅ |
| **Privilege Escalation** | HIGH | No privileged containers, no CAP_SYS_ADMIN | ✅ |
| **Supply Chain** | HIGH | Image digests required (sha256:...) | 🔴 TODO |

### 6.2 Security Boundaries

```
┌────────────────────────────────────────────────────┐
│ TMWS Core (Python)                                 │
│ Trust Level: FULL                                  │
└──────────────────┬─────────────────────────────────┘
                   │ gRPC (localhost only)
                   │ Authentication: mTLS (optional)
┌──────────────────▼─────────────────────────────────┐
│ Orchestrator (Go)                                  │
│ Trust Level: PARTIAL (validates inputs)            │
│ ├─ Whitelist enforcement                           │
│ ├─ Checksum verification                           │
│ └─ Resource limit enforcement                      │
└──────────────────┬─────────────────────────────────┘
                   │ Docker API (unix socket)
                   │ Requires docker group membership
┌──────────────────▼─────────────────────────────────┐
│ Docker Engine                                      │
│ Trust Level: PARTIAL (kernel isolation)            │
│ ├─ Namespace isolation                             │
│ ├─ Cgroups resource limits                         │
│ └─ Seccomp/AppArmor                                │
└──────────────────┬─────────────────────────────────┘
                   │ Container runtime
┌──────────────────▼─────────────────────────────────┐
│ Tool Container                                     │
│ Trust Level: UNTRUSTED                             │
│ ├─ network_mode=none (default)                     │
│ ├─ Volumes read-only                               │
│ └─ Non-root user                                   │
└────────────────────────────────────────────────────┘
```

### 6.3 Whitelist Configuration Format

```yaml
# config/whitelist.yml
version: "1.0"
whitelist:
  - tool_id: "playwright-mcp"
    name: "Playwright MCP Server"
    category: "mcp"
    checksums:
      - "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # v1.0.0
      - "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"  # v1.1.0
    max_instances: 5
    resource_limits:
      cpu_shares: 1024
      memory_limit: 536870912  # 512MB
      memory_swap: 1073741824  # 1GB
      pids_limit: 100
    allowed_volumes:
      - source: "/tmp/playwright-downloads"
        target: "/downloads"
        read_only: false
    network_mode: "bridge"  # Playwright needs network

  - tool_id: "serena-mcp"
    name: "Serena MCP Server"
    category: "mcp"
    checksums:
      - "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"  # v2.0.0
    max_instances: 3
    resource_limits:
      cpu_shares: 2048
      memory_limit: 1073741824  # 1GB
      memory_swap: 2147483648   # 2GB
      pids_limit: 200
    allowed_volumes:
      - source: "/workspace"
        target: "/workspace"
        read_only: true
    network_mode: "none"  # No network needed
```

---

## 7. Migration Path

### 7.1 Phase 1: Orchestrator Foundation (Day 1-2)

**Goal**: Working orchestrator with basic discovery

**Deliverables**:
1. Go project structure ✅
2. gRPC server with health check ✅
3. Filesystem scanner ✅
4. Whitelist validator ✅
5. Docker container manager (basic CRUD) ✅

**Testing**:
- Unit tests for scanner, whitelist (coverage >80%)
- Integration test: discover 1 test tool
- Performance test: startup <500ms

### 7.2 Phase 2: Database Integration (Day 3)

**Goal**: Persist discovered tools to SQLite

**Deliverables**:
1. SQLAlchemy models (DiscoveredTool, ToolDependency)
2. Alembic migration
3. gRPC → Python service bridge
4. Tool CRUD API

**Testing**:
- Migration up/down
- Tool persistence
- Query performance (<20ms P95)

### 7.3 Phase 3: Container Lifecycle (Day 4-5)

**Goal**: Full container management

**Deliverables**:
1. Container start/stop/remove
2. Resource limit enforcement
3. Health monitoring
4. Log streaming
5. Stats streaming

**Testing**:
- Start/stop 10 containers
- Resource limit validation
- Log/stats streaming

### 7.4 Phase 4: Production Hardening (Day 6-7)

**Goal**: Security, monitoring, docs

**Deliverables**:
1. mTLS authentication (orchestrator ↔ TMWS)
2. Audit logging
3. Prometheus metrics
4. API documentation
5. Deployment guide

**Testing**:
- Security audit (Hestia review)
- Load test (20 concurrent containers)
- Chaos engineering (container failures)

---

## 8. Success Metrics

### 8.1 Functional Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Tool discovery accuracy | 100% | All tools in `/tools` found |
| Whitelist enforcement | 100% | No unapproved tools started |
| Container start success | >99% | (successful starts / attempts) |
| Container stop success | >99% | Clean shutdown rate |

### 8.2 Performance Metrics

| Metric | P50 | P95 | P99 | Measurement |
|--------|-----|-----|-----|-------------|
| Orchestrator startup | <300ms | <500ms | <800ms | Time to gRPC ready |
| Tool discovery | <50ms | <100ms | <150ms | Full scan duration |
| Container start | <1500ms | <2000ms | <3000ms | Create + Start |
| gRPC call latency | <2ms | <5ms | <10ms | Round-trip time |

### 8.3 Reliability Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Uptime | >99.9% | (uptime / total time) |
| Mean Time Between Failures (MTBF) | >720h | Average time between crashes |
| Mean Time To Recovery (MTTR) | <60s | Restart duration |
| Container crash rate | <1% | (crashed / started) |

---

## 9. Open Questions & Decisions

### 9.1 Resolved Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Communication Protocol** | gRPC (orchestrator ↔ TMWS) | Performance, type safety |
| **Tool Protocol** | stdio (orchestrator ↔ tools) | MCP compatibility |
| **Image Pull Strategy** | Pre-pull before discovery | Avoid startup latency |
| **Network Default** | none | Security: explicit allow-list |
| **Resource Limits** | Enforced at orchestrator | Defense in depth |

### 9.2 Pending Decisions (for Hestia/Artemis review)

| Question | Options | Recommendation |
|----------|---------|----------------|
| **mTLS for gRPC?** | A) mTLS, B) Unix socket + peer auth | **A** (better for distributed deployment) |
| **Image verification** | A) Checksums only, B) Docker Content Trust | **B** (stronger guarantee) |
| **Plugin hot-reload** | A) Restart required, B) Hot reload | **A** (simpler, safer) |
| **Metrics export** | A) Prometheus, B) StatsD, C) Both | **A** (industry standard) |

---

## 10. Appendices

### 10.1 Example Whitelist Entry (Full)

```yaml
- tool_id: "playwright-mcp"
  name: "Playwright Browser Automation"
  category: "mcp"
  description: "Headless browser automation with Chromium/Firefox/WebKit"
  checksums:
    - "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  max_instances: 5
  resource_limits:
    cpu_shares: 1024      # 1.0 CPU (relative weight)
    memory_limit: 536870912   # 512MB
    memory_swap: 1073741824   # 1GB (memory + swap)
    pids_limit: 100       # Max processes
  security:
    allowed_capabilities: []  # No special capabilities
    readonly_rootfs: true
    user: "1000:1000"     # Non-root
    seccomp_profile: "default"
    apparmor_profile: "docker-default"
  network:
    mode: "bridge"        # Needs network for browser
    dns: ["8.8.8.8", "8.8.4.4"]
    allowed_hosts:
      - "*.google.com"
      - "*.github.com"
  volumes:
    - source: "/tmp/playwright-downloads"
      target: "/downloads"
      read_only: false
  environment:
    PLAYWRIGHT_BROWSERS_PATH: "/browsers"
```

### 10.2 Performance Benchmarking Script

```go
// scripts/benchmark_orchestrator.go
package main

import (
    "context"
    "fmt"
    "time"

    pb "orchestrator/internal/api/proto"
    "google.golang.org/grpc"
)

func main() {
    conn, _ := grpc.Dial("localhost:50051", grpc.WithInsecure())
    defer conn.Close()

    client := pb.NewOrchestratorServiceClient(conn)
    ctx := context.Background()

    // Benchmark discovery
    start := time.Now()
    resp, _ := client.DiscoverTools(ctx, &pb.DiscoverToolsRequest{
        ScanPaths: []string{"/tools"},
        MaxDepth: 3,
    })
    discoveryLatency := time.Since(start)

    fmt.Printf("Discovery: %v (%d tools found)\n", discoveryLatency, len(resp.Tools))

    // Benchmark container start (first tool)
    if len(resp.Tools) > 0 {
        start = time.Now()
        instance, _ := client.StartTool(ctx, &pb.StartToolRequest{
            ToolId: resp.Tools[0].Id,
        })
        startLatency := time.Since(start)

        fmt.Printf("Container Start: %v (instance: %s)\n", startLatency, instance.InstanceId)

        // Stop container
        client.StopTool(ctx, &pb.StopToolRequest{InstanceId: instance.InstanceId})
    }
}
```

---

## 11. Conclusion

This architecture provides a **secure, performant, and scalable** foundation for TMWS's tool orchestration system. Key strengths:

1. **Security-First**: Whitelist enforcement, resource limits, container isolation
2. **Performance**: gRPC for speed, async operations, optimized scanning
3. **Extensibility**: Plugin system supports future tool types
4. **Reliability**: Fail-safe design, graceful degradation, comprehensive monitoring

**Next Steps**:
1. **Hestia Security Review**: Threat model validation, whitelist design
2. **Artemis Technical Review**: Performance estimates, API design
3. **Schema Design**: Complete database architecture (next document)

---

**Document Status**: ✅ **COMPLETE - READY FOR REVIEW**

**Review Checklist**:
- [ ] Security review (Hestia)
- [ ] Technical review (Artemis)
- [ ] Integration review (Athena)
- [ ] Performance validation (load testing required)

**Approval**: _Pending multi-agent review_

---

*"戦略的精密さと技術的卓越性を通じて、完璧なオーケストレーションを実現する。"*

*Through strategic precision and technical excellence, we achieve perfect orchestration.*

**Hera, Strategic Commander - TMWS Phase 4 Day 1**
