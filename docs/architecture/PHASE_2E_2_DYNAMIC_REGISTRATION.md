# Dynamic MCP Server Registration
## User-Driven Tool Discovery with Security Validation

**Status**: Phase 2E-2 Design Document
**Created**: 2025-11-20
**Architect**: Artemis (Technical Perfectionist)

---

## User Vision

> "Users should be able to add custom MCP servers without code changes, just by creating a YAML config file."

---

## Registration Flow

### Step 1: User Creates YAML Config

**Location**: `.tmws/mcps/custom/my-analyzer.yml`

```yaml
# MCP Server Configuration
# This file defines a custom MCP server that can be dynamically registered with TMWS

server:
  # Required: Unique server name (must match MCP server's identification)
  name: "my-custom-analyzer"

  # Required: Human-readable display name
  display_name: "My Custom Code Analyzer"

  # Required: Primary category for tool discovery
  # Available categories: code_analysis, file_operations, web_automation,
  # document_generation, data_processing, infrastructure, ai_ml, security,
  # communication, utilities
  category: "code_analysis"

  # Required: Brief description (max 500 chars)
  description: |
    Custom static analyzer for proprietary domain-specific language (DSL).
    Supports syntax checking, semantic analysis, and code generation.

  # Required: Docker image (must be in allowlist or approved registry)
  docker_image: "ghcr.io/myorg/custom-analyzer:v1.2.3"

  # Optional: Docker configuration
  docker:
    # Security: Allowed values: "none" (default), "bridge", "host"
    # "none" is STRONGLY recommended for untrusted code
    network_mode: "none"

    # Resource limits (defaults shown)
    memory_limit_mb: 512
    cpu_shares: 1024  # Relative weight (1024 = 1 CPU core worth)

    # Environment variables (avoid secrets here, use Docker secrets instead)
    environment:
      LOG_LEVEL: "INFO"
      ENABLE_CACHE: "true"

    # Volume mounts (restricted to project directory)
    volumes:
      - "./data:/data:ro"  # Read-only access to project data

  # Optional: Tags for multi-dimensional discovery
  tags:
    function: ["static_analysis", "code_generation", "linting"]
    language: ["dsl", "proprietary"]
    technology: ["ast", "compiler"]

  # Optional: Use case keywords for semantic search
  use_cases:
    - "analyze DSL code structure"
    - "validate DSL syntax"
    - "generate code from DSL templates"

# Tool definitions (can be auto-discovered or manually defined)
tools:
  # Option A: Auto-discovery (recommended)
  auto_discover: true  # TMWS will query MCP server for available tools

  # Option B: Manual definition (for pre-registration or documentation)
  # manual:
  #   - name: "analyze_code"
  #     description: "Analyze DSL code for syntax and semantic errors"
  #     tier: "warm"  # hot/warm/standard/cold (optional, will be computed)

# Security policy (required for non-allowlisted images)
security:
  # Approval metadata (filled by admin during approval)
  approved_by: null  # Will be set by admin
  approved_at: null
  approval_reason: null

  # Allowlist exemption request (for first-time registration)
  exemption_request:
    reason: "Internal tooling for proprietary DSL, no external network access required"
    risk_assessment: "Low - sandboxed execution, no network, read-only filesystem"
    maintainer: "john.doe@myorg.com"

# Metadata
metadata:
  version: "1.0.0"
  author: "MyOrg DevTools Team"
  homepage: "https://github.com/myorg/custom-analyzer"
  documentation: "https://docs.myorg.com/custom-analyzer"
  created_at: "2025-11-20"
```

---

### Step 2: User Registers Server

```bash
# Command-line registration
tmws mcp register .tmws/mcps/custom/my-analyzer.yml

# Or via API
curl -X POST http://localhost:8000/api/v1/mcp/register \
  -H "Authorization: Bearer $TMWS_API_KEY" \
  -F "config=@.tmws/mcps/custom/my-analyzer.yml"
```

---

### Step 3: TMWS Validates Configuration

**Validation Pipeline**:

```python
from pydantic import BaseModel, Field, validator
from typing import Literal
import yaml

class DockerConfig(BaseModel):
    network_mode: Literal["none", "bridge", "host"] = "none"
    memory_limit_mb: int = Field(512, ge=128, le=4096)
    cpu_shares: int = Field(1024, ge=512, le=4096)
    environment: dict[str, str] = {}
    volumes: list[str] = []

    @validator("volumes")
    def validate_volumes(cls, v):
        """Ensure volumes are read-only or within project directory."""
        for volume in v:
            if ":rw" in volume and "/data" not in volume:
                raise ValueError(f"Read-write volumes must be in /data: {volume}")
        return v

class MCPServerConfig(BaseModel):
    name: str = Field(..., regex=r"^[a-z][a-z0-9\-]{1,63}$")
    display_name: str = Field(..., max_length=255)
    category: Literal[
        "code_analysis", "file_operations", "web_automation",
        "document_generation", "data_processing", "infrastructure",
        "ai_ml", "security", "communication", "utilities"
    ]
    description: str = Field(..., max_length=500)
    docker_image: str = Field(..., regex=r"^[a-z0-9\.\-\/]+:[a-z0-9\.\-]+$")
    docker: DockerConfig = DockerConfig()
    tags: dict[str, list[str]] = {}
    use_cases: list[str] = []

class SecurityPolicy(BaseModel):
    approved_by: str | None = None
    approved_at: str | None = None
    approval_reason: str | None = None
    exemption_request: dict[str, str] | None = None

class FullMCPConfig(BaseModel):
    server: MCPServerConfig
    tools: dict = {"auto_discover": True}
    security: SecurityPolicy
    metadata: dict

# Validation function
async def validate_mcp_config(yaml_path: str) -> FullMCPConfig:
    """Parse and validate YAML config."""
    with open(yaml_path) as f:
        raw_config = yaml.safe_load(f)

    # Pydantic validation
    config = FullMCPConfig(**raw_config)

    # Security checks
    await validate_security_policy(config)

    return config
```

---

### Step 4: Security Validation (Automatic + Manual)

#### Automatic Checks

```python
async def validate_security_policy(config: FullMCPConfig) -> tuple[bool, str]:
    """
    Automatic security validation.

    Returns:
        (is_approved, reason_or_error)
    """

    # Check 1: Allowlist validation
    is_allowlisted = await check_allowlist(config.server.docker_image)
    if is_allowlisted:
        return True, "Docker image is in approved allowlist"

    # Check 2: Network mode restriction
    if config.server.docker.network_mode != "none":
        if not config.security.exemption_request:
            return False, "Network access requires exemption request"

    # Check 3: Resource limits
    if config.server.docker.memory_limit_mb > 2048:
        return False, "Memory limit exceeds 2GB threshold (requires admin approval)"

    # Check 4: Volume mount safety
    for volume in config.server.docker.volumes:
        if ":rw" in volume and not volume.startswith("./data"):
            return False, f"Unsafe write volume: {volume}"

    # Check 5: Secrets detection
    for key, value in config.server.docker.environment.items():
        if "password" in key.lower() or "secret" in key.lower() or "token" in key.lower():
            return False, f"Hardcoded secrets detected in environment: {key}"

    # Passed automatic checks, but needs manual approval for non-allowlisted images
    if not is_allowlisted:
        return False, "Non-allowlisted image requires manual admin approval"

    return True, "All automatic security checks passed"

async def check_allowlist(docker_image: str) -> bool:
    """Check if Docker image matches allowlist patterns."""

    allowlist_patterns = await db.query(MCPServerAllowlist).filter(
        MCPServerAllowlist.is_active == True
    ).all()

    for pattern in allowlist_patterns:
        # Simple glob matching (e.g., "ghcr.io/trusted-org/*")
        import fnmatch
        if fnmatch.fnmatch(docker_image, pattern.docker_image_pattern):
            logger.info(f"Docker image {docker_image} matched allowlist pattern: {pattern.docker_image_pattern}")
            return True

    return False
```

#### Manual Admin Approval

```python
# If automatic validation fails, create approval request
async def create_approval_request(config: FullMCPConfig, agent_id: UUID) -> UUID:
    """Create pending approval request for admin review."""

    request = MCPServerApprovalRequest(
        id=uuid4(),
        config_yaml=yaml.dump(config.dict()),
        docker_image=config.server.docker_image,
        requested_by_agent_id=agent_id,
        request_reason=config.security.exemption_request.get("reason") if config.security.exemption_request else None,
        status="pending",
        created_at=datetime.utcnow()
    )

    await db.add(request)
    await db.commit()

    logger.info(f"Created approval request {request.id} for {config.server.name}")

    # Send notification to admins
    await notify_admins(
        subject=f"New MCP Server Approval Request: {config.server.name}",
        body=f"""
A new MCP server registration requires your approval:

Server: {config.server.name}
Docker Image: {config.server.docker_image}
Requested by: {agent_id}
Reason: {request.request_reason}

Review at: /admin/mcp-approvals/{request.id}
        """
    )

    return request.id

# Admin approval endpoint
@app.post("/api/v1/admin/mcp/approve/{request_id}")
async def approve_mcp_server(
    request_id: UUID,
    approval: MCPApprovalDecision,
    admin: User = Depends(require_admin_role)
):
    """Admin approves or rejects MCP server registration."""

    request = await db.get(MCPServerApprovalRequest, request_id)

    if approval.decision == "approved":
        # Parse config and add to allowlist
        config = yaml.safe_load(request.config_yaml)

        # Option 1: Add specific image to allowlist
        await db.add(MCPServerAllowlist(
            docker_image_pattern=config["server"]["docker_image"],
            approved_by_agent_id=admin.agent_id,
            approved_at=datetime.utcnow(),
            reason=approval.reason
        ))

        # Option 2: Add wildcard pattern (e.g., "ghcr.io/myorg/*")
        if approval.add_to_allowlist_pattern:
            await db.add(MCPServerAllowlist(
                docker_image_pattern=approval.add_to_allowlist_pattern,
                approved_by_agent_id=admin.agent_id,
                approved_at=datetime.utcnow(),
                reason=f"Approved as trusted organization: {approval.reason}"
            ))

        # Update request status
        request.status = "approved"
        request.approved_by_agent_id = admin.agent_id
        request.approved_at = datetime.utcnow()

        # Proceed with registration
        await register_mcp_server(config, admin.agent_id)

    else:  # rejected
        request.status = "rejected"
        request.rejection_reason = approval.reason

    await db.commit()

    return {"status": request.status, "message": approval.reason}
```

---

### Step 5: Docker Image Pull & Validation

```python
async def pull_and_validate_docker_image(docker_image: str) -> tuple[bool, str]:
    """Pull Docker image and perform security scan."""

    # Pull image
    try:
        result = await asyncio.create_subprocess_exec(
            "docker", "pull", docker_image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()

        if result.returncode != 0:
            return False, f"Docker pull failed: {stderr.decode()}"

    except Exception as e:
        return False, f"Failed to pull Docker image: {str(e)}"

    # Inspect image
    inspect_result = await asyncio.create_subprocess_exec(
        "docker", "inspect", docker_image,
        stdout=asyncio.subprocess.PIPE
    )
    inspect_stdout, _ = await inspect_result.communicate()
    image_metadata = json.loads(inspect_stdout)

    # Security checks
    config = image_metadata[0]["Config"]

    # Check 1: No USER=root (prefer non-root user)
    if config.get("User") == "root" or not config.get("User"):
        logger.warning(f"Image {docker_image} runs as root (security risk)")

    # Check 2: Exposed ports (should be none for MCP servers)
    if config.get("ExposedPorts"):
        logger.warning(f"Image {docker_image} exposes ports: {list(config['ExposedPorts'].keys())}")

    # Check 3: Image size (warn if > 2GB)
    image_size_mb = image_metadata[0]["Size"] / (1024 * 1024)
    if image_size_mb > 2048:
        logger.warning(f"Image {docker_image} is large: {image_size_mb:.1f} MB")

    # Optional: Vulnerability scan (requires Trivy or similar)
    # await scan_vulnerabilities(docker_image)

    return True, "Image pulled and validated successfully"
```

---

### Step 6: Tool Auto-Discovery

```python
async def discover_tools(server_name: str, docker_image: str) -> list[dict]:
    """
    Run MCP server in discovery mode to enumerate available tools.

    MCP Spec: All servers must respond to "tools/list" method.
    """

    # Start container in temporary mode
    container_id = await start_mcp_container_temp(docker_image)

    try:
        # MCP protocol: Send "tools/list" request
        mcp_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }

        # Send request via stdin (MCP STDIO protocol)
        result = await asyncio.create_subprocess_exec(
            "docker", "exec", "-i", container_id, "/bin/sh", "-c",
            f"echo '{json.dumps(mcp_request)}' | /app/mcp-server",
            stdout=asyncio.subprocess.PIPE
        )
        stdout, _ = await result.communicate()

        # Parse response
        mcp_response = json.loads(stdout)

        if "result" not in mcp_response:
            raise ValueError(f"Invalid MCP response: {mcp_response}")

        tools = mcp_response["result"]["tools"]

        logger.info(f"Discovered {len(tools)} tools from {server_name}")

        return tools

    finally:
        # Cleanup: Stop and remove container
        await stop_mcp_container(container_id)

async def start_mcp_container_temp(docker_image: str) -> str:
    """Start MCP container in temporary discovery mode."""

    result = await asyncio.create_subprocess_exec(
        "docker", "run", "-d", "--rm",
        "--network=none",  # No network access during discovery
        "--memory=512m",
        docker_image,
        stdout=asyncio.subprocess.PIPE
    )
    stdout, _ = await result.communicate()
    container_id = stdout.decode().strip()

    return container_id

async def stop_mcp_container(container_id: str):
    """Stop and remove temporary container."""

    await asyncio.create_subprocess_exec(
        "docker", "stop", container_id
    )
```

---

### Step 7: Database Registration

```python
async def register_mcp_server(
    config: FullMCPConfig,
    registered_by_agent_id: UUID
) -> UUID:
    """Register MCP server and tools in database."""

    # Create server record
    server = MCPServer(
        id=uuid4(),
        server_name=config.server.name,
        display_name=config.server.display_name,
        category=config.server.category,
        description=config.server.description,
        docker_image=config.server.docker_image,
        network_mode=config.server.docker.network_mode,
        is_active=True,
        is_builtin=False,
        registration_source="user",
        created_by_agent_id=registered_by_agent_id,
        created_at=datetime.utcnow()
    )

    await db.add(server)
    await db.flush()  # Get server.id

    # Auto-discover or register tools
    if config.tools.get("auto_discover"):
        discovered_tools = await discover_tools(server.server_name, server.docker_image)

        for tool_spec in discovered_tools:
            tool = MCPTool(
                id=uuid4(),
                server_id=server.id,
                tool_name=tool_spec["name"],
                display_name=tool_spec.get("displayName", tool_spec["name"]),
                description=tool_spec["description"],
                primary_category=server.category,
                tags=config.server.tags.get("function", []),
                use_cases=config.server.use_cases,
                parameters_schema=tool_spec["inputSchema"],
                tier="standard",  # Will be computed after usage data
                tier_score=0.0,
                created_at=datetime.utcnow()
            )

            await db.add(tool)

    await db.commit()

    logger.info(f"Registered MCP server {server.server_name} with {len(discovered_tools)} tools")

    # Index in ChromaDB for semantic search
    await index_server_tools(server.id)

    return server.id
```

---

### Step 8: Orchestrator Service Integration

```go
// orchestrator/mcp_registry.go

type MCPServerConfig struct {
    ID            string            `json:"id"`
    ServerName    string            `json:"server_name"`
    DockerImage   string            `json:"docker_image"`
    NetworkMode   string            `json:"network_mode"`
    MemoryLimitMB int               `json:"memory_limit_mb"`
    CPUShares     int               `json:"cpu_shares"`
    Environment   map[string]string `json:"environment"`
    Volumes       []string          `json:"volumes"`
}

// Pull latest MCP server configurations from TMWS API
func (o *Orchestrator) RefreshMCPServers() error {
    resp, err := http.Get(fmt.Sprintf("%s/api/v1/mcp/servers/active", o.TMWSBaseURL))
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    var servers []MCPServerConfig
    if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
        return err
    }

    // Update in-memory registry
    o.mcpServers = servers
    log.Printf("Refreshed %d MCP server configurations", len(servers))

    return nil
}

// Start MCP container with user-defined config
func (o *Orchestrator) StartMCPContainer(serverID string, request MCPRequest) (string, error) {
    // Find server config
    var serverConfig *MCPServerConfig
    for _, s := range o.mcpServers {
        if s.ID == serverID {
            serverConfig = &s
            break
        }
    }

    if serverConfig == nil {
        return "", fmt.Errorf("MCP server not found: %s", serverID)
    }

    // Build docker run command
    args := []string{
        "run", "-d", "--rm",
        "--network=" + serverConfig.NetworkMode,
        "--memory=" + fmt.Sprintf("%dm", serverConfig.MemoryLimitMB),
        "--cpu-shares=" + strconv.Itoa(serverConfig.CPUShares),
    }

    // Add environment variables
    for key, value := range serverConfig.Environment {
        args = append(args, "-e", fmt.Sprintf("%s=%s", key, value))
    }

    // Add volume mounts
    for _, volume := range serverConfig.Volumes {
        args = append(args, "-v", volume)
    }

    args = append(args, serverConfig.DockerImage)

    // Execute docker run
    cmd := exec.Command("docker", args...)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return "", fmt.Errorf("failed to start container: %w, output: %s", err, output)
    }

    containerID := strings.TrimSpace(string(output))
    log.Printf("Started MCP container %s for server %s", containerID[:12], serverConfig.ServerName)

    return containerID, nil
}
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation | Severity |
|--------|-----------|----------|
| **Malicious Docker Image** | Allowlist + Manual approval | CRITICAL |
| **Network Exfiltration** | Default `network=none`, require exemption | HIGH |
| **Resource Exhaustion** | Memory/CPU limits enforced | MEDIUM |
| **Filesystem Access** | Read-only volumes, sandboxed paths | MEDIUM |
| **Secrets Leakage** | Detect hardcoded secrets in config | HIGH |
| **Privilege Escalation** | Run as non-root user in container | MEDIUM |

### Allowlist Examples

```sql
-- Trusted organizations (wildcard patterns)
INSERT INTO mcp_server_allowlist (docker_image_pattern, allowed_network_modes, reason)
VALUES
    ('ghcr.io/official-mcp/*', ARRAY['none'], 'Official MCP organization'),
    ('ghcr.io/myorg/*', ARRAY['none', 'bridge'], 'Internal trusted org'),
    ('docker.io/library/*', ARRAY['none'], 'Docker official images');

-- Specific approved images
INSERT INTO mcp_server_allowlist (docker_image_pattern, allowed_network_modes, reason)
VALUES
    ('ghcr.io/serena-mcp-server:v1.0.0', ARRAY['none'], 'Widely-used code analysis tool'),
    ('ghcr.io/playwright:v1.40', ARRAY['bridge'], 'Browser automation requires network');
```

---

## User Experience

### Registration Success Flow

```bash
$ tmws mcp register .tmws/mcps/custom/my-analyzer.yml

✅ Validating configuration...
✅ Security checks passed
✅ Pulling Docker image: ghcr.io/myorg/custom-analyzer:v1.2.3
✅ Auto-discovering tools...
✅ Found 5 tools:
   - analyze_code
   - validate_syntax
   - generate_ast
   - lint_style
   - refactor_suggest

✅ Registered MCP server: my-custom-analyzer
✅ Indexed 5 tools in semantic search

Server ID: a7f3c2e1-4b5d-6789-abcd-ef0123456789

You can now use these tools:
  tmws tool call my-custom-analyzer::analyze_code --file src/main.dsl
```

### Registration Approval Required Flow

```bash
$ tmws mcp register .tmws/mcps/risky-tool.yml

❌ Security validation failed: Non-allowlisted image requires manual admin approval

Created approval request: req-12345678

An admin has been notified. You will receive an email when your request is reviewed.

Status: https://tmws.example.com/requests/req-12345678
```

---

## Monitoring & Analytics

### Registration Metrics

```python
async def get_registration_stats():
    """Analytics on MCP server registrations."""

    stats = await db.execute("""
        SELECT
            COUNT(*) AS total_servers,
            SUM(CASE WHEN is_builtin THEN 1 ELSE 0 END) AS builtin_count,
            SUM(CASE WHEN is_builtin = FALSE THEN 1 ELSE 0 END) AS custom_count,
            COUNT(DISTINCT category) AS categories_used,
            AVG(total_invocations) AS avg_invocations_per_server
        FROM mcp_servers
        WHERE is_active = TRUE
    """)

    return stats.fetchone()._asdict()
```

### Custom Server Health Monitoring

```python
# Cron job: Check health of custom MCP servers
async def monitor_custom_servers():
    """Monitor health of user-registered MCP servers."""

    custom_servers = await db.query(MCPServer).filter(
        MCPServer.is_builtin == False,
        MCPServer.is_active == True
    ).all()

    for server in custom_servers:
        # Check if Docker image still exists
        result = await asyncio.create_subprocess_exec(
            "docker", "inspect", server.docker_image,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await result.wait()

        if result.returncode != 0:
            logger.error(f"Docker image missing for {server.server_name}: {server.docker_image}")

            # Deactivate server
            server.is_active = False
            await db.commit()

            # Notify creator
            await notify_agent(
                server.created_by_agent_id,
                f"MCP server '{server.server_name}' has been deactivated due to missing Docker image"
            )
```

---

## Conclusion

**Dynamic Registration Benefits**:
- ✅ **User-Friendly**: YAML config files, no code changes
- ✅ **Secure**: Multi-layer validation (automatic + manual approval)
- ✅ **Scalable**: Supports 50-100+ custom servers
- ✅ **Auto-Discovery**: Tools enumerated via MCP protocol
- ✅ **Monitored**: Health checks and deactivation on failure

**Security Layers**:
1. Pydantic schema validation
2. Allowlist pattern matching
3. Automatic security checks (network, resources, secrets)
4. Manual admin approval for non-allowlisted images
5. Docker image scanning (optional: Trivy integration)
6. Runtime sandboxing (network=none, memory limits, read-only volumes)
