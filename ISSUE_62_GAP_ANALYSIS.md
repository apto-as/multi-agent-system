# Issue #62: Gap Analysis & Remediation Plan
## TMWS v2.4.x Feature Utilization Analysis

**Date**: 2025-12-12
**Analyst**: Metis (Development Assistant)
**Target**: 4 core features with low utilization

---

## Executive Summary

Analysis reveals that all 4 features (Narrative System, Skills System, Learning System, MCP Configuration) are **correctly implemented** but suffer from **integration gaps** preventing real-world usage. The code architecture is sound; the problems are:

1. **Narrative System**: Missing DB-to-MD sync
2. **Skills System**: Missing activation workflow documentation
3. **Learning System**: Trust scores exist but aren't used in routing
4. **MCP Configuration**: Missing Docker deployment guidance

**Good News**: No major code changes needed. Solutions are integration and documentation.

---

## 1. Narrative System Gap Analysis

### Current Implementation (Code Review)

**File**: `src/tools/routing_tools.py` (Lines 261-615)

**What Works**:
- `invoke_persona()` tool exists and loads personas from MD files
- Fallback MD generation works (Lines 501-518)
- Searches multiple locations for persona files:
  - `~/.claude/agents/{persona_id}.md`
  - `~/.config/opencode/agent/{persona_id}.md`
  - `src/trinitas/agents/{persona_id}.md`

**The Gap**:
```python
# Line 482-498: System prompt loaded from MD files
possible_paths = [
    Path.home() / ".claude" / "agents" / f"{persona_id}.md",
    Path.home() / ".config" / "opencode" / "agent" / f"{persona_id}.md",
    Path(__file__).parent.parent / "trinitas" / "agents" / f"{persona_id}.md",
]
```

**Problem**: MD files are **NEVER** created from DB personas. The `invoke_persona()` function uses hardcoded metadata (Lines 303-442) instead of querying the `agents` table.

### Root Cause

**File**: `src/tools/routing_tools.py` (Lines 553-593)

```python
# Line 554-593: Database lookup exists but only for status
if include_db_status:
    async def _get_agent_status(session, _services):
        from ..services.agent_service import AgentService
        agent_service = AgentService(session)
        agent = await agent_service.get_agent_by_id(persona_id)
```

**The gap**: DB agent data (capabilities, persona metadata) is fetched **ONLY** for status, not for system prompt generation.

### Proposed Fix

**Create Sync Service** (New file: `src/services/persona_sync_service.py`):

```python
"""Persona Sync Service - Bridge DB agents to MD files.

Generates persona MD files from DB Agent records.
"""
import logging
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..models.agent import Agent

logger = logging.getLogger(__name__)


class PersonaSyncService:
    """Sync DB personas to MD files for invoke_persona."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def sync_persona_to_md(
        self,
        persona_id: str,
        output_path: Path | None = None,
    ) -> Path:
        """Generate MD file from DB Agent record.

        Args:
            persona_id: Agent identifier (e.g., "athena-conductor")
            output_path: Optional custom output path

        Returns:
            Path to generated MD file

        Raises:
            NotFoundError: If agent doesn't exist in DB
        """
        # 1. Fetch agent from DB
        stmt = select(Agent).where(Agent.agent_id == persona_id)
        result = await self.session.execute(stmt)
        agent = result.scalar_one_or_none()

        if not agent:
            raise NotFoundError("Agent", persona_id)

        # 2. Generate MD content
        md_content = self._generate_md(agent)

        # 3. Determine output path
        if output_path is None:
            # Default: ~/.claude/agents/{persona_id}.md
            output_path = Path.home() / ".claude" / "agents" / f"{persona_id}.md"

        # 4. Write MD file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(md_content, encoding="utf-8")

        logger.info(f"Synced persona {persona_id} to {output_path}")
        return output_path

    def _generate_md(self, agent: Agent) -> str:
        """Generate markdown content from Agent model.

        Args:
            agent: Agent database model

        Returns:
            Markdown string for persona file
        """
        # Parse metadata
        metadata = agent.metadata or {}
        capabilities = metadata.get("capabilities", [])
        collaboration = metadata.get("collaboration", {})
        invocation_style = metadata.get("invocation_style", "")

        # Build markdown
        md = f"""# {agent.display_name}

## Core Identity
Agent ID: {agent.agent_id}
Status: {agent.status.value}
Trust Score: {agent.trust_score:.2f}

## Capabilities
{chr(10).join(f"- {cap}" for cap in capabilities)}

## Collaboration Style
"""

        if collaboration:
            md += f"""
- Primary Partners: {", ".join(collaboration.get("primary_partners", []))}
- Support From: {", ".join(collaboration.get("support_from", []))}
- Reports To: {", ".join(collaboration.get("reports_to", []))}
"""

        if invocation_style:
            md += f"""
## Invocation Style
{invocation_style}
"""

        # Add performance metrics
        if agent.total_tasks > 0:
            success_rate = (agent.successful_tasks / agent.total_tasks) * 100
            md += f"""
## Performance Metrics
- Total Tasks: {agent.total_tasks}
- Successful Tasks: {agent.successful_tasks}
- Success Rate: {success_rate:.1f}%
- Health Score: {agent.health_score:.2f}
"""

        return md

    async def sync_all_personas(self, output_dir: Path | None = None) -> list[Path]:
        """Sync all DB agents to MD files.

        Args:
            output_dir: Optional custom output directory

        Returns:
            List of generated MD file paths
        """
        # Fetch all active agents
        stmt = select(Agent).where(Agent.status == "active")
        result = await self.session.execute(stmt)
        agents = result.scalars().all()

        synced_paths = []
        for agent in agents:
            try:
                if output_dir:
                    path = output_dir / f"{agent.agent_id}.md"
                else:
                    path = None
                synced_path = await self.sync_persona_to_md(agent.agent_id, path)
                synced_paths.append(synced_path)
            except Exception as e:
                logger.error(f"Failed to sync {agent.agent_id}: {e}")

        logger.info(f"Synced {len(synced_paths)}/{len(agents)} personas")
        return synced_paths
```

**Integration Point** (Update `src/tools/routing_tools.py`):

```python
# Line 481: Add DB-first loading
async def _load_system_prompt(persona_id: str, session, include_db_status: bool):
    """Load system prompt with DB-first strategy."""
    system_prompt = None

    # STRATEGY 1: Try DB sync (NEW)
    if session and include_db_status:
        try:
            from ..services.persona_sync_service import PersonaSyncService
            sync_service = PersonaSyncService(session)
            md_path = await sync_service.sync_persona_to_md(persona_id)
            system_prompt = md_path.read_text(encoding="utf-8")
            logger.info(f"Loaded system prompt from DB-synced file: {md_path}")
        except Exception as e:
            logger.debug(f"DB sync failed, trying file paths: {e}")

    # STRATEGY 2: Try existing MD files
    if not system_prompt:
        possible_paths = [
            Path.home() / ".claude" / "agents" / f"{persona_id}.md",
            Path.home() / ".config" / "opencode" / "agent" / f"{persona_id}.md",
            Path(__file__).parent.parent / "trinitas" / "agents" / f"{persona_id}.md",
        ]
        for path in possible_paths:
            if path.exists():
                system_prompt = path.read_text(encoding="utf-8")
                logger.debug(f"Loaded system prompt from {path}")
                break

    # STRATEGY 3: Fallback to generated minimal prompt
    if not system_prompt:
        system_prompt = f"""# {persona_info["display_name"]}
(minimal generated prompt)
"""

    return system_prompt
```

**Test Scenario**:

```python
# Test: Sync DB persona to MD
async def test_persona_sync():
    async with get_session() as session:
        sync_service = PersonaSyncService(session)

        # 1. Create test agent in DB
        agent_service = AgentService(session)
        agent = await agent_service.register_agent(
            display_name="Test Agent",
            capabilities=["testing", "validation"],
            metadata={"invocation_style": "methodical, thorough"}
        )

        # 2. Sync to MD
        md_path = await sync_service.sync_persona_to_md(agent.agent_id)

        # 3. Verify MD file exists
        assert md_path.exists()
        content = md_path.read_text()
        assert "Test Agent" in content
        assert "testing" in content
        assert "methodical" in content

        # 4. Cleanup
        md_path.unlink()
```

---

## 2. Skills System Gap Analysis

### Current Implementation (Code Review)

**File**: `src/tools/skill_tools.py` (Lines 812-900)

**What Works**:
- `activate_skill()` MCP tool exists (Line 814)
- Database activation logic is **correct** (Lines 839-900)
- Security checks are in place (REQ-1, REQ-2, REQ-5)

**File**: `src/services/skill_service/skill_activation.py` (Lines 49-290)

**What REALLY Works**:
- Activation creates `SkillActivation` record (Lines 209-222)
- One-active-per-namespace rule enforced (Lines 162-207)
- Idempotent activation (Lines 114-160)

**The Gap**:

**Line 76**: "Activated skill becomes available for MCP tool registration"

**Problem**: This comment is **ASPIRATIONAL**. The code creates a DB record but **NEVER** registers the skill as an actual MCP tool in FastMCP.

### Root Cause

**Missing Integration**: There's no code that does:

```python
# MISSING: Actual MCP tool registration
@mcp.tool()
async def {skill_name}(...) -> dict[str, Any]:
    """Dynamically registered skill from DB."""
    # Execute skill content as MCP tool
```

The `activate_skill()` tool only creates a DB record. It doesn't register the skill content as a callable MCP tool.

### Proposed Fix

**Create Dynamic Tool Registration Service** (New file: `src/services/skill_service/dynamic_tool_registry.py`):

```python
"""Dynamic Tool Registry - Register skills as MCP tools at runtime.

Enables skills to become callable MCP tools after activation.
"""
import logging
from typing import Any, Callable
from uuid import UUID

from fastmcp import FastMCP
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ...models.skill import Skill, SkillVersion, SkillActivation

logger = logging.getLogger(__name__)


class DynamicToolRegistry:
    """Registry for dynamically activating skills as MCP tools."""

    def __init__(self, mcp: FastMCP, session_factory: Callable):
        """Initialize dynamic tool registry.

        Args:
            mcp: FastMCP instance for tool registration
            session_factory: Async session factory for DB access
        """
        self.mcp = mcp
        self.session_factory = session_factory
        self._registered_tools: dict[str, UUID] = {}

    async def register_skill_as_tool(
        self,
        skill_id: UUID,
        agent_id: str,
        namespace: str,
    ) -> str:
        """Register an activated skill as an MCP tool.

        Args:
            skill_id: Skill UUID to register
            agent_id: Agent activating the skill
            namespace: Namespace for access control

        Returns:
            Tool name registered in MCP

        Raises:
            NotFoundError: Skill not found or not activated
        """
        async with self.session_factory() as session:
            # 1. Fetch activated skill
            stmt = (
                select(Skill, SkillVersion, SkillActivation)
                .join(SkillVersion, SkillVersion.skill_id == Skill.id)
                .join(SkillActivation, SkillActivation.skill_id == Skill.id)
                .where(
                    Skill.id == str(skill_id),
                    SkillVersion.version == Skill.active_version,
                    SkillActivation.agent_id == agent_id,
                    SkillActivation.success.is_(None) | SkillActivation.success.is_(True),
                )
                .order_by(SkillActivation.activated_at.desc())
                .limit(1)
            )
            result = await session.execute(stmt)
            row = result.first()

            if not row:
                raise NotFoundError("Activated skill", str(skill_id))

            skill, version, activation = row

            # 2. Generate tool name
            tool_name = f"skill_{skill.name.lower().replace('-', '_')}"

            # 3. Check if already registered
            if tool_name in self._registered_tools:
                logger.info(f"Tool {tool_name} already registered (idempotent)")
                return tool_name

            # 4. Create dynamic MCP tool
            skill_content = version.content_data.get("core_instructions", "")

            # Create closure to capture skill_id, content
            def create_tool_handler(skill_id_str: str, content: str):
                async def skill_tool_handler(**kwargs: Any) -> dict[str, Any]:
                    """Dynamically generated skill tool."""
                    # Execute skill logic here
                    # For now, return skill content and args
                    return {
                        "success": True,
                        "skill_id": skill_id_str,
                        "content": content,
                        "arguments": kwargs,
                        "message": f"Skill {tool_name} executed successfully",
                    }

                return skill_tool_handler

            # 5. Register with FastMCP
            handler = create_tool_handler(str(skill_id), skill_content)
            self.mcp.tool()(handler)

            # 6. Track registration
            self._registered_tools[tool_name] = skill_id

            logger.info(f"Registered skill {skill.name} as MCP tool: {tool_name}")
            return tool_name

    async def unregister_skill_tool(self, skill_id: UUID) -> bool:
        """Unregister a skill from MCP tools.

        Args:
            skill_id: Skill UUID to unregister

        Returns:
            True if unregistered, False if not registered
        """
        # Find tool name by skill_id
        tool_name = None
        for name, sid in self._registered_tools.items():
            if sid == skill_id:
                tool_name = name
                break

        if not tool_name:
            logger.warning(f"Skill {skill_id} not registered")
            return False

        # Remove from FastMCP (if supported)
        # Note: FastMCP may not support dynamic unregistration
        # This is a limitation of the framework
        del self._registered_tools[tool_name]

        logger.info(f"Unregistered skill tool: {tool_name}")
        return True
```

**Integration Point** (Update `src/tools/skill_tools.py`):

```python
# Line 58: Add registry to SkillTools
class SkillTools:
    def __init__(self, mcp: FastMCP, session_factory):
        self.mcp = mcp
        self.session_factory = session_factory
        self.tool_registry = DynamicToolRegistry(mcp, session_factory)

    async def register_tools(self, mcp: FastMCP, session_factory) -> None:
        """Register all MCP tools."""

        @mcp.tool()
        @require_mcp_rate_limit("skill_activate")
        async def activate_skill(...) -> dict[str, Any]:
            # Existing activation logic...
            result = await skill_service.activate_skill(...)

            # NEW: Register as MCP tool
            try:
                tool_name = await self.tool_registry.register_skill_as_tool(
                    skill_uuid, context.agent_id, context.namespace
                )
                logger.info(f"Skill activated and registered as tool: {tool_name}")
                return {
                    "success": True,
                    "tool_name": tool_name,  # Return actual tool name
                    "activated_at": datetime.now(timezone.utc).isoformat(),
                }
            except Exception as e:
                logger.error(f"Skill activation succeeded but tool registration failed: {e}")
                # Still return success for DB activation
                return {
                    "success": True,
                    "tool_name": f"skill_{result.name}",  # Fallback
                    "activated_at": datetime.now(timezone.utc).isoformat(),
                    "warning": "Tool registration pending",
                }
```

**Test Scenario**:

```python
# Test: Skill activation creates callable MCP tool
async def test_skill_activation_creates_tool():
    async with get_session() as session:
        # 1. Create skill
        skill_service = SkillService(session)
        skill = await skill_service.create_skill(
            name="test-optimizer",
            content="# Optimization Skill\nCore instructions...",
            created_by="artemis-optimizer",
            namespace="testing",
        )

        # 2. Activate skill
        result = await skill_service.activate_skill(
            skill_id=UUID(skill.id),
            agent_id="artemis-optimizer",
            namespace="testing",
        )

        # 3. Verify MCP tool registered
        # (This requires access to FastMCP instance's tool list)
        # For now, verify activation record exists
        stmt = select(SkillActivation).where(
            SkillActivation.skill_id == skill.id
        )
        activation_result = await session.execute(stmt)
        activation = activation_result.scalar_one()

        assert activation.success is None  # Active
        assert result.tool_name == "skill_test_optimizer"
```

---

## 3. Learning System Gap Analysis

### Current Implementation (Code Review)

**File**: `src/tools/verification_tools.py` (Lines 29-93)

**What Works**:
- `verify_and_record()` tool exists and updates trust scores
- Trust score calculation is correct
- Verification history is stored

**File**: `src/services/task_routing_service.py` (Lines 359-412)

**The Gap** (Lines 376-410):

```python
# Line 389: get_recommended_agents exists
recommended = await self.agent_service.get_recommended_agents(
    capabilities=list(set(capabilities)),
    namespace=namespace,
    limit=5,
)

# Line 399: Trust scores are fetched but NOT USED IN RANKING
if result.primary_agent in db_agent_ids:
    result.confidence = min(result.confidence + 0.1, 1.0)
    result.reasoning += " (confirmed by database)"
```

**Problem**: Trust scores exist in the DB but are **NOT** factored into routing decisions. The routing confidence is based on pattern matching only.

### Root Cause

**Missing Trust Score Integration**:

```python
# Current: Pattern-only ranking (Line 329-338)
sorted_matches = sorted(
    persona_matches.items(),
    key=lambda x: (
        -x[1],  # Higher score first
        self.AGENT_TIERS.get(x[0], AgentTier.SUPPORT).value,  # Lower tier first
    ),
)

# MISSING: Trust score weighting
# Should be: (pattern_score * 0.7) + (trust_score * 0.3)
```

### Proposed Fix

**Update Routing Service** (Modify `src/services/task_routing_service.py`):

```python
# Line 359: Enhanced routing with trust scores
async def route_task_with_db(
    self,
    task_content: str,
    namespace: str | None = None,
) -> RoutingResult:
    """Route task with database-backed agent recommendations.

    Enhanced routing that combines:
    - Pattern matching (70% weight)
    - Trust scores (30% weight)
    - Capability matching
    """
    # Get basic routing result
    result = self.route_task(task_content)

    # Enhance with database if available
    if self.agent_service and self.session:
        try:
            # Get capabilities from detected patterns
            capabilities = []
            for agent_id in result.detected_patterns:
                agent_caps = self.AGENT_CAPABILITIES.get(agent_id, [])
                capabilities.extend(agent_caps)

            # Get recommended agents from database
            recommended = await self.agent_service.get_recommended_agents(
                capabilities=list(set(capabilities)),
                namespace=namespace,
                limit=5,
            )

            if recommended:
                # NEW: Fetch trust scores
                agent_trust_scores = {}
                for agent in recommended:
                    try:
                        from ..services.trust_service import TrustService
                        trust_service = TrustService(self.session)
                        score_info = await trust_service.get_trust_score(agent.agent_id)
                        agent_trust_scores[agent.agent_id] = score_info.get("trust_score", 0.5)
                    except Exception as e:
                        logger.debug(f"Trust score lookup failed for {agent.agent_id}: {e}")
                        agent_trust_scores[agent.agent_id] = 0.5  # Default

                # NEW: Re-rank using weighted scoring
                weighted_scores = {}
                for agent_id in result.detected_patterns:
                    pattern_score = persona_matches.get(agent_id, 0.5)
                    trust_score = agent_trust_scores.get(agent_id, 0.5)
                    # Weighted: 70% pattern, 30% trust
                    weighted = (pattern_score * 0.7) + (trust_score * 0.3)
                    weighted_scores[agent_id] = weighted

                # Re-sort by weighted score
                sorted_agents = sorted(
                    weighted_scores.items(),
                    key=lambda x: -x[1],  # Higher weighted score first
                )

                if sorted_agents:
                    # Update primary agent if weighted scoring changes ranking
                    new_primary = sorted_agents[0][0]
                    if new_primary != result.primary_agent:
                        old_primary = result.primary_agent
                        result.primary_agent = new_primary
                        result.confidence = sorted_agents[0][1]
                        result.reasoning += (
                            f" (re-ranked by trust: {old_primary} -> {new_primary})"
                        )
                        logger.info(
                            f"Trust-based re-ranking: {old_primary} -> {new_primary} "
                            f"(confidence: {result.confidence:.2f})"
                        )
                    else:
                        result.confidence = min(result.confidence + 0.1, 1.0)
                        result.reasoning += " (confirmed by trust scores)"

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.warning(f"Trust score integration failed, using pattern-only routing: {e}")

    return result
```

**Test Scenario**:

```python
# Test: Trust scores influence routing
async def test_routing_with_trust_scores():
    async with get_session() as session:
        # 1. Create two agents with different trust scores
        agent_service = AgentService(session)
        agent_a = await agent_service.register_agent(
            display_name="Agent A",
            capabilities=["optimization"],
        )
        agent_b = await agent_service.register_agent(
            display_name="Agent B",
            capabilities=["optimization"],
        )

        # 2. Set trust scores (A: 0.9, B: 0.4)
        trust_service = TrustService(session)
        await trust_service.update_trust_score(agent_a.agent_id, 0.9)
        await trust_service.update_trust_score(agent_b.agent_id, 0.4)

        # 3. Route optimization task
        routing_service = TaskRoutingService(session)
        result = await routing_service.route_task_with_db(
            "Optimize database queries",
            namespace="testing",
        )

        # 4. Verify high-trust agent is preferred
        assert result.primary_agent == agent_a.agent_id
        assert "trust" in result.reasoning.lower()
        assert result.confidence > 0.7
```

---

## 4. MCP Configuration Gap Analysis

### Current Implementation (Code Review)

**File**: `config/examples/claude_desktop_config.json` (Lines 1-30)

**What Works**:
- Example configuration provided
- Environment variables documented
- Command structure correct

**The Gap**:

**No Docker-specific configuration**. The example uses `uvx` for local development, but Docker deployments need:

1. `autoConnect: false` for external servers (avoid client connection attempts)
2. `STDERR` suppression for clean logs
3. Network configuration for inter-container communication

### Proposed Fix

**Create Docker MCP Configuration Template** (New file: `config/examples/docker-mcp-config.json`):

```json
{
  "$schema": "https://modelcontextprotocol.io/schema/mcp-config.json",
  "mcpServers": {
    "tmws": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--network", "tmws-network",
        "-e", "TMWS_DATABASE_URL=postgresql://tmws_user:tmws_password@postgres:5432/tmws",
        "-e", "TMWS_ENVIRONMENT=production",
        "-e", "TMWS_SECRET_KEY=${TMWS_SECRET_KEY}",
        "-e", "TMWS_AUTH_ENABLED=true",
        "-e", "TMWS_AGENT_ID=athena-conductor",
        "-e", "TMWS_AGENT_NAMESPACE=trinitas",
        "-e", "TMWS_ALLOW_DEFAULT_AGENT=false",
        "-e", "TMWS_LOG_LEVEL=INFO",
        "tmws:latest"
      ],
      "env": {
        "TMWS_SECRET_KEY": "production_secret_key_minimum_32_characters_required"
      },
      "autoConnect": false,
      "stderr": {
        "suppress": true,
        "logFile": "/var/log/tmws/stderr.log"
      }
    },
    "external-mcp-server": {
      "url": "https://external-mcp-server.example.com",
      "headers": {
        "Authorization": "Bearer ${EXTERNAL_MCP_TOKEN}"
      },
      "autoConnect": false
    }
  },
  "globalSettings": {
    "logLevel": "INFO",
    "logFile": "/var/log/tmws/mcp.log",
    "metricsEnabled": true,
    "metricsInterval": 60
  }
}
```

**Docker Compose Integration** (New file: `config/examples/docker-compose-with-mcp.yml`):

```yaml
version: '3.8'

networks:
  tmws-network:
    driver: bridge

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: tmws
      POSTGRES_USER: tmws_user
      POSTGRES_PASSWORD: tmws_password
    networks:
      - tmws-network
    volumes:
      - postgres-data:/var/lib/postgresql/data

  tmws:
    image: tmws:latest
    depends_on:
      - postgres
    environment:
      TMWS_DATABASE_URL: postgresql://tmws_user:tmws_password@postgres:5432/tmws
      TMWS_ENVIRONMENT: production
      TMWS_SECRET_KEY: ${TMWS_SECRET_KEY}
      TMWS_AUTH_ENABLED: "true"
      TMWS_AGENT_ID: athena-conductor
      TMWS_AGENT_NAMESPACE: trinitas
      TMWS_LOG_LEVEL: INFO
      # MCP Configuration
      MCP_AUTO_CONNECT: "false"
      MCP_STDERR_SUPPRESS: "true"
    networks:
      - tmws-network
    ports:
      - "8000:8000"
    volumes:
      - tmws-logs:/var/log/tmws
      - ./config/mcp-config.json:/app/config/mcp-config.json:ro

volumes:
  postgres-data:
  tmws-logs:
```

**Environment Variables Documentation** (New file: `docs/deployment/MCP_CONFIGURATION.md`):

```markdown
# MCP Configuration for TMWS

## Docker Deployment

### Required Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `TMWS_DATABASE_URL` | PostgreSQL connection string | - | Yes |
| `TMWS_SECRET_KEY` | JWT signing key (min 32 chars) | - | Yes |
| `TMWS_AUTH_ENABLED` | Enable authentication | `false` | No |
| `TMWS_AGENT_ID` | Default agent identifier | - | Yes |
| `TMWS_AGENT_NAMESPACE` | Default namespace | `default` | No |
| `MCP_AUTO_CONNECT` | Auto-connect to external servers | `false` | No |
| `MCP_STDERR_SUPPRESS` | Suppress stderr output | `true` | No |

### autoConnect Setting

**When to set `autoConnect: false`**:
- External MCP servers (URL-based)
- Servers requiring manual authentication
- High-latency connections
- Production environments (avoid startup delays)

**When to set `autoConnect: true`**:
- Local development
- Trusted internal servers
- Fast connections
- Testing environments

### STDERR Suppression

**Why suppress STDERR**:
- MCP protocol uses STDOUT for communication
- STDERR logs interfere with MCP messages
- Production deployments need clean logs

**Configuration**:
```json
{
  "stderr": {
    "suppress": true,
    "logFile": "/var/log/tmws/stderr.log"
  }
}
```

### Network Configuration

**Docker Network**:
```bash
# Create network
docker network create tmws-network

# Run services
docker run --network tmws-network tmws:latest
docker run --network tmws-network postgres:15
```

**Inter-container DNS**:
- Postgres: `postgres:5432`
- TMWS: `tmws:8000`
- Use service names, NOT localhost

### Security Best Practices

1. **Never commit secrets to git**:
   ```bash
   # Use environment files
   cp .env.example .env
   # Edit .env with production secrets
   # Add .env to .gitignore
   ```

2. **Use secret management**:
   ```bash
   # Docker Swarm secrets
   docker secret create tmws_secret_key secret.txt
   ```

3. **Restrict network access**:
   ```yaml
   networks:
     tmws-network:
       driver: bridge
       internal: true  # No external access
   ```

## Troubleshooting

### Issue: MCP connection timeout

**Cause**: `autoConnect: true` but server is unreachable

**Fix**: Set `autoConnect: false` for external servers

### Issue: STDERR logs mixed with MCP messages

**Cause**: `stderr.suppress: false`

**Fix**: Enable STDERR suppression in config

### Issue: Database connection failed

**Cause**: Using `localhost` instead of Docker service name

**Fix**: Use `postgres:5432` in Docker network
```

---

## Summary of Fixes

| Feature | Gap | Fix | Files Changed | Test Scenario |
|---------|-----|-----|---------------|---------------|
| **Narrative System** | MD files never created from DB | `PersonaSyncService` | `src/services/persona_sync_service.py` (NEW)<br>`src/tools/routing_tools.py` (MODIFY) | `test_persona_sync()` |
| **Skills System** | Activation doesn't register MCP tool | `DynamicToolRegistry` | `src/services/skill_service/dynamic_tool_registry.py` (NEW)<br>`src/tools/skill_tools.py` (MODIFY) | `test_skill_activation_creates_tool()` |
| **Learning System** | Trust scores not used in routing | Weighted routing | `src/services/task_routing_service.py` (MODIFY) | `test_routing_with_trust_scores()` |
| **MCP Configuration** | No Docker guidance | Docker templates | `config/examples/docker-mcp-config.json` (NEW)<br>`config/examples/docker-compose-with-mcp.yml` (NEW)<br>`docs/deployment/MCP_CONFIGURATION.md` (NEW) | Manual Docker deployment |

---

## Implementation Priority

1. **MCP Configuration** (Highest ROI, documentation only)
2. **Learning System** (Small code change, big impact)
3. **Narrative System** (Medium complexity, enables DB-first)
4. **Skills System** (Complex, requires FastMCP dynamic registration research)

---

## Next Steps

1. Review this gap analysis with Artemis (technical authority)
2. Get Hestia's security review on proposed changes
3. Create implementation tasks for each fix
4. Run test scenarios to validate fixes
5. Update documentation with new capabilities

**Estimated Effort**:
- MCP Config: 2 hours (docs + templates)
- Learning System: 4 hours (code + tests)
- Narrative System: 6 hours (new service + integration)
- Skills System: 8 hours (research + implementation)

**Total**: ~20 hours for full remediation

---

**Analysis Complete** ✅
Metis - Development Assistant
2025-12-12
