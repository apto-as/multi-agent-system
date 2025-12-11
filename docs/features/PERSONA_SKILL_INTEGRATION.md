# Persona-Skill Integration (Issue #59)

**Status**: ✅ Implemented
**Version**: v2.4.16
**Created**: 2025-12-11
**Components**: PersonaLoader, PersonaMarkdownParser, MCP Tools

---

## Overview

The Persona-Skill Integration feature enables TMWS to load persona definitions from Markdown files into the database, creating a bidirectional link between personas and their associated skills. This integration provides:

- **Automated persona import** from Markdown definitions
- **Structured metadata extraction** (frontmatter, identity, emoji, tier)
- **Database persistence** with create/update operations
- **MCP tool enhancement** for persona-based skill filtering
- **Support for all 11 Trinitas personas** (9 specialists + 2 orchestrators)

### Why This Feature?

Previously, persona definitions existed only in Markdown files (`.claude/agents/`) and were not integrated with the skill system. This created a disconnect between personas and their associated capabilities. The new integration:

1. **Centralizes persona data** in the TMWS database
2. **Enables persona-based skill queries** via MCP tools
3. **Maintains single source of truth** (Markdown files remain authoritative)
4. **Supports dynamic persona updates** via CLI import script

---

## Quick Start

### Prerequisites

- TMWS database initialized (`alembic upgrade head`)
- Persona Markdown files in `dist-config/claudecode/agents/`
- Python 3.11+ environment

### Basic Import

Import all personas from the default directory:

```bash
python scripts/import_personas.py
```

**Expected output:**
```
Importing personas from dist-config/claudecode/agents/
Found 11 persona files

✓ Created: Clotho (clotho-orchestrator.md)
✓ Created: Lachesis (lachesis-orchestrator.md)
✓ Created: Athena (athena-conductor.md)
...
────────────────────────────────────────────────────────────
Summary:

  11 created
  0 updated

Total: 11 persona files processed
────────────────────────────────────────────────────────────
```

### Dry-Run Mode

Preview changes without committing to the database:

```bash
python scripts/import_personas.py --dry-run
```

**Output includes:**
```
[DRY RUN MODE - No changes will be committed]

[DRY RUN] + Would create: Clotho (clotho-orchestrator.md)
[DRY RUN] ~ Would update: Athena (athena-conductor.md)
...
[DRY RUN] Would create 10, update 1 (no changes committed)
```

---

## CLI Usage

### Command Reference

```bash
python scripts/import_personas.py [OPTIONS]
```

#### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--source` | Path | `dist-config/claudecode/agents` | Directory containing persona `.md` files |
| `--dry-run` | Flag | `false` | Preview changes without committing |
| `-v, --verbose` | Flag | `false` | Enable verbose logging output |

#### Examples

**Standard import:**
```bash
python scripts/import_personas.py
```

**Custom source directory:**
```bash
python scripts/import_personas.py --source /path/to/agents
```

**Dry-run with verbose logging:**
```bash
python scripts/import_personas.py --dry-run --verbose
```

#### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success - all personas imported without errors |
| `1` | Error - one or more personas failed to import |
| `130` | Cancelled - user interrupted with Ctrl+C |

### Security: Path Validation

The import script includes path traversal protection (M-1 security fix):

```python
# ✅ ALLOWED: Paths within project root
--source dist-config/claudecode/agents        # Relative path
--source /absolute/path/within/project        # Absolute within project

# ❌ BLOCKED: Paths outside project root
--source ../../etc/passwd                     # Path traversal
--source /tmp/malicious                       # Outside project
```

If a path outside the project boundary is provided:
```
Error: Security: Source path must be within project root.
  Provided: ../../etc/passwd
  Project root: /Users/apto-as/workspace/github.com/apto-as/tmws
  Use paths relative to project root (e.g., dist-config/claudecode/agents)
```

---

## MCP Tools

### New Tool: `list_skills_by_persona`

Filter skills by persona identifier.

**Tool Name:** `mcp__tmws__list_skills_by_persona`

**Parameters:**
```python
{
    "agent_id": "aurora-researcher",       # Required: Agent identifier
    "persona": "hestia-auditor",           # Required: Persona filter
    "api_key": "sk_...",                   # Optional: API key
    "jwt_token": "eyJ...",                 # Optional: JWT token
    "detail_level": 2,                     # Optional: 1=metadata, 2=core, 3=full
    "namespace": "default",                # Optional: Filter by namespace
    "include_shared": true,                # Optional: Include shared skills
    "limit": 50,                           # Optional: Max results (1-100)
    "offset": 0                            # Optional: Pagination offset
}
```

**Response:**
```json
{
    "success": true,
    "persona": "hestia-auditor",
    "skills": [
        {
            "id": "uuid-...",
            "name": "security_audit",
            "display_name": "Security Audit",
            "description": "Perform comprehensive security audit",
            "persona": "hestia-auditor",
            "version": "1.0.0",
            "created_at": "2025-12-11T10:30:00Z"
        }
    ],
    "total": 1,
    "limit": 50,
    "offset": 0
}
```

**Use Cases:**
- List all skills available to a specific persona
- Filter skill catalog by persona expertise
- Discover capabilities of a persona
- Build persona-specific skill recommendations

### Enhanced Tool: `list_skills`

The existing `list_skills` tool now supports persona filtering via the `persona` parameter.

**Example:**
```python
mcp__tmws__list_skills(
    agent_id="aurora-researcher",
    persona="artemis-optimizer",  # NEW: Filter by persona
    limit=20
)
```

---

## API Reference

### PersonaMarkdownParser

**Module:** `src/utils/persona_markdown_parser.py`

Parses persona Markdown files and extracts structured metadata.

#### Key Classes

**`ParsedPersona`** (dataclass)
```python
@dataclass
class ParsedPersona:
    agent_id: str              # Persona identifier (e.g., "athena-conductor")
    name: str                  # Display name (e.g., "Athena")
    display_name: str          # Full title line
    emoji: str                 # Unicode emoji (e.g., "🏛️")
    role: str                  # Role from frontmatter
    tier: str                  # Tier (ORCHESTRATOR, STRATEGIC, SPECIALIST, SUPPORT)
    version: str               # Semantic version
    partner: str | None        # Optional partner persona
    identity: str              # Identity section content
    markdown_source: str       # Full Markdown content
    frontmatter: dict          # All frontmatter key-value pairs
```

**`PersonaMarkdownParser`**
```python
class PersonaMarkdownParser:
    def parse_file(self, file_path: Path) -> ParsedPersona:
        """Parse a persona Markdown file from disk."""

    def parse_content(self, content: str) -> ParsedPersona:
        """Parse persona Markdown content string."""

    def extract_frontmatter(self, content: str) -> dict:
        """Extract YAML-like frontmatter between --- markers."""

    def extract_emoji(self, title: str) -> str:
        """Extract emoji from title line."""

    def extract_name(self, title: str) -> str:
        """Extract persona name from title."""
```

#### Usage Example

```python
from pathlib import Path
from src.utils.persona_markdown_parser import PersonaMarkdownParser

parser = PersonaMarkdownParser()

# Parse from file
persona = parser.parse_file(Path("agents/athena-conductor.md"))

print(persona.name)         # "Athena"
print(persona.emoji)        # "🏛️"
print(persona.tier)         # "STRATEGIC"
print(persona.role)         # "Conductor"

# Parse from string
content = """---
agent_id: "test-persona"
role: "Tester"
tier: "SPECIALIST"
---
# Test Persona 🧪 - Automated Tester
"""
persona = parser.parse_content(content)
```

---

### PersonaLoader

**Module:** `src/services/persona_loader.py`

Service to load persona Markdown files into the database.

#### Key Methods

**`load_persona_from_file(file_path: Path)`**

Load a single persona from Markdown file.

```python
from src.services.persona_loader import PersonaLoader

async with get_db_session() as session:
    loader = PersonaLoader(session)

    result = await loader.load_persona_from_file(
        Path("dist-config/claudecode/agents/athena-conductor.md")
    )

    print(result)
    # {
    #     "success": True,
    #     "action": "created",
    #     "persona_id": "uuid-...",
    #     "name": "Athena",
    #     "message": "Created persona 'Athena' from athena-conductor.md"
    # }
```

**`load_all_personas(directory: Path)`**

Load all `.md` files from a directory.

```python
results = await loader.load_all_personas(
    Path("dist-config/claudecode/agents")
)

for result in results:
    if result["success"]:
        print(f"{result['action']}: {result['name']}")
```

**`sync_personas(directory: Path)`**

Sync personas from directory - create new, update existing.

```python
summary = await loader.sync_personas(
    Path("dist-config/claudecode/agents")
)

print(summary)
# {
#     "total": 11,
#     "created": 10,
#     "updated": 1,
#     "errors": 0,
#     "results": [...]
# }
```

#### Error Handling

```python
try:
    result = await loader.load_persona_from_file(path)
except FileNotFoundError:
    # File doesn't exist
except ValidationError:
    # Invalid frontmatter or parsing error
```

---

### Updated Enums

**Module:** `src/models/persona.py`

#### PersonaType

Now supports all 11 Trinitas personas:

```python
class PersonaType(str, Enum):
    # Orchestrators (Tier 0)
    CLOTHO = "clotho"          # Thread Weaver - Workflow orchestration
    LACHESIS = "lachesis"      # Measure Keeper - Resource allocation

    # Strategic (Tier 1)
    ATHENA = "athena"          # Harmonious Conductor
    HERA = "hera"              # Strategic Commander

    # Specialist (Tier 2)
    ARTEMIS = "artemis"        # Technical Perfectionist
    HESTIA = "hestia"          # Security Guardian
    ERIS = "eris"              # Tactical Coordinator
    MUSES = "muses"            # Knowledge Architect

    # Support (Tier 3)
    APHRODITE = "aphrodite"    # UI/UX Designer
    METIS = "metis"            # Development Assistant
    AURORA = "aurora"          # Research Assistant

    # Legacy (backward compatibility)
    BELLONA = "bellona"        # Deprecated: use ERIS
    SESHAT = "seshat"          # Deprecated: use MUSES
```

#### PersonaRole

Role mapping for each persona:

```python
class PersonaRole(str, Enum):
    # Orchestrator roles (Tier 0)
    ORCHESTRATOR = "orchestrator"     # Clotho, Lachesis

    # Strategic roles (Tier 1)
    CONDUCTOR = "conductor"           # Athena
    STRATEGIST = "strategist"         # Hera

    # Specialist roles (Tier 2)
    OPTIMIZER = "optimizer"           # Artemis
    AUDITOR = "auditor"               # Hestia
    COORDINATOR = "coordinator"       # Eris
    DOCUMENTER = "documenter"         # Muses

    # Support roles (Tier 3)
    DESIGNER = "designer"             # Aphrodite
    DEVELOPER = "developer"           # Metis
    RESEARCHER = "researcher"         # Aurora
```

---

## Markdown File Format

Personas are defined in Markdown with YAML frontmatter:

```markdown
---
agent_id: "athena-conductor"
role: "Harmonious Conductor"
tier: "STRATEGIC"
version: "2.4.16"
specialties: "orchestration, workflow automation, resource coordination"
trigger_words: "orchestration, workflow, automation, parallel, coordination"
---

# Athena 🏛️ - Harmonious Conductor

## Core Identity

Athena is the harmonious conductor of the Trinitas system, ensuring
seamless coordination between all agents while maintaining system
balance and optimal resource allocation.

## Affordances

- **orchestrate** (50 tokens): Multi-agent workflow coordination
- **coordinate** (45 tokens): Resource allocation and task distribution
- **balance** (40 tokens): System harmony and load balancing

## Collaboration Patterns

### Optimal Partnerships
- **Primary**: Hera (strategic alignment)
- **Support**: Eris (tactical execution)
- **Handoff**: Aurora (context retrieval)
```

### Required Frontmatter Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | Yes | Unique identifier (kebab-case) |
| `role` | string | Yes | Persona role/title |
| `tier` | string | Yes | ORCHESTRATOR, STRATEGIC, SPECIALIST, SUPPORT |
| `version` | string | Yes | Semantic version (e.g., "2.4.16") |
| `specialties` | string | No | Comma-separated capabilities |
| `trigger_words` | string | No | Comma-separated activation keywords |
| `partner` | string | No | Partner persona identifier |

### Title Format

The first H1 line should follow the pattern:

```
# [Name] [Emoji] - [Role]
```

Examples:
- `# Athena 🏛️ - Harmonious Conductor`
- `# Clotho（クロト）🧵 - Main Orchestrator`
- `# Artemis 🏹 - Technical Perfectionist`

Emojis can be placed before or after the name.

---

## Integration with Existing Systems

### Database Schema

Persona data is stored in the `personas` table:

```sql
CREATE TABLE personas (
    id UUID PRIMARY KEY,
    name VARCHAR NOT NULL UNIQUE,
    type VARCHAR NOT NULL,  -- PersonaType enum value
    role VARCHAR NOT NULL,  -- PersonaRole enum value
    display_name VARCHAR,
    description TEXT,
    specialties JSON,
    tier VARCHAR,
    emoji VARCHAR,
    markdown_source TEXT,
    version VARCHAR,
    trigger_words JSON,
    config JSON,
    preferences JSON,
    is_active BOOLEAN,
    capabilities JSON,
    metadata_json JSON,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Skill Association

Skills can reference personas via the `persona` field:

```python
from src.services.skill_service import SkillService

async with get_db_session() as session:
    skill_service = SkillService(session)

    # Create skill associated with persona
    skill = await skill_service.create_skill(
        agent_id="aurora-researcher",
        name="semantic_search",
        display_name="Semantic Search",
        description="Search memories using semantic similarity",
        persona="aurora-researcher",  # Link to persona
        version="1.0.0"
    )
```

### TMWS Memory Storage

After persona import, store the operation in TMWS memory:

```python
from src.mcp_tools import store_memory

await store_memory(
    agent_id="muses-documenter",
    content="Imported 11 Trinitas personas via PersonaLoader",
    namespace="implementations",
    tags=["persona", "import", "issue-59"],
    importance=0.8
)
```

---

## Testing

### Unit Tests

Test the parser and loader:

```bash
pytest tests/unit/utils/test_persona_markdown_parser.py
pytest tests/unit/services/test_persona_loader.py
```

### Integration Tests

Test the full import workflow:

```bash
pytest tests/integration/test_persona_import.py -v
```

### Manual Validation

Verify personas in database:

```bash
python -m scripts.import_personas --dry-run --verbose
```

Check database:

```sql
SELECT name, type, role, tier, emoji
FROM personas
ORDER BY tier, name;
```

Expected result:
```
      name      |    type    |     role      |     tier      | emoji
----------------+------------+---------------+---------------+-------
 Clotho         | clotho     | orchestrator  | ORCHESTRATOR  | 🧵
 Lachesis       | lachesis   | orchestrator  | ORCHESTRATOR  | 📏
 Athena         | athena     | conductor     | STRATEGIC     | 🏛️
 Hera           | hera       | strategist    | STRATEGIC     | 🎭
 Artemis        | artemis    | optimizer     | SPECIALIST    | 🏹
 Hestia         | hestia     | auditor       | SPECIALIST    | 🔥
 Eris           | eris       | coordinator   | SPECIALIST    | ⚔️
 Muses          | muses      | documenter    | SPECIALIST    | 📚
 Aphrodite      | aphrodite  | designer      | SUPPORT       | 🌸
 Metis          | metis      | developer     | SUPPORT       | 🔧
 Aurora         | aurora     | researcher    | SUPPORT       | 🌅
```

---

## Troubleshooting

### Import Fails with "No H1 title found"

**Cause:** Markdown file is missing a title line starting with `#`

**Solution:** Add a title line:
```markdown
# Persona Name 🎭 - Role Description
```

### Import Fails with "Invalid persona tier"

**Cause:** Frontmatter `tier` field has invalid value

**Solution:** Use one of: `ORCHESTRATOR`, `STRATEGIC`, `SPECIALIST`, `SUPPORT`

### Import Shows "Would update" Instead of "Would create"

**Cause:** Persona with the same `name` already exists in database

**Solution:** This is normal behavior. The loader updates existing personas.

### Path Validation Error

**Cause:** Source path is outside project boundaries (security measure)

**Solution:** Use paths within the project root:
```bash
# ✅ Correct
python scripts/import_personas.py --source dist-config/claudecode/agents

# ❌ Wrong
python scripts/import_personas.py --source /tmp/agents
```

---

## Best Practices

### 1. Always Use Dry-Run First

Before importing, preview changes:
```bash
python scripts/import_personas.py --dry-run
```

### 2. Version Control Persona Files

Keep persona Markdown files in version control:
```bash
git add dist-config/claudecode/agents/*.md
git commit -m "feat: Update persona definitions"
```

### 3. Validate Frontmatter

Ensure all required frontmatter fields are present and valid.

### 4. Use Semantic Versioning

Update `version` field when making significant changes:
- `MAJOR.MINOR.PATCH` (e.g., `2.4.16` → `2.5.0`)

### 5. Test Before Production

Run integration tests after import:
```bash
pytest tests/integration/test_persona_import.py -v
```

### 6. Monitor Import Logs

Use verbose mode to debug issues:
```bash
python scripts/import_personas.py --verbose
```

### 7. Store Import Results in Memory

Document successful imports in TMWS:
```python
await store_memory(
    content=f"Persona import: {summary['created']} created, {summary['updated']} updated",
    namespace="operations",
    importance=0.7
)
```

---

## Future Enhancements

Potential improvements for future versions:

1. **Automatic import on file change** - Watch persona directory for changes
2. **Persona validation CLI** - Lint persona Markdown files
3. **Persona diff tool** - Compare database vs Markdown versions
4. **Bulk export** - Export database personas back to Markdown
5. **Migration tool** - Update legacy persona formats
6. **GraphQL API** - Query persona-skill relationships
7. **Persona activation tracking** - Monitor which personas are invoked most

---

## Related Documentation

- [Skill System Documentation](./SKILL_SYSTEM.md)
- [MCP Tools Reference](../api/MCP_TOOLS.md)
- [Persona Coordination Protocol](../../AGENTS.md)
- [Issue #59 Implementation](../../ISSUE_59_PHASE_2.3_IMPLEMENTATION.md)

---

## Changelog

### v2.4.16 (2025-12-11)

**Added:**
- `PersonaMarkdownParser` for structured Markdown parsing
- `PersonaLoader` service for database persistence
- `import_personas.py` CLI script with dry-run support
- `list_skills_by_persona` MCP tool
- Support for all 11 Trinitas personas in `PersonaType` enum
- Updated `PersonaRole` enum with all roles
- Path validation security (M-1 fix)

**Changed:**
- Enhanced `list_skills` to support persona filtering
- Updated persona database schema with new fields

**Security:**
- Added path traversal protection in import script
- Enforced project boundary validation

---

## TMWS Database Integration for Full Mode (Issue #61)

### Overview

Issue #61 integrates TMWS database references into Trinitas Full Mode persona invocations, enabling real-time agent status retrieval, trust score filtering, and enhanced agent recommendation capabilities.

### API Changes Summary

| Component | Method | New Parameters | Breaking Change |
|-----------|--------|----------------|-----------------|
| `AgentService` | `get_recommended_agents()` | `min_trust_score: float = 0.0` | ❌ No |
| `AgentService` | `search_agents()` | `capabilities: list[str]`, `min_trust_score: float` | ❌ No |
| `RoutingTools` | `invoke_persona()` | `include_db_status: bool = False` | ❌ No |
| MCP Tool | `get_recommended_agents` | `min_trust_score: float \| None` | ❌ No |

### Key Features

#### 1. Trust Score Integration

`get_recommended_agents()` now includes trust score in its scoring algorithm:
- Performance: 25%
- Capability matching: 35%
- Success rate: 20%
- Health score: 10%
- **Trust score: 10%** (NEW)

```python
# Example: Get high-trust agents for security tasks
agents = await agent_service.get_recommended_agents(
    task_type="security_audit",
    capabilities=["vulnerability_scanning"],
    min_trust_score=0.85  # Filter by trust
)
```

#### 2. Real-time DB Status in invoke_persona

```python
result = await invoke_persona(
    persona_id="artemis-optimizer",
    task_description="Optimize queries",
    include_db_status=True  # NEW parameter
)
# Response includes db_status with trust_score, status, health_score, etc.
```

#### 3. Enhanced Agent Search (H-1 Fix)

`search_agents()` now supports capability and trust score filtering:

```python
agents = await agent_service.search_agents(
    query="optimization",
    capabilities=["performance", "profiling"],  # NEW
    min_trust_score=0.7,  # NEW
    limit=5
)
```

### Security Hardening (M-1 Fix)

Reduced exposed fields in `invoke_persona` db_status response:
- ❌ Removed: `verification_accuracy`, `total_verifications`, `accurate_verifications`
- ✅ Retained: `trust_score`, `status`, `health_score`, `total_tasks`, `successful_tasks`

### Trust Score Guidelines

| Score Range | Reliability | Use Case |
|-------------|-------------|----------|
| 0.9-1.0 | Highly reliable | Security-critical operations |
| 0.7-0.89 | Reliable | Production workloads |
| 0.5-0.69 | Developing | Non-critical tasks |
| < 0.5 | Unproven | Development/testing only |

---

**End of Documentation**
