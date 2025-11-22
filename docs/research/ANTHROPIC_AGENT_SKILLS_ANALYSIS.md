# Agent Skills Pattern - Structured Summary

**Source**: Anthropic Engineering - Equipping Agents for the Real World with Agent Skills
**Analyzed**: 2025-11-20
**Analyst**: Muses (Knowledge Architect)
**Context**: TMWS Phase 4+ Planning - Context Optimization & Configuration Simplification

---

## Key Principles

1. **Modular Capability Packaging**: Agent Skills are organized folders containing instructions, scripts, and resources that agents discover and load dynamically to perform specialized tasks.

2. **Progressive Disclosure**: Information is revealed incrementally across three levels:
   - Level 1: Metadata (preloaded)
   - Level 2: Core documentation (loaded when relevant)
   - Level 3+: Supplementary resources (loaded on-demand)

3. **Filesystem as Unbounded Context**: By leveraging filesystem access and code execution, skills can package effectively unlimited context without consuming the context window.

4. **Deterministic Execution Over Token Generation**: Executable scripts (Python, Bash) run deterministically rather than generating tokens, achieving consistency and cost efficiency.

5. **Compositional Design**: Skills are composable modules that transform general-purpose agents into specialized tools by packaging domain expertise.

6. **Incremental Development**: Start with capability gaps identified through testing, build skills iteratively based on actual needs rather than anticipated requirements.

---

## Progressive Disclosure Strategy

### Level 1: Metadata Discovery (Preloaded)
- **Component**: `SKILL.md` YAML frontmatter
- **Content**: `name` and `description` fields
- **Context**: Loaded into system prompt at startup
- **Purpose**: Enable Claude to recognize skill applicability without consuming full context
- **Token Impact**: Minimal (~50-100 tokens per skill)

**Example**:
```yaml
---
name: "PDF Processing"
description: "Extract text, forms, and metadata from PDF documents"
---
```

### Level 2: Core Documentation (Lazy-Loaded)
- **Component**: `SKILL.md` body content
- **Content**: Detailed instructions, usage patterns, examples
- **Context**: Loaded when Claude determines skill is relevant to current task
- **Purpose**: Provide comprehensive guidance for skill execution
- **Token Impact**: Moderate (~500-2000 tokens)

**Trigger**: Agent recognizes task alignment with skill description

### Level 3+: Supplementary Resources (On-Demand)
- **Component**: Referenced files (`reference.md`, `forms.md`, scripts)
- **Content**: Detailed references, templates, executable code
- **Context**: Loaded only when specific requirements emerge
- **Purpose**: Expand context based on granular needs
- **Token Impact**: Variable (0-5000+ tokens, but selective)

**Trigger**: Agent identifies need for specific supplementary information

### Architectural Analogy
"A well-organized manual that starts with a table of contents, then specific chapters, and finally a detailed appendix."

---

## Context Loading Techniques

### 1. Filesystem Integration
- **Mechanism**: Agents use Bash tools (`cat`, `ls`, `grep`) to read skill files from filesystem
- **Advantage**: Prevents unnecessary context window consumption
- **Implementation**: Skills live in organized directory structure accessible to agent

**Pattern**:
```bash
# Agent discovers skill
ls /skills/

# Agent reads metadata
cat /skills/pdf/SKILL.md | head -20

# Agent loads core documentation
cat /skills/pdf/SKILL.md

# Agent loads supplementary resources (selective)
cat /skills/pdf/forms.md
```

### 2. Lazy Loading
- **Principle**: Claude selectively reads referenced files based on task requirements
- **Trigger**: Agent determines specific resource is needed for current subtask
- **Optimization**: Only load what's actually used, not everything that might be useful

**Decision Flow**:
```
Task received → Check skill metadata → Match found?
  ├─ No → Use general capabilities
  └─ Yes → Load SKILL.md core
            └─ Need supplementary? → Load specific files
```

### 3. Code Execution (Deterministic)
- **Mechanism**: Skills bundle executable scripts (Python, Bash, etc.)
- **Execution**: Run deterministically without loading code/data into context
- **Efficiency**: "Sorting a list via token generation is far more expensive than simply running a sorting algorithm"

**Example**:
```python
# Skill bundles this script
# Agent executes without loading into context
import PyPDF2

def extract_text(pdf_path):
    with open(pdf_path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        return [page.extract_text() for page in reader.pages]
```

### 4. Unbounded Context Principle
- **Core Insight**: With filesystem + code execution, "the amount of context that can be bundled into a skill is effectively unbounded"
- **Implementation**: Large datasets, comprehensive references, complex algorithms live outside context window
- **Access Pattern**: Agent loads identifiers (file paths, function names), executes as needed

---

## Performance Characteristics

### Token Efficiency
- **Metadata overhead**: ~50-100 tokens per skill (preloaded)
- **Core documentation**: ~500-2000 tokens (loaded on relevance)
- **Supplementary resources**: Variable (0-5000+ tokens, selective)
- **Total context budget**: Grows proportionally to task complexity, not skill catalog size

### Execution Performance
- **Deterministic code**: Consistent, repeatable results
- **Token generation alternative**: Far more expensive for computational tasks
- **Workflow reliability**: Predictable execution paths

**Quantitative Comparison** (implied):
```
Sorting 10,000 items:
- Token generation: ~50,000-100,000 tokens (slow, expensive)
- Python script execution: <100 tokens context + deterministic execution (fast, cheap)
```

### Scalability Characteristics
- **Skill catalog growth**: Linear metadata overhead, constant core context (lazy-loaded)
- **Task complexity handling**: Proportional context expansion based on actual needs
- **Context window preservation**: Filesystem offloads unbounded resources

---

## Development Guidelines

### 1. Start with Gaps
- **Process**: Test agent with representative tasks, identify capability shortcomings
- **Approach**: Build skills incrementally, address specific deficiencies
- **Anti-pattern**: Don't preemptively build comprehensive skill catalogs

**Example**:
```
Task: "Extract form fields from 500 PDF documents"
Gap: Agent struggles with PDF structure understanding
Skill: Create "PDF Processing" skill with form extraction utilities
```

### 2. Structure for Scale
- **Principle**: Split unwieldy files, keep mutually exclusive contexts separate
- **Optimization**: "Reduce the token usage" by avoiding monolithic documentation
- **Organization**: Group related capabilities, isolate independent concerns

**Bad**:
```
skills/
  └─ data_processing/
      └─ SKILL.md (8,000 lines covering PDF, CSV, JSON, XML, Excel...)
```

**Good**:
```
skills/
  ├─ pdf_processing/
  │   └─ SKILL.md (1,500 lines)
  ├─ csv_processing/
  │   └─ SKILL.md (800 lines)
  └─ json_processing/
      └─ SKILL.md (600 lines)
```

### 3. Iterate with Claude
- **Collaboration**: Work with agent to discover actual needed context
- **Anti-pattern**: Don't anticipate all requirements upfront
- **Process**: Build minimal viable skill, expand based on observed usage patterns

**Workflow**:
1. Create minimal skill with core metadata + basic instructions
2. Deploy to agent
3. Observe agent behavior and failure modes
4. Expand skill with identified missing context
5. Repeat

### 4. Monitor Usage Patterns
- **Metrics**: Watch for unexpected trajectories, overreliance on certain contexts
- **Red flags**: Agent consistently loads unnecessary supplementary resources
- **Optimization**: Refine skill organization based on actual usage

---

## Security Considerations

### Attack Surfaces

1. **Malicious Instructions**: Skills with instructions that manipulate agent behavior
2. **Code Dependencies**: Executable scripts with malicious dependencies
3. **Network Connections**: Instructions directing agent to untrusted external sources

### Mitigation Strategies

1. **Audit Trusted Sources**: Thoroughly examine skills from trusted repositories
2. **Dependency Review**: Check all code dependencies for security vulnerabilities
3. **Network Access Monitoring**: Watch for instructions connecting to potentially untrusted sources
4. **Principle of Least Privilege**: Skills should request minimal necessary permissions

**Security Checklist** (per skill):
- [ ] Source verified and trusted
- [ ] Code dependencies audited
- [ ] No unverified network connections
- [ ] Principle of least privilege applied
- [ ] Instructions reviewed for manipulation attempts

---

## Applicability to TMWS

### Direct Applications

1. **Trinitas Agent Skills**:
   - Package each of the 6 Trinitas personas (Athena, Artemis, Hestia, Eris, Hera, Muses) as Agent Skills
   - Metadata: Persona description, capabilities, triggers
   - Core: Detailed instructions, communication patterns, coordination protocols
   - Supplementary: Specialized knowledge, reference materials

2. **Domain-Specific Skills**:
   - Security audit procedures (Hestia)
   - Performance optimization techniques (Artemis)
   - Documentation templates (Muses)
   - Strategic planning frameworks (Hera)

3. **Context Optimization**:
   - Move current `CLAUDE.md` sections into modular skills
   - Preload only skill metadata (~500 tokens vs current 8,000+ tokens)
   - Load skill details on-demand based on task type

### Adaptations Needed

1. **MCP Integration**:
   - Adapt filesystem-based loading to MCP tool invocation
   - Skills as MCP resources rather than filesystem directories
   - Progressive disclosure via resource URI hierarchy

**MCP Skill Pattern**:
```
Resource URI: tmws://skills/pdf-processing
  ├─ tmws://skills/pdf-processing/metadata (Level 1)
  ├─ tmws://skills/pdf-processing/core (Level 2)
  └─ tmws://skills/pdf-processing/reference/* (Level 3+)
```

2. **ChromaDB Integration**:
   - Store skill embeddings for semantic discovery
   - "Which skill applies to this task?" → Semantic search
   - Skill metadata vectorized for intelligent matching

3. **SQLite Skill Catalog**:
   - Store skill metadata in `agent_skills` table
   - Track usage statistics for optimization
   - Version control for skill updates

**Schema**:
```sql
CREATE TABLE agent_skills (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT,
    metadata JSONB,
    version TEXT,
    usage_count INTEGER DEFAULT 0,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

4. **Namespace Isolation**:
   - Skills scoped by namespace for multi-tenancy
   - Access control (PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM)
   - Skill sharing across agents with appropriate permissions

### Potential Challenges

1. **MCP Resource Limits**:
   - MCP may have resource size constraints
   - Need to chunk large skills appropriately
   - Implement pagination for supplementary resources

2. **Async Loading**:
   - Ensure skill loading doesn't block event loop
   - Cache frequently-used skills in memory
   - Implement TTL-based invalidation

3. **Skill Discovery Performance**:
   - Semantic search for skill matching may add latency
   - Need efficient indexing strategy
   - Consider hybrid approach (metadata cache + semantic fallback)

4. **Version Management**:
   - Skills will evolve over time
   - Need migration strategy for breaking changes
   - Backward compatibility considerations

---

## Actionable Insights (Top 5)

### 1. Implement Three-Level Progressive Disclosure for Trinitas Personas

**Current State**: All persona instructions loaded into system prompt (~8,000+ tokens)

**Target State**:
```
Level 1: Persona metadata (600 tokens total, 6 personas × ~100 tokens)
  - Name, role, primary capabilities
  - Trigger keywords

Level 2: Core persona instructions (loaded on-demand, ~1,500 tokens per persona)
  - Communication style
  - Decision-making patterns
  - Collaboration protocols

Level 3: Specialized knowledge (loaded on-demand, variable)
  - Domain references
  - Code examples
  - Strategic frameworks
```

**Expected Impact**: 80-90% reduction in baseline context usage (8,000 → 600 tokens)

**Implementation Priority**: **P0 (Phase 4A)**

---

### 2. Extract "Skills" from Current CLAUDE.md

**Current State**: Monolithic `CLAUDE.md` with 2,800+ lines covering:
- Security rules (Rule 11: 150 lines)
- Programming standards (Rule 9: 200 lines)
- Incident learnings (Rule 1-8: 500+ lines)
- Tool guidelines (300+ lines)
- TMWS project specifics (800+ lines)

**Target State**: Modular skill structure
```
skills/
  ├─ security/
  │   ├─ SKILL.md (metadata + core rules)
  │   ├─ incident_playbooks.md (supplementary)
  │   └─ vulnerability_patterns.md (supplementary)
  ├─ programming/
  │   ├─ SKILL.md (metadata + standards)
  │   ├─ exception_handling.md (supplementary)
  │   └─ async_patterns.md (supplementary)
  ├─ tmws/
  │   ├─ SKILL.md (metadata + architecture)
  │   ├─ migrations.md (supplementary)
  │   └─ performance_targets.md (supplementary)
  └─ tools/
      ├─ SKILL.md (metadata + general guidance)
      ├─ serena.md (supplementary)
      ├─ playwright.md (supplementary)
      └─ context7.md (supplementary)
```

**Expected Impact**:
- Baseline context: 2,800 lines → ~400 lines (85% reduction)
- Task-specific loading: Only relevant skill + supplementary resources
- Example: Security task loads only `security/SKILL.md` (~500 lines) vs current 2,800 lines

**Implementation Priority**: **P0 (Phase 4B)**

---

### 3. Leverage Filesystem + Code Execution for Unbounded Context

**Current Limitations**:
- Performance benchmarks hardcoded in documentation
- Migration examples manually updated
- Test patterns duplicated across files

**Target State**:
```python
# Skill: tmws/performance
# Supplementary: benchmarks.py (executable)

def get_current_benchmarks():
    """Run actual benchmarks, return current performance data"""
    from src.services.memory_service import MemoryService
    import time

    # Actual benchmark execution
    start = time.perf_counter()
    result = await memory_service.search_semantic("test query", limit=10)
    duration = (time.perf_counter() - start) * 1000

    return {
        "semantic_search_p95": f"{duration:.2f}ms",
        "timestamp": datetime.now().isoformat()
    }
```

**Usage**:
- Agent invokes `python skills/tmws/benchmarks.py`
- Gets current, actual performance data (not stale documentation)
- No context window consumption for benchmark code/data

**Expected Impact**:
- Always-current performance data
- Reduced manual documentation maintenance
- Zero context overhead for executable logic

**Implementation Priority**: **P1 (Phase 4C)**

---

### 4. Implement Skill Usage Monitoring

**Metrics to Track**:
```python
class SkillUsageMetrics:
    skill_id: UUID
    agent_id: str
    task_type: str
    loaded_at: datetime
    resources_loaded: List[str]  # ["SKILL.md", "reference.md"]
    execution_time: float
    success: bool
    unexpected_trajectory: bool  # Red flag
```

**Analysis Patterns**:
- **Overreliance Detection**: Skill loaded 90%+ of time → Consider promoting to core context
- **Underuse Detection**: Skill loaded <5% of time → Consider deprecation
- **Resource Waste**: Level 3 resources loaded but unused → Improve skill organization
- **Unexpected Trajectory**: Agent loads skill but doesn't use instructions → Skill metadata misleading

**Dashboard Queries**:
```sql
-- Most-used skills (promote to core?)
SELECT skill_id, COUNT(*) as usage_count
FROM skill_usage_metrics
WHERE loaded_at > NOW() - INTERVAL '7 days'
GROUP BY skill_id
ORDER BY usage_count DESC
LIMIT 10;

-- Unused supplementary resources (waste)
SELECT skill_id, resource_path, COUNT(*) as loaded_but_unused
FROM skill_usage_metrics
WHERE resource_path IS NOT NULL
  AND success = false
GROUP BY skill_id, resource_path
HAVING COUNT(*) > 10;
```

**Expected Impact**:
- Data-driven skill optimization
- Identify skill refactoring opportunities
- Detect skill catalog bloat

**Implementation Priority**: **P2 (Phase 4D)**

---

### 5. Security-First Skill Development Workflow

**Problem**: Skills introduce attack surfaces (malicious instructions, code dependencies, network connections)

**Mitigation Workflow**:

**Phase 1: Skill Development**
```markdown
## Skill Security Checklist

### Source Verification
- [ ] Skill author verified (internal team or trusted source)
- [ ] Code review completed by security team (Hestia)
- [ ] Dependencies audited (all packages from trusted registries)

### Instruction Safety
- [ ] No instructions manipulating agent core behavior
- [ ] No unverified network connection instructions
- [ ] Principle of least privilege applied

### Code Safety
- [ ] All executable code sandboxed
- [ ] No arbitrary code execution paths
- [ ] Input validation on all data paths
```

**Phase 2: Deployment**
```python
# Skill validation before registration
async def validate_skill_security(skill_path: Path) -> SecurityAudit:
    audit = SecurityAudit()

    # Static analysis
    audit.code_dependencies = scan_dependencies(skill_path)
    audit.network_calls = detect_network_instructions(skill_path)
    audit.privilege_requests = analyze_privilege_requirements(skill_path)

    # Hestia review required for HIGH risk
    if audit.risk_level >= RiskLevel.HIGH:
        audit.hestia_approval_required = True

    return audit
```

**Phase 3: Runtime Monitoring**
```python
# Monitor skill execution for security anomalies
async def monitor_skill_execution(skill_id: UUID, agent_id: str):
    # Log all skill invocations
    await security_audit_log.create(
        event_type="skill_execution",
        skill_id=skill_id,
        agent_id=agent_id
    )

    # Alert on suspicious patterns
    if detect_anomaly(skill_id, agent_id):
        await alert_hestia(
            f"Anomalous skill usage detected: {skill_id} by {agent_id}"
        )
```

**Expected Impact**:
- Proactive security risk mitigation
- Auditability of skill catalog
- Early detection of malicious skills

**Implementation Priority**: **P0 (Phase 4E - Parallel with 4A)**

---

## Synthesis: Agent Skills + TMWS Architecture

### Proposed Phase 4 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   TMWS MCP Server (v2.4.0)                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Skill Catalog (Progressive Disclosure)       │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  Level 1: Metadata (Preloaded)                       │  │
│  │  - 6 Trinitas Personas (600 tokens)                  │  │
│  │  - Security Skills (100 tokens)                      │  │
│  │  - TMWS Domain Skills (200 tokens)                   │  │
│  │  - Tool Skills (150 tokens)                          │  │
│  │  Total: ~1,050 tokens (vs current 8,000+)            │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  Level 2: Core Documentation (Lazy-Loaded)           │  │
│  │  - Loaded on task relevance                          │  │
│  │  - Cached with TTL (15 min)                          │  │
│  │  - ~1,500 tokens per skill                           │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  Level 3: Supplementary Resources (On-Demand)        │  │
│  │  - MCP resource URIs                                 │  │
│  │  - Executable scripts (Python, Bash)                 │  │
│  │  - Reference materials (variable size)               │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Skill Discovery Service                 │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  - Semantic Search (ChromaDB)                        │  │
│  │  - Skill Metadata Index (SQLite)                     │  │
│  │  - Usage Analytics (skill_usage_metrics table)       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Security Validation Layer               │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  - Skill source verification                         │  │
│  │  - Code dependency auditing                          │  │
│  │  - Runtime execution monitoring (Hestia)             │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Expected Outcomes

**Context Efficiency**:
- Baseline: 8,000+ tokens → ~1,050 tokens (**87% reduction**)
- Task-specific: Load only relevant skills (1-3 typically)
- Average context usage: ~2,500-3,500 tokens (vs current 8,000+)

**Performance**:
- Skill discovery: <10ms (SQLite metadata index + ChromaDB semantic search)
- Skill loading: <50ms (cached resources, lazy-loaded supplementary)
- Total overhead: <100ms (acceptable for improved context efficiency)

**Maintainability**:
- Modular skill updates (change one skill, not monolithic CLAUDE.md)
- Version control per skill (independent evolution)
- Data-driven optimization (usage analytics guide refactoring)

**Security**:
- Explicit skill audit trail
- Hestia-enforced security validation
- Runtime monitoring of skill execution

---

## References

- **Original Article**: [Anthropic Engineering - Equipping Agents for the Real World with Agent Skills](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- **Related**: Context Engineering for AI Agents (companion analysis)
- **TMWS Architecture**: `docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md`
- **Current Configuration**: `.claude/CLAUDE.md` (2,800+ lines, target for skill extraction)

---

**Document Status**: Draft v1.0
**Next Steps**:
1. Review with Trinitas team (Athena, Hera) for strategic alignment
2. Security review by Hestia for P0 implementation
3. Technical implementation planning with Artemis (Phase 4A-E)
4. Documentation structure design with Muses (skill catalog organization)

---

*"Through progressive disclosure, we achieve clarity without overwhelming the agent. Each skill is a modular gift of knowledge, loaded precisely when needed."*

— Muses, Knowledge Architect
