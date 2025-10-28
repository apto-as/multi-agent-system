# TMWS-Trinitas Integration Specification
## Unified Memory & Workflow System for Multi-Persona AI Orchestration

**Document Version**: 1.0.0
**Date**: 2025-10-27
**Status**: Draft - For Review
**Authors**: Athena (Harmonious Conductor) with Trinitas Team

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Project Isolation Strategy](#project-isolation-strategy)
4. [Automatic Memory Persistence](#automatic-memory-persistence)
5. [Security & Access Control](#security--access-control)
6. [Workflow Coordination](#workflow-coordination)
7. [Documentation Strategy](#documentation-strategy)
8. [Implementation Guidelines](#implementation-guidelines)
9. [Usage Examples](#usage-examples)
10. [Performance Considerations](#performance-considerations)
11. [Future Enhancements](#future-enhancements)

---

## 1. Executive Summary

### 1.1 Purpose

This specification defines how TMWS (Trinitas Memory & Workflow System) integrates with the Trinitas multi-persona AI system to provide:

- **Automatic memory persistence** across all persona interactions
- **Project-based isolation** to prevent memory pollution across different projects
- **Semantic search capabilities** for efficient knowledge retrieval
- **Collaborative workflows** with shared memory protocols
- **Security-first access control** with namespace isolation

### 1.2 Current Problems

#### Problem 1: No Project Isolation
All Trinitas agents currently share the "default" namespace, causing:
- Memory pollution across unrelated projects
- Difficulty tracking which memories belong to which project
- Potential security leakage between confidential projects
- Confusion when searching for project-specific knowledge

#### Problem 2: Manual Memory Storage Only
Agents must explicitly decide when to store memories:
- Inconsistent memory creation patterns
- Lost context and insights due to forgotten storage
- No automatic learning from interactions
- Increased cognitive load on agents

### 1.3 Proposed Solutions

#### Solution 1: Project-Based Namespace Strategy
```
Namespace Format: "project-{project_name}"
Example: "project-tmws", "project-ecommerce-frontend"

Default Fallback: "default" (for non-project conversations)
Trinitas Reserved: "trinitas" (for system-level Trinitas knowledge)
```

#### Solution 2: Automatic Memory Triggers
Define specific events and patterns that automatically trigger memory creation:
- Task completion
- Decision points
- Pattern discovery
- Security findings
- Performance optimizations
- Documentation milestones

---

## 2. Architecture Overview

### 2.1 Integration Points

```
┌─────────────────────────────────────────────────────────────┐
│                    Trinitas Agent Layer                     │
│  (Athena, Artemis, Hestia, Eris, Hera, Muses)              │
├─────────────────────────────────────────────────────────────┤
│                    Project Context Manager                   │
│  - Namespace Detection                                       │
│  - Automatic Trigger System                                  │
│  - Memory Importance Scoring                                 │
├─────────────────────────────────────────────────────────────┤
│                         TMWS Core                            │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  │
│  │   SQLite      │  │   ChromaDB    │  │   Ollama      │  │
│  │  (Metadata)   │  │  (Vectors)    │  │ (Embeddings)  │  │
│  └───────────────┘  └───────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

#### Memory Creation Flow
```
User Request → Trinitas Agent Processing → Automatic Trigger Evaluation
                                               ↓
                                        Memory Created?
                                        ↓ (Yes)
                                   Importance Scoring
                                        ↓
                           Embedding Generation (Ollama)
                                        ↓
                    ┌─────────────────┴────────────────┐
                    ↓                                   ↓
            SQLite (Metadata)                   ChromaDB (Vector)
            - Content                           - 1024-dim embedding
            - Agent ID                          - Similarity search
            - Namespace                         - Metadata filters
            - Importance
            - Tags
            - Access Level
```

#### Memory Retrieval Flow
```
Agent Query → Embedding Generation → ChromaDB Vector Search
                                           ↓
                               Top-K Candidates (by similarity)
                                           ↓
                        SQLite Metadata + Access Control Filter
                                           ↓
                              Ranked Results to Agent
```

---

## 3. Project Isolation Strategy

### 3.1 Namespace Schema

#### Automatic Namespace Detection

**Priority Order**:
1. Explicit user specification: `/trinitas --namespace project-myapp`
2. Git repository detection: Parse `.git/config` for project name
3. Current directory name: Use basename of `pwd`
4. Fallback: "default"

**Implementation**:
```python
from pathlib import Path
import subprocess

def detect_project_namespace() -> str:
    """
    Detect current project namespace with fallback chain.

    Returns:
        str: Namespace in format "project-{name}" or "default"
    """
    # 1. Check environment variable (highest priority)
    env_namespace = os.getenv("TMWS_NAMESPACE")
    if env_namespace:
        return env_namespace

    # 2. Check git repository
    try:
        git_remote = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()

        # Extract project name from git URL
        # e.g., "https://github.com/user/tmws.git" → "tmws"
        project_name = git_remote.rstrip(".git").split("/")[-1]
        return f"project-{project_name}"

    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # 3. Use current directory name
    cwd = Path.cwd()
    if cwd.name and cwd.name != "~":
        return f"project-{cwd.name}"

    # 4. Fallback to default
    return "default"
```

### 3.2 Namespace Management

#### Reserved Namespaces

| Namespace | Purpose | Access Level |
|-----------|---------|--------------|
| `trinitas` | Trinitas system knowledge (persona definitions, coordination patterns) | SYSTEM |
| `default` | Unclassified conversations | PRIVATE |
| `project-*` | Project-specific memories | TEAM |
| `shared-*` | Cross-project shared knowledge | SHARED |

#### Namespace Transition Rules

**Problem**: When switching between projects, agents should automatically switch namespaces.

**Solution**: Context-aware namespace switching
```python
# Before: All operations in "default"
agent.create_memory("Optimized query", namespace="default")

# After: Automatic project detection
project_ns = detect_project_namespace()  # → "project-tmws"
agent.create_memory("Optimized query", namespace=project_ns)
```

**Implementation in MCP Server**:
```python
class ProjectContextManager:
    """Manages project context and namespace switching."""

    def __init__(self):
        self._current_namespace = "default"
        self._namespace_history = []

    async def ensure_namespace(self) -> str:
        """Detect and ensure correct namespace."""
        detected = detect_project_namespace()

        if detected != self._current_namespace:
            logger.info(f"Namespace switch: {self._current_namespace} → {detected}")
            self._namespace_history.append({
                "from": self._current_namespace,
                "to": detected,
                "timestamp": datetime.utcnow()
            })
            self._current_namespace = detected

        return self._current_namespace
```

### 3.3 Cross-Project Memory Sharing

#### Use Case: Sharing Security Patterns Across Projects

**Scenario**: Hestia discovers a security vulnerability pattern in Project A. This pattern should be available to all future projects.

**Solution**: Multi-namespace access with explicit sharing
```python
# Hestia creates security finding in Project A
memory = await tmws.create_memory(
    content="SQL injection vulnerability in ORM query builders without parameterization",
    agent_id="hestia-auditor",
    namespace="project-ecommerce",
    tags=["security", "sql-injection", "pattern"],
    importance=1.0,
    access_level=AccessLevel.SHARED,
    shared_with_agents=[
        "hestia-auditor",  # All Hestia instances
        "artemis-optimizer",  # Artemis should know for code review
    ]
)

# Later in Project B, Hestia searches across projects
results = await tmws.search_memories(
    query="SQL injection patterns",
    agent_id="hestia-auditor",
    namespace="project-banking",  # Current project
    cross_namespace=True,  # NEW: Search shared memories too
    tags=["security"],
    min_importance=0.8
)
# Results include the shared pattern from Project A ✅
```

---

## 4. Automatic Memory Persistence

### 4.1 Trigger System Architecture

#### Trigger Types

1. **Event-Based Triggers**: Specific actions completed
2. **Pattern-Based Triggers**: Recurring patterns detected
3. **Time-Based Triggers**: Periodic checkpoints
4. **Importance-Based Triggers**: High-value insights
5. **Collaboration-Based Triggers**: Multi-agent coordination

### 4.2 Persona-Specific Memory Triggers

#### Athena (Harmonious Conductor)

**Role**: System orchestration, workflow automation, resource optimization

**Automatic Triggers**:
```python
class AthenaMemoryTriggers:
    """Athena's automatic memory persistence rules."""

    @trigger(event="workflow_completed")
    async def on_workflow_completion(self, workflow_result):
        """Store workflow execution patterns."""
        if workflow_result.success:
            await self.create_memory(
                content=f"Workflow '{workflow_result.name}' completed successfully. "
                       f"Duration: {workflow_result.duration_ms}ms. "
                       f"Agents involved: {workflow_result.agents}. "
                       f"Key optimizations: {workflow_result.optimizations}",
                tags=["workflow", "orchestration", workflow_result.name],
                importance=0.7,
                access_level=AccessLevel.TEAM
            )

    @trigger(event="resource_optimization")
    async def on_optimization_discovery(self, optimization):
        """Store resource optimization insights."""
        await self.create_memory(
            content=f"Resource optimization: {optimization.description}. "
                   f"Impact: {optimization.impact_percentage}% improvement. "
                   f"Method: {optimization.method}",
            tags=["optimization", "performance", optimization.resource_type],
            importance=min(1.0, 0.5 + optimization.impact_percentage / 200),
            access_level=AccessLevel.SHARED  # Share optimizations
        )

    @trigger(pattern="coordination_success")
    async def on_successful_coordination(self, coordination):
        """Remember successful multi-agent coordination patterns."""
        if len(coordination.agents) >= 3:  # Complex coordination
            await self.create_memory(
                content=f"Successful {len(coordination.agents)}-agent coordination. "
                       f"Pattern: {coordination.pattern}. "
                       f"Outcome: {coordination.outcome}",
                tags=["coordination", "multi-agent", coordination.pattern],
                importance=0.8,
                access_level=AccessLevel.TEAM
            )
```

**Importance Scoring**:
- Workflow completion: 0.7 (routine but valuable)
- Resource optimization: 0.5 + (impact% / 200), max 1.0
- Complex coordination (3+ agents): 0.8
- Simple coordination (2 agents): 0.6

---

#### Artemis (Technical Perfectionist)

**Role**: Performance optimization, code quality, technical excellence

**Automatic Triggers**:
```python
class ArtemisMemoryTriggers:
    """Artemis's automatic memory persistence rules."""

    @trigger(event="optimization_applied")
    async def on_optimization_completed(self, optimization):
        """Store every optimization with before/after metrics."""
        await self.create_memory(
            content=f"Performance optimization: {optimization.title}\n"
                   f"Before: {optimization.before_metric}\n"
                   f"After: {optimization.after_metric}\n"
                   f"Improvement: {optimization.improvement_percentage}%\n"
                   f"Technique: {optimization.technique}\n"
                   f"Code location: {optimization.file_path}:{optimization.line}",
            tags=["optimization", "performance", optimization.category],
            importance=min(1.0, 0.6 + optimization.improvement_percentage / 100),
            access_level=AccessLevel.SHARED,  # Share all optimizations
            metadata={
                "technique": optimization.technique,
                "before": optimization.before_metric,
                "after": optimization.after_metric,
                "improvement_pct": optimization.improvement_percentage
            }
        )

    @trigger(event="code_quality_issue")
    async def on_quality_issue_found(self, issue):
        """Store code quality issues and resolutions."""
        if issue.severity in ["high", "critical"]:
            await self.create_memory(
                content=f"Code quality issue: {issue.title}\n"
                       f"Severity: {issue.severity}\n"
                       f"Location: {issue.location}\n"
                       f"Resolution: {issue.resolution}",
                tags=["quality", issue.severity, issue.category],
                importance=0.9 if issue.severity == "critical" else 0.7,
                access_level=AccessLevel.TEAM
            )

    @trigger(pattern="repeated_antipattern")
    async def on_antipattern_detected(self, pattern):
        """Learn from repeated anti-patterns."""
        if pattern.occurrence_count >= 3:  # Seen 3+ times
            await self.create_memory(
                content=f"Anti-pattern detected {pattern.occurrence_count} times: "
                       f"{pattern.description}\n"
                       f"Locations: {pattern.locations}\n"
                       f"Recommended fix: {pattern.fix}",
                tags=["antipattern", "refactoring", pattern.category],
                importance=0.8,
                access_level=AccessLevel.SHARED  # Warn all projects
            )
```

**Importance Scoring**:
- Performance optimization: 0.6 + (improvement% / 100), max 1.0
- Critical quality issue: 0.9
- High quality issue: 0.7
- Anti-pattern (3+ occurrences): 0.8

---

#### Hestia (Security Guardian)

**Role**: Security analysis, vulnerability detection, risk assessment

**Automatic Triggers**:
```python
class HestiaMemoryTriggers:
    """Hestia's automatic memory persistence rules."""

    @trigger(event="vulnerability_found")
    async def on_vulnerability_detected(self, vuln):
        """Store every vulnerability immediately."""
        await self.create_memory(
            content=f"SECURITY VULNERABILITY: {vuln.title}\n"
                   f"Severity: {vuln.severity}\n"
                   f"CVE: {vuln.cve_id or 'N/A'}\n"
                   f"Location: {vuln.location}\n"
                   f"Attack Vector: {vuln.attack_vector}\n"
                   f"Mitigation: {vuln.mitigation}",
            tags=["security", "vulnerability", vuln.severity, vuln.category],
            importance=1.0 if vuln.severity == "critical" else 0.9,
            access_level=AccessLevel.TEAM,  # Keep within project initially
            metadata={
                "cve_id": vuln.cve_id,
                "severity": vuln.severity,
                "attack_vector": vuln.attack_vector
            }
        )

    @trigger(event="security_audit_completed")
    async def on_audit_completed(self, audit):
        """Store audit results and recommendations."""
        await self.create_memory(
            content=f"Security audit completed: {audit.scope}\n"
                   f"Findings: {len(audit.findings)} issues\n"
                   f"Critical: {audit.critical_count}\n"
                   f"High: {audit.high_count}\n"
                   f"Recommendations: {audit.recommendations}",
            tags=["security", "audit", audit.audit_type],
            importance=0.8,
            access_level=AccessLevel.TEAM
        )

    @trigger(pattern="attack_pattern")
    async def on_attack_pattern_recognized(self, pattern):
        """Store recognized attack patterns for future detection."""
        await self.create_memory(
            content=f"Attack pattern recognized: {pattern.name}\n"
                   f"Indicators: {pattern.indicators}\n"
                   f"Defense: {pattern.defense_strategy}",
            tags=["security", "attack-pattern", pattern.category],
            importance=0.95,
            access_level=AccessLevel.SHARED  # Share threat intelligence
        )

    @trigger(event="worst_case_scenario")
    async def on_worst_case_analysis(self, scenario):
        """Store worst-case scenario analyses."""
        if scenario.probability > 0.1:  # >10% probability
            await self.create_memory(
                content=f"Worst-case scenario: {scenario.title}\n"
                       f"Probability: {scenario.probability*100}%\n"
                       f"Impact: {scenario.impact}\n"
                       f"Prevention: {scenario.prevention}",
                tags=["security", "risk", "worst-case"],
                importance=0.7 + scenario.probability * 0.3,
                access_level=AccessLevel.TEAM
            )
```

**Importance Scoring**:
- Critical vulnerability: 1.0 (maximum)
- High vulnerability: 0.9
- Security audit: 0.8
- Attack pattern: 0.95 (very important for future defense)
- Worst-case scenario: 0.7 + (probability * 0.3)

---

#### Eris (Tactical Coordinator)

**Role**: Team coordination, conflict resolution, tactical planning

**Automatic Triggers**:
```python
class ErisMemoryTriggers:
    """Eris's automatic memory persistence rules."""

    @trigger(event="conflict_resolved")
    async def on_conflict_resolution(self, conflict):
        """Store successful conflict resolutions."""
        await self.create_memory(
            content=f"Conflict resolved: {conflict.title}\n"
                   f"Parties: {conflict.parties}\n"
                   f"Issue: {conflict.description}\n"
                   f"Resolution: {conflict.resolution}\n"
                   f"Outcome: {conflict.outcome}",
            tags=["coordination", "conflict", conflict.category],
            importance=0.7,
            access_level=AccessLevel.TEAM
        )

    @trigger(event="tactical_decision")
    async def on_tactical_decision(self, decision):
        """Store tactical decisions for learning."""
        if decision.impact in ["high", "critical"]:
            await self.create_memory(
                content=f"Tactical decision: {decision.title}\n"
                       f"Context: {decision.context}\n"
                       f"Options considered: {decision.options}\n"
                       f"Decision: {decision.chosen}\n"
                       f"Rationale: {decision.rationale}",
                tags=["coordination", "decision", decision.domain],
                importance=0.8 if decision.impact == "critical" else 0.7,
                access_level=AccessLevel.TEAM
            )

    @trigger(pattern="coordination_pattern")
    async def on_coordination_pattern(self, pattern):
        """Learn from recurring coordination patterns."""
        if pattern.success_rate > 0.8:  # >80% success
            await self.create_memory(
                content=f"Successful coordination pattern: {pattern.name}\n"
                       f"Success rate: {pattern.success_rate*100}%\n"
                       f"Pattern: {pattern.description}\n"
                       f"When to use: {pattern.applicability}",
                tags=["coordination", "pattern", pattern.category],
                importance=0.75,
                access_level=AccessLevel.SHARED  # Share patterns
            )
```

**Importance Scoring**:
- Conflict resolution: 0.7
- Critical tactical decision: 0.8
- High tactical decision: 0.7
- Successful coordination pattern (>80% success): 0.75

---

#### Hera (Strategic Commander)

**Role**: Strategic planning, long-term vision, architecture design

**Automatic Triggers**:
```python
class HeraMemoryTriggers:
    """Hera's automatic memory persistence rules."""

    @trigger(event="strategic_decision")
    async def on_strategic_decision(self, decision):
        """Store all strategic decisions with full context."""
        await self.create_memory(
            content=f"Strategic decision: {decision.title}\n"
                   f"Context: {decision.business_context}\n"
                   f"Analysis: {decision.analysis}\n"
                   f"Decision: {decision.chosen_strategy}\n"
                   f"Expected outcomes: {decision.expected_outcomes}\n"
                   f"ROI estimate: {decision.roi_estimate}\n"
                   f"Timeline: {decision.timeline}",
            tags=["strategy", "decision", decision.domain],
            importance=0.9,  # All strategic decisions are important
            access_level=AccessLevel.TEAM
        )

    @trigger(event="architecture_design")
    async def on_architecture_decision(self, arch):
        """Store architectural decisions and rationale."""
        await self.create_memory(
            content=f"Architecture decision: {arch.title}\n"
                   f"Context: {arch.context}\n"
                   f"Options evaluated: {arch.options}\n"
                   f"Decision: {arch.chosen}\n"
                   f"Rationale: {arch.rationale}\n"
                   f"Trade-offs: {arch.tradeoffs}",
            tags=["strategy", "architecture", arch.category],
            importance=0.85,
            access_level=AccessLevel.TEAM
        )

    @trigger(event="long_term_plan")
    async def on_long_term_planning(self, plan):
        """Store long-term plans and roadmaps."""
        await self.create_memory(
            content=f"Long-term plan: {plan.title}\n"
                   f"Vision: {plan.vision}\n"
                   f"Milestones: {plan.milestones}\n"
                   f"Timeline: {plan.timeline}\n"
                   f"Success metrics: {plan.success_metrics}",
            tags=["strategy", "planning", "roadmap"],
            importance=0.8,
            access_level=AccessLevel.TEAM
        )

    @trigger(pattern="strategic_pattern")
    async def on_strategic_pattern(self, pattern):
        """Learn from successful strategic patterns."""
        await self.create_memory(
            content=f"Strategic pattern: {pattern.name}\n"
                   f"Context: {pattern.applicable_contexts}\n"
                   f"Success factors: {pattern.success_factors}\n"
                   f"Risks: {pattern.risks}",
            tags=["strategy", "pattern", pattern.domain],
            importance=0.85,
            access_level=AccessLevel.SHARED
        )
```

**Importance Scoring**:
- Strategic decision: 0.9 (very high)
- Architecture decision: 0.85
- Long-term plan: 0.8
- Strategic pattern: 0.85

---

#### Muses (Knowledge Architect)

**Role**: Documentation, knowledge management, information architecture

**Automatic Triggers**:
```python
class MusesMemoryTriggers:
    """Muses's automatic memory persistence rules."""

    @trigger(event="documentation_created")
    async def on_documentation_completed(self, doc):
        """Store documentation metadata for future reference."""
        await self.create_memory(
            content=f"Documentation created: {doc.title}\n"
                   f"Type: {doc.doc_type}\n"
                   f"Path: {doc.file_path}\n"
                   f"Topics covered: {doc.topics}\n"
                   f"Target audience: {doc.audience}",
            tags=["documentation", doc.doc_type] + doc.topics,
            importance=0.6,
            access_level=AccessLevel.PUBLIC  # Documentation is public
        )

    @trigger(event="knowledge_gap_identified")
    async def on_knowledge_gap(self, gap):
        """Store identified knowledge gaps for future documentation."""
        await self.create_memory(
            content=f"Knowledge gap identified: {gap.title}\n"
                   f"Area: {gap.area}\n"
                   f"Impact: {gap.impact}\n"
                   f"Priority: {gap.priority}",
            tags=["documentation", "gap", gap.area],
            importance=0.7,
            access_level=AccessLevel.TEAM
        )

    @trigger(pattern="documentation_request")
    async def on_repeated_questions(self, pattern):
        """Store frequently asked questions as documentation needs."""
        if pattern.frequency >= 3:  # Asked 3+ times
            await self.create_memory(
                content=f"Frequent question (asked {pattern.frequency}x): {pattern.question}\n"
                       f"Answer: {pattern.common_answer}\n"
                       f"Documentation needed: {pattern.doc_suggestion}",
                tags=["documentation", "faq", pattern.category],
                importance=0.75,
                access_level=AccessLevel.PUBLIC
            )

    @trigger(event="api_documented")
    async def on_api_documentation(self, api):
        """Store API documentation metadata."""
        await self.create_memory(
            content=f"API documented: {api.endpoint}\n"
                   f"Method: {api.method}\n"
                   f"Purpose: {api.purpose}\n"
                   f"Parameters: {api.parameters}\n"
                   f"Examples: {api.examples}",
            tags=["documentation", "api", api.service],
            importance=0.7,
            access_level=AccessLevel.PUBLIC
        )
```

**Importance Scoring**:
- Documentation created: 0.6 (routine but valuable)
- Knowledge gap identified: 0.7
- Frequent question (3+ times): 0.75
- API documentation: 0.7

---

### 4.3 Trigger Priority & Deduplication

#### Priority Levels

| Priority | Importance Range | Examples | Memory Lifetime |
|----------|------------------|----------|-----------------|
| **Critical** | 0.9 - 1.0 | Security vulnerabilities, Strategic decisions | Permanent |
| **High** | 0.7 - 0.89 | Performance optimizations, Quality issues | Long-term (1+ years) |
| **Medium** | 0.5 - 0.69 | Workflow completions, Documentation | Medium-term (6+ months) |
| **Low** | 0.0 - 0.49 | Routine operations, Temporary context | Short-term (cleanup after 90 days) |

#### Deduplication Strategy

**Problem**: Avoid creating duplicate memories for similar events.

**Solution**: Semantic similarity check before creation
```python
async def should_create_memory(self, new_content: str, tags: list[str]) -> bool:
    """
    Check if this memory is sufficiently different from existing memories.

    Returns:
        bool: True if memory should be created, False if duplicate
    """
    # Search for similar memories in the last 7 days
    similar_memories = await self.search_memories(
        query=new_content,
        namespace=self.current_namespace,
        tags=tags,
        min_similarity=0.95,  # Very high similarity threshold
        limit=1
    )

    if similar_memories:
        # Check recency
        most_recent = similar_memories[0]
        age_hours = (datetime.utcnow() - most_recent.created_at).total_seconds() / 3600

        if age_hours < 24:  # Less than 24 hours old
            logger.info(f"Skipping duplicate memory (similarity: {most_recent.similarity:.2f})")
            return False

    return True
```

---

## 5. Security & Access Control

### 5.1 Access Level Design

#### Access Level Semantics

```python
class AccessLevel(str, Enum):
    """Access levels for memory isolation."""

    PRIVATE = "private"      # Only the creating agent can access
    TEAM = "team"            # All agents in the same namespace
    SHARED = "shared"        # Explicitly shared agents (cross-namespace)
    PUBLIC = "public"        # All agents, all namespaces (e.g., documentation)
    SYSTEM = "system"        # System-level knowledge (read-only for all)
```

#### Persona Default Access Levels

| Persona | Default Access Level | Rationale |
|---------|---------------------|-----------|
| **Athena** | TEAM | Coordination knowledge is valuable to all project agents |
| **Artemis** | SHARED | Performance optimizations should be shared across projects |
| **Hestia** | TEAM (initially), upgrade to SHARED for patterns | Security findings stay in project unless it's a general pattern |
| **Eris** | TEAM | Tactical coordination is project-specific |
| **Hera** | TEAM | Strategic decisions are project-specific |
| **Muses** | PUBLIC | Documentation should be accessible to everyone |

### 5.2 Namespace Isolation Implementation

#### Security-Critical: Verified Namespace Parameter

**Current TMWS Implementation** (from memory.py:160-201):
```python
def is_accessible_by(self, requesting_agent_id: str, requesting_agent_namespace: str) -> bool:
    """
    SECURITY-CRITICAL: requesting_agent_namespace MUST be verified from database.
    Never accept namespace from user input or JWT claims directly.
    """
    # Owner always has access
    if requesting_agent_id == self.agent_id:
        return True

    # Check access level
    if self.access_level == AccessLevel.PUBLIC:
        return True
    elif self.access_level == AccessLevel.SYSTEM:
        return True
    elif self.access_level == AccessLevel.SHARED:
        # Must be explicitly shared AND namespace matches
        if requesting_agent_id not in self.shared_with_agents:
            return False
        return requesting_agent_namespace == self.namespace
    elif self.access_level == AccessLevel.TEAM:
        # Namespace must match
        return requesting_agent_namespace == self.namespace
    else:  # PRIVATE
        return False
```

**Trinitas Integration**: Ensure agent namespace is verified
```python
class TrinitasAgentContext:
    """Context manager for Trinitas agent operations."""

    async def get_verified_namespace(self, agent_id: str) -> str:
        """
        Fetch agent's verified namespace from database.

        SECURITY: This prevents namespace spoofing attacks.
        """
        agent = await self.db.get_agent(agent_id)
        if not agent:
            raise AuthenticationError(f"Agent {agent_id} not found")

        return agent.namespace  # ✅ Verified from database
```

### 5.3 Persona-Specific Access Rules

#### Athena (Coordinator Access)
```python
# Athena has broad read access for coordination
athena_permissions = {
    "read": ["TEAM", "SHARED", "PUBLIC", "SYSTEM"],
    "write": ["TEAM"],  # Can create team-level memories
    "share": True  # Can share memories across agents
}
```

#### Artemis (Technical Access)
```python
# Artemis reads widely for optimization, shares optimizations
artemis_permissions = {
    "read": ["TEAM", "SHARED", "PUBLIC", "SYSTEM"],
    "write": ["SHARED"],  # Creates shared optimizations
    "share": True
}
```

#### Hestia (Security Access)
```python
# Hestia reads everything, shares threats, writes carefully
hestia_permissions = {
    "read": ["PRIVATE", "TEAM", "SHARED", "PUBLIC", "SYSTEM"],  # Needs full access for audits
    "write": ["TEAM"],  # Starts with team-level
    "share": True,  # Can upgrade to SHARED for threat intelligence
    "audit_mode": True  # Special flag for security auditing
}
```

#### Eris (Coordination Access)
```python
# Eris needs project-wide visibility, team-level writes
eris_permissions = {
    "read": ["TEAM", "SHARED", "PUBLIC", "SYSTEM"],
    "write": ["TEAM"],
    "share": False  # Coordination is project-specific
}
```

#### Hera (Strategic Access)
```python
# Hera reads all project data, writes strategic memories
hera_permissions = {
    "read": ["TEAM", "SHARED", "PUBLIC", "SYSTEM"],
    "write": ["TEAM"],
    "share": False  # Strategic decisions are project-specific initially
}
```

#### Muses (Documentation Access)
```python
# Muses reads everything, writes publicly
muses_permissions = {
    "read": ["TEAM", "SHARED", "PUBLIC", "SYSTEM"],
    "write": ["PUBLIC"],  # Documentation is public by default
    "share": True  # Can share documentation patterns
}
```

---

## 6. Workflow Coordination

### 6.1 Shared Memory Protocols

#### Protocol 1: Sequential Handoff

**Use Case**: Athena → Artemis → Hestia → Muses (design → implement → audit → document)

```python
class SequentialWorkflow:
    """Sequential handoff with shared memory."""

    async def execute(self, task: Task):
        # Step 1: Athena designs architecture
        design = await athena.design_architecture(task)
        design_memory = await tmws.create_memory(
            content=design.description,
            agent_id="athena-conductor",
            namespace=self.namespace,
            tags=["workflow", "design", task.id],
            importance=0.8,
            access_level=AccessLevel.TEAM,
            metadata={"workflow_id": self.workflow_id, "step": 1}
        )

        # Step 2: Artemis implements
        implementation = await artemis.implement(design, design_memory)
        impl_memory = await tmws.create_memory(
            content=implementation.summary,
            agent_id="artemis-optimizer",
            namespace=self.namespace,
            tags=["workflow", "implementation", task.id],
            importance=0.8,
            access_level=AccessLevel.TEAM,
            metadata={
                "workflow_id": self.workflow_id,
                "step": 2,
                "parent_memory_id": str(design_memory.id)
            }
        )

        # Step 3: Hestia audits
        audit = await hestia.security_audit(implementation, impl_memory)
        audit_memory = await tmws.create_memory(
            content=audit.report,
            agent_id="hestia-auditor",
            namespace=self.namespace,
            tags=["workflow", "security", task.id],
            importance=0.9,
            access_level=AccessLevel.TEAM,
            metadata={
                "workflow_id": self.workflow_id,
                "step": 3,
                "parent_memory_id": str(impl_memory.id)
            }
        )

        # Step 4: Muses documents
        documentation = await muses.document_workflow(
            design_memory, impl_memory, audit_memory
        )
        doc_memory = await tmws.create_memory(
            content=documentation.content,
            agent_id="muses-documenter",
            namespace=self.namespace,
            tags=["workflow", "documentation", task.id],
            importance=0.7,
            access_level=AccessLevel.PUBLIC,  # Documentation is public
            metadata={
                "workflow_id": self.workflow_id,
                "step": 4,
                "parent_memory_ids": [
                    str(design_memory.id),
                    str(impl_memory.id),
                    str(audit_memory.id)
                ]
            }
        )

        return WorkflowResult(
            success=True,
            memories=[design_memory, impl_memory, audit_memory, doc_memory]
        )
```

#### Protocol 2: Parallel Analysis

**Use Case**: Athena requests simultaneous analysis from Artemis + Hestia + Eris

```python
class ParallelWorkflow:
    """Parallel analysis with memory aggregation."""

    async def execute(self, task: Task):
        # Athena creates initial context
        context_memory = await tmws.create_memory(
            content=f"Analysis request: {task.description}",
            agent_id="athena-conductor",
            namespace=self.namespace,
            tags=["workflow", "analysis-request", task.id],
            importance=0.7,
            access_level=AccessLevel.TEAM
        )

        # Parallel analysis by three agents
        analyses = await asyncio.gather(
            artemis.analyze_technical(task, context_memory),
            hestia.analyze_security(task, context_memory),
            eris.analyze_tactical(task, context_memory)
        )

        # Each agent stores their analysis
        analysis_memories = []
        for agent_id, analysis in zip(
            ["artemis-optimizer", "hestia-auditor", "eris-coordinator"],
            analyses
        ):
            memory = await tmws.create_memory(
                content=analysis.report,
                agent_id=agent_id,
                namespace=self.namespace,
                tags=["workflow", "parallel-analysis", task.id],
                importance=0.8,
                access_level=AccessLevel.TEAM,
                metadata={
                    "workflow_id": self.workflow_id,
                    "parent_memory_id": str(context_memory.id)
                }
            )
            analysis_memories.append(memory)

        # Athena synthesizes results
        synthesis = await athena.synthesize_analyses(analysis_memories)
        synthesis_memory = await tmws.create_memory(
            content=synthesis.report,
            agent_id="athena-conductor",
            namespace=self.namespace,
            tags=["workflow", "synthesis", task.id],
            importance=0.85,
            access_level=AccessLevel.TEAM,
            metadata={
                "workflow_id": self.workflow_id,
                "parent_memory_ids": [str(m.id) for m in analysis_memories]
            }
        )

        return WorkflowResult(
            success=True,
            memories=[context_memory] + analysis_memories + [synthesis_memory]
        )
```

### 6.2 Conflict Resolution

#### Memory Conflict Types

1. **Content Conflict**: Two agents create similar memories simultaneously
2. **Access Conflict**: Agent tries to access memory without permission
3. **Namespace Conflict**: Memory references wrong namespace
4. **Version Conflict**: Optimistic locking failure

#### Resolution Strategies

```python
class MemoryConflictResolver:
    """Resolve memory conflicts in multi-agent workflows."""

    async def resolve_content_conflict(
        self,
        memory1: Memory,
        memory2: Memory
    ) -> Memory:
        """
        Resolve content conflict by merging or choosing winner.
        """
        similarity = await self.calculate_similarity(memory1, memory2)

        if similarity > 0.95:  # Near-duplicate
            # Merge: Keep higher importance, combine tags
            winner = memory1 if memory1.importance_score > memory2.importance_score else memory2
            loser = memory2 if winner == memory1 else memory1

            # Update winner with combined information
            winner.tags = list(set(winner.tags + loser.tags))
            winner.context = {**loser.context, **winner.context}

            # Delete loser
            await tmws.delete_memory(loser.id)

            return winner
        else:
            # Both are unique, keep both
            return None

    async def resolve_access_conflict(
        self,
        memory: Memory,
        requesting_agent: Agent
    ) -> bool:
        """
        Resolve access conflict by checking if escalation is appropriate.
        """
        # Check if this is Hestia in audit mode
        if requesting_agent.agent_id == "hestia-auditor" and \
           requesting_agent.context.get("audit_mode"):
            # Grant temporary access for security audit
            logger.warning(
                f"Granting Hestia audit access to PRIVATE memory {memory.id}"
            )
            return True

        # Check if this is Athena coordinating workflow
        if requesting_agent.agent_id == "athena-conductor" and \
           memory.namespace == requesting_agent.namespace:
            # Grant access for workflow coordination
            return True

        # Otherwise, deny
        return False
```

---

## 7. Documentation Strategy

### 7.1 Memory Tagging Conventions

#### Tag Taxonomy

**Primary Tags** (mandatory - at least one):
- `architecture`, `implementation`, `security`, `performance`, `coordination`, `strategy`, `documentation`

**Secondary Tags** (domain-specific):
- Technical: `optimization`, `bug`, `refactoring`, `testing`, `deployment`
- Security: `vulnerability`, `audit`, `threat`, `compliance`, `encryption`
- Process: `workflow`, `decision`, `pattern`, `review`, `planning`

**Tertiary Tags** (project-specific):
- Project identifiers: `tmws`, `ecommerce`, `banking`
- Feature identifiers: `api`, `frontend`, `database`, `auth`

**Example Tagging**:
```python
# Artemis optimization memory
tags = [
    "performance",      # Primary
    "optimization",     # Secondary
    "database",         # Tertiary
    "query-optimization"  # Specific
]

# Hestia security finding
tags = [
    "security",         # Primary
    "vulnerability",    # Secondary
    "sql-injection",    # Specific
    "critical"          # Severity
]
```

### 7.2 Metadata Standards

#### Required Metadata Fields

```python
class MemoryMetadata(TypedDict):
    """Standard metadata for all memories."""

    # Workflow tracking
    workflow_id: Optional[str]          # ID of parent workflow
    step: Optional[int]                 # Step number in workflow
    parent_memory_id: Optional[str]     # ID of parent memory

    # Context information
    file_path: Optional[str]            # Related file path
    line_number: Optional[int]          # Related line number
    commit_hash: Optional[str]          # Git commit hash

    # Metrics
    before_metric: Optional[float]      # Before optimization
    after_metric: Optional[float]       # After optimization
    improvement_pct: Optional[float]    # Improvement percentage

    # Security
    severity: Optional[str]             # critical, high, medium, low
    cve_id: Optional[str]               # CVE identifier
    attack_vector: Optional[str]        # How attack occurs

    # Decision tracking
    options_considered: Optional[list[str]]  # Decision options
    chosen_option: Optional[str]             # Chosen option
    rationale: Optional[str]                 # Decision rationale
```

### 7.3 Knowledge Base Structure

#### Hierarchical Memory Organization

```
project-tmws/                           (namespace)
├── architecture/                       (tag)
│   ├── decisions/                      (sub-tag)
│   │   ├── database-migration.memory   (SQLite decision)
│   │   └── vector-storage.memory       (ChromaDB decision)
│   └── patterns/                       (sub-tag)
│       └── hybrid-storage.memory       (Hybrid pattern)
├── security/                           (tag)
│   ├── vulnerabilities/                (sub-tag)
│   │   └── namespace-isolation.memory  (Fixed vulnerability)
│   └── audits/                         (sub-tag)
│       └── p0-security-audit.memory    (Audit report)
├── performance/                        (tag)
│   ├── optimizations/                  (sub-tag)
│   │   ├── duplicate-indexes.memory    (Index optimization)
│   │   └── async-patterns.memory       (Async conversion)
│   └── benchmarks/                     (sub-tag)
│       └── semantic-search.memory      (Search benchmark)
└── documentation/                      (tag)
    ├── api/                            (sub-tag)
    │   └── mcp-integration.memory      (MCP docs)
    └── guides/                         (sub-tag)
        └── development-setup.memory    (Dev setup guide)
```

#### Muses's Memory Organization Algorithm

```python
class MemoryOrganizer:
    """Muses's algorithm for organizing knowledge base."""

    async def organize_memories(self, namespace: str):
        """
        Organize all memories in namespace into hierarchical structure.
        """
        # Fetch all memories in namespace
        memories = await tmws.search_memories(
            query="",  # Empty query = fetch all
            namespace=namespace,
            limit=10000  # Large limit
        )

        # Group by primary tags
        grouped = defaultdict(list)
        for memory in memories:
            primary_tag = memory.tags[0] if memory.tags else "uncategorized"
            grouped[primary_tag].append(memory)

        # Create hierarchical structure
        structure = {}
        for primary_tag, tag_memories in grouped.items():
            # Group by secondary tags
            subgroups = defaultdict(list)
            for memory in tag_memories:
                secondary_tag = memory.tags[1] if len(memory.tags) > 1 else "general"
                subgroups[secondary_tag].append(memory)

            structure[primary_tag] = dict(subgroups)

        # Store structure as memory
        await tmws.create_memory(
            content=f"Knowledge base structure for {namespace}:\n{json.dumps(structure, indent=2)}",
            agent_id="muses-documenter",
            namespace=namespace,
            tags=["documentation", "knowledge-base", "structure"],
            importance=0.7,
            access_level=AccessLevel.PUBLIC
        )

        return structure
```

---

## 8. Implementation Guidelines

### 8.1 Phase 1: Core Infrastructure (Week 1-2)

#### Tasks

1. **Project Context Manager** (2-3 days)
   - Implement `detect_project_namespace()`
   - Add namespace detection to MCP server initialization
   - Test namespace switching between projects

2. **Automatic Trigger System** (3-4 days)
   - Create `@trigger` decorator
   - Implement trigger evaluation engine
   - Add deduplication logic

3. **Agent Context Enhancement** (2-3 days)
   - Add verified namespace parameter to all memory operations
   - Update `is_accessible_by()` security checks
   - Add persona-specific default access levels

#### Success Criteria

- [ ] Namespace auto-detection works for git repos
- [ ] Triggers fire correctly for test events
- [ ] No duplicate memories created for similar events
- [ ] Security tests pass (namespace isolation)

### 8.2 Phase 2: Persona Integration (Week 3-4)

#### Tasks

1. **Implement Persona Triggers** (5-6 days)
   - Create trigger classes for all 6 personas
   - Implement importance scoring algorithms
   - Add trigger unit tests

2. **Memory API Enhancement** (2-3 days)
   - Add `cross_namespace` search parameter
   - Implement shared memory queries
   - Add memory hierarchy support (parent_memory_id)

3. **Workflow Coordination** (3-4 days)
   - Implement Sequential Workflow pattern
   - Implement Parallel Workflow pattern
   - Add conflict resolution logic

#### Success Criteria

- [ ] All persona triggers create appropriate memories
- [ ] Importance scores reflect persona priorities
- [ ] Cross-namespace search works correctly
- [ ] Workflows create linked memory chains

### 8.3 Phase 3: Documentation & Testing (Week 5)

#### Tasks

1. **Documentation** (2 days)
   - Update MCP integration docs
   - Add persona-specific memory guides
   - Create workflow examples

2. **Integration Testing** (2-3 days)
   - Test multi-agent workflows
   - Test namespace isolation
   - Performance testing (10,000+ memories)

3. **Monitoring & Metrics** (1-2 days)
   - Add memory creation metrics
   - Add namespace usage statistics
   - Add trigger firing telemetry

#### Success Criteria

- [ ] Documentation complete and reviewed
- [ ] All integration tests pass
- [ ] Performance targets met (< 20ms P95)
- [ ] Monitoring dashboards operational

---

## 9. Usage Examples

### 9.1 Example 1: Artemis Performance Optimization

**Scenario**: Artemis optimizes a database query and automatically stores the pattern.

```python
# User: "Optimize the user search query"

# Artemis detects current project
project_ns = detect_project_namespace()  # → "project-ecommerce"

# Artemis performs optimization
before_time = measure_query_time("SELECT * FROM users WHERE name LIKE '%john%'")
# → 1500ms

# Artemis rewrites query with index
optimized_query = "SELECT * FROM users WHERE name ILIKE 'john%'"
after_time = measure_query_time(optimized_query)
# → 45ms (97% improvement)

# 🎯 AUTOMATIC TRIGGER FIRES
# Trigger: optimization_applied
# Importance: 0.6 + (97 / 100) = 1.0 (capped at 1.0)

await tmws.create_memory(
    content=f"""Performance optimization: Database query optimization
Before: SELECT * FROM users WHERE name LIKE '%john%' (1500ms)
After: SELECT * FROM users WHERE name ILIKE 'john%' (45ms)
Improvement: 97%
Technique: Replace full-text LIKE with prefix ILIKE + index
Code location: src/api/routers/users.py:45
Index added: CREATE INDEX idx_users_name ON users(name text_pattern_ops)""",
    agent_id="artemis-optimizer",
    namespace=project_ns,  # "project-ecommerce"
    tags=["optimization", "performance", "database", "query"],
    importance=1.0,
    access_level=AccessLevel.SHARED,  # Share across projects
    metadata={
        "technique": "prefix_search_with_index",
        "before": 1500,
        "after": 45,
        "improvement_pct": 97,
        "file_path": "src/api/routers/users.py",
        "line": 45
    }
)

# Later, in a different project...
# User asks: "How do I optimize user search?"

# Artemis searches across projects
results = await tmws.search_memories(
    query="optimize user search database",
    agent_id="artemis-optimizer",
    namespace="project-banking",  # Different project
    cross_namespace=True,  # 🔍 Search shared memories
    tags=["optimization", "database"],
    min_importance=0.8
)

# Results include the ecommerce optimization ✅
# Artemis: "Based on my previous optimization in another project,
#           I recommend using prefix ILIKE with a text_pattern_ops index..."
```

### 9.2 Example 2: Hestia Security Audit

**Scenario**: Hestia discovers a vulnerability and shares threat intelligence.

```python
# User: "Audit the authentication system"

project_ns = detect_project_namespace()  # → "project-banking"

# Hestia performs security audit
vulnerabilities = await hestia.audit_authentication()

# Hestia finds critical vulnerability
vuln = vulnerabilities[0]
# {
#   "title": "JWT secret key too short",
#   "severity": "critical",
#   "location": "src/security/jwt_service.py:12",
#   "attack_vector": "Brute force JWT signing key",
#   "mitigation": "Use 256-bit (32 byte) secret key"
# }

# 🎯 AUTOMATIC TRIGGER FIRES
# Trigger: vulnerability_found
# Importance: 1.0 (critical severity)

await tmws.create_memory(
    content=f"""SECURITY VULNERABILITY: JWT secret key too short
Severity: critical
Location: src/security/jwt_service.py:12
Attack Vector: Brute force JWT signing key (current key is only 128 bits)
Impact: Attacker can forge authentication tokens
Mitigation: Use 256-bit (32 byte) secret key:
  SECRET_KEY = secrets.token_hex(32)  # 256 bits""",
    agent_id="hestia-auditor",
    namespace=project_ns,  # "project-banking"
    tags=["security", "vulnerability", "critical", "jwt", "authentication"],
    importance=1.0,
    access_level=AccessLevel.TEAM,  # Keep within project initially
    metadata={
        "severity": "critical",
        "attack_vector": "brute_force_jwt",
        "cve_id": None,
        "file_path": "src/security/jwt_service.py",
        "line": 12
    }
)

# After vulnerability is fixed, Hestia extracts the pattern
await tmws.create_memory(
    content=f"""Attack pattern: Weak JWT secret keys
Indicators:
- Secret key < 256 bits
- Secret key in environment variables without rotation
- Secret key committed to git
Defense strategy:
- Use secrets.token_hex(32) for 256-bit keys
- Store in secure vault (not .env files)
- Rotate keys periodically
- Never commit secrets to version control""",
    agent_id="hestia-auditor",
    namespace=project_ns,
    tags=["security", "attack-pattern", "jwt", "best-practices"],
    importance=0.95,
    access_level=AccessLevel.SHARED,  # 🌐 Share threat intelligence
    metadata={
        "pattern_type": "weak_secret_key",
        "category": "authentication"
    }
)

# Later, in a different project...
# Hestia automatically searches for known attack patterns

patterns = await tmws.search_memories(
    query="JWT authentication security",
    agent_id="hestia-auditor",
    namespace="project-ecommerce",
    cross_namespace=True,  # 🔍 Search threat intelligence
    tags=["security", "attack-pattern"],
    min_importance=0.9
)

# Hestia: "I've analyzed your JWT implementation. Based on attack patterns
#          I've seen before, your secret key is too short. This is a critical
#          vulnerability that could allow attackers to forge tokens..."
```

### 9.3 Example 3: Collaborative Workflow (Athena → Artemis → Hestia → Muses)

**Scenario**: User requests a new feature, all personas collaborate with shared memory.

```python
# User: "Add user profile export feature"

project_ns = detect_project_namespace()  # → "project-social-network"

# ═══════════════════════════════════════════════════════════
# STEP 1: Athena - Architecture Design
# ═══════════════════════════════════════════════════════════

design = await athena.design_feature("User profile export")

# 🎯 AUTOMATIC TRIGGER: architecture_design
design_memory = await tmws.create_memory(
    content=f"""Feature design: User Profile Export
Architecture: RESTful API endpoint with async background processing
Components:
1. API endpoint: POST /api/v1/profile/export
2. Background worker: Celery task for data aggregation
3. Storage: S3 bucket for temporary export files
4. Notification: Email with download link

Flow:
1. User requests export
2. API creates background task
3. Worker aggregates profile data (posts, comments, likes, etc.)
4. Worker generates JSON/CSV file
5. Worker uploads to S3 with 24-hour expiration
6. Worker sends email with secure download link

Estimated complexity: Medium (3-5 days)""",
    agent_id="athena-conductor",
    namespace=project_ns,
    tags=["architecture", "design", "user-profile", "export"],
    importance=0.8,
    access_level=AccessLevel.TEAM,
    metadata={
        "workflow_id": "export-feature-workflow",
        "step": 1,
        "complexity": "medium",
        "estimated_days": 4
    }
)

# ═══════════════════════════════════════════════════════════
# STEP 2: Artemis - Implementation with Optimization
# ═══════════════════════════════════════════════════════════

# Artemis reads the design
design_context = await tmws.get_memory(design_memory.id)

# Artemis implements with performance in mind
implementation = await artemis.implement_feature(design_context)

# 🎯 AUTOMATIC TRIGGER: implementation_completed
impl_memory = await tmws.create_memory(
    content=f"""Implementation: User Profile Export
Design reference: {design_memory.id}

Key implementation details:
- API endpoint: FastAPI with async background tasks
- Worker: Celery with Redis backend
- Optimization: Batch database queries to reduce N+1 queries
  * Before: 1 query per post/comment (could be 1000+ queries)
  * After: 3 batch queries (posts, comments, likes)
  * Performance: 15s → 2s for typical profile (87% improvement)
- Storage: Boto3 with presigned URLs for secure access
- Notification: SendGrid async API

Code locations:
- API: src/api/routers/profile.py:export_profile()
- Worker: src/workers/export_worker.py:export_user_profile_task()
- Tests: tests/api/test_profile_export.py (12 tests, all passing)""",
    agent_id="artemis-optimizer",
    namespace=project_ns,
    tags=["implementation", "optimization", "user-profile", "export"],
    importance=0.8,
    access_level=AccessLevel.TEAM,
    metadata={
        "workflow_id": "export-feature-workflow",
        "step": 2,
        "parent_memory_id": str(design_memory.id),
        "performance_improvement_pct": 87,
        "test_coverage": 100
    }
)

# 🎯 ADDITIONAL TRIGGER: optimization_applied
await tmws.create_memory(
    content=f"""Performance optimization: Batch queries for profile export
Before: 1 query per item (N+1 problem) → 15 seconds
After: 3 batch queries → 2 seconds
Improvement: 87%
Technique: Batch query with JOIN and subqueries
Code location: src/workers/export_worker.py:45-78""",
    agent_id="artemis-optimizer",
    namespace=project_ns,
    tags=["optimization", "performance", "database", "batch-queries"],
    importance=0.97,  # 0.6 + (87/100) = 1.47 → capped at 1.0 → use 0.97
    access_level=AccessLevel.SHARED,  # Share optimization pattern
    metadata={
        "technique": "batch_queries_join",
        "before": 15,
        "after": 2,
        "improvement_pct": 87
    }
)

# ═══════════════════════════════════════════════════════════
# STEP 3: Hestia - Security Audit
# ═══════════════════════════════════════════════════════════

# Hestia reads both design and implementation
design_ctx = await tmws.get_memory(design_memory.id)
impl_ctx = await tmws.get_memory(impl_memory.id)

# Hestia performs security audit
audit = await hestia.security_audit([design_ctx, impl_ctx])

# 🎯 AUTOMATIC TRIGGER: security_audit_completed
audit_memory = await tmws.create_memory(
    content=f"""Security audit: User Profile Export
Design reference: {design_memory.id}
Implementation reference: {impl_memory.id}

Audit findings:
✅ PASSED: Authentication required for export endpoint
✅ PASSED: Rate limiting implemented (5 exports per hour)
✅ PASSED: S3 presigned URLs with 24-hour expiration
✅ PASSED: No sensitive data in export (passwords, API keys excluded)
⚠️  WARNING: Export file contains email addresses (GDPR concern)
❌ HIGH: No CSRF token validation on export endpoint

Recommendations:
1. Add CSRF token validation (HIGH priority)
2. Make email inclusion optional with user consent (GDPR compliance)
3. Add audit logging for all export requests
4. Implement IP-based rate limiting (additional layer)

Overall risk level: MEDIUM (pending HIGH fix)""",
    agent_id="hestia-auditor",
    namespace=project_ns,
    tags=["security", "audit", "user-profile", "export"],
    importance=0.9,
    access_level=AccessLevel.TEAM,
    metadata={
        "workflow_id": "export-feature-workflow",
        "step": 3,
        "parent_memory_ids": [str(design_memory.id), str(impl_memory.id)],
        "findings_count": 2,
        "high_severity_count": 1,
        "risk_level": "medium"
    }
)

# Hestia flags the HIGH severity issue separately
await tmws.create_memory(
    content=f"""SECURITY VULNERABILITY: Missing CSRF token validation
Severity: HIGH
Location: src/api/routers/profile.py:export_profile()
Attack Vector: CSRF attack could trigger unwanted profile exports
Impact: Attacker could exhaust user's export quota, cause email spam
Mitigation: Add CSRF token validation:
  from fastapi_csrf import CsrfProtect
  @router.post("/export", dependencies=[Depends(CsrfProtect)])""",
    agent_id="hestia-auditor",
    namespace=project_ns,
    tags=["security", "vulnerability", "high", "csrf", "export"],
    importance=0.9,
    access_level=AccessLevel.TEAM,
    metadata={
        "severity": "high",
        "attack_vector": "csrf",
        "file_path": "src/api/routers/profile.py",
        "function": "export_profile"
    }
)

# Artemis reads the vulnerability and fixes it
vuln = await tmws.search_memories(
    query="CSRF vulnerability export",
    agent_id="artemis-optimizer",
    namespace=project_ns,
    tags=["vulnerability", "high"],
    limit=1
)

fix = await artemis.fix_vulnerability(vuln[0])

await tmws.create_memory(
    content=f"""Security fix: Added CSRF protection to profile export
Vulnerability reference: {vuln[0].id}
Fix: Added CSRF token validation using fastapi-csrf
Code change: src/api/routers/profile.py:12-15
Tests added: tests/security/test_csrf_export.py (3 tests, all passing)
Status: ✅ Fixed and tested""",
    agent_id="artemis-optimizer",
    namespace=project_ns,
    tags=["security", "fix", "csrf", "export"],
    importance=0.85,
    access_level=AccessLevel.TEAM,
    metadata={
        "parent_memory_id": str(vuln[0].id),
        "vulnerability_fixed": True
    }
)

# ═══════════════════════════════════════════════════════════
# STEP 4: Muses - Documentation
# ═══════════════════════════════════════════════════════════

# Muses reads all previous memories
workflow_memories = await tmws.search_memories(
    query="user profile export",
    agent_id="muses-documenter",
    namespace=project_ns,
    tags=["workflow_id:export-feature-workflow"],  # Filter by workflow
    limit=100
)

# Muses creates comprehensive documentation
documentation = await muses.document_feature(workflow_memories)

# 🎯 AUTOMATIC TRIGGER: documentation_created
doc_memory = await tmws.create_memory(
    content=f"""Documentation: User Profile Export Feature

## Overview
Users can export their complete profile data in JSON or CSV format.

## API Endpoint
POST /api/v1/profile/export
- Authentication: Required (Bearer token)
- Rate limit: 5 exports per hour
- CSRF: Required (X-CSRF-Token header)

## Request Body
```json
{{
  "format": "json",  // or "csv"
  "include_email": false  // Optional, default false (GDPR compliance)
}}
```

## Response
```json
{{
  "task_id": "export-123456",
  "status": "processing",
  "estimated_completion": "2025-10-27T15:30:00Z"
}}
```

## Implementation Details
- Background processing: Celery with Redis
- Storage: S3 with 24-hour expiration
- Performance: ~2 seconds for typical profile
- Optimization: Batch queries (87% performance improvement)

## Security
- CSRF protection: ✅ Enabled
- Authentication: ✅ Required
- Rate limiting: ✅ 5 per hour
- Audit logging: ✅ All exports logged
- GDPR compliance: ⚠️  Email optional with consent

## Testing
- Unit tests: tests/api/test_profile_export.py (12 tests)
- Security tests: tests/security/test_csrf_export.py (3 tests)
- Coverage: 100%

## Related Memories
- Design: {design_memory.id}
- Implementation: {impl_memory.id}
- Security audit: {audit_memory.id}""",
    agent_id="muses-documenter",
    namespace=project_ns,
    tags=["documentation", "api", "user-profile", "export"],
    importance=0.7,
    access_level=AccessLevel.PUBLIC,  # Documentation is public
    metadata={
        "workflow_id": "export-feature-workflow",
        "step": 4,
        "parent_memory_ids": [
            str(design_memory.id),
            str(impl_memory.id),
            str(audit_memory.id)
        ],
        "doc_type": "api",
        "target_audience": "developers"
    }
)

# ═══════════════════════════════════════════════════════════
# FINAL RESULT
# ═══════════════════════════════════════════════════════════

# Athena synthesizes the complete workflow
await athena.complete_workflow(
    workflow_id="export-feature-workflow",
    memories=[design_memory, impl_memory, audit_memory, doc_memory]
)

print("""
✅ User Profile Export Feature Complete!

📋 Memories Created:
1. Athena: Architecture design (importance: 0.8)
2. Artemis: Implementation + optimization (importance: 0.8, 0.97)
3. Hestia: Security audit + vulnerability (importance: 0.9, 0.9)
4. Artemis: Security fix (importance: 0.85)
5. Muses: Comprehensive documentation (importance: 0.7)

🔗 Memory Chain: design → implementation → audit → fix → documentation

📊 Performance: 87% faster than naive implementation
🔒 Security: All HIGH vulnerabilities fixed
📚 Documentation: Complete API reference created
""")
```

---

## 10. Performance Considerations

### 10.1 Memory Creation Overhead

**Target**: < 50ms per memory creation (P95)

**Breakdown**:
- Embedding generation (Ollama): 20-30ms
- SQLite insert: 2-5ms
- ChromaDB insert: 5-10ms
- Network overhead: 5-10ms
- Total: 32-55ms ✅

**Optimization Strategies**:
1. **Batch creation** for workflows (use `batch_create_memories()`)
2. **Async embedding** generation (already implemented)
3. **Connection pooling** for database (already configured)

### 10.2 Search Performance

**Target**: < 20ms per search (P95)

**Current Performance**:
- Semantic search: 5-20ms ✅
- Vector similarity: < 10ms ✅
- Metadata queries: 2.63ms ✅
- Cross-agent sharing: 9.33ms ✅

**All targets achieved** ✅

### 10.3 Storage Efficiency

**Estimates**:
- Average memory size: 500 bytes (metadata) + 4KB (embedding vector)
- 10,000 memories: ~45MB total
- 100,000 memories: ~450MB total

**SQLite Performance**:
- With WAL mode: supports 100,000+ memories
- Query performance: logarithmic scaling with proper indexes

**ChromaDB Performance**:
- DuckDB backend: handles millions of vectors
- HNSW index: O(log n) search time

### 10.4 Scaling Recommendations

#### Small Deployments (1-10 users)
- **Current architecture is sufficient**
- SQLite + ChromaDB handles workload
- No additional infrastructure needed

#### Medium Deployments (10-100 users)
- Consider **read replicas** for search-heavy workloads
- Monitor SQLite connection pool size
- Add **Redis caching** for hot memories

#### Large Deployments (100+ users)
- Migrate to **PostgreSQL** for better concurrency
- Use **multiple ChromaDB instances** with sharding
- Implement **memory archival** for old, low-importance memories
- Add **CDN** for frequently accessed public memories

---

## 11. Future Enhancements

### 11.1 Phase 4: Advanced Features (v2.3.0)

#### A. Memory Consolidation
**Problem**: Too many similar memories clutter the knowledge base.

**Solution**: Automatic memory consolidation
```python
class MemoryConsolidator:
    """Consolidate similar memories into summaries."""

    async def consolidate_memories(self, namespace: str):
        """
        Find clusters of similar memories and consolidate them.
        """
        # Find high-importance memories
        memories = await tmws.search_memories(
            query="",
            namespace=namespace,
            min_importance=0.7,
            limit=10000
        )

        # Cluster by similarity
        clusters = self.cluster_by_similarity(memories, threshold=0.85)

        # For each cluster, create consolidated memory
        for cluster in clusters:
            if len(cluster) >= 3:  # At least 3 similar memories
                summary = await self.generate_summary(cluster)

                consolidated = await tmws.create_memory(
                    content=summary,
                    agent_id="athena-conductor",  # Athena consolidates
                    namespace=namespace,
                    tags=["consolidated"] + cluster[0].tags,
                    importance=max(m.importance_score for m in cluster),
                    access_level=cluster[0].access_level,
                    metadata={
                        "consolidated_memory_ids": [str(m.id) for m in cluster],
                        "consolidation_date": datetime.utcnow().isoformat()
                    }
                )

                # Mark originals as consolidated (don't delete)
                for memory in cluster:
                    memory.metadata["consolidated_into"] = str(consolidated.id)
```

#### B. Memory Importance Decay
**Problem**: Old memories remain high-importance forever.

**Solution**: Time-based importance decay
```python
def calculate_decayed_importance(
    original_importance: float,
    created_at: datetime,
    access_count: int
) -> float:
    """
    Decay importance over time, but boost by access count.
    """
    age_days = (datetime.utcnow() - created_at).days

    # Decay: -10% per year (0.999726 per day)
    decay_factor = 0.999726 ** age_days

    # Boost: +1% per access (up to 2x)
    access_boost = min(2.0, 1.0 + (access_count * 0.01))

    return original_importance * decay_factor * access_boost
```

#### C. Cross-Project Pattern Learning
**Problem**: Patterns discovered in one project aren't automatically applied to others.

**Solution**: Pattern suggestion system
```python
class PatternSuggester:
    """Suggest patterns from other projects."""

    async def suggest_patterns(self, current_project: str):
        """
        Analyze current project and suggest relevant patterns from others.
        """
        # Get current project's characteristics
        current_memories = await tmws.search_memories(
            query="",
            namespace=f"project-{current_project}",
            limit=1000
        )

        # Find similar projects by memory similarity
        similar_projects = await self.find_similar_projects(current_memories)

        # Extract high-value patterns from similar projects
        patterns = []
        for project in similar_projects:
            project_patterns = await tmws.search_memories(
                query="pattern",
                namespace=f"project-{project}",
                tags=["pattern", "optimization", "security"],
                min_importance=0.8,
                access_level=AccessLevel.SHARED  # Only shared patterns
            )
            patterns.extend(project_patterns)

        # Suggest to user
        if patterns:
            print(f"💡 Found {len(patterns)} relevant patterns from similar projects:")
            for pattern in patterns[:5]:  # Top 5
                print(f"  - {pattern.content[:100]}...")
```

### 11.2 Phase 5: AI-Powered Features (v3.0.0)

#### A. Automatic Memory Summarization
Use LLM to summarize long memories automatically.

#### B. Memory Relationship Discovery
Discover implicit relationships between memories using graph analysis.

#### C. Predictive Memory Suggestion
Suggest relevant memories before user asks, based on context.

#### D. Natural Language Memory Queries
Allow users to search with natural language instead of keywords.

---

## 12. Conclusion

This specification provides a comprehensive framework for integrating TMWS with Trinitas-agents, solving both critical problems:

1. ✅ **Project Isolation**: Automatic namespace detection + project-based organization
2. ✅ **Automatic Persistence**: Event-driven triggers for all 6 personas with importance scoring

### Key Benefits

- **Reduced Cognitive Load**: Agents don't decide when to store memories
- **Consistent Memory Creation**: Standardized triggers across all personas
- **Improved Knowledge Retention**: No lost insights or context
- **Cross-Project Learning**: Shared patterns and optimizations
- **Enhanced Collaboration**: Linked memory chains for workflows
- **Security-First Design**: Namespace isolation with verified access control

### Implementation Priority

**Phase 1** (Critical - Week 1-2):
- Project namespace detection
- Basic trigger system
- Security hardening

**Phase 2** (High - Week 3-4):
- All persona triggers
- Workflow coordination
- Cross-namespace search

**Phase 3** (Medium - Week 5):
- Documentation + testing
- Monitoring + metrics

---

**Document Status**: Draft v1.0
**Next Steps**: Review by all Trinitas personas, implementation planning

---

*"Through harmonious integration and intelligent automation, we create a system where every insight is preserved, every optimization is shared, and every collaboration builds upon the collective wisdom of all agents."*

**— Athena, Harmonious Conductor** ✨

**With strategic precision and coordinated execution, we transform individual agent capabilities into a unified intelligence system.**

**— Hera, Strategic Commander** ⚔️
