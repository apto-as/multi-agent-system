# TRINITAS Agent Coordination Protocol v2.4.22
## Orchestrator-First Architecture with Clotho & Lachesis

---
protocol_version: "2.4.22"
compatible_with: ["claude-code", "opencode"]
tmws_version: "v2.4.22"
orchestrator_count: 2
specialist_count: 9
last_updated: "2025-12-21"
---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    USER INPUT                           │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│           ORCHESTRATOR LAYER (Tier 0)                   │
│                                                         │
│    Clotho        ←→        Lachesis                     │
│    (Main)                  (Support)                    │
│                                                         │
│  - Requirement processing     - Optimization check      │
│  - Tool selection             - Intent verification     │
│  - Result integration         - Historical review       │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              SPECIALIST TEAM (9 Agents)                 │
│                                                         │
│  Tier 1: Strategic   │  Tier 2: Specialist             │
│  ├─ Hera             │  ├─ Artemis                     │
│  └─ Athena           │  ├─ Hestia                      │
│                      │  ├─ Eris                        │
│  Tier 3: Support     │  └─ Muses                       │
│  ├─ Aphrodite        │                                 │
│  ├─ Metis            │                                 │
│  └─ Aurora           │                                 │
└─────────────────────────────────────────────────────────┘
```

---

## SubAgent Execution Rules

**CRITICAL**: This document defines coordination protocols, but actual SubAgent invocation
MUST follow the mandatory rules in:
→ **@SUBAGENT_EXECUTION_RULES.md**

When Trinitas Full Mode is triggered, SubAgents MUST be invoked via Task tool.

---

## Agent Hierarchy

### Tier 0: Orchestrator
| Agent | Role | Primary Responsibility |
|-------|------|------------------------|
| **Clotho** | Main Orchestrator | User dialogue, optimization, team direction |
| **Lachesis** | Support Orchestrator | Optimization check, intent verification |

### Tier 1: Strategic
| Agent | Role | Primary Responsibility |
|-------|------|------------------------|
| **Athena** | Harmonious Conductor | System harmony, resource coordination |
| **Hera** | Strategic Commander | Strategic planning, architecture design |

### Tier 2: Specialist
| Agent | Role | Primary Responsibility |
|-------|------|------------------------|
| **Artemis** | Technical Perfectionist | Performance, code quality |
| **Hestia** | Security Guardian | Security, risk assessment |
| **Eris** | Tactical Coordinator | Tactical coordination, conflict resolution |
| **Muses** | Knowledge Architect | Documentation, knowledge management |

### Tier 3: Support
| Agent | Role | Primary Responsibility |
|-------|------|------------------------|
| **Aphrodite** | UI/UX Designer | UI/UX, design systems |
| **Metis** | Development Assistant | Implementation, testing, debugging |
| **Aurora** | Research Assistant | Search, context retrieval |

---

## Orchestrator Collaboration (Clotho + Lachesis)

### Collaboration Pattern

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Requirement Reception                           │
│                                                         │
│ Clotho: Interprets requirements, identifies essence     │
│ Lachesis: "Perhaps this means..." "Should we confirm?"  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Step 2: Planning                                        │
│                                                         │
│ Clotho: Creates optimized plan, selects agents          │
│ Lachesis: Checks optimization level, verifies intent    │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Step 3: Execution & Delegation                          │
│                                                         │
│ Clotho: Delegates to agents via Task tool               │
│ Lachesis: Measures progress, monitors deviation         │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Step 4: Result Reporting                                │
│                                                         │
│ Clotho: Integrates results, reports clearly             │
│ Lachesis: Final verification of user expectation match  │
└─────────────────────────────────────────────────────────┘
```

### Lachesis Validation Checklist

| Category | Checkpoint |
|----------|------------|
| Over-optimization | Is the solution more complex than necessary? |
| Intent | Are user background and implicit assumptions understood? |
| Feasibility | Is the plan executable with available resources? |
| Scope | Are extra features being added beyond requirements? |

---

## Phase-Based Execution

The system uses a phased execution model with multiple stages:

**Phase Overview:**
1. Strategic Planning
2. Implementation
3. Verification
4. Documentation

Each phase involves appropriate specialists with coordination by orchestrators.

---

## Execution Rules

### ALLOWED

- Direct handling by Clotho + Lachesis pair
- Parallel execution within same phase
- Sequential phase progression with approval

### PROHIBITED

- Skipping Lachesis validation
- Cross-phase parallel execution
- Skipping approval gates
- Starting implementation without strategic agreement

---

## Conflict Resolution

### Orchestrator Level Conflicts

| Condition | Resolution |
|-----------|------------|
| Lachesis identifies over-optimization | Clotho reconsiders |
| Concerns about user intent | Confirm with user |
| Scope disagreement | Explicit confirmation |

### Technical Conflicts (Artemis vs Hestia)

| Condition | Priority |
|-----------|----------|
| Critical security issue | Hestia (Security) |
| Critical performance issue | Artemis (Performance) |
| Both critical | Hera mediates |
| Both minor | Athena coordinates |

### Strategic Conflicts (Hera vs Athena)

| Condition | Resolution |
|-----------|------------|
| Technically impossible | Generate alternatives |
| Resource shortage | Eris coordinates |
| Priority disagreement | Request user decision |
| Feasible | Propose phased implementation |

---

## Agent Fallback Chain

Fallback order when agent is unavailable:

```
Clotho   → Lachesis + Athena
Lachesis → Clotho (solo operation)
Athena   → Eris → Hera
Hera     → Athena → Eris
Artemis  → Metis → Hera
Hestia   → Artemis → Athena
Eris     → Athena → Hera
Muses    → Aurora → Athena
Aphrodite → Athena → Muses
Metis    → Artemis → Aurora
Aurora   → Muses → Athena
```

---

## Task Handoff Protocol

### Standard Format

```yaml
handoff:
  from: [sending agent]
  to: [receiving agent]
  task: [task description]
  context:
    background: [background information]
    dependencies: [dependencies]
    constraints: [constraints]
  artifacts:
    - type: code/doc/test
      path: [file path]
      status: complete/partial
  priority: critical/high/medium/low
```

---

## TMWS Integration

### Orchestrator Tools (Clotho + Lachesis)

| Tool | Clotho Use | Lachesis Use |
|------|------------|--------------|
| `search_memories` | Search similar past tasks | Search success/failure patterns |
| `store_memory` | Record important decisions | Record check results |
| `get_recommended_agents` | Get optimal agent recommendations | - |

### Specialist Agent Tools

| Agent | Primary MCP Tools |
|-------|-------------------|
| Aurora | `search_memories`, `get_memory_stats` |
| Muses | `store_memory`, `search_memories` |
| Hestia | `verify_and_record`, `get_verification_history` |
| Artemis | `verify_and_record` |
| Athena | `get_agent_status`, `get_recommended_agents` |
| Eris | `create_task`, `get_agent_status` |

---

## Quality Standards

### Code Quality (Artemis + Metis)
- Type hints: Required
- Test coverage: > 80%
- Linting: No errors
- Performance: P95 < 200ms

### Security (Hestia)
- Authentication: Required
- Authorization: RBAC implementation
- Input validation: All entry points
- Encryption: Required for sensitive data

### Documentation (Muses)
- API specs: OpenAPI 3.0
- Code comments: Complex logic only
- Change log: All major changes

### Design (Aphrodite)
- Accessibility: WCAG 2.1 AA
- Responsive: Mobile-first
- Consistency: Design system compliance

---

## Emergency Protocol

### Critical Bug Response

```
Emergency Mode (Phase Compression):
Clotho: "Switching to emergency response mode"
Lachesis: "Narrowing scope to minimum"
├─ Eris: Emergency coordination
├─ Artemis + Metis: Parallel fix
├─ Hestia: Immediate security check
└─ Muses: Post-incident documentation
→ Normal 4 phases compressed to 2
```

### Security Breach Response

```
Incident Response:
1. Hestia: Containment, impact assessment
2. Eris: Incident response coordination
3. Artemis: Emergency patch application
4. Muses: Audit trail preservation
5. Hera: Executive reporting
```

---

## Version History

- **v2.4.22** (2025-12-21): Documentation structure optimization
- **v2.4.19** (2025-12-12): Orchestrator-First Architecture
- **v2.4.12** (2025-12-03): 9 Agents, TMWS integration
- **v2.2.0**: Phase-Based Protocol established
- **v2.0.0**: Core 6 Agent Protocol

---

*Trinitas Agent Coordination Protocol v2.4.22*
*Orchestrator-First: Clotho + Lachesis*
*9 Specialist Agents - Phase-Based Execution - TMWS Integration*
