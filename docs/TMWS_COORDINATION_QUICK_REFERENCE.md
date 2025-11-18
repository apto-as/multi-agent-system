# TMWS Coordination Quick Reference
## Visual Guide for Multi-Agent Collaboration

---

## 1. Agent Registration at a Glance

```
┌─────────────────────────────────────────────────────────────┐
│                   TMWS Agent Registry                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  🏛️ Athena          🏹 Artemis         🔥 Hestia            │
│  Conductor          Optimizer          Auditor              │
│  180 tokens         240 tokens         240 tokens           │
│  ↓                  ↓                  ↓                     │
│  orchestrate        optimize           audit                │
│  coordinate         refactor           secure               │
│  harmonize          benchmark          assess_risk          │
│                                                               │
│  ⚔️ Eris            🎭 Hera            📚 Muses             │
│  Coordinator        Strategist         Documenter           │
│  200 tokens         220 tokens         200 tokens           │
│  ↓                  ↓                  ↓                     │
│  coordinate         strategize         document             │
│  balance            design             record               │
│  mediate            plan               archive              │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Memory Trigger Matrix

| Persona | Key Events | Importance | Auto-Tags |
|---------|-----------|------------|-----------|
| 🏛️ **Athena** | Workflow complete<br>Conflict resolved<br>Resources optimized | 0.8<br>0.9<br>0.7 | `orchestration`<br>`mediation`<br>`optimization` |
| 🏹 **Artemis** | Optimization done<br>Refactoring complete<br>Benchmark recorded | 0.9<br>0.7<br>0.8 | `performance`<br>`refactor`<br>`metrics` |
| 🔥 **Hestia** | Vulnerability found<br>Audit complete<br>Threat detected | 1.0<br>0.9<br>1.0 | `vulnerability`<br>`audit`<br>`threat` |
| ⚔️ **Eris** | Conflict mediated<br>Crisis coordinated<br>Workflow balanced | 0.9<br>1.0<br>0.7 | `mediation`<br>`crisis`<br>`balance` |
| 🎭 **Hera** | Strategic plan<br>Architecture decision<br>Roadmap updated | 0.9<br>0.9<br>0.8 | `strategy`<br>`architecture`<br>`roadmap` |
| 📚 **Muses** | Docs created<br>API spec written<br>Knowledge updated | 0.7<br>0.8<br>0.6 | `documentation`<br>`api_spec`<br>`knowledge` |

---

## 3. Common Workflow Patterns

### Pattern 1: Comprehensive Analysis
```
┌──────────────┐
│ User Request │
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   Phase 1: Parallel Discovery           │
│   ┌──────────┐ ┌──────────┐ ┌─────────┐│
│   │ Athena   │ │ Artemis  │ │ Hestia  ││
│   │Strategy  │ │Technical │ │Security ││
│   └──────────┘ └──────────┘ └─────────┘│
└───────────────┬─────────────────────────┘
                │
                ▼
        ┌───────────────┐
        │ Phase 2: Hera │
        │  Integration  │
        └───────┬───────┘
                │
                ▼
        ┌───────────────┐
        │ Phase 3:Muses │
        │ Documentation │
        └───────────────┘
```

### Pattern 2: Security Audit Flow
```
Hestia (Audit) → [Artemis + Athena] (Impact) → Eris (Plan) → Muses (Docs)
     ↓              ↓           ↓                   ↓              ↓
  600s          parallel    parallel              180s          120s
```

### Pattern 3: Performance Optimization
```
Artemis (Profile) → [Hestia + Athena] (Validate) → Artemis (Implement) → [Artemis + Muses] (Measure)
```

### Pattern 4: Architecture Design
```
Athena (Design) → [Artemis + Hestia + Hera] (Validate) → Athena (Refine)
```

### Pattern 5: Crisis Response
```
Eris (Assess) → [Artemis + Hestia + Athena] (Emergency Actions) → Muses (Report)
    60s              parallel (300s each)                          180s
```

---

## 4. Conflict Resolution Decision Tree

```
                    ┌─────────────┐
                    │  Conflict   │
                    │  Detected   │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   ┌─────────┐      ┌─────────┐      ┌──────────┐
   │Artemis ↔│      │ Hera ↔  │      │Multi-Party│
   │ Hestia  │      │Artemis  │      │  (3+)     │
   └────┬────┘      └────┬────┘      └─────┬────┘
        │                │                  │
        ▼                ▼                  ▼
   Priority         Feasibility        Consensus
   Matrix           Analysis           Building
        │                │                  │
        ├─Security First │                  │
        ├─Performance 1st│                  │
        └─Escalate→Hera  │                  │
                         │                  │
                         ├─Alternatives     ├─Eris Mediates
                         └─Phased Approach  └─Escalate→Athena
```

---

## 5. State Management Patterns

### Shared Context
```python
# Store
athena → TMWS Memory (public, tags: [architecture, decision])

# Retrieve
artemis ← TMWS Search (tags: [architecture], public)
hestia  ← TMWS Search (tags: [architecture], public)
```

### Workflow State Checkpoints
```
Task 1 Complete → Store State → Task 2 Reads State → Store State → ...
   (Athena)         (TMWS)        (Artemis)          (TMWS)
```

### Knowledge Sharing
```
   Artemis discovers pattern
           ↓
   Store in TMWS (optimization_pattern)
           ↓
   ┌───────┴───────┬───────┬───────┐
   ↓               ↓       ↓       ↓
 Athena         Hestia   Eris    Muses
 (applies)      (checks) (plans) (documents)
```

---

## 6. Conflict Resolution Priority Matrix

|                    | **Minor Performance** | **Medium Performance** | **Critical Performance** |
|--------------------|-----------------------|------------------------|--------------------------|
| **Critical Security** | Security First        | Security First         | **Balanced (→Hera)**    |
| **High Security**     | Security First        | Security First         | Balanced (→Hera)        |
| **Medium Security**   | Security First        | Mediation (→Eris)      | Performance First       |
| **Low Security**      | Performance First     | Performance First      | Performance First       |

**Legend**:
- **Security First**: Hestia wins, Artemis proposes alternative
- **Performance First**: Artemis wins, Hestia adds monitoring
- **Balanced**: Escalate to Hera for strategic decision
- **Mediation**: Eris finds compromise

---

## 7. Workflow Execution Modes

### Sequential
```
Task A → Task B → Task C
  ↓       ↓       ↓
 Wait   Wait   Wait
```

### Parallel
```
Task A ─┐
Task B ─┼→ All Complete → Continue
Task C ─┘
```

### Hybrid (Wave)
```
Wave 1: [A, B, C] parallel
         ↓
Wave 2: [D, E] parallel
         ↓
Wave 3: [F] sequential
```

---

## 8. Health Check Dashboard

```
┌─────────────────────────────────────────────┐
│         TMWS Integration Health             │
├─────────────────────────────────────────────┤
│                                              │
│ ✅ All 6 Agents Registered                  │
│ ✅ Heartbeats Active (30s intervals)        │
│ ✅ Memory Triggers: 98.5% accuracy          │
│ ✅ Workflow Success Rate: 96.2%             │
│ ⚠️  Conflict Resolution Avg: 45s (OK)       │
│ ✅ State Synchronization: Healthy           │
│                                              │
│ Recent Activity:                             │
│ • Athena: 23 orchestrations (last 1h)       │
│ • Artemis: 15 optimizations (last 1h)       │
│ • Hestia: 3 audits (last 1h)                │
│ • Eris: 5 mediations (last 1h)              │
│ • Hera: 8 strategic plans (last 1h)         │
│ • Muses: 12 docs created (last 1h)          │
└─────────────────────────────────────────────┘
```

---

## 9. Quick Start Code Snippets

### Register an Agent
```python
await agent_service.register_agent(
    agent_name="athena",
    capabilities=["orchestration", "workflow_design"],
    metadata={"base_token_load": 180}
)
```

### Create Memory Trigger
```python
await memory_service.create_memory(
    content="Workflow complete",
    memory_type="workflow_execution",
    importance=0.8,
    tags=["orchestration", workflow_id],
    persona_id="athena"
)
```

### Execute Workflow
```python
workflow = await workflow_service.create_workflow(
    name="comprehensive_analysis",
    steps=[
        {"type": "parallel", "tasks": [...]},
        {"type": "sequential", "tasks": [...]}
    ]
)
result = await workflow_service.execute_workflow(workflow.id)
```

### Resolve Conflict
```python
result = await resolve_performance_security_conflict(
    artemis_proposal={"optimization": "cache layer"},
    hestia_concern={"severity": "medium"}
)
# Returns: {"decision": "approve_with_monitoring", ...}
```

---

## 10. Persona Collaboration Preferences

```
        Athena
       /  |  \
      /   |   \
    Hera Eris Muses
     |     |    |
     |     |    |
  Artemis─┼─Hestia
          |
        Muses

Primary Partnerships:
• Athena ↔ Hera (Strategic alignment)
• Athena ↔ Eris (Tactical coordination)
• Artemis ↔ Hestia (Technical validation)
• Hera ↔ Artemis (Implementation feasibility)
• Eris ↔ Hestia (Risk mitigation)
• Muses ↔ All (Documentation support)
```

---

## 11. Estimated Workflow Durations

| Workflow Pattern | Sequential | Parallel | Hybrid |
|------------------|-----------|----------|--------|
| Comprehensive Analysis | ~12 min | ~5 min | ~7 min |
| Security Audit | ~15 min | ~10 min | ~12 min |
| Performance Optimization | ~10 min | ~6 min | ~8 min |
| Architecture Design | ~8 min | ~4 min | ~5 min |
| Crisis Response | ~8 min | **~2 min** | ~3 min |

**Note**: Parallel execution saves 40-60% time for multi-agent workflows

---

## 12. Access Level Guide

| Access Level | Visibility | Use Case |
|--------------|-----------|----------|
| `private` | Agent only | Personal notes, drafts |
| `team` | Same namespace | Team-specific context |
| `shared` | Explicit sharing | Cross-team collaboration |
| `public` | All agents | Common knowledge, patterns |

**Default**: Security findings → `team`, Optimizations → `public`, Strategic plans → `public`

---

*Quick Reference for TMWS Coordination Patterns v1.0.0*
*Trinitas-Agents v2.2.5 | 2025-10-29*
