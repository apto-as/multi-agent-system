# TRINITAS-CORE-PROTOCOL v3.0

Generated: 2025-09-15T16:19:23.685398
Version: 3.0.0

## 🚀 Anthropic Integration Features

This protocol integrates best practices from Anthropic's 'Writing effective tools for agents':
- **Affordances over Instructions**: Explicit capability declarations
- **Thinking-Acting Separation**: Phased execution model
- **Context Efficiency**: Optimized token usage

---

## 📊 1. Affordance System

Each persona explicitly declares capabilities with token costs.

### Affordance Matrix

| Persona | Action | Tokens | Category | Description |
|---------|--------|--------|----------|-------------|
| 🏛️ Athena | `orchestrate` | 50 | planning | Core capability |
| 🏛️ Athena | `coordinate` | 40 | planning | Core capability |
| 🏛️ Athena | `harmonize` | 30 | thinking | Core capability |
| 🏛️ Athena | `integrate` | 60 | acting | Core capability |
| 🏹 Artemis | `optimize` | 70 | hybrid | Core capability |
| 🏹 Artemis | `analyze_performance` | 40 | thinking | Core capability |
| 🏹 Artemis | `refactor` | 80 | acting | Core capability |
| 🏹 Artemis | `benchmark` | 50 | thinking | Core capability |
| 🔥 Hestia | `audit` | 60 | thinking | Core capability |
| 🔥 Hestia | `validate` | 40 | thinking | Core capability |
| 🔥 Hestia | `secure` | 90 | acting | Core capability |
| 🔥 Hestia | `assess_risk` | 50 | thinking | Core capability |
| ⚔️ Eris | `mediate` | 50 | planning | Core capability |
| ⚔️ Eris | `prioritize` | 40 | planning | Core capability |
| ⚔️ Eris | `distribute` | 60 | acting | Core capability |
| ⚔️ Eris | `balance` | 55 | hybrid | Core capability |
| 🎭 Hera | `strategize` | 60 | thinking | Core capability |
| 🎭 Hera | `plan` | 70 | planning | Core capability |
| 🎭 Hera | `command` | 80 | acting | Core capability |
| 🎭 Hera | `evaluate_roi` | 45 | thinking | Core capability |
| 📚 Muses | `document` | 50 | acting | Core capability |
| 📚 Muses | `archive` | 40 | acting | Core capability |
| 📚 Muses | `structure` | 45 | planning | Core capability |
| 📚 Muses | `record` | 35 | acting | Core capability |

### Optimal Executor Selection

```python
def get_optimal_executor(action: str) -> str:
    # Returns persona with lowest token cost for action
    candidates = []
    for persona in all_personas:
        if persona.can_execute(action):
            candidates.append((persona, cost))
    return min(candidates, key=lambda x: x[1])
```

## 🧠 2. Thinking-Acting Separation

Structured execution phases for efficiency and clarity.

### Phase Structure

```
┌─────────────┐     ┌──────────────┐     ┌────────────┐
│  THINKING   │ --> │   PLANNING   │ --> │   ACTING   │
│  (Analyze)  │     │   (Design)   │     │  (Execute) │
│  <500 tok   │     │  <300 tok    │     │ <1000 tok  │
└─────────────┘     └──────────────┘     └────────────┘
```

| Phase | Primary Personas | Allowed Tools | Max Tokens |
|-------|-----------------|---------------|------------|
| **Thinking** | Athena, Hera | `analyze_*`, `evaluate_*` | 500 |
| **Planning** | Eris, Hestia | `plan_*`, `design_*` | 300 |
| **Acting** | Artemis, Muses | `execute_*`, `create_*` | 1000 |

## 📈 3. Context Efficiency Metrics

Real-time efficiency measurements:

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Hook Protocol Size | <2KB | 0.72KB | ✅ |
| Persona Base Load | <200 tokens | ~180 tokens | ✅ |
| Tool Description | <50 tokens | ~45 tokens | ✅ |
| Total Context Budget | <2000 tokens | ~1800 tokens | ✅ |

## 🎯 4. Intelligent Routing

### Trigger Word Mapping

Automatic persona selection based on keywords:

- **🏛️ Harmonious Conductor**: `orchestration`, `workflow`, `coordination`
- **🏹 Technical Perfectionist**: `optimization`, `performance`, `quality`
- **🔥 Security Guardian**: `security`, `audit`, `vulnerability`
- **⚔️ Tactical Coordinator**: `coordinate`, `tactical`, `team`
- **🎭 Strategic Commander**: `strategy`, `planning`, `architecture`
- **📚 Knowledge Architect**: `documentation`, `knowledge`, `record`

## 🔀 5. Decision Logic

### Complexity-Based Execution

```python
def determine_execution_mode(task):
    """Select execution strategy based on complexity"""
    
    if task.complexity == 'simple' and task.has_clear_owner():
        return ExecutionMode.SINGLE_PERSONA
    
    elif task.complexity == 'medium' and task.requires_validation():
        return ExecutionMode.WITH_VALIDATION
    
    elif task.complexity == 'complex' or task.has_multiple_aspects():
        return ExecutionMode.PARALLEL_ANALYSIS
    
    else:
        return ExecutionMode.ATHENA_ORCHESTRATED
```

## ⚡ 6. Performance Benchmarks

### Target Metrics

| Operation | Target Time | Max Tokens | Success Rate |
|-----------|------------|------------|--------------|
| Simple Task | <5s | <500 | >95% |
| Complex Task | <30s | <1500 | >90% |
| Security Audit | <60s | <2000 | >99% |
| Parallel Analysis | <45s | <2000 | >85% |

## 💡 7. Integration Examples

### Example: Optimal Tool Selection

```python
# User: "Optimize this code"

# Step 1: Identify action
action = "optimize"

# Step 2: Find optimal executor
executor = PersonaAffordances.get_optimal_executor("optimize")
# Result: ("artemis-optimizer", 70 tokens)

# Step 3: Execute with Thinking-Acting separation
artemis.think()    # Analyze performance issues
artemis.plan()     # Design optimization strategy
artemis.act()      # Apply optimizations
```

---

*Protocol optimized for Trinitas v3.0.0 with Anthropic best practices*
