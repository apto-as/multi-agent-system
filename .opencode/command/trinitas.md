# /trinitas - Trinitas System Command

Execute Trinitas multi-agent orchestration operations.

## Usage

```
/trinitas <operation> [args] [--options]
```

## Available Operations

### Agent Operations

#### execute
Execute a task with a specific Trinitas agent.

```
/trinitas execute <agent> "<task_description>"
```

**Agents:**
- `athena` - System orchestration and coordination
- `artemis` - Performance optimization and code quality
- `hestia` - Security audit and risk assessment
- `eris` - Tactical coordination and conflict resolution
- `hera` - Strategic planning and architecture
- `muses` - Documentation and knowledge management
- `aphrodite` - UI/UX design
- `metis` - Implementation and testing
- `aurora` - Research and context retrieval

**Example:**
```
/trinitas execute artemis "Optimize database query performance"
```

### Analysis Operations

#### analyze
Run parallel analysis with multiple agents.

```
/trinitas analyze "<task>" --personas <agent1,agent2,...>
```

**Options:**
- `--personas`: Comma-separated list of agents (or "all" for all 9)
- `--mode`: Execution mode (parallel, sequential, wave)

**Example:**
```
/trinitas analyze "System architecture review" --personas athena,artemis,hestia
```

### Orchestration Operations

#### orchestrate
Create and manage phase-based orchestrations.

```
/trinitas orchestrate create "<title>" --content "<description>"
/trinitas orchestrate start <id>
/trinitas orchestrate status <id>
/trinitas orchestrate approve <id> --agent <agent_id>
/trinitas orchestrate list
```

**Example:**
```
/trinitas orchestrate create "Implement OAuth2" --content "Add OAuth2 authentication"
```

### Memory Operations

#### remember
Store information in TMWS semantic memory.

```
/trinitas remember <namespace> "<content>" [--importance <0.0-1.0>]
```

**Example:**
```
/trinitas remember project_decisions "Use SQLite for TMWS" --importance 0.9
```

#### recall
Search semantic memory.

```
/trinitas recall "<query>" [--namespace <ns>] [--limit <n>]
```

**Example:**
```
/trinitas recall "authentication decisions" --limit 5
```

### Verification Operations

#### verify
Execute verification and update trust scores.

```
/trinitas verify <agent> "<claim>" --command "<verification_command>"
```

**Example:**
```
/trinitas verify artemis "All tests pass" --command "pytest tests/"
```

#### trust
Check agent trust scores.

```
/trinitas trust <agent>
/trinitas trust --all
```

### Status Operations

#### status
Check system status.

```
/trinitas status           # Overall status
/trinitas status memory    # Memory system
/trinitas status agents    # All 9 agents
/trinitas status tmws      # TMWS connection
```

## Full Mode Execution

For complex multi-phase tasks, use Trinitas Full Mode:

```
Trinitasフルモードで作業し、Athena+Heraが戦略分析後、
Erisを中心に指揮しつつ各エージェント間で協議して進めてください。
```

This activates:
1. **Phase 1**: Strategic Planning (Hera + Athena)
2. **Phase 2**: Implementation (Primary + Support agents)
3. **Phase 3**: Verification (Hestia + Aurora)
4. **Phase 4**: Documentation (Muses + Aphrodite)

Each phase requires approval before advancing.

## MCP Tool Mapping

| Command | TMWS MCP Tool |
|---------|---------------|
| remember | `store_memory` |
| recall | `search_memories` |
| verify | `verify_and_record` |
| trust | `get_agent_trust_score` |
| orchestrate create | `create_orchestration` |
| orchestrate start | `start_orchestration` |
| orchestrate status | `get_orchestration_status` |
| orchestrate approve | `approve_phase` |
| status agents | `get_agent_status` |

## Examples

### Quick Agent Execution
```
/trinitas execute hestia "Review security of auth module"
```

### Parallel Analysis
```
/trinitas analyze "API performance review" --personas artemis,hestia,aurora
```

### Full Orchestration Workflow
```
/trinitas orchestrate create "Refactor payment module" --content "..."
/trinitas orchestrate start abc123
/trinitas orchestrate approve abc123 --agent hera-strategist
```

### Memory Operations
```
/trinitas remember architecture "Microservices pattern adopted" --importance 0.9
/trinitas recall "architecture decisions" --namespace project
```

---

*Trinitas System v2.4.8 - 9 Agents - Phase-Based Execution*
