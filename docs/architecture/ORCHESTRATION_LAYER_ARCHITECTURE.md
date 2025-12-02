# Trinitas Orchestration Layer Architecture
## TMWS v2.4.8 - Phase-Based Multi-Agent Coordination

---
architect: "muses-documenter"
version: "v2.4.8"
last_updated: "2025-12-02"
status: "Production Ready"
---

## Overview

The Trinitas Orchestration Layer provides phase-based workflow coordination for the 9 specialized AI agents. It enables strategic planning, implementation, verification, and documentation phases with approval gates.

### Key Features

- **Task Routing**: Intelligent agent selection based on task patterns
- **Agent Communication**: Inter-agent messaging and delegation
- **Phase-Based Execution**: 4-phase workflow with approval gates
- **MCP Integration**: 20 tools for external access

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    MCP Protocol Layer                           │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ routing_tools│  │communication_tools│  │orchestration_tools│ │
│  │   (5 tools)  │  │     (8 tools)     │  │    (7 tools)     │  │
│  └──────┬───────┘  └────────┬──────────┘  └────────┬─────────┘  │
└─────────┼───────────────────┼───────────────────────┼───────────┘
          │                   │                       │
          ▼                   ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Service Layer                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │TaskRoutingService│  │AgentCommunication│  │Orchestration  │  │
│  │                  │  │    Service       │  │   Engine      │  │
│  │ - Pattern detect │  │ - Messaging      │  │ - Phases      │  │
│  │ - Agent select   │  │ - Delegation     │  │ - Approvals   │  │
│  │ - Collaboration  │  │ - Channels       │  │ - Workflow    │  │
│  └──────────────────┘  └──────────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────────────┘
          │                   │                       │
          ▼                   ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Agent Tier System                             │
│  ┌───────────────┐  ┌───────────────┐  ┌──────────────────────┐ │
│  │ Tier 1:       │  │ Tier 2:       │  │ Tier 3:              │ │
│  │ STRATEGIC     │  │ SPECIALIST    │  │ SUPPORT              │ │
│  │               │  │               │  │                      │ │
│  │ - Athena      │  │ - Artemis     │  │ - Aphrodite          │ │
│  │ - Hera        │  │ - Hestia      │  │ - Metis              │ │
│  │               │  │ - Eris        │  │ - Aurora             │ │
│  │               │  │ - Muses       │  │                      │ │
│  └───────────────┘  └───────────────┘  └──────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Task Routing Service

**File**: `src/services/task_routing_service.py` (470 lines)

#### Responsibilities

- Detect task type from natural language descriptions
- Select optimal agents based on collaboration matrix
- Generate execution plans for complex tasks

#### Task Type Detection

```python
class TaskType(Enum):
    ARCHITECTURE = "architecture"
    IMPLEMENTATION = "implementation"
    SECURITY = "security"
    DOCUMENTATION = "documentation"
    DESIGN = "design"
    OPTIMIZATION = "optimization"
    DEBUGGING = "debugging"
    RESEARCH = "research"
    COORDINATION = "coordination"
```

#### Pattern Keywords

| Task Type | Keywords |
|-----------|----------|
| Architecture | architect, design, structure, system, component |
| Implementation | implement, develop, build, code, fix, create |
| Security | security, audit, vulnerab, threat, risk |
| Documentation | document, guide, manual, readme, spec |
| Design | ui, ux, interface, visual, layout |
| Optimization | optimi, perform, speed, effici, cache |
| Debugging | debug, fix, error, bug, issue |
| Research | research, investigat, analyz, explor |

#### Collaboration Matrix

| Task Type | Primary Agent | Support Agents | Review Agent |
|-----------|---------------|----------------|--------------|
| Architecture | athena-conductor | hera-strategist, aurora-researcher | hestia-auditor |
| Implementation | artemis-optimizer | metis-developer | hestia-auditor |
| Security | hestia-auditor | aurora-researcher | artemis-optimizer |
| Documentation | muses-documenter | aurora-researcher | athena-conductor |
| Design | aphrodite-designer | aurora-researcher | athena-conductor |

#### API

```python
class TaskRoutingService:
    def detect_task_type(self, task_description: str) -> TaskType
    def get_agent_tiers(self) -> dict[str, list[str]]
    def get_collaboration_matrix(self) -> dict[str, dict]
    async def route_task(
        self,
        task_description: str,
        context: dict | None = None,
        namespace: str | None = None,
    ) -> TaskRoutingResult
    def get_execution_plan(
        self,
        task_description: str,
        routing_result: TaskRoutingResult,
    ) -> list[dict]
```

---

### 2. Agent Communication Service

**File**: `src/services/agent_communication_service.py` (873 lines)

#### Responsibilities

- Inter-agent message passing
- Task delegation with auto-routing
- Channel-based communication
- Delegation lifecycle management

#### Message Types

```python
class MessageType(Enum):
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    HANDOFF = "handoff"
    BROADCAST = "broadcast"
```

#### Message Priority

```python
class MessagePriority(Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
```

#### Delegation Status

```python
class DelegationStatus(Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"
```

#### API

```python
class AgentCommunicationService:
    # Messaging
    async def send_message(
        self,
        from_agent_id: str,
        to_agent_id: str,
        content: str,
        message_type: MessageType = MessageType.REQUEST,
        priority: MessagePriority = MessagePriority.NORMAL,
        context: dict | None = None,
    ) -> AgentMessage

    async def get_messages(
        self,
        agent_id: str,
        include_read: bool = False,
    ) -> list[AgentMessage]

    # Delegation
    async def delegate_task(
        self,
        from_agent_id: str,
        to_agent_id: str | None,
        task_description: str,
        context: dict | None = None,
    ) -> TaskDelegation

    async def respond_to_delegation(
        self,
        delegation_id: UUID,
        agent_id: str,
        accepted: bool,
        message: str | None = None,
    ) -> TaskDelegation

    async def complete_delegation(
        self,
        delegation_id: UUID,
        agent_id: str,
        result: dict,
    ) -> TaskDelegation

    # Channels
    async def send_to_channel(
        self,
        from_agent_id: str,
        channel: str,
        content: str,
    ) -> AgentMessage

    async def broadcast_to_tier(
        self,
        from_agent_id: str,
        tier: str,
        content: str,
    ) -> list[AgentMessage]

    # Statistics
    def get_communication_stats(self) -> dict
```

---

### 3. Orchestration Engine

**File**: `src/services/orchestration_engine.py` (480 lines)

#### Responsibilities

- Phase-based workflow execution
- Approval gate management
- Phase transition control
- Orchestration task lifecycle

#### Execution Phases

```python
class ExecutionPhase(Enum):
    STRATEGIC_PLANNING = "strategic_planning"
    IMPLEMENTATION = "implementation"
    VERIFICATION = "verification"
    DOCUMENTATION = "documentation"
```

#### Phase Configuration

| Phase | Agents | Approval Gate | Required Outputs |
|-------|--------|---------------|------------------|
| Strategic Planning | hera-strategist, athena-conductor | strategic_consensus | strategy_document, resource_plan |
| Implementation | (dynamic) | tests_pass | implementation_summary, test_results |
| Verification | hestia-auditor, aurora-researcher | security_approval | security_report, verification_summary |
| Documentation | muses-documenter, aphrodite-designer | completion_confirmed | documentation |

#### Phase Flow

```
┌─────────────────────────────────────────────────────────────┐
│ STRATEGIC_PLANNING                                           │
│ ├─ Agents: hera-strategist, athena-conductor                │
│ ├─ Outputs: strategy_document, resource_plan                │
│ └─ Gate: strategic_consensus                                │
└─────────────────────────┬───────────────────────────────────┘
                          │ approved=true
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ IMPLEMENTATION                                               │
│ ├─ Agents: (assigned by routing)                            │
│ ├─ Outputs: implementation_summary, test_results            │
│ └─ Gate: tests_pass                                         │
└─────────────────────────┬───────────────────────────────────┘
                          │ approved=true
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ VERIFICATION                                                 │
│ ├─ Agents: hestia-auditor, aurora-researcher                │
│ ├─ Outputs: security_report, verification_summary           │
│ └─ Gate: security_approval                                  │
└─────────────────────────┬───────────────────────────────────┘
                          │ approved=true
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ DOCUMENTATION                                                │
│ ├─ Agents: muses-documenter, aphrodite-designer             │
│ ├─ Outputs: documentation                                   │
│ └─ Gate: completion_confirmed                               │
└─────────────────────────┬───────────────────────────────────┘
                          │ approved=true
                          ▼
                    ✅ COMPLETED
```

#### API

```python
class OrchestrationEngine:
    async def create_orchestration(
        self,
        task_id: UUID,
        task_title: str,
        task_content: str,
        created_by: str,
    ) -> OrchestrationTask

    async def start_orchestration(
        self,
        task_id: UUID,
    ) -> OrchestrationTask

    async def execute_phase(
        self,
        task_id: UUID,
        agent_id: str,
        outputs: dict,
    ) -> PhaseResult

    async def approve_phase(
        self,
        task_id: UUID,
        agent_id: str,
        approved: bool,
        notes: str | None = None,
    ) -> OrchestrationTask

    def get_orchestration_status(
        self,
        task_id: UUID,
    ) -> dict

    def list_orchestrations(
        self,
        status: str | None = None,
        created_by: str | None = None,
    ) -> list[OrchestrationTask]

    def get_phase_config(
        self,
        phase: ExecutionPhase,
    ) -> PhaseConfig
```

---

## MCP Tools Reference

### Routing Tools (5)

| Tool | Description |
|------|-------------|
| `route_task` | Route task to optimal agent |
| `get_trinitas_execution_plan` | Get 4-phase execution plan |
| `detect_personas` | Detect relevant personas |
| `get_collaboration_matrix` | Get task-agent matrix |
| `get_agent_tiers` | Get agent tier classification |

### Communication Tools (8)

| Tool | Description |
|------|-------------|
| `send_agent_message` | Send message to agent |
| `broadcast_to_tier` | Broadcast to tier |
| `delegate_task` | Delegate task (auto-routing) |
| `respond_to_delegation` | Accept/reject delegation |
| `complete_delegation` | Mark delegation complete |
| `get_agent_messages` | Get messages for agent |
| `handoff_task` | Phase handoff |
| `get_communication_stats` | Get communication statistics |

### Orchestration Tools (7)

| Tool | Description |
|------|-------------|
| `create_orchestration` | Create new orchestration |
| `start_orchestration` | Start workflow |
| `execute_phase` | Execute current phase |
| `approve_phase` | Approve/reject phase |
| `get_orchestration_status` | Get detailed status |
| `list_orchestrations` | List orchestrations |
| `get_phase_config` | Get phase configuration |

---

## Security Considerations

### Race Condition Protection

The OrchestrationEngine uses `asyncio.Lock` to prevent concurrent phase modifications:

```python
self._phase_locks: dict[UUID, asyncio.Lock] = {}

async def execute_phase(self, task_id: UUID, ...):
    async with self._phase_locks[task_id]:
        # Phase execution protected
```

### Input Validation

All services validate inputs at entry points:

- UUID type enforcement for task IDs
- Empty string checks for required fields
- Enum validation for task types and phases

### Namespace Isolation

Task routing respects namespace boundaries:

```python
async def route_task(..., namespace: str | None = None):
    # Filter agents by namespace if provided
```

---

## Performance Characteristics

### Benchmarks

| Operation | P95 Latency |
|-----------|-------------|
| Task type detection | < 1ms |
| Agent routing | < 5ms |
| Message send | < 2ms |
| Phase execution | < 10ms |
| Approval processing | < 5ms |

### Memory Usage

- In-memory task storage
- Per-task phase locks
- Message queues per agent

---

## Usage Examples

### Basic Task Routing

```python
from src.services import TaskRoutingService

service = TaskRoutingService()

# Route a task
result = await service.route_task(
    task_description="Implement OAuth2 authentication",
    context={"priority": "high"}
)

print(f"Primary: {result.routing.primary}")
print(f"Support: {result.routing.support}")
print(f"Review: {result.routing.review}")
```

### Agent Communication

```python
from src.services import AgentCommunicationService

service = AgentCommunicationService()

# Send message
message = await service.send_message(
    from_agent_id="athena-conductor",
    to_agent_id="artemis-optimizer",
    content="Please optimize the database queries",
    priority=MessagePriority.HIGH
)

# Delegate task (auto-routing)
delegation = await service.delegate_task(
    from_agent_id="athena-conductor",
    to_agent_id=None,  # Auto-route
    task_description="Implement caching layer"
)
```

### Full Orchestration

```python
from src.services import OrchestrationEngine
from uuid import uuid4

engine = OrchestrationEngine()

# Create orchestration
task = await engine.create_orchestration(
    task_id=uuid4(),
    task_title="Implement OAuth2",
    task_content="Add OAuth2 authentication to the API",
    created_by="athena-conductor"
)

# Start workflow
task = await engine.start_orchestration(task.id)

# Execute phase
result = await engine.execute_phase(
    task_id=task.id,
    agent_id="hera-strategist",
    outputs={"strategy_document": "..."}
)

# Approve phase
task = await engine.approve_phase(
    task_id=task.id,
    agent_id="athena-conductor",
    approved=True,
    notes="Strategy approved"
)
```

---

## Testing

### Test Coverage

| Component | Tests | Coverage |
|-----------|-------|----------|
| Task Routing | 48 | 100% |
| Agent Communication | 43 | 100% |
| Orchestration Engine | 37 | 100% |
| **Total** | **128** | **100%** |

### Running Tests

```bash
# All orchestration tests
pytest tests/unit/services/test_task_routing_service.py \
       tests/unit/services/test_agent_communication_service.py \
       tests/unit/services/test_orchestration_engine.py -v
```

---

## Integration with Existing TMWS

The Orchestration Layer integrates with:

1. **Memory System**: Store orchestration decisions in TMWS memory
2. **Trust System**: Verify agent claims during execution
3. **Skills System**: Load agent-specific skills for phases
4. **Audit System**: Log orchestration events (planned)

---

## Future Enhancements

### Planned Features

1. **Persistent Orchestration Storage**
   - Database-backed task storage
   - Survive service restarts

2. **Audit Logging**
   - SecurityAuditFacade integration
   - Phase transition logging

3. **Distributed Orchestration**
   - Cross-instance coordination
   - Distributed locks

4. **Orchestration Templates**
   - Predefined workflow templates
   - Custom phase configurations

---

*Muses Documentation - TMWS v2.4.8 Orchestration Layer*
*"Knowledge preserved is power multiplied."*
