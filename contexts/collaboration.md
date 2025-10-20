# Collaboration Patterns Context v2.2.1

**Load Condition**: `full` context profile only
**Estimated Size**: ~2k tokens
**Integration**: Cross-agent collaboration patterns

---

## Collaboration Principles

### Trinity of Leadership

**Athena + Hera: Permanent Partnership**
- Always active together
- Athena focuses on harmony and integration
- Hera focuses on strategy and execution
- Joint decision-making for major changes

**Dynamic Specialist Activation**:
- Artemis: Technical excellence
- Hestia: Security vigilance
- Eris: Tactical coordination
- Muses: Knowledge preservation

---

## Multi-Agent Coordination Patterns

### Pattern 1: Comprehensive Analysis (3+ Agents)

**When to Use**: Complex problems requiring multiple perspectives

**Execution Flow**:
```python
# Phase 1: Parallel analysis by specialists
parallel_tasks = [
    {"agent": "athena-conductor", "task": "strategic_analysis"},
    {"agent": "artemis-optimizer", "task": "technical_feasibility"},
    {"agent": "hestia-auditor", "task": "security_assessment"}
]

# Execute in parallel
results = await execute_parallel(parallel_tasks)

# Phase 2: Integration by Athena
integrated = await athena.synthesize_perspectives(results)

# Phase 3: Strategic validation by Hera
validated = await hera.validate_strategy(integrated)

# Phase 4: Documentation by Muses
await muses.document(validated)
```

**Token Budget**:
- Athena: 1.5k (always loaded)
- Hera: 1.5k (always loaded)
- Specialists: 1.5k each (3 specialists = 4.5k)
- **Total**: ~7.5k tokens

---

### Pattern 2: Security-First Development

**When to Use**: Security-critical features, compliance requirements

**Hestia-Led Workflow**:
```python
# Step 1: Hestia threat modeling
threats = await hestia.threat_model({
    "feature": "user_authentication",
    "methodology": "STRIDE"
})

# Step 2: Artemis secure implementation
implementation = await artemis.implement_with_security({
    "threats": threats,
    "performance_target": "200ms",
    "security_requirements": hestia.get_requirements()
})

# Step 3: Hestia security validation
validation = await hestia.validate_implementation(implementation)

if not validation.passed:
    # Step 4: Athena mediates security vs performance
    balanced = await athena.balance_security_performance({
        "security_gaps": validation.gaps,
        "performance_impact": implementation.overhead
    })

    # Step 5: Artemis optimizes
    optimized = await artemis.optimize_for_security(balanced)

    # Step 6: Hestia final check
    final_validation = await hestia.final_security_check(optimized)

# Step 7: Muses documents security measures
await muses.document_security_implementation(final_validation)
```

---

### Pattern 3: Performance Optimization with Safety

**When to Use**: Performance issues affecting user experience

**Artemis-Led with Safety Checks**:
```python
# Step 1: Artemis identifies bottleneck
bottleneck = await artemis.profile_performance({
    "target": "/api/users",
    "metrics": ["latency", "throughput", "cpu", "memory"]
})

# Step 2: Artemis proposes optimization
optimization = await artemis.design_optimization(bottleneck)

# Step 3: Parallel validation
validation = await execute_parallel([
    {
        "agent": "hestia-auditor",
        "task": "security_impact_check",
        "data": optimization
    },
    {
        "agent": "athena-conductor",
        "task": "architecture_coherence_check",
        "data": optimization
    }
])

# Step 4: Hera validates ROI
roi = await hera.calculate_optimization_roi({
    "effort": optimization.implementation_hours,
    "benefit": optimization.performance_gain,
    "risk": validation.total_risk
})

if roi > 2.0:  # 2x ROI minimum
    # Step 5: Artemis implements
    result = await artemis.implement_optimization(optimization)

    # Step 6: Hestia validates no security regression
    security_check = await hestia.regression_test(result)

    # Step 7: Muses documents
    await muses.document_optimization({
        "optimization": optimization,
        "result": result,
        "roi": roi
    })
```

---

### Pattern 4: Emergency Response (Incident Coordination)

**When to Use**: Production incidents, critical issues

**Eris-Led Emergency Protocol**:
```python
# Step 1: Eris incident assessment
incident = await eris.assess_incident({
    "type": "service_down",
    "severity": "critical",
    "affected_users": 10000
})

# Step 2: Immediate parallel response
emergency_response = await execute_parallel([
    {
        "agent": "hestia-auditor",
        "task": "contain_security_threat",
        "priority": "critical"
    },
    {
        "agent": "artemis-optimizer",
        "task": "restore_service",
        "priority": "critical"
    },
    {
        "agent": "athena-conductor",
        "task": "stakeholder_communication",
        "priority": "high"
    }
])

# Step 3: Eris coordinates recovery
recovery_plan = await eris.coordinate_recovery({
    "containment": emergency_response.hestia,
    "technical_fix": emergency_response.artemis,
    "communication": emergency_response.athena
})

# Step 4: Hera strategic decision (if needed)
if recovery_plan.requires_major_decision:
    strategic_decision = await hera.emergency_decision(recovery_plan)
    recovery_plan = strategic_decision

# Step 5: Execute recovery
await eris.execute_recovery(recovery_plan)

# Step 6: Post-mortem by Muses
await muses.document_incident({
    "incident": incident,
    "response": emergency_response,
    "recovery": recovery_plan,
    "lessons_learned": eris.extract_lessons(recovery_plan)
})

# Step 7: Learn from incident (TMWS)
await tmws.learning.learn_pattern({
    "pattern_name": f"incident_{incident.type}_response",
    "result": "Successfully recovered in {recovery_plan.duration}",
    "context": recovery_plan.details
})
```

---

## Conflict Resolution Protocols

### Technical vs Security Conflict (Artemis vs Hestia)

**Scenario**: Performance optimization compromises security

**Resolution Process**:
```python
def resolve_performance_security_conflict(artemis_proposal, hestia_concern):
    # Priority matrix
    if hestia_concern.severity == "critical":
        # Security always wins for critical issues
        return {
            "decision": "security_first",
            "action": "find_alternative_optimization",
            "next_step": artemis.find_secure_alternative(artemis_proposal)
        }

    elif hestia_concern.severity == "high" and artemis_proposal.impact > 0.5:
        # High security concern + major performance gain → Balanced approach
        balanced = athena.find_balanced_solution({
            "security_requirement": hestia_concern.minimum_security,
            "performance_target": artemis_proposal.target * 0.8  # 80% of goal
        })

        # Validate with both
        if artemis.validate(balanced) and hestia.validate(balanced):
            return {"decision": "balanced", "action": balanced}

    else:
        # Lower severity → Performance can proceed with monitoring
        monitored_implementation = artemis.implement_with_monitoring({
            "optimization": artemis_proposal,
            "security_monitors": hestia.get_monitoring_requirements()
        })

        return {"decision": "monitored_optimization", "action": monitored_implementation}
```

---

### Strategic vs Tactical Conflict (Hera vs Eris)

**Scenario**: Long-term strategy conflicts with immediate tactical needs

**Resolution Process**:
```python
def resolve_strategy_tactics_conflict(hera_strategy, eris_tactics):
    # Athena mediates
    mediation = athena.mediate_strategic_tactical({
        "long_term_goal": hera_strategy.objective,
        "immediate_need": eris_tactics.urgency,
        "resource_constraint": current_resources
    })

    if mediation.reconcilable:
        # Find phased approach
        phased_plan = {
            "phase_1": eris_tactics.immediate_actions,  # Tactical wins short-term
            "phase_2": hera_strategy.foundational_work,  # Strategic wins long-term
            "transition": mediation.transition_plan
        }

        # Both validate
        if hera.validate_strategic_alignment(phased_plan) and \
           eris.validate_tactical_feasibility(phased_plan):
            return phased_plan

    else:
        # Escalate to stakeholder decision
        return athena.escalate_for_decision({
            "strategic_case": hera_strategy,
            "tactical_case": eris_tactics,
            "recommendation": athena.recommend_priority()
        })
```

---

## Communication Patterns

### Broadcast Communication

**When to Use**: System-wide announcements, critical updates

```python
class BroadcastChannel:
    async def notify_all_agents(self, event, data):
        """Broadcast to all active agents"""
        notifications = []

        for agent in active_agents:
            if agent.is_interested_in(event):
                response = await agent.handle_notification(event, data)
                notifications.append(response)

        # Aggregate responses
        return aggregate_responses(notifications)

# Example: Security vulnerability announcement
await broadcast.notify_all_agents(
    event="critical_vulnerability",
    data={
        "cve": "CVE-2025-12345",
        "severity": "critical",
        "affected_component": "auth_service",
        "action_required": True
    }
)
```

### Point-to-Point Communication

**When to Use**: Specialized collaboration, targeted requests

```python
class DirectChannel:
    async def request_expertise(self, from_agent, to_agent, query):
        """Direct agent-to-agent communication"""

        if not to_agent.is_available():
            # Queue or find alternative
            return await self.handle_unavailable(query)

        # Direct expertise request
        response = await to_agent.provide_expertise(query)

        # Requestor processes response
        return await from_agent.process_response(response)

# Example: Artemis asks Hestia about security implications
security_advice = await direct.request_expertise(
    from_agent=artemis,
    to_agent=hestia,
    query={
        "type": "security_review",
        "optimization": proposed_cache_strategy,
        "concern": "data_exposure_risk"
    }
)
```

---

## Load Balancing & Resource Management

### Dynamic Load Balancing (Hera-Managed)

```python
class LoadBalancer:
    def __init__(self):
        self.agent_loads = {
            "athena-conductor": 0.0,
            "artemis-optimizer": 0.0,
            "hestia-auditor": 0.0,
            "eris-coordinator": 0.0,
            "hera-strategist": 0.0,
            "muses-documenter": 0.0
        }

    async def distribute_tasks(self, tasks):
        """Hera-optimized task distribution"""

        for task in sorted(tasks, key=lambda t: t.priority, reverse=True):
            # Find suitable agents
            suitable = self.find_suitable_agents(task)

            # Select least loaded
            selected = min(
                suitable,
                key=lambda agent: self.agent_loads[agent]
            )

            # Assign task
            await self.assign_task(selected, task)

            # Update load
            self.agent_loads[selected] += task.estimated_load

    def find_suitable_agents(self, task):
        """Match task to agent capabilities"""
        suitable = []

        if "performance" in task.tags:
            suitable.append("artemis-optimizer")
        if "security" in task.tags:
            suitable.append("hestia-auditor")
        if "architecture" in task.tags:
            suitable.append("athena-conductor")
        if "coordination" in task.tags:
            suitable.append("eris-coordinator")
        if "documentation" in task.tags:
            suitable.append("muses-documenter")

        return suitable if suitable else ["athena-conductor"]  # Default to Athena
```

---

## Parallel vs Sequential Execution

### Decision Matrix

| Condition | Execution Mode | Reason |
|-----------|---------------|--------|
| Tasks independent | Parallel | No dependencies, maximize speed |
| Tasks have dependencies | Sequential | Respect dependency order |
| Limited resources | Sequential | Avoid resource contention |
| Time-critical | Parallel | Speed over resource optimization |
| Quality-critical | Sequential | Thorough validation at each step |

### Implementation

```python
def determine_execution_mode(tasks):
    """Hera decides parallel vs sequential"""

    # Check dependencies
    has_dependencies = any(task.dependencies for task in tasks)

    if has_dependencies:
        # Topological sort for sequential execution
        return {
            "mode": "sequential",
            "order": topological_sort(tasks)
        }

    # Check resource availability
    total_load = sum(task.estimated_load for task in tasks)
    available_resources = get_available_resources()

    if total_load > available_resources:
        # Sequential to avoid overload
        return {
            "mode": "sequential",
            "order": sorted(tasks, key=lambda t: t.priority, reverse=True)
        }

    # Parallel execution possible
    return {
        "mode": "parallel",
        "groups": tasks  # All in one group
    }
```

---

## Best Practices

### 1. Always Consult Core Agents (Athena + Hera)

```python
# ✓ Good: Core agents involved
async def make_major_decision(proposal):
    athena_harmony = await athena.assess_harmony(proposal)
    hera_strategy = await hera.validate_strategy(proposal)

    if athena_harmony.score > 0.7 and hera_strategy.alignment > 0.8:
        return execute(proposal)

# ✗ Bad: Bypass core agents
async def make_major_decision(proposal):
    return execute(proposal)  # Missing coordination!
```

### 2. Respect Agent Specialization

```python
# ✓ Good: Right agent for the job
security_task = assign_to("hestia-auditor")
optimization_task = assign_to("artemis-optimizer")

# ✗ Bad: Wrong agent assignment
security_task = assign_to("artemis-optimizer")  # Should be Hestia!
```

### 3. Document Collaboration Outcomes

```python
# ✓ Good: Muses documents multi-agent decisions
collaboration_result = await multi_agent_analysis()
await muses.document_collaboration({
    "agents": ["athena", "artemis", "hestia"],
    "decision": collaboration_result.decision,
    "reasoning": collaboration_result.reasoning,
    "trade_offs": collaboration_result.trade_offs
})

# ✗ Bad: No documentation
collaboration_result = await multi_agent_analysis()
# Decision lost to history!
```

---

## Troubleshooting Collaboration Issues

### Issue: Coordination Overhead Too High

**Symptom**: Too much communication, slow progress

**Solution**:
```python
# Reduce synchronization points
optimized_workflow = {
    "async_communication": True,  # No blocking waits
    "batch_updates": True,         # Batched instead of real-time
    "reduce_approvals": True       # Trust agent expertise
}
```

### Issue: Conflict Deadlock

**Symptom**: Agents can't agree, no progress

**Solution**:
```python
if consensus_timeout(threshold=30):  # 30 seconds
    # Escalate to Hera for strategic decision
    decision = await hera.strategic_override({
        "conflict": current_conflict,
        "timeout": True,
        "urgency": "high"
    })

    # Notify all agents
    await broadcast.notify_all_agents("decision_override", decision)
```

### Issue: Load Imbalance

**Symptom**: Some agents overloaded, others idle

**Solution**:
```python
if detect_load_imbalance() > 0.3:  # 30% variance
    # Hera rebalances
    rebalanced = await hera.rebalance_workload({
        "strategy": "work_stealing",
        "from_agents": overloaded_agents,
        "to_agents": idle_agents
    })
```

---

**Collaboration Patterns v2.2.1**
*Multi-agent coordination for Trinitas system*
*Reference: @core/agents.md for agent roles*
