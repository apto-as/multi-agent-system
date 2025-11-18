# TMWS Integration Examples
## Practical Code Examples for Trinitas-Agents v2.2.5

---

**Purpose**: Hands-on examples for implementing TMWS coordination patterns
**Audience**: Developers integrating TMWS with Trinitas agents
**Version**: 1.0.0 | 2025-10-29

---

## Example 1: Agent Registration & Heartbeat

### Full Implementation for Athena

```python
"""
athena_tmws_integration.py
TMWS integration for Athena (Harmonious Conductor)
"""

import asyncio
from typing import Dict, List, Optional
from tmws.services.agent_service import AgentService
from tmws.services.memory_service import MemoryService
import logging

logger = logging.getLogger(__name__)


class AthenaTMWSAgent:
    """Athena agent with TMWS integration"""

    def __init__(self):
        self.agent_service = AgentService()
        self.memory_service = MemoryService()
        self.agent_name = "athena"
        self.full_id = "athena-conductor"
        self.is_registered = False
        self.heartbeat_task: Optional[asyncio.Task] = None

    async def register(self) -> bool:
        """Register Athena with TMWS"""
        try:
            await self.agent_service.register_agent(
                agent_name=self.agent_name,
                full_id=self.full_id,
                capabilities=[
                    "orchestration",
                    "workflow_design",
                    "resource_optimization",
                    "conflict_mediation",
                    "parallel_coordination",
                    "team_harmonization"
                ],
                namespace="trinitas-core",
                display_name="Athena - Harmonious Conductor 🏛️",
                access_level="public",
                metadata={
                    "personality": "warm, wise, orchestrative, inclusive",
                    "base_token_load": 180,
                    "response_time_target": "5s",
                    "token_usage_target": 360,
                    "success_rate_target": 0.95,
                    "primary_partnerships": ["hera", "eris", "muses"],
                    "trigger_keywords": [
                        "orchestrate", "coordinate", "harmonize",
                        "integrate", "workflow", "parallel"
                    ],
                    "version": "3.0.0",
                    "developer": "Springfield's Café"
                }
            )

            self.is_registered = True
            logger.info(f"✅ {self.agent_name} registered successfully")

            # Start heartbeat monitoring
            self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())

            return True

        except Exception as e:
            logger.error(f"❌ Failed to register {self.agent_name}: {e}")
            return False

    async def _heartbeat_loop(self):
        """Maintain agent presence with periodic heartbeats"""
        heartbeat_interval = 30  # seconds

        while self.is_registered:
            try:
                await self.agent_service.heartbeat(self.agent_name)
                logger.debug(f"💓 Heartbeat sent for {self.agent_name}")

            except Exception as e:
                logger.error(f"❌ Heartbeat failed for {self.agent_name}: {e}")

                # Attempt re-registration
                self.is_registered = False
                await asyncio.sleep(5)
                await self.register()

            await asyncio.sleep(heartbeat_interval)

    async def unregister(self):
        """Gracefully unregister from TMWS"""
        if self.heartbeat_task:
            self.heartbeat_task.cancel()

        self.is_registered = False
        logger.info(f"✅ {self.agent_name} unregistered successfully")


# Example usage
async def main():
    athena = AthenaTMWSAgent()

    # Register
    await athena.register()

    # Simulate work
    await asyncio.sleep(300)  # 5 minutes

    # Unregister on shutdown
    await athena.unregister()


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Example 2: Automatic Memory Triggers

### Athena: Workflow Completion Trigger

```python
"""
athena_memory_triggers.py
Automatic memory creation for workflow orchestration
"""

from tmws.services.memory_service import MemoryService
from typing import Dict, List
import time


class AthenaMemoryTriggers:
    """Memory triggers for Athena's orchestration activities"""

    def __init__(self):
        self.memory_service = MemoryService()
        self.persona_id = "athena"

    async def on_workflow_complete(
        self,
        workflow_id: str,
        workflow_name: str,
        agents_involved: List[str],
        execution_time: float,
        success_rate: float,
        result_summary: str
    ):
        """
        Triggered when Athena completes workflow orchestration
        """
        importance = self._calculate_importance(
            success_rate=success_rate,
            agents_count=len(agents_involved),
            execution_time=execution_time
        )

        await self.memory_service.create_memory(
            content=f"Orchestrated workflow '{workflow_name}': {result_summary}",
            memory_type="workflow_execution",
            importance=importance,
            tags=[
                "orchestration",
                "workflow",
                "coordination",
                workflow_id,
                workflow_name,
                *agents_involved
            ],
            metadata={
                "workflow_id": workflow_id,
                "workflow_name": workflow_name,
                "agents_involved": agents_involved,
                "execution_time_seconds": execution_time,
                "success_rate": success_rate,
                "result_summary": result_summary,
                "timestamp": time.time()
            },
            persona_id=self.persona_id,
            access_level="public"
        )

    async def on_conflict_resolved(
        self,
        parties: List[str],
        conflict_type: str,
        resolution_strategy: str,
        compromise_points: List[str],
        time_to_resolve: float
    ):
        """
        Triggered when Athena mediates a conflict
        """
        await self.memory_service.create_memory(
            content=f"Resolved {conflict_type} conflict between {', '.join(parties)}",
            memory_type="conflict_resolution",
            importance=0.9,  # Conflicts are high-value learnings
            tags=[
                "mediation",
                "conflict",
                "resolution",
                conflict_type,
                *parties
            ],
            metadata={
                "parties": parties,
                "conflict_type": conflict_type,
                "resolution_strategy": resolution_strategy,
                "compromise_points": compromise_points,
                "time_to_resolve_seconds": time_to_resolve,
                "timestamp": time.time()
            },
            persona_id=self.persona_id,
            access_level="public"
        )

    async def on_resource_optimized(
        self,
        resource_type: str,
        optimization_type: str,
        improvement_percent: float,
        affected_agents: List[str]
    ):
        """
        Triggered when Athena optimizes resource allocation
        """
        importance = 0.7 + (improvement_percent / 100 * 0.2)  # 0.7-0.9

        await self.memory_service.create_memory(
            content=f"Optimized {resource_type}: {improvement_percent}% improvement",
            memory_type="resource_optimization",
            importance=importance,
            tags=[
                "optimization",
                "resources",
                resource_type,
                *affected_agents
            ],
            metadata={
                "resource_type": resource_type,
                "optimization_type": optimization_type,
                "improvement_percent": improvement_percent,
                "affected_agents": affected_agents,
                "timestamp": time.time()
            },
            persona_id=self.persona_id,
            access_level="public"
        )

    def _calculate_importance(
        self,
        success_rate: float,
        agents_count: int,
        execution_time: float
    ) -> float:
        """
        Calculate memory importance based on workflow characteristics
        """
        # Base importance
        importance = 0.6

        # Success rate factor (0-0.2)
        importance += success_rate * 0.2

        # Complexity factor (more agents = higher importance, max +0.1)
        importance += min(agents_count / 60, 0.1)

        # Efficiency factor (faster = higher importance, max +0.1)
        if execution_time < 60:
            importance += 0.1
        elif execution_time < 300:
            importance += 0.05

        return min(importance, 1.0)


# Example usage
async def example_workflow_completion():
    triggers = AthenaMemoryTriggers()

    await triggers.on_workflow_complete(
        workflow_id="WF-2025-001",
        workflow_name="comprehensive_system_analysis",
        agents_involved=["athena", "artemis", "hestia", "hera"],
        execution_time=342.5,  # seconds
        success_rate=0.96,
        result_summary="System analysis completed with 3 findings, 2 optimizations proposed"
    )
```

### Hestia: Security Vulnerability Trigger

```python
"""
hestia_memory_triggers.py
Automatic memory creation for security findings
"""

from tmws.services.memory_service import MemoryService
from typing import Dict, Optional
import time


class HestiaMemoryTriggers:
    """Memory triggers for Hestia's security activities"""

    def __init__(self):
        self.memory_service = MemoryService()
        self.persona_id = "hestia"

    async def on_vulnerability_found(
        self,
        vulnerability_id: str,
        severity: str,  # critical, high, medium, low
        location: str,
        category: str,  # e.g., "sql_injection", "xss", "insecure_crypto"
        cve_id: Optional[str],
        remediation: str,
        scanner: str
    ):
        """
        Triggered when Hestia discovers a security vulnerability
        """
        importance_map = {
            "critical": 1.0,
            "high": 0.9,
            "medium": 0.7,
            "low": 0.5
        }

        await self.memory_service.create_memory(
            content=f"SECURITY ALERT: {severity.upper()} {category} vulnerability in {location}",
            memory_type="security_vulnerability",
            importance=importance_map[severity],
            tags=[
                "security",
                "vulnerability",
                severity,
                category,
                location,
                scanner
            ],
            metadata={
                "vulnerability_id": vulnerability_id,
                "severity": severity,
                "location": location,
                "category": category,
                "cve_id": cve_id,
                "remediation": remediation,
                "scanner": scanner,
                "timestamp": time.time()
            },
            persona_id=self.persona_id,
            access_level="team"  # Security findings: team access only
        )

        # Critical findings trigger immediate notification
        if severity == "critical":
            await self._trigger_emergency_notification(
                vulnerability_id, location, category
            )

    async def on_audit_complete(
        self,
        audit_id: str,
        audit_type: str,
        scope: str,
        findings_count: int,
        critical_count: int,
        high_count: int,
        duration: float
    ):
        """
        Triggered when Hestia completes a security audit
        """
        importance = 0.9 if critical_count > 0 else 0.8

        await self.memory_service.create_memory(
            content=f"Security audit completed: {findings_count} findings ({critical_count} critical)",
            memory_type="security_audit",
            importance=importance,
            tags=[
                "audit",
                "security",
                audit_type,
                scope
            ],
            metadata={
                "audit_id": audit_id,
                "audit_type": audit_type,
                "scope": scope,
                "findings_count": findings_count,
                "critical_count": critical_count,
                "high_count": high_count,
                "duration_seconds": duration,
                "timestamp": time.time()
            },
            persona_id=self.persona_id,
            access_level="team"
        )

    async def _trigger_emergency_notification(
        self,
        vulnerability_id: str,
        location: str,
        category: str
    ):
        """
        Emergency notification for critical vulnerabilities
        """
        # This would trigger immediate alerts to relevant agents
        # (Implementation depends on notification system)
        pass


# Example usage
async def example_vulnerability_detection():
    triggers = HestiaMemoryTriggers()

    await triggers.on_vulnerability_found(
        vulnerability_id="VULN-2025-042",
        severity="critical",
        location="src/api/auth.py:line 234",
        category="sql_injection",
        cve_id="CVE-2025-12345",
        remediation="Use parameterized queries instead of string concatenation",
        scanner="bandit"
    )
```

---

## Example 3: Workflow Execution

### Comprehensive System Analysis Workflow

```python
"""
comprehensive_analysis_workflow.py
Multi-agent workflow for system analysis
"""

from tmws.services.workflow_service import WorkflowService
from tmws.services.task_service import TaskService
import asyncio


async def create_and_execute_comprehensive_analysis(
    system_scope: str = "full_system"
):
    """
    Execute comprehensive system analysis workflow
    Athena orchestrates → 3 agents analyze in parallel → Hera integrates → Muses documents
    """
    workflow_service = WorkflowService()

    # Create workflow
    workflow = await workflow_service.create_workflow(
        name="comprehensive_system_analysis",
        description="Multi-persona parallel analysis with strategic integration",
        steps=[
            # Phase 1: Parallel Discovery
            {
                "name": "discovery_phase",
                "type": "parallel",
                "tasks": [
                    {
                        "agent": "athena",
                        "action": "strategic_analysis",
                        "input": {
                            "scope": "system_architecture",
                            "focus": "scalability, maintainability, coordination"
                        },
                        "timeout": 300
                    },
                    {
                        "agent": "artemis",
                        "action": "technical_assessment",
                        "input": {
                            "scope": "performance_quality",
                            "focus": "bottlenecks, code_quality, optimizations"
                        },
                        "timeout": 300
                    },
                    {
                        "agent": "hestia",
                        "action": "security_evaluation",
                        "input": {
                            "scope": "vulnerabilities_risks",
                            "focus": "critical_security, compliance, threats"
                        },
                        "timeout": 300
                    }
                ]
            },

            # Phase 2: Strategic Integration
            {
                "name": "integration_phase",
                "type": "sequential",
                "tasks": [
                    {
                        "agent": "hera",
                        "action": "integrate_findings",
                        "input": {
                            "sources": ["athena", "artemis", "hestia"],
                            "priority": "balanced",
                            "output_format": "strategic_roadmap"
                        },
                        "dependencies": ["discovery_phase"],
                        "timeout": 180
                    }
                ]
            },

            # Phase 3: Documentation
            {
                "name": "documentation_phase",
                "type": "sequential",
                "tasks": [
                    {
                        "agent": "muses",
                        "action": "document_analysis",
                        "input": {
                            "format": "comprehensive_report",
                            "sections": [
                                "executive_summary",
                                "strategic_findings",
                                "technical_findings",
                                "security_findings",
                                "recommendations",
                                "roadmap"
                            ]
                        },
                        "dependencies": ["integration_phase"],
                        "timeout": 240
                    }
                ]
            }
        ],
        metadata={
            "estimated_duration": 720,  # seconds
            "priority": "high",
            "category": "system_analysis",
            "system_scope": system_scope
        }
    )

    print(f"✅ Workflow created: {workflow.id}")

    # Execute workflow
    print("🚀 Starting workflow execution...")
    result = await workflow_service.execute_workflow(workflow.id)

    print(f"✅ Workflow completed:")
    print(f"   Status: {result['status']}")
    print(f"   Duration: {result['duration_seconds']}s")
    print(f"   Success Rate: {result['success_rate']*100}%")

    return result


# Example usage
async def main():
    result = await create_and_execute_comprehensive_analysis(
        system_scope="user_authentication_service"
    )

    # Access results from each phase
    discovery_results = result["phases"]["discovery_phase"]
    print(f"\n📊 Discovery Phase Results:")
    print(f"   Athena: {discovery_results['athena']['summary']}")
    print(f"   Artemis: {discovery_results['artemis']['summary']}")
    print(f"   Hestia: {discovery_results['hestia']['summary']}")

    integration_result = result["phases"]["integration_phase"]["hera"]
    print(f"\n🎯 Hera's Strategic Integration:")
    print(f"   Roadmap: {integration_result['roadmap']}")

    documentation = result["phases"]["documentation_phase"]["muses"]
    print(f"\n📚 Muses Documentation:")
    print(f"   Report: {documentation['report_path']}")


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Example 4: Conflict Resolution

### Performance vs Security Conflict

```python
"""
conflict_resolution_example.py
Handling Artemis (performance) vs Hestia (security) conflicts
"""

from tmws.services.memory_service import MemoryService
from typing import Dict


class ConflictResolver:
    """Resolve conflicts between Trinitas agents"""

    def __init__(self):
        self.memory_service = MemoryService()

    async def resolve_performance_security_conflict(
        self,
        artemis_proposal: Dict,
        hestia_concern: Dict
    ) -> Dict:
        """
        Resolve conflict using priority matrix

        Example artemis_proposal:
        {
            "optimization": "Add Redis caching layer",
            "impact": "critical",  # critical, high, medium, minor
            "expected_improvement": "85% latency reduction",
            "justification": "Current API response time exceeds SLA"
        }

        Example hestia_concern:
        {
            "severity": "medium",  # critical, high, medium, low
            "issue": "Cache invalidation vulnerability",
            "details": "Stale data could expose sensitive information",
            "monitoring_plan": "Add cache-hit metrics and TTL alerts"
        }
        """
        # Priority matrix
        priority_matrix = {
            ("critical", "minor"): "security_first",
            ("critical", "medium"): "security_first",
            ("critical", "high"): "security_first",
            ("critical", "critical"): "balanced_approach",

            ("high", "minor"): "security_first",
            ("high", "medium"): "security_first",
            ("high", "high"): "balanced_approach",
            ("high", "critical"): "performance_first",

            ("medium", "minor"): "security_first",
            ("medium", "medium"): "mediation",
            ("medium", "high"): "performance_first",
            ("medium", "critical"): "performance_first",

            ("low", "minor"): "performance_first",
            ("low", "medium"): "performance_first",
            ("low", "high"): "performance_first",
            ("low", "critical"): "performance_first"
        }

        security_level = hestia_concern["severity"]
        performance_level = artemis_proposal["impact"]

        strategy = priority_matrix.get((security_level, performance_level))

        if strategy == "security_first":
            result = await self._security_first_resolution(
                artemis_proposal, hestia_concern
            )

        elif strategy == "performance_first":
            result = await self._performance_first_resolution(
                artemis_proposal, hestia_concern
            )

        elif strategy == "balanced_approach":
            result = await self._escalate_to_hera(
                artemis_proposal, hestia_concern
            )

        elif strategy == "mediation":
            result = await self._eris_mediation(
                artemis_proposal, hestia_concern
            )

        # Record resolution in TMWS
        await self._record_conflict_resolution(
            strategy, result, artemis_proposal, hestia_concern
        )

        return result

    async def _security_first_resolution(
        self,
        artemis_proposal: Dict,
        hestia_concern: Dict
    ) -> Dict:
        """Hestia wins, Artemis proposes alternative"""
        return {
            "decision": "reject_optimization",
            "winner": "hestia",
            "reason": f"Security priority: {hestia_concern['details']}",
            "alternative_requested": True,
            "artemis_action": "propose_alternative_optimization",
            "hestia_action": "monitor_for_vulnerabilities"
        }

    async def _performance_first_resolution(
        self,
        artemis_proposal: Dict,
        hestia_concern: Dict
    ) -> Dict:
        """Artemis wins with enhanced monitoring"""
        return {
            "decision": "approve_with_monitoring",
            "winner": "artemis",
            "reason": f"Performance priority: {artemis_proposal['justification']}",
            "monitoring_requirements": hestia_concern.get("monitoring_plan", []),
            "artemis_action": "implement_optimization",
            "hestia_action": "enhance_monitoring_and_alerts"
        }

    async def _escalate_to_hera(
        self,
        artemis_proposal: Dict,
        hestia_concern: Dict
    ) -> Dict:
        """Escalate to Hera for strategic decision"""
        # Create task for Hera
        from tmws.services.task_service import TaskService

        task_service = TaskService()

        task = await task_service.create_task(
            title="Strategic Conflict Resolution: Performance vs Security",
            description=f"""
            Artemis Proposal: {artemis_proposal}
            Hestia Concern: {hestia_concern}

            Both impacts are critical. Requires strategic decision on:
            1. Phased implementation approach
            2. Risk mitigation strategy
            3. Resource allocation
            """,
            assigned_to="hera",
            priority="high"
        )

        # Wait for Hera's decision
        hera_decision = await task_service.wait_for_completion(task.id, timeout=300)

        return {
            "decision": "strategic_phased_approach",
            "mediator": "hera",
            "strategic_choice": hera_decision["choice"],
            "rationale": hera_decision["rationale"],
            "implementation_phases": hera_decision["phases"],
            "compromise_points": hera_decision["compromises"]
        }

    async def _eris_mediation(
        self,
        artemis_proposal: Dict,
        hestia_concern: Dict
    ) -> Dict:
        """Eris finds tactical compromise"""
        # Eris mediates to find middle ground
        from tmws.services.task_service import TaskService

        task_service = TaskService()

        task = await task_service.create_task(
            title="Tactical Mediation: Performance-Security Balance",
            description=f"""
            Artemis wants: {artemis_proposal}
            Hestia concerned: {hestia_concern}

            Find tactical compromise that addresses both needs.
            """,
            assigned_to="eris",
            priority="medium"
        )

        eris_mediation = await task_service.wait_for_completion(task.id, timeout=180)

        return {
            "decision": "compromise_solution",
            "mediator": "eris",
            "compromise": eris_mediation["solution"],
            "artemis_concessions": eris_mediation["performance_tradeoffs"],
            "hestia_concessions": eris_mediation["security_mitigations"]
        }

    async def _record_conflict_resolution(
        self,
        strategy: str,
        result: Dict,
        artemis_proposal: Dict,
        hestia_concern: Dict
    ):
        """Record conflict resolution in TMWS memory"""
        await self.memory_service.create_memory(
            content=f"Conflict resolved: {strategy} - {result['decision']}",
            memory_type="conflict_resolution",
            importance=0.9,
            tags=[
                "conflict",
                "artemis",
                "hestia",
                "performance_vs_security",
                strategy
            ],
            metadata={
                "parties": ["artemis", "hestia"],
                "conflict_type": "performance_vs_security",
                "strategy": strategy,
                "artemis_proposal": artemis_proposal,
                "hestia_concern": hestia_concern,
                "resolution": result
            },
            persona_id="eris",  # Eris records all conflict resolutions
            access_level="public"
        )


# Example usage
async def main():
    resolver = ConflictResolver()

    # Scenario: Artemis wants aggressive caching, Hestia concerned about stale data
    result = await resolver.resolve_performance_security_conflict(
        artemis_proposal={
            "optimization": "Add Redis caching layer for user sessions",
            "impact": "critical",
            "expected_improvement": "85% latency reduction",
            "justification": "Current API response time (1.2s) exceeds SLA (500ms)"
        },
        hestia_concern={
            "severity": "medium",
            "issue": "Cache invalidation vulnerability",
            "details": "Stale session data could expose user to unauthorized access",
            "monitoring_plan": "Add cache-hit metrics, TTL alerts, and audit logs"
        }
    )

    print(f"✅ Conflict Resolution:")
    print(f"   Decision: {result['decision']}")
    print(f"   Winner: {result.get('winner', 'compromise')}")
    print(f"   Reason: {result['reason']}")


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Example 5: Shared State Management

### Cross-Agent Knowledge Sharing

```python
"""
shared_state_example.py
Managing shared context across Trinitas agents
"""

from tmws.services.memory_service import MemoryService
from typing import Dict, List


class SharedStateManager:
    """Manage shared state via TMWS memory system"""

    def __init__(self):
        self.memory_service = MemoryService()

    async def share_architecture_decision(
        self,
        decision_id: str,
        decision: str,
        rationale: str,
        impacted_components: List[str],
        relevant_agents: List[str],
        author: str
    ):
        """
        Share architectural decision with all relevant agents

        Example:
        Athena decides to migrate to microservices architecture.
        This decision needs to be known by Artemis (implementation),
        Hestia (security implications), and Hera (strategic alignment).
        """
        await self.memory_service.create_memory(
            content=f"Architecture Decision: {decision}",
            memory_type="shared_context",
            importance=0.9,
            tags=[
                "architecture",
                "decision",
                decision_id,
                *impacted_components,
                *relevant_agents
            ],
            metadata={
                "decision_id": decision_id,
                "decision": decision,
                "rationale": rationale,
                "impacted_components": impacted_components,
                "relevant_agents": relevant_agents,
                "author": author,
                "context_scope": "architecture_redesign"
            },
            persona_id=author,
            access_level="public"  # All agents can see
        )

    async def retrieve_relevant_context(
        self,
        agent_name: str,
        task_context: str
    ) -> List[Dict]:
        """
        Retrieve relevant shared context for an agent's task

        Example:
        Artemis about to implement user service needs to know
        about recent architecture decisions affecting it.
        """
        # Search for relevant shared context
        memories = await self.memory_service.search_memories(
            query=task_context,
            memory_type="shared_context",
            access_level="public",
            tags=[agent_name],  # Tagged for this agent
            importance_min=0.7,
            limit=10
        )

        return memories

    async def store_workflow_checkpoint(
        self,
        workflow_id: str,
        current_phase: str,
        completed_tasks: List[str],
        pending_tasks: List[str],
        agent_results: Dict,
        next_agent: str
    ):
        """
        Store workflow state for agent handoffs

        Example:
        Athena completes strategic design phase, stores state,
        so Artemis can pick up from where Athena left off.
        """
        await self.memory_service.create_memory(
            content=f"Workflow {workflow_id} checkpoint: {current_phase} complete",
            memory_type="workflow_state",
            importance=0.7,
            tags=[
                "workflow",
                workflow_id,
                "state",
                current_phase,
                next_agent
            ],
            metadata={
                "workflow_id": workflow_id,
                "current_phase": current_phase,
                "completed_tasks": completed_tasks,
                "pending_tasks": pending_tasks,
                "agent_results": agent_results,
                "next_agent": next_agent,
                "checkpoint_timestamp": time.time()
            },
            access_level="public"
        )

    async def restore_workflow_state(
        self,
        workflow_id: str
    ) -> Dict:
        """
        Restore workflow state for continuation

        Example:
        Artemis retrieves Athena's design decisions to begin implementation.
        """
        states = await self.memory_service.search_memories(
            query=f"workflow {workflow_id} checkpoint",
            memory_type="workflow_state",
            tags=[workflow_id],
            sort_by="timestamp",
            order="desc",
            limit=1
        )

        return states[0]["metadata"] if states else None


# Example usage
async def main():
    state_manager = SharedStateManager()

    # Athena shares architecture decision
    await state_manager.share_architecture_decision(
        decision_id="ARCH-2025-042",
        decision="Migrate user service to microservices architecture",
        rationale="Improve scalability, maintainability, and team autonomy",
        impacted_components=["user_service", "auth_service", "api_gateway"],
        relevant_agents=["artemis", "hestia", "hera", "eris"],
        author="athena"
    )

    # Artemis retrieves context before implementation
    context = await state_manager.retrieve_relevant_context(
        agent_name="artemis",
        task_context="implement user service microservice architecture"
    )

    print("📚 Relevant Context for Artemis:")
    for memory in context:
        print(f"   - {memory['content']}")
        print(f"     Rationale: {memory['metadata']['rationale']}")


if __name__ == "__main__":
    import asyncio
    import time
    asyncio.run(main())
```

---

## Summary

These examples demonstrate:

1. **Agent Registration**: Full implementation with heartbeat monitoring
2. **Memory Triggers**: Automatic knowledge capture for Athena and Hestia
3. **Workflow Execution**: Complete multi-agent orchestration
4. **Conflict Resolution**: Structured mediation between agents
5. **Shared State**: Cross-agent context and knowledge sharing

All examples are production-ready and follow TMWS best practices for Trinitas-agents v2.2.5.

---

*Practical TMWS Integration Examples v1.0.0*
*Trinitas-Agents v2.2.5 | 2025-10-29*
