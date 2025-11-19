"""Agent service for TMWS v2.0 - Universal Multi-Agent Platform.
Replaces PersonaService with universal agent management capabilities.
"""

import logging
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..core.exceptions import DatabaseError, NotFoundError, ValidationError
from ..models.agent import Agent, AgentNamespace, AgentTeam
from ..models.memory import Memory
from ..models.task import Task

logger = logging.getLogger(__name__)


class AgentService:
    """Universal agent management service.

    Provides comprehensive agent lifecycle management, namespace organization,
    and performance tracking for any AI agent type.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    # Agent CRUD Operations

    async def create_agent(
        self,
        agent_id: str,
        display_name: str,
        agent_type: str,
        agent_subtype: str | None = None,
        capabilities: dict[str, Any] = None,
        configuration: dict[str, Any] = None,
        namespace: str = "default",
        access_level: str = "standard",
        parent_agent_id: str | None = None,
        team_memberships: list[str] = None,
        learning_enabled: bool = True,
        adaptation_rate: float = 0.1,
    ) -> Agent:
        """Create a new agent with comprehensive configuration."""

        # Validate agent_id uniqueness
        existing = await self.get_agent_by_id(agent_id)
        if existing:
            raise ValidationError(f"Agent with ID '{agent_id}' already exists")

        # Validate parent agent exists if specified
        if parent_agent_id:
            parent = await self.get_agent_by_id(parent_agent_id)
            if not parent:
                raise ValidationError(f"Parent agent '{parent_agent_id}' not found")

        # Validate namespace exists
        namespace_exists = await self.namespace_exists(namespace)
        if not namespace_exists:
            # Auto-create namespace if it doesn't exist
            await self.create_namespace(
                namespace=namespace,
                display_name=f"Auto-created namespace: {namespace}",
                access_policy="private",
            )

        agent = Agent(
            agent_id=agent_id,
            display_name=display_name,
            agent_type=agent_type,
            agent_subtype=agent_subtype,
            capabilities=capabilities or {},
            configuration=configuration or {},
            namespace=namespace,
            access_level=access_level,
            parent_agent_id=parent_agent_id,
            team_memberships=team_memberships or [],
            learning_enabled=learning_enabled,
            adaptation_rate=adaptation_rate,
        )

        try:
            self.session.add(agent)
            await self.session.commit()
            await self.session.refresh(agent)

            logger.info(f"Created agent {agent_id}: {display_name} ({agent_type})")
            return agent

        except (KeyboardInterrupt, SystemExit):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Failed to create agent {agent_id}: {e}",
                exc_info=True,
                extra={"agent_id": agent_id, "agent_type": agent_type, "namespace": namespace},
            )
            raise DatabaseError(f"Failed to create agent: {e}") from e

    async def get_agent_by_id(self, agent_id: str) -> Agent | None:
        """Get an agent by their ID."""
        try:
            result = await self.session.execute(
                select(Agent)
                .where(Agent.agent_id == agent_id)
                .options(selectinload(Agent.tasks)),
            )
            return result.scalar_one_or_none()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to get agent {agent_id}: {e}",
                exc_info=True,
                extra={"agent_id": agent_id},
            )
            return None

    async def get_agent_by_display_name(
        self, display_name: str, namespace: str = None,
    ) -> Agent | None:
        """Get an agent by their display name, optionally within a namespace."""
        try:
            query = select(Agent).where(Agent.display_name == display_name)
            if namespace:
                query = query.where(Agent.namespace == namespace)

            result = await self.session.execute(query)
            return result.scalar_one_or_none()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to get agent by name {display_name}: {e}",
                exc_info=True,
                extra={"display_name": display_name, "namespace": namespace},
            )
            return None

    async def list_agents(
        self,
        namespace: str = None,
        agent_type: str = None,
        access_level: str = None,
        status: str = None,
        is_active: bool = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Agent]:
        """List agents with optional filtering."""
        try:
            query = select(Agent)

            # Apply filters
            conditions = []
            if namespace:
                conditions.append(Agent.namespace == namespace)
            if agent_type:
                conditions.append(Agent.agent_type == agent_type)
            if access_level:
                conditions.append(Agent.access_level == access_level)
            if status:
                conditions.append(Agent.status == status)
            if is_active is not None:
                conditions.append(Agent.is_active == is_active)

            if conditions:
                query = query.where(and_(*conditions))

            query = query.order_by(Agent.last_activity.desc()).limit(limit).offset(offset)

            result = await self.session.execute(query)
            return list(result.scalars().all())

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to list agents: {e}",
                exc_info=True,
                extra={
                    "namespace": namespace,
                    "agent_type": agent_type,
                    "access_level": access_level,
                    "status": status,
                    "is_active": is_active,
                },
            )
            return []

    async def update_agent(self, agent_id: str, updates: dict[str, Any]) -> Agent:
        """Update an existing agent.

        WARNING: This method does NOT have authorization checks for trust_score.
        Use update_agent_trust_score() for trust score modifications (V-TRUST-1 fix).
        """
        agent = await self.get_agent_by_id(agent_id)
        if not agent:
            raise NotFoundError(f"Agent {agent_id} not found")

        # V-TRUST-1: Prevent trust_score modification via update_agent
        if "trust_score" in updates:
            raise ValidationError(
                "Cannot update trust_score via update_agent(). "
                "Use update_agent_trust_score() with SYSTEM privilege instead."
            )

        try:
            # Apply updates
            for field, value in updates.items():
                if hasattr(agent, field):
                    setattr(agent, field, value)

            # Update activity timestamp
            agent.update_activity()

            await self.session.commit()
            await self.session.refresh(agent)

            logger.info(f"Updated agent {agent_id}")
            return agent

        except (KeyboardInterrupt, SystemExit):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Failed to update agent {agent_id}: {e}",
                exc_info=True,
                extra={"agent_id": agent_id, "updates": updates},
            )
            raise DatabaseError(f"Failed to update agent: {e}") from e

    async def update_agent_trust_score(
        self,
        agent_id: str,
        new_score: float,
        reason: str,
        requesting_user: "Any",  # User object with privilege verification
    ) -> float:
        """Update agent trust score with SYSTEM authorization (V-TRUST-1 fix).

        SECURITY-CRITICAL: Only SYSTEM users can modify trust scores directly.
        Regular trust score updates should go through TrustService.update_trust_score()
        which uses EWMA based on verification results.

        Args:
            agent_id: Target agent identifier
            new_score: New trust score (0.0-1.0)
            reason: Reason for score change (for audit log)
            requesting_user: User with SYSTEM privilege

        Returns:
            New trust score

        Raises:
            AuthorizationError: If requesting_user lacks SYSTEM privilege
            ValidationError: If new_score is out of range [0.0, 1.0]
            NotFoundError: If agent doesn't exist
            DatabaseError: If update fails

        Performance target: <5ms P95

        Example:
            >>> from src.core.authorization import User
            >>> admin_user = User(user_id="admin-1", role="system", is_admin=True)
            >>> new_score = await service.update_agent_trust_score(
            ...     agent_id="agent-123",
            ...     new_score=0.75,
            ...     reason="manual_override_after_review",
            ...     requesting_user=admin_user
            ... )
        """
        from src.core.authorization import verify_system_privilege

        # V-TRUST-1: Authorization check (SYSTEM privilege required)
        await verify_system_privilege(
            requesting_user,
            operation="update_trust_score",
            details={"agent_id": agent_id, "new_score": new_score, "reason": reason},
        )

        # Validate score range
        if not 0.0 <= new_score <= 1.0:
            raise ValidationError(
                f"trust_score must be in [0.0, 1.0], got {new_score}"
            )

        # Fetch agent
        agent = await self.get_agent_by_id(agent_id)
        if not agent:
            raise NotFoundError(f"Agent {agent_id} not found")

        try:
            # Store old score for audit
            old_score = agent.trust_score

            # Update trust_score in metadata_json (backward compatibility)
            # Some legacy code may read from Agent.metadata_json
            if "metadata_json" in agent.__dict__:
                metadata = agent.__dict__.get("metadata_json", {}) or {}
                metadata["trust_score"] = new_score
                agent.__dict__["metadata_json"] = metadata

            # Update Agent.trust_score field (primary source)
            agent.trust_score = new_score

            await self.session.commit()
            await self.session.refresh(agent)

            # AUDIT LOG: Trust score updated by SYSTEM user
            logger.warning(
                "trust_score_manual_override",
                extra={
                    "agent_id": agent_id,
                    "old_score": old_score,
                    "new_score": new_score,
                    "reason": reason,
                    "requesting_user_id": requesting_user.user_id,
                    "authorized": True,
                },
            )

            return new_score

        except (KeyboardInterrupt, SystemExit):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Failed to update trust score for agent {agent_id}: {e}",
                exc_info=True,
                extra={"agent_id": agent_id, "new_score": new_score},
            )
            raise DatabaseError(f"Failed to update trust score: {e}") from e

    async def deactivate_agent(self, agent_id: str) -> Agent:
        """Deactivate an agent (soft delete)."""
        return await self.update_agent(agent_id, {"is_active": False})

    async def activate_agent(self, agent_id: str) -> Agent:
        """Reactivate a deactivated agent."""
        return await self.update_agent(agent_id, {"is_active": True})

    async def delete_agent(self, agent_id: str, force: bool = False) -> bool:
        """Delete an agent (hard delete if force=True, otherwise soft delete)."""
        if not force:
            await self.deactivate_agent(agent_id)
            return True

        agent = await self.get_agent_by_id(agent_id)
        if not agent:
            return False

        try:
            await self.session.delete(agent)
            await self.session.commit()

            logger.info(f"Hard deleted agent {agent_id}")
            return True

        except (KeyboardInterrupt, SystemExit):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Failed to delete agent {agent_id}: {e}",
                exc_info=True,
                extra={"agent_id": agent_id, "force_delete": force},
            )
            raise DatabaseError(f"Failed to delete agent: {e}") from e

    # Agent Performance and Analytics

    async def get_agent_stats(self, agent_id: str) -> dict[str, Any]:
        """Get comprehensive statistics for an agent."""
        agent = await self.get_agent_by_id(agent_id)
        if not agent:
            raise NotFoundError(f"Agent {agent_id} not found")

        try:
            # Count memories
            memory_count = await self.session.scalar(
                select(func.count(Memory.id)).where(Memory.agent_id == agent_id),
            )

            # Count tasks
            task_count = await self.session.scalar(
                select(func.count(Task.id)).where(Task.assigned_agent_id == agent_id),
            )

            # Count completed tasks
            completed_tasks = await self.session.scalar(
                select(func.count(Task.id)).where(
                    and_(Task.assigned_agent_id == agent_id, Task.status == "completed"),
                ),
            )

            # Average quality score
            avg_quality = (
                await self.session.scalar(
                    select(func.avg(Task.quality_score)).where(
                        and_(Task.assigned_agent_id == agent_id, Task.quality_score.isnot(None)),
                    ),
                )
                or 0.0
            )

            # Calculate success rate
            success_rate = (completed_tasks / task_count) if task_count > 0 else 0.0

            return {
                "agent_id": agent_id,
                "display_name": agent.display_name,
                "agent_type": agent.agent_type,
                "namespace": agent.namespace,
                "is_active": agent.is_active,
                "performance_score": agent.performance_score,
                "capability_score": agent.capability_score,
                "total_memories": memory_count,
                "total_tasks": task_count,
                "completed_tasks": completed_tasks,
                "success_rate": success_rate,
                "average_quality_score": float(avg_quality),
                "last_activity": agent.last_activity.isoformat() if agent.last_activity else None,
                "created_at": agent.created_at.isoformat(),
                "updated_at": agent.updated_at.isoformat(),
            }

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to get agent stats for {agent_id}: {e}",
                exc_info=True,
                extra={"agent_id": agent_id},
            )
            raise DatabaseError(f"Failed to get agent stats: {e}") from e

    async def update_performance_metrics(self, agent_id: str) -> None:
        """Update agent performance metrics based on recent activity."""
        agent = await self.get_agent_by_id(agent_id)
        if not agent:
            return

        try:
            # Get recent task performance (last 30 days)
            from datetime import datetime, timedelta

            thirty_days_ago = datetime.utcnow() - timedelta(days=30)

            # Calculate performance score based on recent tasks
            recent_tasks = await self.session.execute(
                select(Task).where(
                    and_(
                        Task.assigned_agent_id == agent_id,
                        Task.completed_at >= thirty_days_ago,
                        Task.status == "completed",
                    ),
                ),
            )

            tasks = list(recent_tasks.scalars().all())
            if tasks:
                # Performance factors: quality, efficiency, success rate
                quality_scores = [t.quality_score for t in tasks if t.quality_score is not None]
                efficiency_scores = [
                    t.efficiency_score for t in tasks if t.efficiency_score is not None
                ]

                avg_quality = sum(quality_scores) / len(quality_scores) if quality_scores else 5.0
                avg_efficiency = (
                    sum(efficiency_scores) / len(efficiency_scores) if efficiency_scores else 1.0
                )

                # Calculate composite performance score (0-10 scale)
                performance_score = min(10.0, (avg_quality + avg_efficiency * 5.0) / 2.0)
                agent.update_performance_score(performance_score)

            # Update counters
            memory_count = await self.session.scalar(
                select(func.count(Memory.id)).where(Memory.agent_id == agent_id),
            )
            task_count = await self.session.scalar(
                select(func.count(Task.id)).where(Task.assigned_agent_id == agent_id),
            )

            agent.total_memories = memory_count or 0
            agent.total_tasks = task_count or 0
            agent.update_activity()

            await self.session.commit()

        except (KeyboardInterrupt, SystemExit):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Failed to update performance metrics for {agent_id}: {e}",
                exc_info=True,
                extra={"agent_id": agent_id},
            )

    # Agent Memory Management

    async def get_agent_memories(
        self,
        agent_id: str,
        memory_type: str = None,
        access_level: str = None,
        is_archived: bool = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Memory]:
        """Get memories associated with an agent."""
        try:
            query = select(Memory).where(Memory.agent_id == agent_id)

            if memory_type:
                query = query.where(Memory.memory_type == memory_type)
            if access_level:
                query = query.where(Memory.access_level == access_level)
            if is_archived is not None:
                query = query.where(Memory.is_archived == is_archived)

            query = query.order_by(Memory.accessed_at.desc()).limit(limit).offset(offset)

            result = await self.session.execute(query)
            return list(result.scalars().all())

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to get memories for agent {agent_id}: {e}",
                exc_info=True,
                extra={
                    "agent_id": agent_id,
                    "memory_type": memory_type,
                    "access_level": access_level,
                },
            )
            return []

    async def get_agent_tasks(
        self,
        agent_id: str,
        status: str = None,
        task_type: str = None,
        include_collaborating: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Task]:
        """Get tasks associated with an agent."""
        try:
            if include_collaborating:
                # Include tasks where agent is assigned or collaborating
                query = select(Task).where(
                    (Task.assigned_agent_id == agent_id)
                    | (Task.collaborating_agents.contains([agent_id])),
                )
            else:
                query = select(Task).where(Task.assigned_agent_id == agent_id)

            if status:
                query = query.where(Task.status == status)
            if task_type:
                query = query.where(Task.task_type == task_type)

            query = query.order_by(Task.created_at.desc()).limit(limit).offset(offset)

            result = await self.session.execute(query)
            return list(result.scalars().all())

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to get tasks for agent {agent_id}: {e}",
                exc_info=True,
                extra={
                    "agent_id": agent_id,
                    "status": status,
                    "task_type": task_type,
                    "include_collaborating": include_collaborating,
                },
            )
            return []

    # Namespace Management

    async def create_namespace(
        self,
        namespace: str,
        display_name: str,
        description: str = None,
        parent_namespace: str = None,
        access_policy: str = "private",
        max_agents: int = None,
    ) -> AgentNamespace:
        """Create a new agent namespace."""
        existing = await self.get_namespace(namespace)
        if existing:
            raise ValidationError(f"Namespace '{namespace}' already exists")

        namespace_obj = AgentNamespace(
            namespace=namespace,
            display_name=display_name,
            description=description,
            parent_namespace=parent_namespace,
            access_policy=access_policy,
            max_agents=max_agents,
        )

        try:
            self.session.add(namespace_obj)
            await self.session.commit()
            await self.session.refresh(namespace_obj)

            logger.info(f"Created namespace: {namespace}")
            return namespace_obj

        except (KeyboardInterrupt, SystemExit):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Failed to create namespace {namespace}: {e}",
                exc_info=True,
                extra={"namespace": namespace, "access_policy": access_policy},
            )
            raise DatabaseError(f"Failed to create namespace: {e}") from e

    async def get_namespace(self, namespace: str) -> AgentNamespace | None:
        """Get a namespace by name."""
        try:
            result = await self.session.execute(
                select(AgentNamespace).where(AgentNamespace.namespace == namespace),
            )
            return result.scalar_one_or_none()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to get namespace {namespace}: {e}",
                exc_info=True,
                extra={"namespace": namespace},
            )
            return None

    async def namespace_exists(self, namespace: str) -> bool:
        """Check if a namespace exists."""
        result = await self.get_namespace(namespace)
        return result is not None

    async def list_namespaces(
        self, access_policy: str = None, is_active: bool = None, limit: int = 50, offset: int = 0,
    ) -> list[AgentNamespace]:
        """List namespaces with optional filtering."""
        try:
            query = select(AgentNamespace)

            conditions = []
            if access_policy:
                conditions.append(AgentNamespace.access_policy == access_policy)
            if is_active is not None:
                conditions.append(AgentNamespace.is_active == is_active)

            if conditions:
                query = query.where(and_(*conditions))

            query = query.order_by(AgentNamespace.namespace).limit(limit).offset(offset)

            result = await self.session.execute(query)
            return list(result.scalars().all())

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to list namespaces: {e}",
                exc_info=True,
                extra={"access_policy": access_policy, "is_active": is_active},
            )
            return []

    # Team Management

    async def create_team(
        self,
        team_id: str,
        display_name: str,
        description: str = None,
        namespace: str = "default",
        team_type: str = "collaborative",
        team_lead: str = None,
        max_members: int = None,
    ) -> AgentTeam:
        """Create a new agent team."""
        existing = await self.get_team(team_id)
        if existing:
            raise ValidationError(f"Team '{team_id}' already exists")

        team = AgentTeam(
            team_id=team_id,
            display_name=display_name,
            description=description,
            namespace=namespace,
            team_type=team_type,
            team_lead=team_lead,
            max_members=max_members,
        )

        try:
            self.session.add(team)
            await self.session.commit()
            await self.session.refresh(team)

            logger.info(f"Created team: {team_id}")
            return team

        except (KeyboardInterrupt, SystemExit):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Failed to create team {team_id}: {e}",
                exc_info=True,
                extra={"team_id": team_id, "namespace": namespace, "team_type": team_type},
            )
            raise DatabaseError(f"Failed to create team: {e}") from e

    async def get_team(self, team_id: str) -> AgentTeam | None:
        """Get a team by ID."""
        try:
            result = await self.session.execute(
                select(AgentTeam).where(AgentTeam.team_id == team_id),
            )
            return result.scalar_one_or_none()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to get team {team_id}: {e}",
                exc_info=True,
                extra={"team_id": team_id},
            )
            return None

    async def add_agent_to_team(self, team_id: str, agent_id: str) -> bool:
        """Add an agent to a team."""
        team = await self.get_team(team_id)
        if not team:
            raise NotFoundError(f"Team {team_id} not found")

        agent = await self.get_agent_by_id(agent_id)
        if not agent:
            raise NotFoundError(f"Agent {agent_id} not found")

        try:
            success = team.add_member(agent_id)
            if success:
                # Update agent's team memberships
                if team_id not in agent.team_memberships:
                    agent.team_memberships.append(team_id)

                await self.session.commit()
                logger.info(f"Added agent {agent_id} to team {team_id}")
                return True
            return False

        except (KeyboardInterrupt, SystemExit):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Failed to add agent {agent_id} to team {team_id}: {e}",
                exc_info=True,
                extra={"team_id": team_id, "agent_id": agent_id},
            )
            return False

    async def remove_agent_from_team(self, team_id: str, agent_id: str) -> bool:
        """Remove an agent from a team."""
        team = await self.get_team(team_id)
        if not team:
            return False

        agent = await self.get_agent_by_id(agent_id)
        if not agent:
            return False

        try:
            success = team.remove_member(agent_id)
            if success:
                # Update agent's team memberships
                if team_id in agent.team_memberships:
                    agent.team_memberships.remove(team_id)

                await self.session.commit()
                logger.info(f"Removed agent {agent_id} from team {team_id}")
                return True
            return False

        except (KeyboardInterrupt, SystemExit):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Failed to remove agent {agent_id} from team {team_id}: {e}",
                exc_info=True,
                extra={"team_id": team_id, "agent_id": agent_id},
            )
            return False

    # Migration and Compatibility

    async def migrate_from_personas(self) -> dict[str, Any]:
        """Migrate existing Persona data to Agent format."""
        try:
            # This would be implemented to migrate data from the old persona table
            # For now, create default Trinitas agents
            default_agents = Agent.create_default_agents()
            created_agents = []

            for agent_data in default_agents:
                try:
                    agent = await self.create_agent(**agent_data)
                    created_agents.append(agent.agent_id)
                except ValidationError:
                    # Agent already exists, skip
                    logger.info(f"Agent {agent_data['agent_id']} already exists, skipping")
                    continue

            logger.info(f"Migration complete: created {len(created_agents)} agents")
            return {"created_agents": created_agents, "total_created": len(created_agents)}

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(f"Migration failed: {e}", exc_info=True)
            raise DatabaseError(f"Migration failed: {e}") from e

    # Search and Discovery

    async def search_agents(
        self, query: str, namespace: str = None, agent_type: str = None, limit: int = 20,
    ) -> list[Agent]:
        """Search agents by name, capabilities, or other attributes."""
        try:
            # Simple text search - could be enhanced with full-text search
            search_query = select(Agent).where(
                (Agent.display_name.ilike(f"%{query}%"))
                | (Agent.agent_id.ilike(f"%{query}%"))
                | (Agent.agent_type.ilike(f"%{query}%")),
            )

            if namespace:
                search_query = search_query.where(Agent.namespace == namespace)
            if agent_type:
                search_query = search_query.where(Agent.agent_type == agent_type)

            search_query = search_query.where(Agent.is_active).limit(limit)

            result = await self.session.execute(search_query)
            return list(result.scalars().all())

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to search agents with query '{query}': {e}",
                exc_info=True,
                extra={"query": query, "namespace": namespace, "agent_type": agent_type},
            )
            return []

    async def get_recommended_agents(
        self,
        _task_type: str = None,
        capabilities: list[str] = None,
        namespace: str = None,
        limit: int = 10,
    ) -> list[Agent]:
        """Get recommended agents based on task requirements."""
        try:
            query = select(Agent).where(Agent.is_active)

            if namespace:
                query = query.where(Agent.namespace == namespace)

            # Order by performance score and capability match
            query = query.order_by(Agent.performance_score.desc()).limit(limit * 2)

            result = await self.session.execute(query)
            candidates = list(result.scalars().all())

            # Sophisticated matching based on capabilities
            scored_agents = []
            for agent in candidates:
                score = 0.0

                # Base score from performance
                score += agent.performance_score * 0.3

                # Capability matching score
                if capabilities and agent.capabilities:
                    agent_caps = set(agent.capabilities.get("skills", []))
                    required_caps = set(capabilities)
                    if required_caps:
                        overlap = len(agent_caps & required_caps)
                        total = len(required_caps)
                        capability_score = (overlap / total) if total > 0 else 0
                        score += capability_score * 0.4

                # Success rate factor
                if agent.successful_tasks > 0 and agent.total_tasks > 0:
                    success_rate = agent.successful_tasks / agent.total_tasks
                    score += success_rate * 0.2

                # Health score factor
                score += agent.health_score * 0.1

                scored_agents.append((score, agent))

            # Sort by score and return top matches
            scored_agents.sort(key=lambda x: x[0], reverse=True)
            return [agent for _, agent in scored_agents[:limit]]

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Failed to get recommended agents: {e}",
                exc_info=True,
                extra={
                    "task_type": _task_type,
                    "capabilities": capabilities,
                    "namespace": namespace,
                },
            )
            return []
