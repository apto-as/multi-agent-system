"""Task Service for TMWS
Handles task management and execution tracking
"""

import logging
from collections import deque
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..core.exceptions import NotFoundError, ValidationError
from ..models import Persona, Task
from .base_service import BaseService

logger = logging.getLogger(__name__)


class TaskService(BaseService):
    """Service for managing tasks."""

    def __init__(self, session: AsyncSession):
        super().__init__(session)

    async def create_task(
        self,
        title: str,
        description: str,
        task_type: str = "general",
        priority: str = "medium",
        assigned_persona_id: UUID | None = None,
        dependencies: list[str] = None,
        metadata: dict[str, Any] = None,
    ) -> Task:
        """Create a new task with circular dependency checking."""
        # Validate priority
        valid_priorities = ["low", "medium", "high", "critical"]
        if priority not in valid_priorities:
            raise ValidationError(
                f"Invalid priority: {priority}. Must be one of {valid_priorities}",
            )

        # Validate persona if assigned
        if assigned_persona_id:
            persona_result = await self.session.execute(
                select(Persona).where(Persona.id == assigned_persona_id),
            )
            if not persona_result.scalar_one_or_none():
                raise NotFoundError(f"Persona {assigned_persona_id} not found")

        # Check for circular dependencies before creating
        if dependencies:
            # Create temporary task ID for validation
            temp_task_id = UUID("00000000-0000-0000-0000-000000000000")
            if await self._would_create_circular_dependency(temp_task_id, dependencies):
                raise ValidationError("Cannot create task: would create circular dependency")

        task = Task(
            title=title,
            description=description,
            task_type=task_type,
            priority=priority,
            status="pending",
            progress=0.0,
            assigned_persona_id=assigned_persona_id,
            dependencies=dependencies or [],
            metadata_json=metadata or {},
        )

        self.session.add(task)
        await self.session.commit()
        await self.session.refresh(task)

        logger.info(f"Created task {task.id}: {title}")
        return task

    async def get_task(self, task_id: UUID) -> Task | None:
        """Get a task by ID."""
        result = await self.session.execute(
            select(Task).where(Task.id == task_id).options(selectinload(Task.assigned_persona)),
        )
        return result.scalar_one_or_none()

    async def update_task(self, task_id: UUID, updates: dict[str, Any]) -> Task:
        """Update an existing task."""
        task = await self.get_task(task_id)
        if not task:
            raise NotFoundError(f"Task {task_id} not found")

        # Update allowed fields
        allowed_fields = [
            "title",
            "description",
            "task_type",
            "priority",
            "status",
            "progress",
            "assigned_persona_id",
            "dependencies",
            "result",
            "metadata_json",
            "started_at",
            "completed_at",
        ]

        for key, value in updates.items():
            if key in allowed_fields:
                # Special handling for dependencies to check circular refs
                if key == "dependencies" and value:
                    if await self._would_create_circular_dependency(task_id, value):
                        raise ValidationError(
                            "Cannot update task: would create circular dependency",
                        )
                # Special handling for status changes
                elif key == "status":
                    await self._handle_status_change(task, value)
                else:
                    setattr(task, key, value)

        task.updated_at = datetime.utcnow()
        await self.session.commit()
        await self.session.refresh(task)

        logger.info(f"Updated task {task_id}")
        return task

    async def _handle_status_change(self, task: Task, new_status: str):
        """Handle special logic for status changes."""
        valid_statuses = ["pending", "in_progress", "completed", "failed", "cancelled"]
        if new_status not in valid_statuses:
            raise ValidationError(f"Invalid status: {new_status}")

        old_status = task.status
        task.status = new_status

        # Set timestamps based on status
        if new_status == "in_progress" and not task.started_at:
            task.started_at = datetime.utcnow()
        elif new_status in ["completed", "failed", "cancelled"] and not task.completed_at:
            task.completed_at = datetime.utcnow()
            if new_status == "completed":
                task.progress = 1.0

        logger.info(f"Task {task.id} status changed from {old_status} to {new_status}")

    async def delete_task(self, task_id: UUID) -> bool:
        """Delete a task."""
        task = await self.get_task(task_id)
        if not task:
            raise NotFoundError(f"Task {task_id} not found")

        await self.session.delete(task)
        await self.session.commit()

        logger.info(f"Deleted task {task_id}")
        return True

    async def list_tasks(
        self,
        status: str = None,
        priority: str = None,
        task_type: str = None,
        assigned_persona_id: UUID = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Task]:
        """List tasks with filters."""
        stmt = select(Task).options(selectinload(Task.assigned_persona))

        conditions = []
        if status:
            conditions.append(Task.status == status)
        if priority:
            conditions.append(Task.priority == priority)
        if task_type:
            conditions.append(Task.task_type == task_type)
        if assigned_persona_id:
            conditions.append(Task.assigned_persona_id == assigned_persona_id)

        if conditions:
            stmt = stmt.where(and_(*conditions))

        # Order by priority and creation date
        priority_order = func.case(
            (Task.priority == "critical", 1),
            (Task.priority == "high", 2),
            (Task.priority == "medium", 3),
            (Task.priority == "low", 4),
            else_=5,
        )

        stmt = stmt.order_by(priority_order, Task.created_at.desc())
        stmt = stmt.limit(limit).offset(offset)

        result = await self.session.execute(stmt)
        tasks = result.scalars().all()

        return tasks

    async def get_pending_tasks(
        self, assigned_persona_id: UUID = None, limit: int = 10,
    ) -> list[Task]:
        """Get pending tasks, optionally filtered by persona."""
        conditions = [Task.status == "pending"]
        if assigned_persona_id:
            conditions.append(Task.assigned_persona_id == assigned_persona_id)

        stmt = select(Task).where(and_(*conditions))
        stmt = stmt.order_by(Task.created_at)
        stmt = stmt.limit(limit)

        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_task_dependencies(self, task_id: UUID) -> list[Task]:
        """Get all tasks that this task depends on."""
        task = await self.get_task(task_id)
        if not task or not task.dependencies:
            return []

        # Dependencies are stored as task IDs
        dependency_ids = [UUID(dep) for dep in task.dependencies]

        stmt = select(Task).where(Task.id.in_(dependency_ids))
        result = await self.session.execute(stmt)

        return result.scalars().all()

    async def check_dependencies_met(self, task_id: UUID) -> bool:
        """Check if all dependencies for a task are completed."""
        dependencies = await self.get_task_dependencies(task_id)

        return all(dep.status == "completed" for dep in dependencies)

    async def count_active_tasks(self) -> int:
        """Count tasks that are pending or in progress."""
        stmt = select(func.count(Task.id)).where(
            or_(Task.status == "pending", Task.status == "in_progress"),
        )

        result = await self.session.execute(stmt)
        count = result.scalar()

        return count or 0

    async def get_task_stats(self) -> dict[str, Any]:
        """Get task statistics."""
        # Count by status
        status_counts_stmt = select(Task.status, func.count(Task.id).label("count")).group_by(
            Task.status,
        )

        status_counts_result = await self.session.execute(status_counts_stmt)
        status_counts = {row.status: row.count for row in status_counts_result}

        # Count by priority
        priority_counts_stmt = select(Task.priority, func.count(Task.id).label("count")).group_by(
            Task.priority,
        )

        priority_counts_result = await self.session.execute(priority_counts_stmt)
        priority_counts = {row.priority: row.count for row in priority_counts_result}

        # Average completion time for completed tasks
        completion_time_stmt = select(
            func.avg(func.extract("epoch", Task.completed_at - Task.started_at)),
        ).where(
            and_(
                Task.status == "completed",
                Task.started_at.isnot(None),
                Task.completed_at.isnot(None),
            ),
        )

        completion_time_result = await self.session.execute(completion_time_stmt)
        avg_completion_seconds = completion_time_result.scalar()

        return {
            "tasks_by_status": status_counts,
            "tasks_by_priority": priority_counts,
            "active_tasks": status_counts.get("pending", 0) + status_counts.get("in_progress", 0),
            "completed_tasks": status_counts.get("completed", 0),
            "failed_tasks": status_counts.get("failed", 0),
            "avg_completion_time_seconds": float(avg_completion_seconds)
            if avg_completion_seconds
            else None,
        }

    async def _would_create_circular_dependency(
        self, task_id: UUID, new_dependencies: list[str],
    ) -> bool:
        """Check if adding dependencies would create a circular dependency."""
        # Build dependency graph
        graph = await self._build_dependency_graph()

        # Add the proposed dependencies temporarily
        graph[str(task_id)] = [str(dep) for dep in new_dependencies]

        # Check for cycles using DFS
        return self._has_cycle(graph)

    async def _build_dependency_graph(self) -> dict[str, list[str]]:
        """Build a graph of task dependencies."""
        stmt = select(Task.id, Task.dependencies)
        result = await self.session.execute(stmt)

        graph = {}
        for task_id, deps in result:
            if deps:
                graph[str(task_id)] = [str(dep) for dep in deps]
            else:
                graph[str(task_id)] = []

        return graph

    def _has_cycle(self, graph: dict[str, list[str]]) -> bool:
        """Detect cycles in dependency graph using DFS."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color = dict.fromkeys(graph, WHITE)

        def visit(node: str) -> bool:
            if color[node] == GRAY:
                return True  # Back edge found, cycle detected
            if color[node] == BLACK:
                return False  # Already processed

            color[node] = GRAY
            for neighbor in graph.get(node, []):
                if neighbor in color and visit(neighbor):
                    return True
            color[node] = BLACK
            return False

        # Check each component
        return any(color[node] == WHITE and visit(node) for node in graph)

    async def get_task_execution_order(self) -> list[UUID]:
        """Get topologically sorted task execution order."""
        graph = await self._build_dependency_graph()

        # Kahn's algorithm for topological sort
        in_degree = dict.fromkeys(graph, 0)

        for node in graph:
            for neighbor in graph[node]:
                if neighbor in in_degree:
                    in_degree[neighbor] += 1

        queue = deque([node for node in in_degree if in_degree[node] == 0])
        result = []

        while queue:
            node = queue.popleft()
            result.append(UUID(node))

            for neighbor in graph.get(node, []):
                if neighbor in in_degree:
                    in_degree[neighbor] -= 1
                    if in_degree[neighbor] == 0:
                        queue.append(neighbor)

        # If we couldn't process all nodes, there's a cycle
        if len(result) != len(graph):
            logger.warning("Circular dependency detected in task graph")
            return []

        return result

    async def validate_task_graph(self) -> dict[str, Any]:
        """Validate the entire task dependency graph."""
        graph = await self._build_dependency_graph()
        has_cycle = self._has_cycle(graph)

        # Find orphaned tasks (tasks with dependencies that don't exist)
        all_task_ids = set(graph.keys())
        orphaned = []

        for task_id, deps in graph.items():
            for dep in deps:
                if dep not in all_task_ids:
                    orphaned.append({"task_id": task_id, "missing_dependency": dep})

        # Calculate dependency depth for each task
        depths = {}

        def calculate_depth(node: str, visited: set[str] = None) -> int:
            if visited is None:
                visited = set()

            if node in depths:
                return depths[node]

            if node in visited:
                return -1  # Cycle detected

            visited.add(node)

            if not graph.get(node):
                depths[node] = 0
            else:
                max_dep_depth = 0
                for dep in graph[node]:
                    if dep in graph:
                        dep_depth = calculate_depth(dep, visited.copy())
                        if dep_depth == -1:
                            depths[node] = -1
                            return -1
                        max_dep_depth = max(max_dep_depth, dep_depth)
                depths[node] = max_dep_depth + 1

            return depths[node]

        for task_id in graph:
            calculate_depth(task_id)

        return {
            "has_circular_dependencies": has_cycle,
            "orphaned_dependencies": orphaned,
            "task_count": len(graph),
            "max_dependency_depth": max(depths.values()) if depths else 0,
            "dependency_depths": depths,
            "is_valid": not has_cycle and len(orphaned) == 0,
        }
