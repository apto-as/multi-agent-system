"""Agent Communication Tools for TMWS MCP Server.

Provides inter-agent messaging and task delegation capabilities through MCP.
Part of the Trinitas multi-agent orchestration system.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from fastmcp import FastMCP

from ..services.agent_communication_service import (
    AgentCommunicationService,
    MessagePriority,
    MessageType,
)
from ..services.task_routing_service import AgentTier
from .base_tool import BaseTool


class CommunicationTools(BaseTool):
    """Agent communication tools for inter-agent messaging and delegation."""

    async def register_tools(self, mcp: FastMCP) -> None:
        """Register communication tools with FastMCP instance."""

        @mcp.tool()
        async def send_agent_message(
            from_agent: str,
            to_agents: list[str],
            content: str,
            message_type: str = "direct",
            priority: str = "medium",
            metadata: dict[str, Any] | None = None,
            requires_response: bool = False,
        ) -> dict[str, Any]:
            """Send a message from one agent to other agent(s).

            Enables inter-agent communication within the Trinitas system.
            Messages are queued and can be retrieved by recipient agents.

            Args:
                from_agent: Sending agent ID (e.g., "athena-conductor")
                to_agents: List of recipient agent IDs
                content: Message content
                message_type: Type of message (direct, broadcast, delegation, response, status, handoff)
                priority: Priority level (low, medium, high, urgent, critical)
                metadata: Additional message metadata
                requires_response: Whether recipients must respond

            Returns:
                Dict containing message details including message_id

            Example:
                send_agent_message(
                    from_agent="hera-strategist",
                    to_agents=["artemis-optimizer"],
                    content="Phase 1 planning complete. Ready for implementation.",
                    priority="high"
                )

            """
            async def _send_message(session, _services):
                comm_service = AgentCommunicationService(session)

                # Parse message type
                msg_type = MessageType.DIRECT
                for mt in MessageType:
                    if mt.value == message_type:
                        msg_type = mt
                        break

                # Parse priority
                msg_priority = MessagePriority.MEDIUM
                for p in MessagePriority:
                    if p.name.lower() == priority.lower():
                        msg_priority = p
                        break

                message = await comm_service.send_message(
                    from_agent=from_agent,
                    to_agents=to_agents,
                    content=content,
                    message_type=msg_type,
                    priority=msg_priority,
                    metadata=metadata,
                    requires_response=requires_response,
                )

                return {
                    "message_id": str(message.id),
                    "from_agent": message.from_agent,
                    "to_agents": message.to_agents,
                    "message_type": message.message_type.value,
                    "priority": message.priority.name,
                    "created_at": message.created_at.isoformat(),
                }

            result = await self.execute_with_session(_send_message)
            return self.format_success(
                result.get("data", result),
                f"Message sent from {from_agent} to {len(to_agents)} agent(s)",
            )

        @mcp.tool()
        async def broadcast_to_tier(
            from_agent: str,
            tier: str,
            content: str,
            priority: str = "medium",
            metadata: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            """Broadcast a message to all agents in a tier.

            Sends a message to all agents in the specified tier:
            - STRATEGIC: Athena, Hera (system-wide coordination)
            - SPECIALIST: Artemis, Hestia, Eris, Muses (domain expertise)
            - SUPPORT: Aphrodite, Metis, Aurora (task execution)

            Args:
                from_agent: Sending agent ID
                tier: Target tier (STRATEGIC, SPECIALIST, SUPPORT)
                content: Message content
                priority: Priority level
                metadata: Additional metadata

            Returns:
                Dict containing broadcast details

            Example:
                broadcast_to_tier(
                    from_agent="athena-conductor",
                    tier="SPECIALIST",
                    content="Phase 2 implementation starting. Prepare for assignments."
                )

            """
            async def _broadcast(session, _services):
                comm_service = AgentCommunicationService(session)

                # Parse tier
                target_tier = AgentTier.SPECIALIST
                for t in AgentTier:
                    if t.name == tier.upper():
                        target_tier = t
                        break

                # Parse priority
                msg_priority = MessagePriority.MEDIUM
                for p in MessagePriority:
                    if p.name.lower() == priority.lower():
                        msg_priority = p
                        break

                message = await comm_service.broadcast_to_tier(
                    from_agent=from_agent,
                    tier=target_tier,
                    content=content,
                    priority=msg_priority,
                    metadata=metadata,
                )

                return {
                    "message_id": str(message.id),
                    "from_agent": message.from_agent,
                    "broadcast_tier": tier.upper(),
                    "recipients": message.to_agents,
                    "recipient_count": len(message.to_agents),
                    "created_at": message.created_at.isoformat(),
                }

            result = await self.execute_with_session(_broadcast)
            return self.format_success(
                result.get("data", result),
                f"Broadcast sent to {tier.upper()} tier",
            )

        @mcp.tool()
        async def delegate_task(
            from_agent: str,
            task_content: str,
            to_agent: str | None = None,
            priority: str = "medium",
            context: dict[str, Any] | None = None,
            deadline: str | None = None,
            auto_route: bool = True,
        ) -> dict[str, Any]:
            """Delegate a task to another agent.

            If to_agent is not specified and auto_route is True, uses
            intelligent routing to find the optimal agent based on task content.

            Args:
                from_agent: Delegating agent ID
                task_content: Description of the task to delegate
                to_agent: Optional specific target agent (auto-routed if not specified)
                priority: Task priority (low, medium, high, urgent, critical)
                context: Additional task context
                deadline: Optional deadline in ISO format
                auto_route: Whether to auto-route if no target specified

            Returns:
                Dict containing delegation details including delegation_id

            Example:
                # Auto-routed delegation
                delegate_task(
                    from_agent="athena-conductor",
                    task_content="Optimize database query performance",
                    priority="high"
                )
                # Returns delegation to artemis-optimizer (auto-detected)

                # Explicit delegation
                delegate_task(
                    from_agent="hera-strategist",
                    task_content="Implement authentication module",
                    to_agent="metis-developer"
                )

            """
            async def _delegate(session, _services):
                comm_service = AgentCommunicationService(session)

                # Parse priority
                msg_priority = MessagePriority.MEDIUM
                for p in MessagePriority:
                    if p.name.lower() == priority.lower():
                        msg_priority = p
                        break

                # Parse deadline if provided
                parsed_deadline = None
                if deadline:
                    parsed_deadline = datetime.fromisoformat(deadline)

                delegation = await comm_service.delegate_task(
                    from_agent=from_agent,
                    task_content=task_content,
                    to_agent=to_agent,
                    priority=msg_priority,
                    context=context,
                    deadline=parsed_deadline,
                    auto_route=auto_route,
                )

                return {
                    "delegation_id": str(delegation.id),
                    "from_agent": delegation.from_agent,
                    "to_agent": delegation.to_agent,
                    "task_content": delegation.task_content,
                    "priority": delegation.priority.name,
                    "status": delegation.status,
                    "auto_routed": to_agent is None,
                    "deadline": delegation.deadline.isoformat() if delegation.deadline else None,
                    "created_at": delegation.created_at.isoformat(),
                }

            result = await self.execute_with_session(_delegate)
            data = result.get("data", result)
            return self.format_success(
                data,
                f"Task delegated to {data.get('to_agent', 'unknown')}",
            )

        @mcp.tool()
        async def respond_to_delegation(
            delegation_id: str,
            agent_id: str,
            accept: bool,
            response_message: str | None = None,
        ) -> dict[str, Any]:
            """Respond to a task delegation request.

            Accept or reject a delegation that was sent to this agent.

            Args:
                delegation_id: ID of the delegation to respond to
                agent_id: Responding agent ID (must match delegation target)
                accept: Whether to accept the delegation
                response_message: Optional response message

            Returns:
                Dict containing updated delegation status

            Example:
                respond_to_delegation(
                    delegation_id="abc123...",
                    agent_id="artemis-optimizer",
                    accept=True,
                    response_message="Accepting optimization task. Starting analysis."
                )

            """
            async def _respond(session, _services):
                comm_service = AgentCommunicationService(session)

                delegation = await comm_service.respond_to_delegation(
                    delegation_id=UUID(delegation_id),
                    agent_id=agent_id,
                    accept=accept,
                    response_message=response_message,
                )

                return {
                    "delegation_id": str(delegation.id),
                    "from_agent": delegation.from_agent,
                    "to_agent": delegation.to_agent,
                    "status": delegation.status,
                    "response": "accepted" if accept else "rejected",
                }

            result = await self.execute_with_session(_respond)
            return self.format_success(
                result.get("data", result),
                f"Delegation {'accepted' if accept else 'rejected'}",
            )

        @mcp.tool()
        async def complete_delegation(
            delegation_id: str,
            agent_id: str,
            result: dict[str, Any],
            success: bool = True,
        ) -> dict[str, Any]:
            """Mark a delegation as completed.

            Report completion of a delegated task with results.

            Args:
                delegation_id: ID of the delegation to complete
                agent_id: Completing agent ID (must match delegation target)
                result: Task result data
                success: Whether task completed successfully

            Returns:
                Dict containing completion details

            Example:
                complete_delegation(
                    delegation_id="abc123...",
                    agent_id="artemis-optimizer",
                    result={"optimizations_applied": 3, "performance_gain": "40%"},
                    success=True
                )

            """
            async def _complete(session, _services):
                comm_service = AgentCommunicationService(session)

                delegation = await comm_service.complete_delegation(
                    delegation_id=UUID(delegation_id),
                    agent_id=agent_id,
                    result=result,
                    success=success,
                )

                return {
                    "delegation_id": str(delegation.id),
                    "from_agent": delegation.from_agent,
                    "to_agent": delegation.to_agent,
                    "status": delegation.status,
                    "result": result,
                }

            result = await self.execute_with_session(_complete)
            return self.format_success(
                result.get("data", result),
                f"Delegation {'completed' if success else 'failed'}",
            )

        @mcp.tool()
        async def get_agent_messages(
            agent_id: str,
            message_type: str | None = None,
            limit: int = 50,
        ) -> dict[str, Any]:
            """Get pending messages for an agent.

            Retrieves messages queued for the specified agent.

            Args:
                agent_id: Target agent ID
                message_type: Optional filter by type (direct, broadcast, delegation, etc.)
                limit: Maximum messages to return

            Returns:
                Dict containing list of messages

            Example:
                get_agent_messages(agent_id="artemis-optimizer")

            """
            comm_service = AgentCommunicationService()

            # Parse message type if provided
            msg_type = None
            if message_type:
                for mt in MessageType:
                    if mt.value == message_type:
                        msg_type = mt
                        break

            messages = comm_service.get_messages(
                agent_id=agent_id,
                message_type=msg_type,
                limit=limit,
            )

            return self.format_success(
                {
                    "agent_id": agent_id,
                    "message_count": len(messages),
                    "messages": [
                        {
                            "id": str(m.id),
                            "from_agent": m.from_agent,
                            "message_type": m.message_type.value,
                            "content": m.content,
                            "priority": m.priority.name,
                            "requires_response": m.requires_response,
                            "created_at": m.created_at.isoformat(),
                        }
                        for m in messages
                    ],
                },
                f"Retrieved {len(messages)} messages for {agent_id}",
            )

        @mcp.tool()
        async def handoff_task(
            from_agent: str,
            to_agent: str,
            task_content: str,
            context: dict[str, Any],
            artifacts: list[dict[str, Any]] | None = None,
            priority: str = "high",
        ) -> dict[str, Any]:
            """Hand off a task from one agent to another with full context.

            Used for phase transitions in Trinitas Full Mode. Transfers complete
            task context including background, dependencies, and artifacts.

            Args:
                from_agent: Handing off agent ID
                to_agent: Receiving agent ID
                task_content: Task description
                context: Full task context including:
                    - background: Background information
                    - dependencies: Task dependencies
                    - constraints: Constraints to consider
                    - current_phase: Current execution phase
                    - next_phase: Next execution phase
                artifacts: List of artifacts (code, docs, etc.)
                priority: Handoff priority (default: high)

            Returns:
                Dict containing handoff message details

            Example:
                handoff_task(
                    from_agent="hera-strategist",
                    to_agent="artemis-optimizer",
                    task_content="Implement authentication system per strategy doc",
                    context={
                        "background": "New auth system replacing legacy",
                        "dependencies": ["user_model", "session_service"],
                        "constraints": ["Must support OAuth 2.0"],
                        "current_phase": "Phase 1: Strategic Planning",
                        "next_phase": "Phase 2: Implementation"
                    },
                    artifacts=[{"type": "doc", "path": "docs/auth_strategy.md"}]
                )

            """
            async def _handoff(session, _services):
                comm_service = AgentCommunicationService(session)

                # Parse priority
                msg_priority = MessagePriority.HIGH
                for p in MessagePriority:
                    if p.name.lower() == priority.lower():
                        msg_priority = p
                        break

                message = await comm_service.handoff_task(
                    from_agent=from_agent,
                    to_agent=to_agent,
                    task_content=task_content,
                    context=context,
                    artifacts=artifacts,
                    priority=msg_priority,
                )

                return {
                    "message_id": str(message.id),
                    "from_agent": message.from_agent,
                    "to_agent": message.to_agents[0],
                    "message_type": "handoff",
                    "from_phase": context.get("current_phase"),
                    "to_phase": context.get("next_phase"),
                    "artifact_count": len(artifacts) if artifacts else 0,
                    "created_at": message.created_at.isoformat(),
                }

            result = await self.execute_with_session(_handoff)
            return self.format_success(
                result.get("data", result),
                f"Task handed off from {from_agent} to {to_agent}",
            )

        @mcp.tool()
        async def get_communication_stats(agent_id: str) -> dict[str, Any]:
            """Get communication statistics for an agent.

            Returns message counts, delegation statistics, and channel memberships.

            Args:
                agent_id: Target agent ID

            Returns:
                Dict containing communication statistics

            Example:
                get_communication_stats(agent_id="athena-conductor")

            """
            async def _get_stats(session, _services):
                comm_service = AgentCommunicationService(session)
                return await comm_service.get_agent_communication_stats(agent_id)

            result = await self.execute_with_session(_get_stats)
            return self.format_success(
                result.get("data", result),
                f"Communication stats for {agent_id}",
            )
