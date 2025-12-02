"""Agent Communication Service for TMWS Orchestration Layer.

Implements inter-agent messaging, task delegation, and communication
channels for the Trinitas multi-agent orchestration system.

This service enables:
- Direct agent-to-agent messaging
- Task delegation with automatic routing
- Broadcast messaging to agent groups/tiers
- Communication history and audit trail
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Memory
from .agent_service import AgentService
from .task_routing_service import AgentTier, TaskRoutingService

logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Types of inter-agent messages."""

    DIRECT = "direct"  # One-to-one message
    BROADCAST = "broadcast"  # One-to-many message
    DELEGATION = "delegation"  # Task delegation request
    RESPONSE = "response"  # Response to a previous message
    STATUS = "status"  # Status update
    HANDOFF = "handoff"  # Task handoff between agents


class MessagePriority(Enum):
    """Message priority levels."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    URGENT = 4
    CRITICAL = 5


@dataclass
class AgentMessage:
    """Represents an inter-agent message."""

    id: UUID
    from_agent: str
    to_agents: list[str]
    message_type: MessageType
    content: str
    priority: MessagePriority
    metadata: dict[str, Any]
    created_at: datetime
    expires_at: datetime | None = None
    in_reply_to: UUID | None = None
    requires_response: bool = False


@dataclass
class DelegationRequest:
    """Request to delegate a task to another agent."""

    id: UUID
    from_agent: str
    to_agent: str
    task_content: str
    priority: MessagePriority
    context: dict[str, Any]
    deadline: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: str = "pending"  # pending, accepted, rejected, completed, failed


@dataclass
class CommunicationChannel:
    """A communication channel for agent groups."""

    id: UUID
    name: str
    description: str
    members: list[str]
    created_by: str
    created_at: datetime
    is_active: bool = True


class AgentCommunicationService:
    """Service for managing inter-agent communication.

    Provides:
    - Direct messaging between agents
    - Task delegation with automatic routing
    - Broadcast messaging to tiers/groups
    - Communication history tracking
    - Message queuing and delivery

    Integrates with:
    - TaskRoutingService for intelligent delegation
    - AgentService for agent lookups
    - Memory system for persistence
    """

    def __init__(self, session: AsyncSession | None = None):
        """Initialize agent communication service.

        Args:
            session: Optional async database session.
        """
        self.session = session
        self._agent_service: AgentService | None = None
        self._routing_service: TaskRoutingService | None = None

        # In-memory message queue (production would use Redis/NATS)
        self._message_queue: dict[str, list[AgentMessage]] = {}
        self._channels: dict[UUID, CommunicationChannel] = {}
        self._delegations: dict[UUID, DelegationRequest] = {}

    @property
    def agent_service(self) -> AgentService | None:
        """Lazy-load agent service if session available."""
        if self._agent_service is None and self.session is not None:
            self._agent_service = AgentService(self.session)
        return self._agent_service

    @property
    def routing_service(self) -> TaskRoutingService:
        """Lazy-load routing service."""
        if self._routing_service is None:
            self._routing_service = TaskRoutingService(self.session)
        return self._routing_service

    async def send_message(
        self,
        from_agent: str,
        to_agents: list[str],
        content: str,
        message_type: MessageType = MessageType.DIRECT,
        priority: MessagePriority = MessagePriority.MEDIUM,
        metadata: dict[str, Any] | None = None,
        in_reply_to: UUID | None = None,
        requires_response: bool = False,
        ttl_hours: int | None = None,
    ) -> AgentMessage:
        """Send a message from one agent to other agent(s).

        Args:
            from_agent: Sending agent ID
            to_agents: List of recipient agent IDs
            content: Message content
            message_type: Type of message
            priority: Message priority level
            metadata: Additional message metadata
            in_reply_to: ID of message this replies to
            requires_response: Whether recipients must respond
            ttl_hours: Optional time-to-live in hours

        Returns:
            The created AgentMessage

        Raises:
            ValueError: If from_agent or to_agents are invalid
        """
        if not from_agent or not to_agents:
            raise ValueError("Both from_agent and to_agents are required")

        # Validate agents exist (if session available)
        if self.agent_service:
            sender = await self.agent_service.get_agent_by_id(from_agent)
            if not sender:
                raise ValueError(f"Sender agent not found: {from_agent}")

        # Calculate expiration if TTL provided
        expires_at = None
        if ttl_hours:
            expires_at = datetime.now(UTC).replace(
                hour=datetime.now(UTC).hour + ttl_hours,
            )

        message = AgentMessage(
            id=uuid4(),
            from_agent=from_agent,
            to_agents=to_agents,
            message_type=message_type,
            content=content,
            priority=priority,
            metadata=metadata or {},
            created_at=datetime.now(UTC),
            expires_at=expires_at,
            in_reply_to=in_reply_to,
            requires_response=requires_response,
        )

        # Queue message for each recipient
        for agent_id in to_agents:
            if agent_id not in self._message_queue:
                self._message_queue[agent_id] = []
            self._message_queue[agent_id].append(message)

        logger.info(
            f"Message {message.id} sent from {from_agent} to {to_agents} "
            f"(type={message_type.value}, priority={priority.name})",
        )

        # Persist to memory if session available
        await self._persist_message(message)

        return message

    async def broadcast_to_tier(
        self,
        from_agent: str,
        tier: AgentTier,
        content: str,
        priority: MessagePriority = MessagePriority.MEDIUM,
        metadata: dict[str, Any] | None = None,
    ) -> AgentMessage:
        """Broadcast a message to all agents in a tier.

        Args:
            from_agent: Sending agent ID
            tier: Target agent tier
            content: Message content
            priority: Message priority
            metadata: Additional metadata

        Returns:
            The broadcast message
        """
        # Get agents in the specified tier
        tier_agents = [
            agent_id
            for agent_id, agent_tier in TaskRoutingService.AGENT_TIERS.items()
            if agent_tier == tier
        ]

        if not tier_agents:
            raise ValueError(f"No agents found in tier: {tier.name}")

        return await self.send_message(
            from_agent=from_agent,
            to_agents=tier_agents,
            content=content,
            message_type=MessageType.BROADCAST,
            priority=priority,
            metadata={**(metadata or {}), "broadcast_tier": tier.name},
        )

    async def delegate_task(
        self,
        from_agent: str,
        task_content: str,
        to_agent: str | None = None,
        priority: MessagePriority = MessagePriority.MEDIUM,
        context: dict[str, Any] | None = None,
        deadline: datetime | None = None,
        auto_route: bool = True,
    ) -> DelegationRequest:
        """Delegate a task to another agent.

        If to_agent is not specified and auto_route is True, uses
        TaskRoutingService to find the optimal agent.

        Args:
            from_agent: Delegating agent ID
            task_content: Description of the task
            to_agent: Optional specific target agent
            priority: Task priority
            context: Additional task context
            deadline: Optional deadline
            auto_route: Whether to auto-route if no target specified

        Returns:
            The delegation request

        Raises:
            ValueError: If routing fails or agents are invalid
        """
        target_agent = to_agent

        # Auto-route if no target specified
        if not target_agent and auto_route:
            routing_result = self.routing_service.route_task(task_content)
            target_agent = routing_result.primary_agent

            logger.info(
                f"Auto-routed delegation to {target_agent} "
                f"(confidence={routing_result.confidence:.2f})",
            )

        if not target_agent:
            raise ValueError("No target agent specified and auto_route is disabled")

        delegation = DelegationRequest(
            id=uuid4(),
            from_agent=from_agent,
            to_agent=target_agent,
            task_content=task_content,
            priority=priority,
            context=context or {},
            deadline=deadline,
        )

        self._delegations[delegation.id] = delegation

        # Send delegation message
        await self.send_message(
            from_agent=from_agent,
            to_agents=[target_agent],
            content=task_content,
            message_type=MessageType.DELEGATION,
            priority=priority,
            metadata={
                "delegation_id": str(delegation.id),
                "deadline": deadline.isoformat() if deadline else None,
                **(context or {}),
            },
            requires_response=True,
        )

        logger.info(
            f"Task delegated from {from_agent} to {target_agent} "
            f"(delegation_id={delegation.id})",
        )

        return delegation

    async def respond_to_delegation(
        self,
        delegation_id: UUID,
        agent_id: str,
        accept: bool,
        response_message: str | None = None,
    ) -> DelegationRequest:
        """Respond to a delegation request.

        Args:
            delegation_id: ID of the delegation
            agent_id: Responding agent ID
            accept: Whether to accept the delegation
            response_message: Optional response message

        Returns:
            Updated delegation request

        Raises:
            ValueError: If delegation not found or agent mismatch
        """
        delegation = self._delegations.get(delegation_id)
        if not delegation:
            raise ValueError(f"Delegation not found: {delegation_id}")

        if delegation.to_agent != agent_id:
            raise ValueError(
                f"Agent {agent_id} is not the target of delegation {delegation_id}",
            )

        delegation.status = "accepted" if accept else "rejected"

        # Send response message
        await self.send_message(
            from_agent=agent_id,
            to_agents=[delegation.from_agent],
            content=response_message or f"Delegation {'accepted' if accept else 'rejected'}",
            message_type=MessageType.RESPONSE,
            priority=delegation.priority,
            metadata={
                "delegation_id": str(delegation_id),
                "delegation_status": delegation.status,
            },
        )

        return delegation

    async def complete_delegation(
        self,
        delegation_id: UUID,
        agent_id: str,
        result: dict[str, Any],
        success: bool = True,
    ) -> DelegationRequest:
        """Mark a delegation as completed.

        Args:
            delegation_id: ID of the delegation
            agent_id: Completing agent ID
            result: Task result data
            success: Whether task completed successfully

        Returns:
            Updated delegation request
        """
        delegation = self._delegations.get(delegation_id)
        if not delegation:
            raise ValueError(f"Delegation not found: {delegation_id}")

        if delegation.to_agent != agent_id:
            raise ValueError(
                f"Agent {agent_id} is not the target of delegation {delegation_id}",
            )

        delegation.status = "completed" if success else "failed"

        # Send completion message
        await self.send_message(
            from_agent=agent_id,
            to_agents=[delegation.from_agent],
            content=f"Task {'completed' if success else 'failed'}",
            message_type=MessageType.RESPONSE,
            priority=delegation.priority,
            metadata={
                "delegation_id": str(delegation_id),
                "delegation_status": delegation.status,
                "result": result,
            },
        )

        return delegation

    def get_messages(
        self,
        agent_id: str,
        unread_only: bool = False,  # noqa: ARG002 - Reserved for future read tracking
        message_type: MessageType | None = None,
        limit: int = 50,
    ) -> list[AgentMessage]:
        """Get messages for an agent.

        Args:
            agent_id: Target agent ID
            unread_only: Only return unread messages (reserved for future use)
            message_type: Filter by message type
            limit: Maximum messages to return

        Returns:
            List of messages
        """
        messages = self._message_queue.get(agent_id, [])

        # Filter by type if specified
        if message_type:
            messages = [m for m in messages if m.message_type == message_type]

        # Filter expired messages
        now = datetime.now(UTC)
        messages = [
            m for m in messages
            if m.expires_at is None or m.expires_at > now
        ]

        # Sort by priority (descending) then created_at (ascending)
        messages.sort(key=lambda m: (-m.priority.value, m.created_at))

        return messages[:limit]

    def clear_messages(self, agent_id: str) -> int:
        """Clear all messages for an agent.

        Args:
            agent_id: Target agent ID

        Returns:
            Number of messages cleared
        """
        count = len(self._message_queue.get(agent_id, []))
        self._message_queue[agent_id] = []
        return count

    async def create_channel(
        self,
        name: str,
        description: str,
        members: list[str],
        created_by: str,
    ) -> CommunicationChannel:
        """Create a communication channel for a group of agents.

        Args:
            name: Channel name
            description: Channel description
            members: Initial member agent IDs
            created_by: Creating agent ID

        Returns:
            The created channel
        """
        channel = CommunicationChannel(
            id=uuid4(),
            name=name,
            description=description,
            members=members,
            created_by=created_by,
            created_at=datetime.now(UTC),
        )

        self._channels[channel.id] = channel

        logger.info(
            f"Channel '{name}' created by {created_by} with {len(members)} members",
        )

        return channel

    async def send_to_channel(
        self,
        channel_id: UUID,
        from_agent: str,
        content: str,
        priority: MessagePriority = MessagePriority.MEDIUM,
        metadata: dict[str, Any] | None = None,
    ) -> AgentMessage:
        """Send a message to all members of a channel.

        Args:
            channel_id: Target channel ID
            from_agent: Sending agent ID
            content: Message content
            priority: Message priority
            metadata: Additional metadata

        Returns:
            The sent message

        Raises:
            ValueError: If channel not found or sender not a member
        """
        channel = self._channels.get(channel_id)
        if not channel:
            raise ValueError(f"Channel not found: {channel_id}")

        if from_agent not in channel.members:
            raise ValueError(f"Agent {from_agent} is not a member of channel {channel.name}")

        # Exclude sender from recipients
        recipients = [m for m in channel.members if m != from_agent]

        return await self.send_message(
            from_agent=from_agent,
            to_agents=recipients,
            content=content,
            message_type=MessageType.BROADCAST,
            priority=priority,
            metadata={
                **(metadata or {}),
                "channel_id": str(channel_id),
                "channel_name": channel.name,
            },
        )

    def get_channel(self, channel_id: UUID) -> CommunicationChannel | None:
        """Get a channel by ID."""
        return self._channels.get(channel_id)

    def list_channels(self, member_agent: str | None = None) -> list[CommunicationChannel]:
        """List all channels, optionally filtered by member.

        Args:
            member_agent: Optional filter by member agent ID

        Returns:
            List of channels
        """
        channels = list(self._channels.values())

        if member_agent:
            channels = [c for c in channels if member_agent in c.members]

        return channels

    async def handoff_task(
        self,
        from_agent: str,
        to_agent: str,
        task_content: str,
        context: dict[str, Any],
        artifacts: list[dict[str, Any]] | None = None,
        priority: MessagePriority = MessagePriority.HIGH,
    ) -> AgentMessage:
        """Hand off a task from one agent to another with full context.

        This is used for phase transitions in Trinitas Full Mode.

        Args:
            from_agent: Handing off agent ID
            to_agent: Receiving agent ID
            task_content: Task description
            context: Full task context including background, dependencies, constraints
            artifacts: List of artifacts (code, docs, etc.)
            priority: Handoff priority

        Returns:
            The handoff message
        """
        handoff_metadata = {
            "handoff_type": "task_handoff",
            "context": context,
            "artifacts": artifacts or [],
            "from_phase": context.get("current_phase"),
            "to_phase": context.get("next_phase"),
        }

        return await self.send_message(
            from_agent=from_agent,
            to_agents=[to_agent],
            content=task_content,
            message_type=MessageType.HANDOFF,
            priority=priority,
            metadata=handoff_metadata,
            requires_response=True,
        )

    def get_delegation(self, delegation_id: UUID) -> DelegationRequest | None:
        """Get a delegation by ID."""
        return self._delegations.get(delegation_id)

    def list_delegations(
        self,
        from_agent: str | None = None,
        to_agent: str | None = None,
        status: str | None = None,
    ) -> list[DelegationRequest]:
        """List delegations with optional filters.

        Args:
            from_agent: Filter by delegating agent
            to_agent: Filter by target agent
            status: Filter by status

        Returns:
            List of matching delegations
        """
        delegations = list(self._delegations.values())

        if from_agent:
            delegations = [d for d in delegations if d.from_agent == from_agent]
        if to_agent:
            delegations = [d for d in delegations if d.to_agent == to_agent]
        if status:
            delegations = [d for d in delegations if d.status == status]

        return delegations

    async def get_agent_communication_stats(self, agent_id: str) -> dict[str, Any]:
        """Get communication statistics for an agent.

        Args:
            agent_id: Target agent ID

        Returns:
            Dict with communication statistics
        """
        messages = self._message_queue.get(agent_id, [])
        delegations_received = self.list_delegations(to_agent=agent_id)
        delegations_sent = self.list_delegations(from_agent=agent_id)

        # Count by message type
        type_counts: dict[str, int] = {}
        for msg in messages:
            type_name = msg.message_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        # Count delegations by status
        delegation_status_counts = {
            "pending": len([d for d in delegations_received if d.status == "pending"]),
            "accepted": len([d for d in delegations_received if d.status == "accepted"]),
            "completed": len([d for d in delegations_received if d.status == "completed"]),
            "failed": len([d for d in delegations_received if d.status == "failed"]),
        }

        return {
            "agent_id": agent_id,
            "pending_messages": len(messages),
            "messages_by_type": type_counts,
            "delegations_received": len(delegations_received),
            "delegations_sent": len(delegations_sent),
            "delegation_status": delegation_status_counts,
            "channels": len(self.list_channels(member_agent=agent_id)),
        }

    async def _persist_message(self, message: AgentMessage) -> None:
        """Persist a message to the memory system.

        Args:
            message: Message to persist
        """
        if not self.session:
            return

        try:
            # Store as a memory entry for audit trail
            memory = Memory(
                content=message.content,
                agent_id=message.from_agent,
                namespace="agent_communication",
                importance_score=message.priority.value / 5.0,
                metadata={
                    "message_id": str(message.id),
                    "message_type": message.message_type.value,
                    "to_agents": message.to_agents,
                    "priority": message.priority.name,
                    "requires_response": message.requires_response,
                    "in_reply_to": str(message.in_reply_to) if message.in_reply_to else None,
                },
                tags=["agent_message", message.message_type.value],
            )
            self.session.add(memory)
            await self.session.commit()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.warning(f"Failed to persist message: {e}")
            # Don't fail the message send if persistence fails
            await self.session.rollback()
