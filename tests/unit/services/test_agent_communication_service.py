"""Unit tests for AgentCommunicationService.

Tests inter-agent messaging, task delegation, and communication channels
for the Trinitas multi-agent orchestration system.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from src.services.agent_communication_service import (
    AgentCommunicationService,
    AgentMessage,
    CommunicationChannel,
    DelegationRequest,
    MessagePriority,
    MessageType,
)
from src.services.task_routing_service import AgentTier


class TestMessageEnums:
    """Tests for message-related enums."""

    def test_message_type_values(self):
        """Verify message type enum values."""
        assert MessageType.DIRECT.value == "direct"
        assert MessageType.BROADCAST.value == "broadcast"
        assert MessageType.DELEGATION.value == "delegation"
        assert MessageType.RESPONSE.value == "response"
        assert MessageType.STATUS.value == "status"
        assert MessageType.HANDOFF.value == "handoff"

    def test_message_priority_values(self):
        """Verify priority ordering."""
        assert MessagePriority.LOW.value == 1
        assert MessagePriority.MEDIUM.value == 2
        assert MessagePriority.HIGH.value == 3
        assert MessagePriority.URGENT.value == 4
        assert MessagePriority.CRITICAL.value == 5


class TestDataclasses:
    """Tests for dataclass structures."""

    def test_agent_message_creation(self):
        """Verify AgentMessage can be created."""
        msg = AgentMessage(
            id=uuid4(),
            from_agent="athena-conductor",
            to_agents=["artemis-optimizer"],
            message_type=MessageType.DIRECT,
            content="Test message",
            priority=MessagePriority.HIGH,
            metadata={"key": "value"},
            created_at=datetime.now(UTC),
        )
        assert msg.from_agent == "athena-conductor"
        assert msg.priority == MessagePriority.HIGH
        assert msg.expires_at is None
        assert msg.requires_response is False

    def test_delegation_request_creation(self):
        """Verify DelegationRequest can be created."""
        delegation = DelegationRequest(
            id=uuid4(),
            from_agent="athena-conductor",
            to_agent="artemis-optimizer",
            task_content="Optimize query",
            priority=MessagePriority.HIGH,
            context={"background": "Performance issue"},
        )
        assert delegation.status == "pending"
        assert delegation.deadline is None

    def test_communication_channel_creation(self):
        """Verify CommunicationChannel can be created."""
        channel = CommunicationChannel(
            id=uuid4(),
            name="strategic-council",
            description="Strategic planning channel",
            members=["athena-conductor", "hera-strategist"],
            created_by="athena-conductor",
            created_at=datetime.now(UTC),
        )
        assert channel.is_active is True
        assert len(channel.members) == 2


class TestAgentCommunicationService:
    """Tests for AgentCommunicationService."""

    @pytest.fixture
    def comm_service(self):
        """Create a communication service instance."""
        return AgentCommunicationService()

    class TestSendMessage:
        """Tests for send_message method."""

        @pytest.fixture
        def comm_service(self):
            return AgentCommunicationService()

        @pytest.mark.asyncio
        async def test_send_direct_message(self, comm_service):
            """Can send direct message between agents."""
            message = await comm_service.send_message(
                from_agent="athena-conductor",
                to_agents=["artemis-optimizer"],
                content="Test message",
            )
            assert message.from_agent == "athena-conductor"
            assert "artemis-optimizer" in message.to_agents
            assert message.message_type == MessageType.DIRECT

        @pytest.mark.asyncio
        async def test_message_queued_for_recipient(self, comm_service):
            """Message is queued for recipient agent."""
            await comm_service.send_message(
                from_agent="athena-conductor",
                to_agents=["artemis-optimizer"],
                content="Test message",
            )
            messages = comm_service.get_messages("artemis-optimizer")
            assert len(messages) == 1
            assert messages[0].content == "Test message"

        @pytest.mark.asyncio
        async def test_message_queued_for_multiple_recipients(self, comm_service):
            """Message is queued for all recipients."""
            await comm_service.send_message(
                from_agent="athena-conductor",
                to_agents=["artemis-optimizer", "hestia-auditor"],
                content="Test message",
            )
            assert len(comm_service.get_messages("artemis-optimizer")) == 1
            assert len(comm_service.get_messages("hestia-auditor")) == 1

        @pytest.mark.asyncio
        async def test_send_with_priority(self, comm_service):
            """Can set message priority."""
            message = await comm_service.send_message(
                from_agent="athena-conductor",
                to_agents=["artemis-optimizer"],
                content="Urgent message",
                priority=MessagePriority.URGENT,
            )
            assert message.priority == MessagePriority.URGENT

        @pytest.mark.asyncio
        async def test_send_with_metadata(self, comm_service):
            """Can include metadata in message."""
            metadata = {"task_id": "123", "phase": "implementation"}
            message = await comm_service.send_message(
                from_agent="athena-conductor",
                to_agents=["artemis-optimizer"],
                content="Test message",
                metadata=metadata,
            )
            assert message.metadata["task_id"] == "123"

        @pytest.mark.asyncio
        async def test_send_requires_from_agent(self, comm_service):
            """Raises error if from_agent missing."""
            with pytest.raises(ValueError, match="Both from_agent and to_agents are required"):
                await comm_service.send_message(
                    from_agent="",
                    to_agents=["artemis-optimizer"],
                    content="Test",
                )

        @pytest.mark.asyncio
        async def test_send_requires_to_agents(self, comm_service):
            """Raises error if to_agents empty."""
            with pytest.raises(ValueError, match="Both from_agent and to_agents are required"):
                await comm_service.send_message(
                    from_agent="athena-conductor",
                    to_agents=[],
                    content="Test",
                )

    class TestBroadcastToTier:
        """Tests for broadcast_to_tier method."""

        @pytest.fixture
        def comm_service(self):
            return AgentCommunicationService()

        @pytest.mark.asyncio
        async def test_broadcast_to_strategic_tier(self, comm_service):
            """Can broadcast to strategic tier."""
            message = await comm_service.broadcast_to_tier(
                from_agent="eris-coordinator",
                tier=AgentTier.STRATEGIC,
                content="Strategic update",
            )
            assert message.message_type == MessageType.BROADCAST
            assert "athena-conductor" in message.to_agents
            assert "hera-strategist" in message.to_agents

        @pytest.mark.asyncio
        async def test_broadcast_to_specialist_tier(self, comm_service):
            """Can broadcast to specialist tier."""
            message = await comm_service.broadcast_to_tier(
                from_agent="athena-conductor",
                tier=AgentTier.SPECIALIST,
                content="Specialist update",
            )
            assert "artemis-optimizer" in message.to_agents
            assert "hestia-auditor" in message.to_agents
            assert "eris-coordinator" in message.to_agents
            assert "muses-documenter" in message.to_agents

        @pytest.mark.asyncio
        async def test_broadcast_to_support_tier(self, comm_service):
            """Can broadcast to support tier."""
            message = await comm_service.broadcast_to_tier(
                from_agent="athena-conductor",
                tier=AgentTier.SUPPORT,
                content="Support update",
            )
            assert "aphrodite-designer" in message.to_agents
            assert "metis-developer" in message.to_agents
            assert "aurora-researcher" in message.to_agents

        @pytest.mark.asyncio
        async def test_broadcast_includes_tier_metadata(self, comm_service):
            """Broadcast includes tier in metadata."""
            message = await comm_service.broadcast_to_tier(
                from_agent="athena-conductor",
                tier=AgentTier.STRATEGIC,
                content="Update",
            )
            assert message.metadata["broadcast_tier"] == "STRATEGIC"

    class TestDelegateTask:
        """Tests for delegate_task method."""

        @pytest.fixture
        def comm_service(self):
            return AgentCommunicationService()

        @pytest.mark.asyncio
        async def test_delegate_to_specific_agent(self, comm_service):
            """Can delegate to specific agent."""
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Optimize query performance",
                to_agent="artemis-optimizer",
            )
            assert delegation.from_agent == "athena-conductor"
            assert delegation.to_agent == "artemis-optimizer"
            assert delegation.status == "pending"

        @pytest.mark.asyncio
        async def test_auto_route_delegation(self, comm_service):
            """Auto-routes to optimal agent when not specified."""
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Optimize query performance",
                auto_route=True,
            )
            # Should route to artemis-optimizer based on "optimize" keyword
            assert delegation.to_agent == "artemis-optimizer"

        @pytest.mark.asyncio
        async def test_auto_route_security_task(self, comm_service):
            """Auto-routes security tasks to hestia."""
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Security audit the authentication system",
                auto_route=True,
            )
            assert delegation.to_agent == "hestia-auditor"

        @pytest.mark.asyncio
        async def test_delegation_with_context(self, comm_service):
            """Can include context in delegation."""
            context = {"background": "Performance issue", "priority_reason": "Customer SLA"}
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Fix performance issue",
                to_agent="artemis-optimizer",
                context=context,
            )
            assert delegation.context["background"] == "Performance issue"

        @pytest.mark.asyncio
        async def test_delegation_with_deadline(self, comm_service):
            """Can set deadline on delegation."""
            deadline = datetime.now(UTC)
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Task",
                to_agent="artemis-optimizer",
                deadline=deadline,
            )
            assert delegation.deadline == deadline

        @pytest.mark.asyncio
        async def test_delegation_sends_message(self, comm_service):
            """Delegation sends message to target agent."""
            await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Task",
                to_agent="artemis-optimizer",
            )
            messages = comm_service.get_messages("artemis-optimizer")
            assert len(messages) == 1
            assert messages[0].message_type == MessageType.DELEGATION

        @pytest.mark.asyncio
        async def test_delegation_requires_target_or_auto_route(self, comm_service):
            """Raises error if no target and auto_route disabled."""
            with pytest.raises(ValueError, match="No target agent specified"):
                await comm_service.delegate_task(
                    from_agent="athena-conductor",
                    task_content="Task",
                    auto_route=False,
                )

    class TestRespondToDelegation:
        """Tests for respond_to_delegation method."""

        @pytest.fixture
        def comm_service(self):
            return AgentCommunicationService()

        @pytest.mark.asyncio
        async def test_accept_delegation(self, comm_service):
            """Can accept a delegation."""
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Task",
                to_agent="artemis-optimizer",
            )
            updated = await comm_service.respond_to_delegation(
                delegation_id=delegation.id,
                agent_id="artemis-optimizer",
                accept=True,
            )
            assert updated.status == "accepted"

        @pytest.mark.asyncio
        async def test_reject_delegation(self, comm_service):
            """Can reject a delegation."""
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Task",
                to_agent="artemis-optimizer",
            )
            updated = await comm_service.respond_to_delegation(
                delegation_id=delegation.id,
                agent_id="artemis-optimizer",
                accept=False,
            )
            assert updated.status == "rejected"

        @pytest.mark.asyncio
        async def test_response_sends_message(self, comm_service):
            """Response sends message to delegating agent."""
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Task",
                to_agent="artemis-optimizer",
            )
            await comm_service.respond_to_delegation(
                delegation_id=delegation.id,
                agent_id="artemis-optimizer",
                accept=True,
                response_message="Starting work",
            )
            # Check message sent to original sender
            messages = comm_service.get_messages("athena-conductor")
            assert len(messages) == 1
            assert messages[0].message_type == MessageType.RESPONSE

        @pytest.mark.asyncio
        async def test_respond_wrong_agent_raises(self, comm_service):
            """Raises error if wrong agent responds."""
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Task",
                to_agent="artemis-optimizer",
            )
            with pytest.raises(ValueError, match="is not the target"):
                await comm_service.respond_to_delegation(
                    delegation_id=delegation.id,
                    agent_id="hestia-auditor",  # Wrong agent
                    accept=True,
                )

        @pytest.mark.asyncio
        async def test_respond_invalid_delegation_raises(self, comm_service):
            """Raises error for invalid delegation ID."""
            with pytest.raises(ValueError, match="Delegation not found"):
                await comm_service.respond_to_delegation(
                    delegation_id=uuid4(),
                    agent_id="artemis-optimizer",
                    accept=True,
                )

    class TestCompleteDelegation:
        """Tests for complete_delegation method."""

        @pytest.fixture
        def comm_service(self):
            return AgentCommunicationService()

        @pytest.mark.asyncio
        async def test_complete_delegation_success(self, comm_service):
            """Can complete delegation successfully."""
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Task",
                to_agent="artemis-optimizer",
            )
            updated = await comm_service.complete_delegation(
                delegation_id=delegation.id,
                agent_id="artemis-optimizer",
                result={"output": "done"},
                success=True,
            )
            assert updated.status == "completed"

        @pytest.mark.asyncio
        async def test_complete_delegation_failure(self, comm_service):
            """Can mark delegation as failed."""
            delegation = await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Task",
                to_agent="artemis-optimizer",
            )
            updated = await comm_service.complete_delegation(
                delegation_id=delegation.id,
                agent_id="artemis-optimizer",
                result={"error": "timeout"},
                success=False,
            )
            assert updated.status == "failed"

    class TestGetMessages:
        """Tests for get_messages method."""

        @pytest.fixture
        def comm_service(self):
            return AgentCommunicationService()

        @pytest.mark.asyncio
        async def test_get_messages_empty(self, comm_service):
            """Returns empty list for agent with no messages."""
            messages = comm_service.get_messages("artemis-optimizer")
            assert messages == []

        @pytest.mark.asyncio
        async def test_get_messages_sorted_by_priority(self, comm_service):
            """Messages sorted by priority (high first)."""
            await comm_service.send_message(
                from_agent="a",
                to_agents=["target"],
                content="Low",
                priority=MessagePriority.LOW,
            )
            await comm_service.send_message(
                from_agent="b",
                to_agents=["target"],
                content="High",
                priority=MessagePriority.HIGH,
            )
            messages = comm_service.get_messages("target")
            assert messages[0].content == "High"
            assert messages[1].content == "Low"

        @pytest.mark.asyncio
        async def test_get_messages_filter_by_type(self, comm_service):
            """Can filter messages by type."""
            await comm_service.send_message(
                from_agent="a",
                to_agents=["target"],
                content="Direct",
                message_type=MessageType.DIRECT,
            )
            await comm_service.send_message(
                from_agent="b",
                to_agents=["target"],
                content="Status",
                message_type=MessageType.STATUS,
            )
            messages = comm_service.get_messages(
                "target",
                message_type=MessageType.DIRECT,
            )
            assert len(messages) == 1
            assert messages[0].content == "Direct"

        @pytest.mark.asyncio
        async def test_get_messages_respects_limit(self, comm_service):
            """Respects limit parameter."""
            for i in range(10):
                await comm_service.send_message(
                    from_agent="a",
                    to_agents=["target"],
                    content=f"Message {i}",
                )
            messages = comm_service.get_messages("target", limit=5)
            assert len(messages) == 5

    class TestClearMessages:
        """Tests for clear_messages method."""

        @pytest.fixture
        def comm_service(self):
            return AgentCommunicationService()

        @pytest.mark.asyncio
        async def test_clear_messages(self, comm_service):
            """Can clear all messages for agent."""
            await comm_service.send_message(
                from_agent="a",
                to_agents=["target"],
                content="Message 1",
            )
            await comm_service.send_message(
                from_agent="b",
                to_agents=["target"],
                content="Message 2",
            )
            count = comm_service.clear_messages("target")
            assert count == 2
            assert len(comm_service.get_messages("target")) == 0

    class TestChannels:
        """Tests for communication channels."""

        @pytest.fixture
        def comm_service(self):
            return AgentCommunicationService()

        @pytest.mark.asyncio
        async def test_create_channel(self, comm_service):
            """Can create a communication channel."""
            channel = await comm_service.create_channel(
                name="strategic-council",
                description="Strategic planning",
                members=["athena-conductor", "hera-strategist"],
                created_by="athena-conductor",
            )
            assert channel.name == "strategic-council"
            assert len(channel.members) == 2

        @pytest.mark.asyncio
        async def test_send_to_channel(self, comm_service):
            """Can send message to channel."""
            channel = await comm_service.create_channel(
                name="test-channel",
                description="Test",
                members=["athena-conductor", "hera-strategist", "artemis-optimizer"],
                created_by="athena-conductor",
            )
            message = await comm_service.send_to_channel(
                channel_id=channel.id,
                from_agent="athena-conductor",
                content="Channel message",
            )
            # Sender excluded from recipients
            assert "athena-conductor" not in message.to_agents
            assert "hera-strategist" in message.to_agents

        @pytest.mark.asyncio
        async def test_send_to_channel_nonmember_raises(self, comm_service):
            """Non-members cannot send to channel."""
            channel = await comm_service.create_channel(
                name="test-channel",
                description="Test",
                members=["athena-conductor", "hera-strategist"],
                created_by="athena-conductor",
            )
            with pytest.raises(ValueError, match="not a member"):
                await comm_service.send_to_channel(
                    channel_id=channel.id,
                    from_agent="artemis-optimizer",  # Not a member
                    content="Message",
                )

        @pytest.mark.asyncio
        async def test_list_channels_for_member(self, comm_service):
            """Can list channels for a member."""
            await comm_service.create_channel(
                name="channel-1",
                description="Test 1",
                members=["athena-conductor", "hera-strategist"],
                created_by="athena-conductor",
            )
            await comm_service.create_channel(
                name="channel-2",
                description="Test 2",
                members=["artemis-optimizer"],
                created_by="artemis-optimizer",
            )
            channels = comm_service.list_channels(member_agent="athena-conductor")
            assert len(channels) == 1
            assert channels[0].name == "channel-1"

    class TestHandoffTask:
        """Tests for handoff_task method."""

        @pytest.fixture
        def comm_service(self):
            return AgentCommunicationService()

        @pytest.mark.asyncio
        async def test_handoff_task(self, comm_service):
            """Can hand off task between agents."""
            message = await comm_service.handoff_task(
                from_agent="hera-strategist",
                to_agent="artemis-optimizer",
                task_content="Implement auth system",
                context={
                    "current_phase": "Phase 1",
                    "next_phase": "Phase 2",
                    "background": "Strategic plan complete",
                },
            )
            assert message.message_type == MessageType.HANDOFF
            assert message.metadata["from_phase"] == "Phase 1"
            assert message.metadata["to_phase"] == "Phase 2"

        @pytest.mark.asyncio
        async def test_handoff_with_artifacts(self, comm_service):
            """Can include artifacts in handoff."""
            artifacts = [
                {"type": "doc", "path": "docs/strategy.md"},
                {"type": "code", "path": "src/auth.py"},
            ]
            message = await comm_service.handoff_task(
                from_agent="hera-strategist",
                to_agent="artemis-optimizer",
                task_content="Task",
                context={},
                artifacts=artifacts,
            )
            assert len(message.metadata["artifacts"]) == 2

    class TestCommunicationStats:
        """Tests for get_agent_communication_stats method."""

        @pytest.fixture
        def comm_service(self):
            return AgentCommunicationService()

        @pytest.mark.asyncio
        async def test_get_empty_stats(self, comm_service):
            """Returns stats for agent with no activity."""
            stats = await comm_service.get_agent_communication_stats("artemis-optimizer")
            assert stats["pending_messages"] == 0
            assert stats["delegations_received"] == 0

        @pytest.mark.asyncio
        async def test_get_stats_with_messages(self, comm_service):
            """Returns correct stats after activity."""
            await comm_service.send_message(
                from_agent="athena-conductor",
                to_agents=["artemis-optimizer"],
                content="Message 1",
            )
            await comm_service.delegate_task(
                from_agent="athena-conductor",
                task_content="Task",
                to_agent="artemis-optimizer",
            )
            stats = await comm_service.get_agent_communication_stats("artemis-optimizer")
            assert stats["pending_messages"] == 2  # 1 message + 1 delegation message
            assert stats["delegations_received"] == 1
