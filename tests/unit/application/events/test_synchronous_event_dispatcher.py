"""
Unit tests for SynchronousEventDispatcher

This module tests the SynchronousEventDispatcher implementation.
Tests follow TDD RED phase methodology - expecting failures until implementation exists.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, call
from uuid import uuid4

import pytest

from src.application.events.synchronous_dispatcher import (
    SynchronousEventDispatcher,
)
from src.domain.events import (
    MCPConnectedEvent,
    MCPDisconnectedEvent,
    ToolsDiscoveredEvent,
)


@pytest.mark.asyncio
class TestSynchronousEventDispatcher:
    """Test suite for SynchronousEventDispatcher"""

    @pytest.fixture
    def dispatcher(self):
        """Create SynchronousEventDispatcher instance"""
        return SynchronousEventDispatcher()

    @pytest.fixture
    def mock_handler(self):
        """Create mock async handler"""
        return AsyncMock()

    @pytest.fixture
    def mock_sync_handler(self):
        """Create mock synchronous handler"""
        return MagicMock()

    @pytest.fixture
    def sample_connected_event(self):
        """Create sample MCPConnectedEvent"""
        return MCPConnectedEvent(
            connection_id=uuid4(),
            server_name="test_server",
            namespace="test-namespace",
            tools=[],
        )

    @pytest.fixture
    def sample_disconnected_event(self):
        """Create sample MCPDisconnectedEvent"""
        return MCPDisconnectedEvent(
            connection_id=uuid4(),
            server_name="test_server",
            namespace="test-namespace",
        )

    @pytest.fixture
    def sample_tools_discovered_event(self):
        """Create sample ToolsDiscoveredEvent"""
        return ToolsDiscoveredEvent(
            connection_id=uuid4(),
            server_name="test_server",
            tools=[],
        )

    async def test_register_handler(self, dispatcher, mock_handler, sample_connected_event):
        """
        Test handler registration

        Arrange:
            - Create dispatcher
            - Create handler for MCPConnectedEvent

        Act:
            - Register handler

        Assert:
            - Handler registered in internal dict
            - Handler can be retrieved for event type
        """
        # Act
        dispatcher.register(MCPConnectedEvent, mock_handler)

        # Assert - Handler registered
        # Note: This tests internal implementation, may need adjustment
        assert MCPConnectedEvent in dispatcher._handlers
        assert mock_handler in dispatcher._handlers[MCPConnectedEvent]

    async def test_dispatch_event_to_single_handler(
        self, dispatcher, mock_handler, sample_connected_event
    ):
        """
        Test event dispatch to single handler

        Arrange:
            - Register handler for MCPConnectedEvent

        Act:
            - Dispatch MCPConnectedEvent

        Assert:
            - Handler called once with correct event
        """
        # Arrange
        dispatcher.register(MCPConnectedEvent, mock_handler)

        # Act
        await dispatcher.dispatch_all([sample_connected_event])

        # Assert
        mock_handler.assert_called_once_with(sample_connected_event)

    async def test_dispatch_event_to_multiple_handlers(self, dispatcher, sample_connected_event):
        """
        Test event dispatch to multiple handlers for same event type

        Arrange:
            - Register 3 handlers for MCPConnectedEvent

        Act:
            - Dispatch event

        Assert:
            - All 3 handlers called with correct event
        """
        # Arrange
        handler1 = AsyncMock()
        handler2 = AsyncMock()
        handler3 = AsyncMock()

        dispatcher.register(MCPConnectedEvent, handler1)
        dispatcher.register(MCPConnectedEvent, handler2)
        dispatcher.register(MCPConnectedEvent, handler3)

        # Act
        await dispatcher.dispatch_all([sample_connected_event])

        # Assert
        handler1.assert_called_once_with(sample_connected_event)
        handler2.assert_called_once_with(sample_connected_event)
        handler3.assert_called_once_with(sample_connected_event)

    async def test_dispatch_multiple_events(
        self,
        dispatcher,
        sample_connected_event,
        sample_tools_discovered_event,
    ):
        """
        Test dispatching multiple different events

        Arrange:
            - Register handler for MCPConnectedEvent
            - Register handler for ToolsDiscoveredEvent

        Act:
            - Dispatch both events

        Assert:
            - Each handler called for correct event type only
        """
        # Arrange
        connected_handler = AsyncMock()
        tools_handler = AsyncMock()

        dispatcher.register(MCPConnectedEvent, connected_handler)
        dispatcher.register(ToolsDiscoveredEvent, tools_handler)

        # Act
        await dispatcher.dispatch_all([sample_connected_event, sample_tools_discovered_event])

        # Assert
        connected_handler.assert_called_once_with(sample_connected_event)
        tools_handler.assert_called_once_with(sample_tools_discovered_event)

    async def test_async_handler_support(self, dispatcher, sample_connected_event):
        """
        Test async handler is awaited correctly

        Arrange:
            - Register async handler

        Act:
            - Dispatch event

        Assert:
            - Async handler awaited correctly
            - Handler executed successfully
        """
        # Arrange
        call_count = 0

        async def async_handler(event):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.01)  # Simulate async operation
            assert isinstance(event, MCPConnectedEvent)

        dispatcher.register(MCPConnectedEvent, async_handler)

        # Act
        await dispatcher.dispatch_all([sample_connected_event])

        # Assert
        assert call_count == 1

    async def test_sync_handler_support(
        self, dispatcher, mock_sync_handler, sample_connected_event
    ):
        """
        Test synchronous (non-async) handler support

        Arrange:
            - Register sync (non-async) handler

        Act:
            - Dispatch event

        Assert:
            - Handler executed via asyncio.to_thread()
            - Handler called with correct event
        """

        # Arrange
        def sync_handler(event):
            # Synchronous handler (no async/await)
            pass

        # Wrap in mock to track calls
        mock_sync_handler.side_effect = sync_handler
        dispatcher.register(MCPConnectedEvent, mock_sync_handler)

        # Act
        await dispatcher.dispatch_all([sample_connected_event])

        # Assert
        mock_sync_handler.assert_called_once_with(sample_connected_event)

    async def test_handler_error_isolation(self, dispatcher, sample_connected_event):
        """
        Test handler errors are isolated and don't affect other handlers

        Arrange:
            - Register handler that raises exception
            - Register handler that succeeds

        Act:
            - Dispatch event

        Assert:
            - Exception logged but NOT raised (error isolation)
            - Subsequent handlers still execute
        """
        # Arrange
        call_order = []

        async def failing_handler(event):
            call_order.append("failing")
            raise Exception("Handler failed")

        async def successful_handler(event):
            call_order.append("successful")

        dispatcher.register(MCPConnectedEvent, failing_handler)
        dispatcher.register(MCPConnectedEvent, successful_handler)

        # Act - Should NOT raise exception
        await dispatcher.dispatch_all([sample_connected_event])

        # Assert
        assert "failing" in call_order
        assert "successful" in call_order
        # Both handlers executed despite first one failing

    async def test_no_handler_registered(self, dispatcher, sample_connected_event):
        """
        Test dispatch with no handlers registered

        Arrange:
            - DO NOT register any handlers

        Act:
            - Dispatch MCPConnectedEvent

        Assert:
            - No error raised
            - Debug log "No handlers registered"
        """
        # Act - Should NOT raise exception
        await dispatcher.dispatch_all([sample_connected_event])

        # Assert - No error raised (test passes if we reach here)
        assert True


# Additional test for multiple event types with same handler
@pytest.mark.asyncio
async def test_same_handler_for_multiple_event_types():
    """
    Test same handler registered for multiple event types

    Arrange:
        - Register same handler for MCPConnectedEvent and MCPDisconnectedEvent

    Act:
        - Dispatch both event types

    Assert:
        - Handler called twice (once for each event)
    """
    # Arrange
    dispatcher = SynchronousEventDispatcher()
    handler = AsyncMock()

    connected_event = MCPConnectedEvent(
        connection_id=uuid4(),
        server_name="test_server",
        namespace="test-namespace",
        tools=[],
    )

    disconnected_event = MCPDisconnectedEvent(
        connection_id=uuid4(),
        server_name="test_server",
        namespace="test-namespace",
    )

    dispatcher.register(MCPConnectedEvent, handler)
    dispatcher.register(MCPDisconnectedEvent, handler)

    # Act
    await dispatcher.dispatch_all([connected_event, disconnected_event])

    # Assert
    assert handler.call_count == 2
    handler.assert_has_calls(
        [
            call(connected_event),
            call(disconnected_event),
        ]
    )
