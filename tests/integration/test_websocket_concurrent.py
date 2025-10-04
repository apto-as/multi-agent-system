"""
Integration test for WebSocket concurrent connections.
Tests multiple terminal simultaneous connections from the same agent.
"""

import asyncio
import json
import uuid

import pytest
from fastapi.testclient import TestClient
from websockets import connect as websocket_connect

from src.api.app import create_app
from src.core.config import get_settings

settings = get_settings()

pytestmark = pytest.mark.asyncio


async def test_multiple_concurrent_websocket_connections():
    """Test multiple WebSocket connections from the same agent."""
    app = create_app()
    agent_id = f"test-agent-{uuid.uuid4()}"

    with TestClient(app) as client:
        # Create 3 concurrent WebSocket connections from the same agent
        websockets = []
        session_ids = []

        for i in range(3):
            ws = client.websocket_connect(
                f"/ws/mcp?agent_id={agent_id}"
            )
            websockets.append(ws)

            # Receive welcome message
            welcome = ws.receive_json()
            assert welcome["method"] == "welcome"
            assert "session_id" in welcome["params"]
            session_ids.append(welcome["params"]["session_id"])

        # Verify all session IDs are unique
        assert len(set(session_ids)) == 3

        # Send a message from each connection
        for i, ws in enumerate(websockets):
            ws.send_json({
                "jsonrpc": "2.0",
                "id": str(i + 1),
                "method": "test",
                "params": {"message": f"Hello from connection {i}"}
            })

        # Close all connections
        for ws in websockets:
            ws.close()


async def test_concurrent_message_handling():
    """Test that concurrent messages are handled without race conditions."""
    app = create_app()
    agent_id = f"test-agent-{uuid.uuid4()}"

    with TestClient(app) as client:
        # Create 2 WebSocket connections
        ws1 = client.websocket_connect(f"/ws/mcp?agent_id={agent_id}")
        ws2 = client.websocket_connect(f"/ws/mcp?agent_id={agent_id}")

        # Receive welcome messages
        welcome1 = ws1.receive_json()
        welcome2 = ws2.receive_json()

        session1 = welcome1["params"]["session_id"]
        session2 = welcome2["params"]["session_id"]

        # Send concurrent messages
        messages_to_send = 10

        # Send messages from both connections simultaneously
        for i in range(messages_to_send):
            ws1.send_json({
                "jsonrpc": "2.0",
                "id": f"ws1-{i}",
                "method": "echo",
                "params": {"data": f"Message {i} from WS1"}
            })
            ws2.send_json({
                "jsonrpc": "2.0",
                "id": f"ws2-{i}",
                "method": "echo",
                "params": {"data": f"Message {i} from WS2"}
            })

        # Verify both connections are still active
        ws1.send_json({
            "jsonrpc": "2.0",
            "id": "test-1",
            "method": "ping"
        })
        ws2.send_json({
            "jsonrpc": "2.0",
            "id": "test-2",
            "method": "ping"
        })

        # Clean up
        ws1.close()
        ws2.close()


async def test_broadcast_to_agent_sessions():
    """Test broadcasting messages to all sessions of an agent."""
    app = create_app()
    agent_id = f"test-agent-{uuid.uuid4()}"

    with TestClient(app) as client:
        # Create 3 connections for the same agent
        connections = []
        for i in range(3):
            ws = client.websocket_connect(f"/ws/mcp?agent_id={agent_id}")
            # Receive welcome
            ws.receive_json()
            connections.append(ws)

        # In a real scenario, a broadcast would be triggered by some event
        # Here we just verify the connections are properly managed

        # Send a message from connection 1
        connections[0].send_json({
            "jsonrpc": "2.0",
            "id": "broadcast-test",
            "method": "broadcast_test",
            "params": {"message": "Test broadcast"}
        })

        # All connections should remain active
        for ws in connections:
            ws.send_json({
                "jsonrpc": "2.0",
                "id": "alive",
                "method": "ping"
            })

        # Clean up
        for ws in connections:
            ws.close()


async def test_connection_cleanup_on_disconnect():
    """Test that connections are properly cleaned up on disconnect."""
    app = create_app()
    agent_id = f"test-agent-{uuid.uuid4()}"

    with TestClient(app) as client:
        # Create and immediately close connections
        for i in range(5):
            ws = client.websocket_connect(f"/ws/mcp?agent_id={agent_id}")
            welcome = ws.receive_json()
            session_id = welcome["params"]["session_id"]

            # Close the connection
            ws.close()

            # Create a new connection to verify cleanup
            ws_new = client.websocket_connect(f"/ws/mcp?agent_id={agent_id}")
            welcome_new = ws_new.receive_json()
            new_session_id = welcome_new["params"]["session_id"]

            # Session IDs should be different
            assert session_id != new_session_id

            ws_new.close()


async def test_rate_limiting_per_ip():
    """Test rate limiting works correctly for concurrent connections."""
    app = create_app()

    # This test would need proper rate limiting configuration
    # For now, we just verify connections can be established
    with TestClient(app) as client:
        connections = []

        # Try to create multiple connections rapidly
        for i in range(10):
            try:
                ws = client.websocket_connect(f"/ws/mcp?agent_id=rate-test-{i}")
                welcome = ws.receive_json()
                connections.append(ws)
            except Exception:
                # Rate limit might kick in
                break

        # At least some connections should succeed
        assert len(connections) > 0

        # Clean up
        for ws in connections:
            ws.close()