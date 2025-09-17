#!/usr/bin/env python3
"""
TMWS WebSocket MCP Server v2.2.0 - Shared Server Architecture
Harmonious design for multiple Claude Code instances with unified state management.

Athena's Design Philosophy:
- Gentle orchestration of multiple concurrent sessions
- Seamless WebSocket transport for MCP protocol messages
- Warm session management with context preservation
- Beautiful backward compatibility with existing tools
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from contextlib import asynccontextmanager

import websockets
from websockets.server import WebSocketServerProtocol
from fastmcp import FastMCP
from pydantic import BaseModel

from src.core.config import get_settings
from src.services.memory_service import MemoryService
from src.services.agent_service import AgentService
from src.services.workflow_service import WorkflowService
from src.services.task_service import TaskService
from src.core.database import get_db_session
from src.security.audit_logger_async import AsyncAuditLogger

# Configure logging with Athena's warm approach
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Get settings
settings = get_settings()


class MCPMessage(BaseModel):
    """MCP protocol message structure"""
    jsonrpc: str = "2.0"
    id: Optional[str] = None
    method: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None


@dataclass
class ClientSession:
    """Individual Claude Code session context"""
    session_id: str
    websocket: WebSocketServerProtocol
    agent_id: str
    namespace: str = "default"
    capabilities: Dict[str, Any] = field(default_factory=dict)
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    context: Dict[str, Any] = field(default_factory=dict)
    active_workflows: Set[str] = field(default_factory=set)

    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now(timezone.utc)

    @property
    def session_duration(self) -> float:
        """Get session duration in seconds"""
        return (datetime.now(timezone.utc) - self.connected_at).total_seconds()


class SharedSessionManager:
    """Harmonious session management for multiple Claude Code instances"""

    def __init__(self):
        self.sessions: Dict[str, ClientSession] = {}
        self.agent_sessions: Dict[str, Set[str]] = {}  # agent_id -> session_ids
        self.websocket_sessions: Dict[WebSocketServerProtocol, str] = {}  # ws -> session_id
        self.lock = asyncio.Lock()

    async def create_session(
        self,
        websocket: WebSocketServerProtocol,
        agent_id: str,
        namespace: str = "default",
        capabilities: Dict[str, Any] = None
    ) -> str:
        """Create a new client session with warm welcome"""
        async with self.lock:
            session_id = str(uuid.uuid4())

            session = ClientSession(
                session_id=session_id,
                websocket=websocket,
                agent_id=agent_id,
                namespace=namespace,
                capabilities=capabilities or {}
            )

            self.sessions[session_id] = session
            self.websocket_sessions[websocket] = session_id

            # Track agent sessions
            if agent_id not in self.agent_sessions:
                self.agent_sessions[agent_id] = set()
            self.agent_sessions[agent_id].add(session_id)

            logger.info(f"✨ New session created: {session_id} for agent {agent_id}")
            return session_id

    async def remove_session(self, session_id: str):
        """Remove session with graceful cleanup"""
        async with self.lock:
            if session_id not in self.sessions:
                return

            session = self.sessions[session_id]

            # Remove from websocket mapping
            if session.websocket in self.websocket_sessions:
                del self.websocket_sessions[session.websocket]

            # Remove from agent sessions
            if session.agent_id in self.agent_sessions:
                self.agent_sessions[session.agent_id].discard(session_id)
                if not self.agent_sessions[session.agent_id]:
                    del self.agent_sessions[session.agent_id]

            # Remove session
            del self.sessions[session_id]

            logger.info(f"👋 Session {session_id} gracefully removed after {session.session_duration:.1f}s")

    async def get_session(self, session_id: str) -> Optional[ClientSession]:
        """Get session with activity update"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.update_activity()
            return session
        return None

    async def get_session_by_websocket(self, websocket: WebSocketServerProtocol) -> Optional[ClientSession]:
        """Get session by WebSocket connection"""
        session_id = self.websocket_sessions.get(websocket)
        if session_id:
            return await self.get_session(session_id)
        return None

    async def get_agent_sessions(self, agent_id: str) -> List[ClientSession]:
        """Get all sessions for a specific agent"""
        session_ids = self.agent_sessions.get(agent_id, set())
        return [self.sessions[sid] for sid in session_ids if sid in self.sessions]

    async def broadcast_to_agent(self, agent_id: str, message: MCPMessage):
        """Broadcast message to all sessions of an agent"""
        sessions = await self.get_agent_sessions(agent_id)
        tasks = []
        for session in sessions:
            tasks.append(self._send_message(session.websocket, message))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_message(self, websocket: WebSocketServerProtocol, message: MCPMessage):
        """Send message to WebSocket with error handling"""
        try:
            await websocket.send(message.model_dump_json())
        except Exception as e:
            logger.error(f"Failed to send message: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get harmonious session statistics"""
        total_sessions = len(self.sessions)
        unique_agents = len(self.agent_sessions)
        avg_duration = 0

        if self.sessions:
            avg_duration = sum(s.session_duration for s in self.sessions.values()) / total_sessions

        return {
            "total_sessions": total_sessions,
            "unique_agents": unique_agents,
            "average_session_duration_seconds": avg_duration,
            "agent_distribution": {
                agent_id: len(sessions)
                for agent_id, sessions in self.agent_sessions.items()
            }
        }


class WebSocketMCPServer:
    """Harmonious WebSocket MCP Server with unified state management"""

    def __init__(self):
        self.session_manager = SharedSessionManager()
        self.memory_service = MemoryService()
        self.agent_service = AgentService()
        self.workflow_service = WorkflowService()
        self.task_service = TaskService()
        self.audit_logger = AsyncAuditLogger()

        # Create FastMCP instance for tool registration
        self.mcp = FastMCP("TMWS WebSocket MCP Server v2.2.0")
        self._register_tools()

        # Server state
        self.server = None
        self.running = False

    def _register_tools(self):
        """Register all MCP tools with warm delegation"""

        @self.mcp.tool()
        async def get_agent_info(session_id: str = None) -> Dict[str, Any]:
            """Get current agent information and session details"""
            session = await self.session_manager.get_session(session_id)
            if not session:
                return {"error": "Session not found"}

            return {
                "agent_id": session.agent_id,
                "namespace": session.namespace,
                "capabilities": session.capabilities,
                "session_id": session.session_id,
                "connected_at": session.connected_at.isoformat(),
                "session_duration_seconds": session.session_duration,
                "version": settings.api_version
            }

        @self.mcp.tool()
        async def create_memory(
            content: str,
            tags: List[str] = None,
            importance: float = 0.5,
            access_level: str = "private",
            context_data: Dict[str, Any] = None,
            session_id: str = None
        ) -> Dict[str, Any]:
            """Create memory with session context"""
            session = await self.session_manager.get_session(session_id)
            if not session:
                return {"error": "Session not found"}

            try:
                memory = await self.memory_service.create_memory(
                    content=content,
                    tags=tags or [],
                    importance=importance,
                    metadata=context_data or {},
                    persona_id=session.agent_id
                )

                await self.audit_logger.log_event(
                    event_type="memory_created",
                    user_id=session.agent_id,
                    resource=f"memory:{memory.id}",
                    action="create",
                    result="success",
                    metadata={"session_id": session.session_id}
                )

                return {
                    "success": True,
                    "memory_id": str(memory.id),
                    "agent_id": session.agent_id,
                    "message": "Memory created with harmonious care ✨"
                }
            except Exception as e:
                logger.error(f"Memory creation error: {e}")
                return {"error": f"Failed to create memory: {str(e)}"}

        @self.mcp.tool()
        async def search_memories(
            query: str,
            limit: int = 10,
            min_importance: float = 0.0,
            include_shared: bool = True,
            session_id: str = None
        ) -> Dict[str, Any]:
            """Search memories with session context"""
            session = await self.session_manager.get_session(session_id)
            if not session:
                return {"error": "Session not found"}

            try:
                memories = await self.memory_service.search_memories(
                    query=query,
                    limit=limit,
                    persona_id=session.agent_id if not include_shared else None,
                    min_importance=min_importance
                )

                return {
                    "success": True,
                    "query": query,
                    "count": len(memories),
                    "memories": [
                        {
                            "id": str(memory.id),
                            "content": memory.content,
                            "importance": memory.importance,
                            "tags": memory.tags,
                            "created_at": memory.created_at.isoformat(),
                            "persona_id": memory.persona_id
                        }
                        for memory in memories
                    ]
                }
            except Exception as e:
                logger.error(f"Memory search error: {e}")
                return {"error": f"Failed to search memories: {str(e)}"}

        @self.mcp.tool()
        async def get_session_statistics() -> Dict[str, Any]:
            """Get harmonious session statistics"""
            return {
                "success": True,
                "statistics": self.session_manager.get_statistics(),
                "server_version": settings.api_version,
                "uptime_seconds": None  # Will be calculated by server
            }

    async def handle_handshake(self, websocket: WebSocketServerProtocol, path: str):
        """Handle initial WebSocket handshake with warm welcome"""
        try:
            # Extract agent info from connection
            agent_id = websocket.request_headers.get("X-Agent-ID", "default-agent")
            namespace = websocket.request_headers.get("X-Agent-Namespace", "default")

            # Parse capabilities if provided
            capabilities = {}
            caps_header = websocket.request_headers.get("X-Agent-Capabilities")
            if caps_header:
                try:
                    capabilities = json.loads(caps_header)
                except json.JSONDecodeError:
                    capabilities = {"raw": caps_header}

            # Create session
            session_id = await self.session_manager.create_session(
                websocket=websocket,
                agent_id=agent_id,
                namespace=namespace,
                capabilities=capabilities
            )

            # Send welcome message
            welcome = MCPMessage(
                method="welcome",
                params={
                    "session_id": session_id,
                    "server_version": settings.api_version,
                    "agent_id": agent_id,
                    "message": "Welcome to TMWS! 🌟 Ready for harmonious collaboration."
                }
            )
            await websocket.send(welcome.model_dump_json())

            logger.info(f"🤝 Handshake completed for agent {agent_id} (session: {session_id})")

        except Exception as e:
            logger.error(f"Handshake error: {e}")
            await websocket.close(code=1011, reason="Handshake failed")

    async def handle_message(self, websocket: WebSocketServerProtocol, raw_message: str):
        """Handle incoming MCP message with gentle processing"""
        try:
            # Parse MCP message
            data = json.loads(raw_message)
            message = MCPMessage(**data)

            # Get session context
            session = await self.session_manager.get_session_by_websocket(websocket)
            if not session:
                error_response = MCPMessage(
                    id=message.id,
                    error={"code": -1, "message": "Session not found"}
                )
                await websocket.send(error_response.model_dump_json())
                return

            # Process message based on method
            if message.method:
                await self._handle_method_call(websocket, session, message)
            else:
                logger.warning(f"Unknown message type from session {session.session_id}")

        except json.JSONDecodeError:
            logger.error("Invalid JSON received")
            error_response = MCPMessage(
                error={"code": -32700, "message": "Parse error"}
            )
            await websocket.send(error_response.model_dump_json())
        except Exception as e:
            logger.error(f"Message handling error: {e}")
            error_response = MCPMessage(
                id=getattr(message, 'id', None),
                error={"code": -32603, "message": f"Internal error: {str(e)}"}
            )
            await websocket.send(error_response.model_dump_json())

    async def _handle_method_call(self, websocket: WebSocketServerProtocol, session: ClientSession, message: MCPMessage):
        """Handle MCP method calls with harmonious delegation"""
        try:
            # Add session_id to params for context
            params = message.params or {}
            params["session_id"] = session.session_id

            # Execute tool (this is simplified - in reality you'd need proper MCP tool routing)
            if message.method == "get_agent_info":
                result = await self.mcp.tools["get_agent_info"](**params)
            elif message.method == "create_memory":
                result = await self.mcp.tools["create_memory"](**params)
            elif message.method == "search_memories":
                result = await self.mcp.tools["search_memories"](**params)
            elif message.method == "get_session_statistics":
                result = await self.mcp.tools["get_session_statistics"](**params)
            else:
                result = {"error": f"Unknown method: {message.method}"}

            # Send response
            response = MCPMessage(
                id=message.id,
                result=result
            )
            await websocket.send(response.model_dump_json())

        except Exception as e:
            logger.error(f"Method call error: {e}")
            error_response = MCPMessage(
                id=message.id,
                error={"code": -32603, "message": f"Method execution failed: {str(e)}"}
            )
            await websocket.send(error_response.model_dump_json())

    async def handle_client_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle complete client connection lifecycle"""
        try:
            # Perform handshake
            await self.handle_handshake(websocket, path)

            # Message loop
            async for raw_message in websocket:
                await self.handle_message(websocket, raw_message)

        except websockets.exceptions.ConnectionClosed:
            logger.info("Client connection closed normally")
        except Exception as e:
            logger.error(f"Connection error: {e}")
        finally:
            # Cleanup session
            session = await self.session_manager.get_session_by_websocket(websocket)
            if session:
                await self.session_manager.remove_session(session.session_id)

    async def start_server(self, host: str = "127.0.0.1", port: int = 8001):
        """Start the harmonious WebSocket server"""
        logger.info(f"🌟 Starting TMWS WebSocket MCP Server v{settings.api_version}")
        logger.info(f"🏡 Listening on {host}:{port}")

        self.server = await websockets.serve(
            self.handle_client_connection,
            host,
            port,
            ping_interval=30,  # Keep connections alive
            ping_timeout=10,
            max_size=1024 * 1024,  # 1MB max message size
            compression=None  # Disable compression for simplicity
        )

        self.running = True
        logger.info("✨ WebSocket MCP Server is ready for harmonious connections!")

        # Keep server running
        await self.server.wait_closed()

    async def stop_server(self):
        """Stop server gracefully"""
        if self.server:
            logger.info("🛑 Stopping WebSocket MCP Server gracefully...")
            self.server.close()
            await self.server.wait_closed()
            self.running = False
            logger.info("👋 Server stopped harmoniously")


@asynccontextmanager
async def create_ws_mcp_server():
    """Create WebSocket MCP server with context management"""
    server = WebSocketMCPServer()
    try:
        yield server
    finally:
        await server.stop_server()


async def main():
    """Main entry point for WebSocket MCP Server"""
    server = WebSocketMCPServer()

    try:
        await server.start_server(
            host=settings.api_host,
            port=getattr(settings, 'ws_mcp_port', 8001)
        )
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
    finally:
        await server.stop_server()


if __name__ == "__main__":
    asyncio.run(main())