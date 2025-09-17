#!/usr/bin/env python3
"""
WebSocket MCP Endpoint for TMWS v2.2.0
Enables multiple Claude Code instances to share a single server
"""

import json
import asyncio
import logging
import uuid
import time
from typing import Dict, Set, Optional, Any
from datetime import datetime, timezone

from fastapi import WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
import jwt

from src.core.config import get_settings
from src.core.database import get_db
from src.services.memory_service import MemoryService
from src.services.task_service import TaskService
from src.services.workflow_service import WorkflowService
from src.services.persona_service import PersonaService

logger = logging.getLogger(__name__)
settings = get_settings()

# Security
security = HTTPBearer(auto_error=False)

class MCPMessage(BaseModel):
    """MCP Protocol Message"""
    jsonrpc: str = Field(default="2.0", pattern="^2\\.0$")
    id: Optional[str] = Field(None, max_length=36, pattern="^[a-zA-Z0-9-_]+$")
    method: Optional[str] = Field(None, max_length=50, pattern="^[a-zA-Z_][a-zA-Z0-9_/]*$")
    params: Optional[Dict[str, Any]] = Field(default_factory=dict)
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None

    @validator('params')
    def validate_params_size(cls, v):
        if v and len(json.dumps(v)) > 64 * 1024:  # 64KB limit
            raise ValueError("Parameters too large")
        return v


class WebSocketSession:
    """WebSocket client session"""
    def __init__(self, session_id: str, websocket: WebSocket, agent_id: str):
        self.session_id = session_id
        self.websocket = websocket
        self.agent_id = agent_id
        self.connected_at = datetime.now(timezone.utc)
        self.last_activity = datetime.now(timezone.utc)
        self.request_count = 0
        self.metadata = {}

    def update_activity(self):
        self.last_activity = datetime.now(timezone.utc)
        self.request_count += 1


class ConnectionManager:
    """Manages WebSocket connections for multiple clients"""

    def __init__(self):
        # Active connections: session_id -> WebSocketSession
        self.active_connections: Dict[str, WebSocketSession] = {}
        # Agent connections: agent_id -> Set[session_id]
        self.agent_sessions: Dict[str, Set[str]] = {}
        # Rate limiting: ip -> List[timestamp]
        self.rate_limits: Dict[str, list] = {}

    async def connect(self, websocket: WebSocket, agent_id: str) -> str:
        """Accept new WebSocket connection"""
        await websocket.accept()

        session_id = str(uuid.uuid4())
        session = WebSocketSession(session_id, websocket, agent_id)

        self.active_connections[session_id] = session

        if agent_id not in self.agent_sessions:
            self.agent_sessions[agent_id] = set()
        self.agent_sessions[agent_id].add(session_id)

        logger.info(f"WebSocket connected: session={session_id}, agent={agent_id}")
        return session_id

    def disconnect(self, session_id: str):
        """Remove WebSocket connection"""
        if session_id in self.active_connections:
            session = self.active_connections[session_id]

            # Remove from agent sessions
            if session.agent_id in self.agent_sessions:
                self.agent_sessions[session.agent_id].discard(session_id)
                if not self.agent_sessions[session.agent_id]:
                    del self.agent_sessions[session.agent_id]

            del self.active_connections[session_id]
            logger.info(f"WebSocket disconnected: session={session_id}")

    async def send_message(self, session_id: str, message: dict):
        """Send message to specific client"""
        if session_id in self.active_connections:
            session = self.active_connections[session_id]
            await session.websocket.send_json(message)
            session.update_activity()

    async def broadcast_to_agent(self, agent_id: str, message: dict):
        """Broadcast message to all sessions of an agent"""
        if agent_id in self.agent_sessions:
            for session_id in self.agent_sessions[agent_id]:
                await self.send_message(session_id, message)

    def get_session_stats(self) -> dict:
        """Get connection statistics"""
        return {
            "total_connections": len(self.active_connections),
            "unique_agents": len(self.agent_sessions),
            "sessions_by_agent": {
                agent: len(sessions)
                for agent, sessions in self.agent_sessions.items()
            }
        }

    def check_rate_limit(self, client_ip: str) -> bool:
        """Check if client exceeds rate limit"""
        now = time.time()
        minute_ago = now - 60

        if client_ip not in self.rate_limits:
            self.rate_limits[client_ip] = []

        # Clean old requests
        self.rate_limits[client_ip] = [
            t for t in self.rate_limits[client_ip] if t > minute_ago
        ]

        # Check rate limit (60 requests per minute)
        if len(self.rate_limits[client_ip]) >= 60:
            return False

        self.rate_limits[client_ip].append(now)
        return True


# Global connection manager
manager = ConnectionManager()


class MCPHandler:
    """Handles MCP protocol messages"""

    def __init__(self, db_session):
        self.db = db_session
        self.memory_service = MemoryService(db_session)
        self.task_service = TaskService(db_session)
        self.workflow_service = WorkflowService(db_session)
        self.persona_service = PersonaService(db_session)

    async def handle_request(self, message: MCPMessage, session: WebSocketSession) -> dict:
        """Route and handle MCP request"""
        try:
            if not message.method:
                raise ValueError("Method is required")

            # Route to appropriate handler
            method_handlers = {
                "initialize": self.handle_initialize,
                "tools/list": self.handle_list_tools,
                "tools/call": self.handle_tool_call,
                "resources/list": self.handle_list_resources,
                "resources/get": self.handle_get_resource,
                "memory/store": self.handle_store_memory,
                "memory/search": self.handle_search_memory,
                "task/create": self.handle_create_task,
                "task/list": self.handle_list_tasks,
                "workflow/execute": self.handle_execute_workflow,
                "agent/info": self.handle_agent_info,
            }

            handler = method_handlers.get(message.method)
            if not handler:
                raise ValueError(f"Unknown method: {message.method}")

            result = await handler(message.params or {}, session)

            return {
                "jsonrpc": "2.0",
                "id": message.id,
                "result": result
            }

        except Exception as e:
            logger.error(f"Error handling MCP request: {e}")
            return {
                "jsonrpc": "2.0",
                "id": message.id,
                "error": {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e) if settings.environment == "development" else None
                }
            }

    async def handle_initialize(self, params: dict, session: WebSocketSession) -> dict:
        """Handle initialization request"""
        return {
            "protocolVersion": "1.0",
            "serverName": "TMWS",
            "serverVersion": settings.api_version,
            "capabilities": {
                "tools": True,
                "resources": True,
                "memory": True,
                "tasks": True,
                "workflows": True
            }
        }

    async def handle_list_tools(self, params: dict, session: WebSocketSession) -> dict:
        """List available MCP tools"""
        tools = [
            {
                "name": "store_memory",
                "description": "Store information in semantic memory",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string"},
                        "importance": {"type": "number", "minimum": 0, "maximum": 1}
                    }
                }
            },
            {
                "name": "search_memories",
                "description": "Search semantic memories",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 100}
                    }
                }
            },
            {
                "name": "create_task",
                "description": "Create a new task",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "priority": {"type": "string", "enum": ["low", "medium", "high", "urgent"]}
                    }
                }
            }
        ]
        return {"tools": tools}

    async def handle_tool_call(self, params: dict, session: WebSocketSession) -> dict:
        """Execute tool call"""
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        if tool_name == "store_memory":
            memory = await self.memory_service.create_memory(
                content=tool_args.get("content"),
                importance=tool_args.get("importance", 0.5),
                agent_id=session.agent_id,
                metadata={"session_id": session.session_id}
            )
            return {"success": True, "memory_id": str(memory.id)}

        elif tool_name == "search_memories":
            memories = await self.memory_service.search_memories(
                query=tool_args.get("query"),
                limit=tool_args.get("limit", 10),
                agent_id=session.agent_id
            )
            return {"memories": [m.to_dict() for m in memories]}

        elif tool_name == "create_task":
            task = await self.task_service.create_task(
                title=tool_args.get("title"),
                description=tool_args.get("description"),
                priority=tool_args.get("priority", "medium"),
                assigned_persona=session.agent_id
            )
            return {"success": True, "task_id": str(task.id)}

        else:
            raise ValueError(f"Unknown tool: {tool_name}")

    async def handle_list_resources(self, params: dict, session: WebSocketSession) -> dict:
        """List available resources"""
        # Return agent's memories as resources
        memories = await self.memory_service.list_memories(
            agent_id=session.agent_id,
            limit=100
        )

        resources = [
            {
                "uri": f"memory://{m.id}",
                "name": f"Memory {m.id[:8]}",
                "mimeType": "text/plain",
                "description": m.content[:100]
            }
            for m in memories
        ]

        return {"resources": resources}

    async def handle_get_resource(self, params: dict, session: WebSocketSession) -> dict:
        """Get specific resource"""
        uri = params.get("uri")

        if uri and uri.startswith("memory://"):
            memory_id = uri.replace("memory://", "")
            memory = await self.memory_service.get_memory(memory_id)

            if memory:
                return {
                    "uri": uri,
                    "mimeType": "text/plain",
                    "content": memory.content,
                    "metadata": memory.metadata
                }

        raise ValueError(f"Resource not found: {uri}")

    async def handle_store_memory(self, params: dict, session: WebSocketSession) -> dict:
        """Store memory (direct method)"""
        memory = await self.memory_service.create_memory(
            content=params.get("content"),
            importance=params.get("importance", 0.5),
            agent_id=session.agent_id,
            metadata=params.get("metadata", {})
        )
        return {"memory_id": str(memory.id), "created_at": memory.created_at.isoformat()}

    async def handle_search_memory(self, params: dict, session: WebSocketSession) -> dict:
        """Search memories (direct method)"""
        memories = await self.memory_service.search_memories(
            query=params.get("query"),
            limit=params.get("limit", 10),
            agent_id=session.agent_id
        )
        return {"memories": [m.to_dict() for m in memories]}

    async def handle_create_task(self, params: dict, session: WebSocketSession) -> dict:
        """Create task (direct method)"""
        task = await self.task_service.create_task(**params)
        return task.to_dict()

    async def handle_list_tasks(self, params: dict, session: WebSocketSession) -> dict:
        """List tasks"""
        tasks = await self.task_service.list_tasks(
            assigned_persona=session.agent_id,
            limit=params.get("limit", 50)
        )
        return {"tasks": [t.to_dict() for t in tasks]}

    async def handle_execute_workflow(self, params: dict, session: WebSocketSession) -> dict:
        """Execute workflow"""
        workflow = await self.workflow_service.execute_workflow(
            workflow_id=params.get("workflow_id"),
            parameters=params.get("parameters", {})
        )
        return workflow.to_dict()

    async def handle_agent_info(self, params: dict, session: WebSocketSession) -> dict:
        """Get agent information"""
        return {
            "agent_id": session.agent_id,
            "session_id": session.session_id,
            "connected_at": session.connected_at.isoformat(),
            "request_count": session.request_count,
            "server_stats": manager.get_session_stats()
        }


async def verify_token(credentials: Optional[HTTPAuthorizationCredentials] = None) -> Optional[str]:
    """Verify JWT token for WebSocket authentication"""
    if settings.environment == "development" and not settings.auth_enabled:
        return "dev-agent"  # Development mode bypass

    if not credentials:
        return None

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.secret_key,
            algorithms=["HS256"]
        )
        return payload.get("sub")  # Return agent_id
    except jwt.InvalidTokenError:
        return None


async def websocket_endpoint(
    websocket: WebSocket,
    db=Depends(get_db),
    agent_id: Optional[str] = None
):
    """WebSocket endpoint for MCP protocol"""

    # Extract agent_id from headers or query params
    if not agent_id:
        agent_id = websocket.headers.get("X-Agent-ID", "default-agent")

    # Rate limiting check
    client_ip = websocket.client.host
    if not manager.check_rate_limit(client_ip):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Rate limit exceeded")
        return

    # Connect client
    session_id = await manager.connect(websocket, agent_id)
    session = manager.active_connections[session_id]

    # Create handler
    async with db as db_session:
        handler = MCPHandler(db_session)

        try:
            # Send welcome message
            await manager.send_message(session_id, {
                "jsonrpc": "2.0",
                "method": "welcome",
                "params": {
                    "message": f"Connected to TMWS v{settings.api_version}",
                    "session_id": session_id,
                    "agent_id": agent_id
                }
            })

            # Message loop
            while True:
                # Receive message
                data = await websocket.receive_json()

                # Parse and validate
                try:
                    message = MCPMessage(**data)
                except ValueError as e:
                    await manager.send_message(session_id, {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32700,
                            "message": "Parse error",
                            "data": str(e)
                        }
                    })
                    continue

                # Handle request
                response = await handler.handle_request(message, session)

                # Send response
                await manager.send_message(session_id, response)

        except WebSocketDisconnect:
            manager.disconnect(session_id)
            logger.info(f"Client {session_id} disconnected normally")

        except Exception as e:
            logger.error(f"WebSocket error for {session_id}: {e}")
            manager.disconnect(session_id)
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR)


# HTTP endpoints for monitoring
async def get_websocket_stats():
    """Get WebSocket connection statistics"""
    return {
        "status": "healthy",
        "stats": manager.get_session_stats(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


async def list_active_sessions():
    """List active WebSocket sessions"""
    sessions = []
    for session_id, session in manager.active_connections.items():
        sessions.append({
            "session_id": session_id,
            "agent_id": session.agent_id,
            "connected_at": session.connected_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "request_count": session.request_count
        })

    return {"sessions": sessions}


def setup_websocket_routes(app):
    """Add WebSocket routes to FastAPI app"""
    app.add_api_websocket_route("/ws/mcp", websocket_endpoint)
    app.add_api_route("/api/v1/ws/stats", get_websocket_stats, methods=["GET"])
    app.add_api_route("/api/v1/ws/sessions", list_active_sessions, methods=["GET"])