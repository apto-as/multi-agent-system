"""
Simplified TMWS FastAPI Application for Testing
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import json
import uuid
import structlog

from .daemon import TMWSDaemon
from .handlers.websocket_handler import WebSocketHandler
from .handlers.mcp_bridge import MCPBridge
from ..core.config import Settings

logger = structlog.get_logger()

# Global daemon instance
daemon: TMWSDaemon = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global daemon
    
    # Startup
    logger.info("Starting simplified TMWS server...")
    settings = Settings()
    daemon = TMWSDaemon(settings)
    await daemon.initialize_services()
    logger.info("TMWS server started")
    
    yield
    
    # Shutdown
    logger.info("Shutting down TMWS server...")
    if daemon:
        await daemon.shutdown()
    logger.info("TMWS server shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="TMWS Server (Simplified)",
    description="Simplified TMWS Server for Testing",
    version="2.0.0-test",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "TMWS",
        "version": "2.0.0-test",
        "status": "running",
        "mode": "simplified"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    global daemon
    if not daemon:
        return {"status": "unhealthy", "error": "Daemon not initialized"}
    
    status = daemon.get_status()
    return {
        "status": "healthy" if status["running"] else "unhealthy",
        "details": status
    }


@app.websocket("/ws/mcp")
async def mcp_websocket_endpoint(websocket: WebSocket):
    """MCP WebSocket endpoint."""
    global daemon
    
    if not daemon:
        await websocket.close(code=1011, reason="Service unavailable")
        return
    
    await websocket.accept()
    client_id = str(uuid.uuid4())
    
    try:
        # Create MCP handler
        from .handlers.mcp_websocket import MCPWebSocketHandler
        handler = MCPWebSocketHandler(websocket, daemon, client_id)
        
        # Register client
        await daemon.register_client(client_id, {
            "type": "mcp_websocket",
            "handler": handler
        })
        
        # Run MCP protocol
        await handler.run()
        
    except WebSocketDisconnect:
        logger.info("MCP WebSocket disconnected", client_id=client_id)
    except Exception as e:
        logger.error("MCP WebSocket error", client_id=client_id, error=str(e))
    finally:
        await daemon.disconnect_client(client_id)