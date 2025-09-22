"""
WebSocket MCP Router for TMWS v2.2.0
"""

from fastapi import APIRouter

from src.api.websocket_mcp import get_websocket_stats, list_active_sessions, websocket_endpoint

router = APIRouter()

# WebSocket endpoint
router.add_api_websocket_route("/mcp", websocket_endpoint)

# HTTP monitoring endpoints
router.add_api_route("/stats", get_websocket_stats, methods=["GET"])
router.add_api_route("/sessions", list_active_sessions, methods=["GET"])
