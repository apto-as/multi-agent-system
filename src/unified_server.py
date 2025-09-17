#!/usr/bin/env python3
"""
TMWS Unified Server v2.2.0 - Shared Server for Multiple Claude Code Instances
Athena-Hera orchestrated multi-client support via MCP protocol.

Architecture:
- FastAPI with REST API endpoints
- WebSocket MCP endpoint for multiple Claude Code connections
- Optional stdio MCP for direct connections
- Unified database pool and session management
"""

import asyncio
import logging
import signal
import sys
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor

import uvicorn
from fastapi import FastAPI

# Ensure src is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.config import get_settings
from src.api.app import create_app
from src.mcp_server import run_server as run_mcp_stdio

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class ServerConfig:
    """Unified server configuration for multi-client support"""
    # REST API with WebSocket MCP
    api_host: str = "0.0.0.0"  # Listen on all interfaces for multi-client access
    api_port: int = 8000
    api_reload: bool = False

    # Stdio MCP (optional, for single direct connections)
    stdio_enabled: bool = True

    # Monitoring
    health_check_interval: float = 30.0

    @classmethod
    def from_settings(cls) -> "ServerConfig":
        """Create config from settings"""
        return cls(
            api_host=getattr(settings, 'api_host', '0.0.0.0'),
            api_port=getattr(settings, 'api_port', 8000),
            api_reload=getattr(settings, 'api_reload', False),
            stdio_enabled=getattr(settings, 'stdio_enabled', True)
        )


class UnifiedServerManager:
    """
    Orchestration of shared server for multiple Claude Code instances.
    Enables concurrent connections via WebSocket MCP.
    """

    def __init__(self, config: ServerConfig):
        self.config = config
        self.running = False
        self.shutdown_event = asyncio.Event()
        self.executor = ThreadPoolExecutor(max_workers=2)

        # Server components
        self.fastapi_app: Optional[FastAPI] = None
        self.api_server: Optional[uvicorn.Server] = None
        self.stdio_task: Optional[asyncio.Task] = None

        # Server statistics
        self.server_stats = {
            "api_requests": 0,
            "ws_connections": 0,
            "active_sessions": 0
        }

    async def initialize(self):
        """Initialize server components"""
        logger.info("🚀 Initializing TMWS v2.2.0 Shared Server")

        try:
            # Create FastAPI app with WebSocket MCP endpoint
            self.fastapi_app = create_app()
            logger.info("✅ FastAPI app created with WebSocket MCP endpoint")

            # Setup signal handlers
            self._setup_signal_handlers()

            logger.info("✅ Server initialization complete")

        except Exception as e:
            logger.error(f"❌ Initialization failed: {e}")
            raise

    def _setup_signal_handlers(self):
        """Setup graceful signal handlers"""
        def signal_handler(sig, frame):
            logger.info(f"📡 Received signal {sig}, initiating graceful shutdown...")
            asyncio.create_task(self.shutdown())

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    async def start_api_server(self):
        """Start FastAPI server with WebSocket MCP"""
        logger.info(f"🌐 Starting shared server on http://{self.config.api_host}:{self.config.api_port}")

        config = uvicorn.Config(
            app=self.fastapi_app,
            host=self.config.api_host,
            port=self.config.api_port,
            reload=self.config.api_reload,
            log_level="info",
            access_log=True
        )

        self.api_server = uvicorn.Server(config)

        try:
            await self.api_server.serve()
        except Exception as e:
            logger.error(f"❌ API server error: {e}")
            raise

    def run_stdio_mcp(self):
        """Run stdio MCP server for direct connections"""
        logger.info("📝 Starting stdio MCP server for direct connections")
        try:
            run_mcp_stdio()
        except Exception as e:
            logger.error(f"❌ Stdio MCP error: {e}")

    async def monitor_health(self):
        """Monitor server health"""
        while not self.shutdown_event.is_set():
            try:
                # Check WebSocket MCP connections
                ws_stats_url = f"http://localhost:{self.config.api_port}/ws/stats"
                # Could fetch stats here if needed

                await asyncio.sleep(self.config.health_check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(5)


    async def start_all_services(self):
        """Start all services for multi-client support"""
        logger.info("="*60)
        logger.info("🚀 TMWS v2.2.0 Shared Server Starting...")
        logger.info("="*60)

        tasks = []

        # Start FastAPI with WebSocket MCP
        logger.info(f"📡 REST API: http://{self.config.api_host}:{self.config.api_port}")
        logger.info(f"🌐 WebSocket MCP: ws://{self.config.api_host}:{self.config.api_port}/ws/mcp")
        api_task = asyncio.create_task(self.start_api_server())
        tasks.append(api_task)

        # Optionally start stdio MCP
        if self.config.stdio_enabled:
            logger.info("📝 Stdio MCP: Available via uvx or direct execution")
            loop = asyncio.get_event_loop()
            self.stdio_task = loop.run_in_executor(
                self.executor,
                self.run_stdio_mcp
            )
            tasks.append(self.stdio_task)

        # Start health monitor
        health_task = asyncio.create_task(self.monitor_health())
        tasks.append(health_task)

        self.running = True
        logger.info("="*60)
        logger.info("✅ Server ready for multiple Claude Code connections!")
        logger.info("="*60)

        # Wait for shutdown
        try:
            await self.shutdown_event.wait()
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            await self.shutdown()

    async def shutdown(self):
        """Graceful shutdown"""
        if not self.running:
            return

        logger.info("🛑 Shutting down server...")
        self.running = False
        self.shutdown_event.set()

        # Shutdown API server
        if self.api_server:
            await self.api_server.shutdown()

        # Shutdown stdio task
        if self.stdio_task:
            self.stdio_task.cancel()

        # Shutdown executor
        self.executor.shutdown(wait=True)

        logger.info("✅ Server stopped")





async def main():
    """Main entry point"""

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create server with default config
    config = ServerConfig.from_settings()
    server = UnifiedServerManager(config)

    try:
        await server.initialize()
        await server.start_all_services()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        await server.shutdown()
        sys.exit(1)


def run():
    """Synchronous entry point"""
    asyncio.run(main())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Gracefully stopped by user")
    except Exception as e:
        print(f"\n❌ Server failed: {e}")
        sys.exit(1)