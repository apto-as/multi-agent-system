#!/usr/bin/env python3
"""
Run Simplified TMWS Server for Testing
"""

import sys
import uvicorn
from pathlib import Path
import argparse
import structlog

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tmws.core.config import Settings

logger = structlog.get_logger()


def main():
    """Main entry point for simplified TMWS server."""
    parser = argparse.ArgumentParser(description="Simplified TMWS Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--log-level", default="info", help="Log level")
    
    args = parser.parse_args()
    
    # Load settings
    settings = Settings()
    
    # Override with command line arguments
    host = args.host or settings.api_host
    port = args.port or settings.api_port
    
    logger.info("Starting simplified TMWS Server",
               host=host,
               port=port)
    
    # Run the server
    uvicorn.run(
        "tmws.server.simple_app:app",
        host=host,
        port=port,
        reload=False,
        log_level=args.log_level.lower(),
        access_log=True
    )


if __name__ == "__main__":
    main()