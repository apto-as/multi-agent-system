#!/usr/bin/env python3
"""
TMWS Server - Simple startup script for shared server mode.
"""

import sys
import os
import asyncio
import argparse
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main entry point for TMWS server."""
    parser = argparse.ArgumentParser(description="TMWS Server v2.1.0")
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to (default: 8000)"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)"
    )
    
    args = parser.parse_args()
    
    # Set environment variables
    os.environ["TMWS_API_HOST"] = args.host
    os.environ["TMWS_API_PORT"] = str(args.port)
    
    logger.info(f"Starting TMWS Server v2.1.0 on {args.host}:{args.port}")
    
    try:
        # Import here to avoid circular imports
        from src.main import main as run_server
        
        # Run the server
        run_server()
        
    except ImportError as e:
        logger.error(f"Failed to import server modules: {e}")
        logger.info("Make sure all dependencies are installed: pip install -e .")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()