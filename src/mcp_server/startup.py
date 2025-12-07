"""Server startup logic - first run setup, license validation, and main entry points."""

import asyncio
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from .constants import __version__
from .lifecycle import cleanup_server, initialize_server
from .server import HybridMCPServer

logger = logging.getLogger(__name__)


def first_run_setup():
    """First-run setup for uvx one-command installation.

    Creates necessary directories, initializes database schema, and displays setup information.
    """
    # Configure logging to stderr early to keep stdout clean for MCP STDIO protocol
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )
    logging.getLogger("sqlalchemy").handlers = []
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    TMWS_HOME = Path.home() / ".tmws"
    TMWS_DATA_DIR = TMWS_HOME / "data"
    TMWS_CHROMA_DIR = TMWS_HOME / "chroma"
    INITIALIZED_FLAG = TMWS_HOME / ".initialized"

    # Check if this is first run
    if not INITIALIZED_FLAG.exists():
        # Output to stderr for visibility
        print("=" * 60, file=sys.stderr)
        print(f"🚀 TMWS v{__version__} - First-time Setup", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(file=sys.stderr)
        print(f"📁 Data directory: {TMWS_HOME}", file=sys.stderr)
        print(f"   ├── Database: {TMWS_DATA_DIR}/tmws.db", file=sys.stderr)
        print(f"   ├── ChromaDB: {TMWS_CHROMA_DIR}", file=sys.stderr)
        print(f"   ├── MCP config: {TMWS_HOME}/mcp.json", file=sys.stderr)
        print(f"   └── Secret key: {TMWS_HOME}/.secret_key", file=sys.stderr)
        print(file=sys.stderr)
        print("✅ Smart defaults enabled:", file=sys.stderr)
        print("   • SQLite database (development)", file=sys.stderr)
        print("   • Auto-generated secret key", file=sys.stderr)
        print("   • Multilingual-E5 embeddings (1024-dim)", file=sys.stderr)
        print("   • ChromaDB vector search", file=sys.stderr)
        print(file=sys.stderr)

        # Create TMWS_HOME directory
        TMWS_HOME.mkdir(parents=True, exist_ok=True)
        TMWS_DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Create default MCP configuration file
        MCP_CONFIG_FILE = TMWS_HOME / "mcp.json"
        if not MCP_CONFIG_FILE.exists():
            import json

            default_mcp_config = {
                "$schema": "https://tmws.dev/schemas/mcp-servers.json",
                "$comment": (
                    "TMWS MCP Server Configuration. "
                    "Edit this file to add/remove MCP servers."
                ),
                "mcpServers": {
                    "context7": {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["-y", "@upstash/context7-mcp@latest"],
                        "autoConnect": True,
                        "$comment": "Documentation lookup - https://context7.com",
                    },
                    "playwright": {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["-y", "@anthropic/mcp-playwright@latest"],
                        "autoConnect": True,
                        "$comment": "Browser automation - https://playwright.dev",
                    },
                    "serena": {
                        "type": "stdio",
                        "command": "uvx",
                        "args": ["--from", "serena-mcp-server", "serena"],
                        "autoConnect": True,
                        "$comment": "Code analysis - https://github.com/oraios/serena",
                    },
                    "chrome-devtools": {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["-y", "@anthropic/mcp-chrome-devtools@latest"],
                        "autoConnect": False,
                        "$comment": (
                            "Chrome DevTools - requires Chrome with remote debugging "
                            "(chrome --remote-debugging-port=9222)"
                        ),
                    },
                },
            }
            with open(MCP_CONFIG_FILE, "w") as f:
                json.dump(default_mcp_config, f, indent=2)
            print(f"   └── MCP config: {MCP_CONFIG_FILE}", file=sys.stderr)

        # Initialize database schema
        print("🔧 Initializing database schema...", file=sys.stderr)
        try:
            from src.core.config import get_settings
            from src.core.database import get_engine
            from src.models import TMWSBase

            async def init_db_schema():
                import os

                settings = get_settings()
                print(f"🔍 Current working directory: {os.getcwd()}", file=sys.stderr)
                print(f"🔍 HOME: {os.environ.get('HOME')}", file=sys.stderr)
                print(f"🔍 USER: {os.environ.get('USER')}", file=sys.stderr)
                print(
                    f"🔍 Settings database_url_async: {settings.database_url_async}",
                    file=sys.stderr,
                )

                # Extract and verify database path
                if "sqlite" in settings.database_url_async:
                    db_path_str = settings.database_url_async.replace(
                        "sqlite+aiosqlite://", ""
                    ).replace("sqlite://", "")
                    db_path = Path(db_path_str)
                    print(f"🔍 Database file path: {db_path}", file=sys.stderr)
                    print(f"🔍 Database parent exists: {db_path.parent.exists()}", file=sys.stderr)
                    print(
                        f"🔍 Database parent writable: {os.access(db_path.parent, os.W_OK)}",
                        file=sys.stderr,
                    )

                # Get the engine - let aiosqlite create the database file automatically
                engine = get_engine()
                print(f"🔍 Engine URL: {engine.url}", file=sys.stderr)

                # Create tables (aiosqlite will create the database file if it doesn't exist)
                print("🔧 Creating database schema...", file=sys.stderr)
                async with engine.begin() as conn:
                    await conn.run_sync(TMWSBase.metadata.create_all)
                await engine.dispose()

                # Clear engine cache to avoid event loop conflicts
                import src.core.database as db_module

                db_module._engine = None

                print("✅ Database schema initialized", file=sys.stderr)

            asyncio.run(init_db_schema())
        except Exception as e:
            print(f"⚠️  Database initialization error: {e}", file=sys.stderr)
            import traceback

            traceback.print_exc(file=sys.stderr)

        print(file=sys.stderr)
        print("📝 For Claude Desktop, add to config:", file=sys.stderr)
        print(
            """
{
  "tmws": {
    "command": "uvx",
    "args": ["tmws-mcp-server"]
  }
}
""",
            file=sys.stderr,
        )
        print("=" * 60, file=sys.stderr)
        print(file=sys.stderr)

        # Mark as initialized
        INITIALIZED_FLAG.touch()


async def validate_license_at_startup(license_key: str) -> dict:
    """
    Validate license key synchronously at startup.

    Args:
        license_key: License key string (format: TMWS-{TIER}-{UUID}-{CHECKSUM})

    Returns:
        dict: Validation result with keys:
            - valid (bool): Whether license is valid
            - tier (str|None): License tier (FREE, STANDARD, ENTERPRISE, UNLIMITED)
            - expires_at (str|None): Expiration timestamp (ISO format)
            - error (str|None): Error message if invalid
            - grace_period (bool): True if in 7-day grace period for expired license
    """

    from src.core.database import get_db_session
    from src.services.license_service import LicenseService

    try:
        async with get_db_session() as session:
            service = LicenseService(db_session=session)
            result = await service.validate_license_key(key=license_key)

            # Check for grace period (7 days after expiration)
            grace_period = False
            if not result.valid and result.expires_at:
                days_expired = (datetime.utcnow() - result.expires_at).days
                if 0 <= days_expired <= 7:
                    grace_period = True
                    logger.warning(
                        f"⚠️  License expired {days_expired} days ago. "
                        f"Grace period: {7 - days_expired} days remaining."
                    )

            return {
                "valid": result.valid or grace_period,
                "tier": result.tier.value if result.tier else None,
                "expires_at": result.expires_at.isoformat() if result.expires_at else None,
                "error": result.error_message,
                "grace_period": grace_period,
            }
    except Exception as e:
        logger.error(f"License validation failed: {e}", exc_info=True)
        return {
            "valid": False,
            "tier": None,
            "expires_at": None,
            "error": f"Validation error: {str(e)}",
            "grace_period": False,
        }


async def async_main():
    """Async main entry point for MCP server."""
    from src.core.exceptions import (
        MCPInitializationError,
        ServiceInitializationError,
    )

    # Configure logging to stderr to keep stdout clean for MCP STDIO protocol
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,  # MCP STDIO: stdout is reserved for JSON-RPC
    )
    # Ensure SQLAlchemy logs also go to stderr
    logging.getLogger("sqlalchemy").handlers = []
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    server = HybridMCPServer()

    try:
        # Initialize server
        await initialize_server(server)

        logger.info(
            f"🚀 TMWS v{__version__} MCP Server Started\n"
            "   Architecture: Hybrid (SQLite + Chroma)\n"
            "   Embeddings: Multilingual-E5 (1024-dim)\n"
            "   Vector Search: Chroma (P95: 0.47ms)\n"
            f"   Agent ID: {server.agent_id}\n"
            f"   Instance: {server.instance_id}",
        )

        # Run MCP server (async version to work within existing event loop)
        await server.mcp.run_async()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except (MCPInitializationError, ServiceInitializationError) as e:
        # Expected initialization errors - already logged
        logger.error(f"Server failed to initialize: {e}")
    except Exception as e:
        # Unexpected errors - log critical
        logger.critical(f"Unexpected server error: {e}", exc_info=True)
    finally:
        await cleanup_server(server)


def main():
    """
    CLI entry point with mandatory license validation.

    Phase 2E-2: Startup License Gate
    - Validates TMWS_LICENSE_KEY environment variable
    - Enforces license tier restrictions
    - 7-day grace period for expired licenses
    - Fail-fast on invalid/missing license
    """

    # ========================================
    # Phase 2E-2: License Validation (NEW)
    # ========================================
    license_key = os.getenv("TMWS_LICENSE_KEY")

    if not license_key:
        logger.critical(
            "❌ TMWS requires a valid license key to start.\n"
            "\n"
            "Please set the TMWS_LICENSE_KEY environment variable:\n"
            "  export TMWS_LICENSE_KEY='your-license-key'\n"
            "\n"
            "To obtain a license key:\n"
            "  - FREE tier: https://trinitas.ai/licensing/free\n"
            "  - STANDARD tier: https://trinitas.ai/licensing/standard\n"
            "  - ENTERPRISE tier: contact sales@trinitas.ai\n"
        )
        sys.exit(1)

    # Validate license (async call from sync context)
    validation = asyncio.run(validate_license_at_startup(license_key))

    if not validation["valid"]:
        logger.critical(
            f"❌ Invalid license key: {validation['error']}\n"
            "\n"
            "Please check:\n"
            "  1. License key format: TMWS-{{TIER}}-{{UUID}}-{{CHECKSUM}}\n"
            "  2. License has not been revoked\n"
            "  3. License has not expired (7-day grace period available)\n"
            "\n"
            "To renew or upgrade:\n"
            "  https://trinitas.ai/licensing/renew\n"
        )
        sys.exit(1)

    # Log successful validation
    if validation["grace_period"]:
        logger.warning(
            f"⚠️  TMWS starting with EXPIRED license (grace period active)\n"
            f"   Tier: {validation['tier']}\n"
            f"   Expired: {validation['expires_at']}\n"
            f"   Please renew soon: https://trinitas.ai/licensing/renew\n"
        )
    else:
        logger.info(
            f"✅ License validated successfully\n"
            f"   Tier: {validation['tier']}\n"
            f"   Expires: {validation['expires_at'] or 'Never (lifetime license)'}\n"
        )

    # ========================================
    # Phase 2: Server Startup (EXISTING)
    # ========================================
    # First-run setup (synchronous)
    first_run_setup()

    # Run async main
    asyncio.run(async_main())
