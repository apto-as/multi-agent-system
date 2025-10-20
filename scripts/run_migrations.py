#!/usr/bin/env python3
"""
TMWS Database Migration Runner v2.2.0

This script handles database migrations for TMWS
including automatic backup and rollback capabilities
"""

import argparse
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class MigrationRunner:
    """Handles database migrations with safety features."""

    def __init__(self, database_url: str | None = None):
        """Initialize migration runner."""
        self.database_url = database_url or os.getenv(
            "TMWS_DATABASE_URL", "postgresql://tmws_user:tmws_password@localhost:5432/tmws"
        )
        self.alembic_ini = Path(__file__).parent.parent / "alembic.ini"
        self.backup_dir = Path(__file__).parent.parent / "backups"
        self.backup_dir.mkdir(exist_ok=True)

    def get_engine(self) -> Engine:
        """Create database engine."""
        return create_engine(self.database_url)

    def get_current_revision(self) -> str | None:
        """Get current database revision."""
        try:
            engine = self.get_engine()
            with engine.connect() as conn:
                context = MigrationContext.configure(conn)
                return context.get_current_revision()
        except Exception as e:
            logger.error(f"Failed to get current revision: {e}")
            return None

    def get_pending_migrations(self) -> list[str]:
        """Get list of pending migrations."""
        config = Config(str(self.alembic_ini))
        script_dir = ScriptDirectory.from_config(config)

        current_rev = self.get_current_revision()
        if current_rev is None:
            # No migrations applied yet
            return [rev.revision for rev in script_dir.walk_revisions()]

        pending = []
        for rev in script_dir.walk_revisions():
            if rev.revision == current_rev:
                break
            pending.append(rev.revision)

        return list(reversed(pending))

    def backup_database(self, prefix: str = "migration") -> Path | None:
        """Create database backup before migration."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"{prefix}_backup_{timestamp}.sql"

        try:
            # Parse database URL
            from urllib.parse import urlparse

            db_url = urlparse(self.database_url)

            # Build pg_dump command
            cmd = [
                "pg_dump",
                "-h",
                db_url.hostname or "localhost",
                "-p",
                str(db_url.port or 5432),
                "-U",
                db_url.username or "tmws_user",
                "-d",
                db_url.path.lstrip("/"),
                "-f",
                str(backup_file),
                "--verbose",
                "--no-owner",
                "--no-acl",
            ]

            # Set password via environment
            env = os.environ.copy()
            if db_url.password:
                env["PGPASSWORD"] = db_url.password

            logger.info(f"Creating backup: {backup_file}")
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Backup failed: {result.stderr}")
                return None

            # Compress backup
            subprocess.run(["gzip", str(backup_file)])
            backup_file = backup_file.with_suffix(".sql.gz")

            logger.info(f"Backup created successfully: {backup_file}")
            return backup_file

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            return None

    def restore_database(self, backup_file: Path) -> bool:
        """Restore database from backup."""
        try:
            # Parse database URL
            from urllib.parse import urlparse

            db_url = urlparse(self.database_url)

            # Decompress if needed
            if backup_file.suffix == ".gz":
                logger.info("Decompressing backup...")
                subprocess.run(["gunzip", str(backup_file)])
                backup_file = backup_file.with_suffix("")

            # Build psql command
            cmd = [
                "psql",
                "-h",
                db_url.hostname or "localhost",
                "-p",
                str(db_url.port or 5432),
                "-U",
                db_url.username or "tmws_user",
                "-d",
                db_url.path.lstrip("/"),
                "-f",
                str(backup_file),
                "--single-transaction",
            ]

            # Set password via environment
            env = os.environ.copy()
            if db_url.password:
                env["PGPASSWORD"] = db_url.password

            logger.info(f"Restoring from backup: {backup_file}")
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Restore failed: {result.stderr}")
                return False

            logger.info("Database restored successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to restore database: {e}")
            return False

    def run_upgrade(self, revision: str = "head", backup: bool = True) -> bool:
        """Run database upgrade."""
        try:
            # Check pending migrations
            pending = self.get_pending_migrations()
            if not pending and revision == "head":
                logger.info("Database is already up to date")
                return True

            # Create backup if requested
            backup_file = None
            if backup:
                backup_file = self.backup_database()
                if not backup_file:
                    logger.error("Backup failed, aborting migration")
                    return False

            # Run migration
            logger.info(f"Running migration to: {revision}")
            config = Config(str(self.alembic_ini))
            config.set_main_option("sqlalchemy.url", self.database_url)

            try:
                command.upgrade(config, revision)
                logger.info("Migration completed successfully")
                return True

            except Exception as e:
                logger.error(f"Migration failed: {e}")

                # Attempt rollback if we have a backup
                if backup_file:
                    logger.info("Attempting to restore from backup...")
                    if self.restore_database(backup_file):
                        logger.info("Database restored to pre-migration state")
                    else:
                        logger.error("Failed to restore database")

                return False

        except Exception as e:
            logger.error(f"Failed to run upgrade: {e}")
            return False

    def run_downgrade(self, revision: str = "-1", backup: bool = True) -> bool:
        """Run database downgrade."""
        try:
            # Create backup if requested
            backup_file = None
            if backup:
                backup_file = self.backup_database(prefix="downgrade")
                if not backup_file:
                    logger.error("Backup failed, aborting downgrade")
                    return False

            # Run downgrade
            logger.info(f"Running downgrade to: {revision}")
            config = Config(str(self.alembic_ini))
            config.set_main_option("sqlalchemy.url", self.database_url)

            command.downgrade(config, revision)
            logger.info("Downgrade completed successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to run downgrade: {e}")
            return False

    def check_migration_status(self) -> dict[str, Any]:
        """Check migration status and return info."""
        try:
            config = Config(str(self.alembic_ini))
            script_dir = ScriptDirectory.from_config(config)

            current_rev = self.get_current_revision()
            pending = self.get_pending_migrations()

            # Get all revisions
            all_revisions = []
            for rev in script_dir.walk_revisions():
                all_revisions.append(
                    {
                        "revision": rev.revision,
                        "description": rev.doc,
                        "branch_labels": list(rev.branch_labels) if rev.branch_labels else [],
                        "is_current": rev.revision == current_rev,
                        "is_pending": rev.revision in pending,
                    }
                )

            return {
                "current_revision": current_rev,
                "pending_count": len(pending),
                "pending_revisions": pending,
                "all_revisions": all_revisions,
                "database_url": self.database_url.split("@")[1]
                if "@" in self.database_url
                else "unknown",
            }

        except Exception as e:
            logger.error(f"Failed to check migration status: {e}")
            return {"error": str(e), "current_revision": None, "pending_count": 0}

    def create_migration(self, message: str) -> bool:
        """Create a new migration."""
        try:
            config = Config(str(self.alembic_ini))
            config.set_main_option("sqlalchemy.url", self.database_url)

            logger.info(f"Creating migration: {message}")
            command.revision(config, message=message, autogenerate=True)
            logger.info("Migration created successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to create migration: {e}")
            return False

    def initialize_alembic(self) -> bool:
        """Initialize Alembic for the project."""
        try:
            if not self.alembic_ini.exists():
                logger.info("Initializing Alembic...")
                command.init(Config(), str(self.alembic_ini.parent))
                logger.info("Alembic initialized successfully")
            else:
                logger.info("Alembic already initialized")

            return True

        except Exception as e:
            logger.error(f"Failed to initialize Alembic: {e}")
            return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="TMWS Database Migration Runner")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Upgrade command
    upgrade_parser = subparsers.add_parser("upgrade", help="Upgrade database")
    upgrade_parser.add_argument(
        "--revision", default="head", help="Target revision (default: head)"
    )
    upgrade_parser.add_argument(
        "--no-backup", action="store_true", help="Skip backup before migration"
    )

    # Downgrade command
    downgrade_parser = subparsers.add_parser("downgrade", help="Downgrade database")
    downgrade_parser.add_argument("--revision", default="-1", help="Target revision (default: -1)")
    downgrade_parser.add_argument(
        "--no-backup", action="store_true", help="Skip backup before downgrade"
    )

    # Status command
    subparsers.add_parser("status", help="Show migration status")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create new migration")
    create_parser.add_argument("message", help="Migration message")

    # Initialize command
    subparsers.add_parser("init", help="Initialize Alembic")

    # Parse arguments
    args = parser.parse_args()

    # Create runner
    runner = MigrationRunner()

    # Execute command
    if args.command == "upgrade":
        success = runner.run_upgrade(revision=args.revision, backup=not args.no_backup)
        sys.exit(0 if success else 1)

    elif args.command == "downgrade":
        success = runner.run_downgrade(revision=args.revision, backup=not args.no_backup)
        sys.exit(0 if success else 1)

    elif args.command == "status":
        status = runner.check_migration_status()
        print("\n" + "=" * 50)
        print("TMWS Migration Status")
        print("=" * 50)
        print(f"Database: {status.get('database_url', 'unknown')}")
        print(f"Current Revision: {status.get('current_revision', 'none')}")
        print(f"Pending Migrations: {status.get('pending_count', 0)}")

        if status.get("pending_revisions"):
            print("\nPending Revisions:")
            for rev in status["pending_revisions"]:
                print(f"  - {rev}")

        print("\nAll Revisions:")
        for rev in status.get("all_revisions", []):
            marker = "[CURRENT]" if rev["is_current"] else "[PENDING]" if rev["is_pending"] else ""
            print(f"  {rev['revision']}: {rev['description']} {marker}")

        print("=" * 50)

    elif args.command == "create":
        success = runner.create_migration(args.message)
        sys.exit(0 if success else 1)

    elif args.command == "init":
        success = runner.initialize_alembic()
        sys.exit(0 if success else 1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
