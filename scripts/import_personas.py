#!/usr/bin/env python3
"""CLI script to import persona Markdown files into TMWS database.

This script provides a command-line interface to sync persona definitions
from Markdown files (typically in dist-config/claudecode/agents/) into
the TMWS database.

Features:
- Dry-run mode to preview changes without committing
- Progress reporting with colored output
- Transaction safety (rollback on any error)
- Summary statistics

Usage:
    # Import from default location
    python scripts/import_personas.py

    # Dry-run mode (no changes)
    python scripts/import_personas.py --dry-run

    # Custom source directory
    python scripts/import_personas.py --source /path/to/agents

    # Verbose output
    python scripts/import_personas.py --verbose

Examples:
    # Standard import
    $ python scripts/import_personas.py
    Importing personas from dist-config/claudecode/agents/
    ✓ Created: Clotho (clotho-orchestrator.md)
    ✓ Updated: Athena (athena-conductor.md)
    ✓ Created: Artemis (artemis-optimizer.md)
    ---
    Summary: 2 created, 1 updated, 0 errors

    # Dry-run
    $ python scripts/import_personas.py --dry-run
    [DRY RUN] Would create: Clotho (clotho-orchestrator.md)
    [DRY RUN] Would update: Athena (athena-conductor.md)
    ---
    [DRY RUN] Would create 2, update 1 (no changes committed)
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.database import get_db_session
from src.services.persona_loader import PersonaLoader

# ANSI color codes for terminal output
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_BLUE = "\033[94m"
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"


def validate_source_path(source: Path, project_root: Path) -> Path:
    """Validate that source path is within project boundaries.

    Security measure to prevent path traversal attacks (M-1 fix).

    Args:
        source: The source path to validate
        project_root: The project root directory

    Returns:
        Resolved absolute path if valid

    Raises:
        ValueError: If source is outside project boundaries
    """
    resolved = source.resolve()
    project_resolved = project_root.resolve()

    # Check if source is within project root
    try:
        resolved.relative_to(project_resolved)
    except ValueError:
        raise ValueError(
            f"Security: Source path must be within project root.\n"
            f"  Provided: {source}\n"
            f"  Project root: {project_root}\n"
            f"  Use paths relative to project root (e.g., dist-config/claudecode/agents)"
        )

    return resolved


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )


def print_colored(text: str, color: str = COLOR_RESET):
    """Print colored text to stdout."""
    print(f"{color}{text}{COLOR_RESET}")


def print_result(result: dict, dry_run: bool = False):
    """Print a single import result with colors."""
    prefix = "[DRY RUN] " if dry_run else ""

    if result["success"]:
        action = result["action"]
        name = result["name"]

        if action == "created":
            symbol = "✓" if not dry_run else "+"
            color = COLOR_GREEN
            verb = "Created" if not dry_run else "Would create"
        elif action == "updated":
            symbol = "↻" if not dry_run else "~"
            color = COLOR_BLUE
            verb = "Updated" if not dry_run else "Would update"
        else:
            symbol = "?"
            color = COLOR_YELLOW
            verb = "Unknown"

        print_colored(f"{prefix}{symbol} {verb}: {name}", color)
    else:
        print_colored(f"{prefix}✗ Error: {result['name']} - {result['message']}", COLOR_RED)


def print_summary(summary: dict, dry_run: bool = False):
    """Print import summary with statistics."""
    prefix = "[DRY RUN] " if dry_run else ""

    print()
    print_colored("─" * 60, COLOR_BOLD)
    print_colored(f"{prefix}Summary:", COLOR_BOLD)
    print()

    total = summary["total"]
    created = summary["created"]
    updated = summary["updated"]
    errors = summary["errors"]

    if created > 0:
        verb = "created" if not dry_run else "would create"
        print_colored(f"  {created} {verb}", COLOR_GREEN)

    if updated > 0:
        verb = "updated" if not dry_run else "would update"
        print_colored(f"  {updated} {verb}", COLOR_BLUE)

    if errors > 0:
        print_colored(f"  {errors} errors", COLOR_RED)

    print()
    print_colored(f"Total: {total} persona files processed", COLOR_BOLD)

    if dry_run:
        print_colored("(No changes committed - this was a dry run)", COLOR_YELLOW)

    print_colored("─" * 60, COLOR_BOLD)


async def import_personas(
    source: Path,
    dry_run: bool = False,
    verbose: bool = False,
) -> int:
    """Import personas from directory into database.

    Args:
        source: Directory containing persona Markdown files
        dry_run: If True, preview changes without committing
        verbose: Enable verbose logging

    Returns:
        Exit code (0 for success, 1 for errors)
    """
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    # Validate source directory
    if not source.exists():
        print_colored(f"Error: Source directory not found: {source}", COLOR_RED)
        return 1

    if not source.is_dir():
        print_colored(f"Error: Path is not a directory: {source}", COLOR_RED)
        return 1

    # Count persona files
    md_files = list(source.glob("*.md"))
    if not md_files:
        print_colored(f"Error: No .md files found in {source}", COLOR_RED)
        return 1

    print()
    print_colored(f"Importing personas from {source}/", COLOR_BOLD)
    print_colored(f"Found {len(md_files)} persona files", COLOR_BOLD)
    print()

    if dry_run:
        print_colored("[DRY RUN MODE - No changes will be committed]", COLOR_YELLOW)
        print()

    try:
        async with get_db_session() as session:
            loader = PersonaLoader(session)

            # Load all personas
            summary = await loader.sync_personas(source)

            # Print individual results
            for result in summary["results"]:
                print_result(result, dry_run=dry_run)

            # Print summary
            print_summary(summary, dry_run=dry_run)

            # Rollback if dry-run
            if dry_run:
                await session.rollback()
                logger.info("Rolled back transaction (dry-run mode)")
            else:
                # Commit handled by get_db_session context manager
                logger.info("Transaction committed successfully")

            # Return error code if any errors
            return 1 if summary["errors"] > 0 else 0

    except KeyboardInterrupt:
        print()
        print_colored("Import cancelled by user", COLOR_YELLOW)
        return 130  # Standard exit code for SIGINT

    except Exception as e:
        print()
        print_colored(f"Fatal error during import: {e}", COLOR_RED)
        logger.exception("Import failed with exception")
        return 1


def main():
    """Main entry point for CLI script."""
    parser = argparse.ArgumentParser(
        description="Import persona Markdown files into TMWS database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard import
  python scripts/import_personas.py

  # Dry-run mode (preview changes)
  python scripts/import_personas.py --dry-run

  # Custom source directory
  python scripts/import_personas.py --source /path/to/agents

  # Verbose output
  python scripts/import_personas.py --verbose
        """,
    )

    parser.add_argument(
        "--source",
        type=Path,
        default=Path("dist-config/claudecode/agents"),
        help="Directory containing persona .md files (default: dist-config/claudecode/agents)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without committing to database",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging output",
    )

    args = parser.parse_args()

    # Security: Validate source path is within project boundaries (M-1 fix)
    try:
        validated_source = validate_source_path(args.source, project_root)
    except ValueError as e:
        print_colored(f"Error: {e}", COLOR_RED)
        sys.exit(1)

    # Run async import
    exit_code = asyncio.run(import_personas(
        source=validated_source,
        dry_run=args.dry_run,
        verbose=args.verbose,
    ))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
