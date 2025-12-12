"""PersonaSyncService - Sync personas between DB and Markdown files.

Bridges the P0.1 Narrative Gap by providing dual-source persona loading:
1. DB Priority: Prefer Agent model (dynamic, real-time)
2. MD Fallback: Use static files (~/.claude/agents/) if not in DB
3. Sync Operations: Bidirectional sync (MD→DB, DB→MD)

Architecture:
- Agent model stores persona data (display_name, capabilities, config)
- Persona model stores extended metadata (tier, emoji, markdown_source)
- PersonaLoader handles MD→DB import
- This service provides merged views and sync operations

Author: Metis (Implementation)
Created: 2025-12-12 (Phase 2: P0.1 Narrative Gap)
"""

import logging
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.agent import Agent
from ..models.persona import Persona
from .persona_loader import PersonaLoader

logger = logging.getLogger(__name__)


class PersonaSyncService:
    """Service for syncing personas between database and Markdown files.

    Provides dual-source loading with DB priority:
    1. Check Agent model (real-time status)
    2. Check Persona model (extended metadata)
    3. Fallback to MD file if not in DB

    Features:
    - get_persona_merged(): Return merged view (DB + MD)
    - sync_md_to_db(): Import MD personas to DB
    - sync_db_to_md(): Export DB personas to MD (backup)
    - DB Priority pattern for invoke_persona integration
    """

    def __init__(self, session: AsyncSession):
        """Initialize persona sync service.

        Args:
            session: Async database session
        """
        self.session = session
        self.persona_loader = PersonaLoader(session)

    async def get_persona_merged(
        self,
        persona_id: str,
        include_md_fallback: bool = True,
    ) -> dict[str, Any] | None:
        """Get merged persona data from DB and MD files.

        Priority:
        1. Agent model (real-time status, trust score, task metrics)
        2. Persona model (extended metadata: tier, emoji, markdown_source)
        3. MD file (fallback if not in DB)

        Args:
            persona_id: Persona identifier (e.g., "athena-conductor", "artemis")
            include_md_fallback: Whether to fallback to MD file if not in DB

        Returns:
            Merged persona dict or None if not found:
            {
                "source": "db" | "md" | "merged",
                "persona_id": str,
                "display_name": str,
                "agent_data": {...},  # From Agent model
                "persona_data": {...},  # From Persona model
                "md_data": {...},  # From MD file (if fallback)
            }
        """
        # Normalize persona_id (handle short names)
        normalized_id = self._normalize_persona_id(persona_id)

        # Step 1: Try Agent model
        agent = await self._get_agent(normalized_id)

        # Step 2: Try Persona model
        persona = await self._get_persona(normalized_id)

        # If found in DB, return merged view
        if agent or persona:
            return {
                "source": "db" if not include_md_fallback else "merged",
                "persona_id": normalized_id,
                "display_name": agent.display_name if agent else (
                    persona.display_name if persona else normalized_id
                ),
                "agent_data": agent.to_dict() if agent else None,
                "persona_data": persona.to_dict() if persona else None,
                "md_data": None,  # MD fallback not needed
            }

        # Step 3: Fallback to MD file if requested
        if include_md_fallback:
            md_data = await self._load_from_md_file(normalized_id)
            if md_data:
                return {
                    "source": "md",
                    "persona_id": normalized_id,
                    "display_name": md_data.get("display_name", normalized_id),
                    "agent_data": None,
                    "persona_data": None,
                    "md_data": md_data,
                }

        # Not found
        logger.warning(f"Persona not found: {persona_id}")
        return None

    async def sync_md_to_db(
        self,
        directory: Path | None = None,
    ) -> dict[str, Any]:
        """Sync personas from Markdown files to database.

        Creates or updates Agent/Persona records from MD files.

        Args:
            directory: Directory containing MD files (default: ~/.claude/agents)

        Returns:
            Sync results:
            {
                "total": int,
                "created": int,
                "updated": int,
                "errors": int,
                "results": list[dict],
            }
        """
        if directory is None:
            directory = Path.home() / ".claude" / "agents"

        if not directory.exists():
            logger.warning(f"Directory not found: {directory}")
            return {
                "total": 0,
                "created": 0,
                "updated": 0,
                "errors": 1,
                "results": [{
                    "success": False,
                    "action": "error",
                    "message": f"Directory not found: {directory}",
                }],
            }

        # Use PersonaLoader to import MD files
        results = await self.persona_loader.sync_personas(directory)

        logger.info(
            f"MD→DB sync complete: {results['created']} created, "
            f"{results['updated']} updated, {results['errors']} errors"
        )

        return results

    async def sync_db_to_md(
        self,
        output_directory: Path | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Export database personas to Markdown files (backup).

        Writes Agent/Persona data to MD files for backup or external use.

        Args:
            output_directory: Output directory (default: ~/.claude/agents_backup)
            overwrite: Whether to overwrite existing files

        Returns:
            Export results:
            {
                "total": int,
                "written": int,
                "skipped": int,
                "errors": int,
            }
        """
        if output_directory is None:
            output_directory = Path.home() / ".claude" / "agents_backup"

        # Create output directory
        output_directory.mkdir(parents=True, exist_ok=True)

        # Get all personas from DB
        stmt = select(Persona).where(Persona.is_active == True)  # noqa: E712
        result = await self.session.execute(stmt)
        personas = list(result.scalars().all())

        written = 0
        skipped = 0
        errors = 0

        for persona in personas:
            try:
                output_path = output_directory / f"{persona.name}.md"

                # Skip if exists and not overwrite
                if output_path.exists() and not overwrite:
                    logger.debug(f"Skipped (exists): {output_path}")
                    skipped += 1
                    continue

                # Generate MD content
                md_content = self._generate_md_from_persona(persona)

                # Write to file
                output_path.write_text(md_content, encoding="utf-8")
                logger.debug(f"Exported: {output_path}")
                written += 1

            except Exception as e:
                logger.error(f"Failed to export {persona.name}: {e}")
                errors += 1

        logger.info(
            f"DB→MD export complete: {written} written, "
            f"{skipped} skipped, {errors} errors"
        )

        return {
            "total": len(personas),
            "written": written,
            "skipped": skipped,
            "errors": errors,
        }

    async def _get_agent(self, persona_id: str) -> Agent | None:
        """Get Agent model by persona_id."""
        stmt = select(Agent).where(Agent.agent_id == persona_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_persona(self, persona_id: str) -> Persona | None:
        """Get Persona model by name."""
        stmt = select(Persona).where(Persona.name == persona_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def _load_from_md_file(self, persona_id: str) -> dict[str, Any] | None:
        """Load persona from Markdown file (fallback)."""
        possible_paths = [
            Path.home() / ".claude" / "agents" / f"{persona_id}.md",
            Path.home() / ".config" / "opencode" / "agent" / f"{persona_id}.md",
        ]

        for path in possible_paths:
            if path.exists():
                try:
                    content = path.read_text(encoding="utf-8")
                    return {
                        "display_name": persona_id.capitalize(),
                        "content": content,
                        "source_path": str(path),
                    }
                except Exception as e:
                    logger.warning(f"Failed to read {path}: {e}")

        return None

    def _normalize_persona_id(self, persona_id: str) -> str:
        """Normalize persona_id to full format (e.g., athena → athena-conductor)."""
        persona_id = persona_id.lower().strip()

        # Short name mapping
        short_to_full = {
            "athena": "athena-conductor",
            "artemis": "artemis-optimizer",
            "hestia": "hestia-auditor",
            "eris": "eris-coordinator",
            "hera": "hera-strategist",
            "muses": "muses-documenter",
            "aphrodite": "aphrodite-designer",
            "metis": "metis-developer",
            "aurora": "aurora-researcher",
            "clotho": "clotho-orchestrator",
            "lachesis": "lachesis-support",
        }

        return short_to_full.get(persona_id, persona_id)

    def _generate_md_from_persona(self, persona: Persona) -> str:
        """Generate Markdown content from Persona model."""
        # If markdown_source exists, use it directly
        if persona.markdown_source:
            return persona.markdown_source

        # Otherwise, generate minimal MD
        emoji = persona.emoji or ""
        tier = persona.tier or "UNKNOWN"

        return f"""# {emoji} {persona.display_name}

## Core Identity
{persona.description}

## Tier
{tier}

## Specialties
{', '.join(persona.specialties)}

## Capabilities
{', '.join(persona.capabilities)}

## Version
{persona.version or 'Unknown'}

---
*Generated from database by PersonaSyncService*
*Created: {persona.created_at.isoformat() if persona.created_at else 'Unknown'}*
"""
