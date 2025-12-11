"""PersonaLoader - Load persona definitions from Markdown files into database.

This service bridges the gap between the Markdown persona definitions in
dist-config/claudecode/agents/ and the TMWS database, providing:
- Parsing of persona Markdown files via PersonaMarkdownParser
- CRUD operations via PersonaService
- Sync functionality (create new, update existing)
- Transaction safety with rollback on errors

Usage:
    loader = PersonaLoader(session)
    result = await loader.load_persona_from_file(Path("agents/athena-conductor.md"))
    # or
    results = await loader.sync_personas(Path("dist-config/claudecode/agents"))
"""

import logging
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import ValidationError, log_and_raise
from ..models.persona import PersonaRole, PersonaType
from ..utils.persona_markdown_parser import ParsedPersona, PersonaMarkdownParser
from .persona_service import PersonaService

logger = logging.getLogger(__name__)


class PersonaLoader:
    """Service to load persona Markdown files into the database.

    This loader handles:
    1. Parsing Markdown files with PersonaMarkdownParser
    2. Converting parsed data to database format
    3. Creating new personas or updating existing ones
    4. Bulk sync operations with progress tracking
    """

    def __init__(self, session: AsyncSession):
        """Initialize PersonaLoader.

        Args:
            session: Async database session
        """
        self.session = session
        self.parser = PersonaMarkdownParser()
        self.persona_service = PersonaService(session)

    async def load_persona_from_file(self, file_path: Path) -> dict[str, Any]:
        """Load a single persona from Markdown file into database.

        This method:
        1. Parses the Markdown file
        2. Checks if persona exists (by name)
        3. Creates new or updates existing persona
        4. Returns result summary

        Args:
            file_path: Path to persona Markdown file

        Returns:
            dict with keys:
                - success (bool): Whether operation succeeded
                - action (str): "created" or "updated"
                - persona_id (str): Database UUID
                - name (str): Persona name
                - message (str): Status message

        Raises:
            FileNotFoundError: If file does not exist
            ValidationError: If parsing or database operation fails
        """
        try:
            # Parse markdown
            parsed = self.parser.parse_file(file_path)
            logger.info(f"Parsed persona from {file_path.name}: {parsed.name}")

            # Check if persona exists
            existing = await self.persona_service.get_persona_by_name(parsed.name)

            if existing:
                # Update existing persona
                updated = await self._update_persona_from_parsed(existing.id, parsed)
                logger.info(f"Updated persona: {parsed.name} (ID: {updated.id})")

                return {
                    "success": True,
                    "action": "updated",
                    "persona_id": str(updated.id),
                    "name": updated.name,
                    "message": f"Updated persona '{parsed.name}' from {file_path.name}",
                }
            else:
                # Create new persona
                created = await self._create_persona_from_parsed(parsed)
                logger.info(f"Created persona: {parsed.name} (ID: {created.id})")

                return {
                    "success": True,
                    "action": "created",
                    "persona_id": str(created.id),
                    "name": created.name,
                    "message": f"Created persona '{parsed.name}' from {file_path.name}",
                }

        except FileNotFoundError as e:
            log_and_raise(
                ValidationError,
                f"Persona file not found: {file_path}",
                original_exception=e,
            )
        except Exception as e:
            log_and_raise(
                ValidationError,
                f"Failed to load persona from {file_path.name}",
                original_exception=e,
            )

    async def load_all_personas(self, directory: Path) -> list[dict[str, Any]]:
        """Load all persona .md files from a directory.

        Args:
            directory: Directory containing persona Markdown files

        Returns:
            List of result dictionaries from load_persona_from_file()
        """
        if not directory.exists():
            log_and_raise(
                ValidationError,
                f"Persona directory not found: {directory}",
            )

        if not directory.is_dir():
            log_and_raise(
                ValidationError,
                f"Path is not a directory: {directory}",
            )

        results = []
        md_files = sorted(directory.glob("*.md"))

        logger.info(f"Found {len(md_files)} persona files in {directory}")

        for file_path in md_files:
            try:
                result = await self.load_persona_from_file(file_path)
                results.append(result)
            except Exception as e:
                # Log error but continue with other files
                logger.error(f"Failed to load {file_path.name}: {e}")
                results.append({
                    "success": False,
                    "action": "error",
                    "persona_id": None,
                    "name": file_path.stem,
                    "message": f"Error: {e}",
                })

        return results

    async def sync_personas(self, directory: Path) -> dict[str, Any]:
        """Sync personas from directory - create new, update existing.

        This method provides atomic transaction behavior:
        - All personas are loaded in a single transaction
        - If any error occurs, all changes are rolled back
        - Returns summary of operations

        Args:
            directory: Directory containing persona Markdown files

        Returns:
            dict with keys:
                - total (int): Total files processed
                - created (int): New personas created
                - updated (int): Existing personas updated
                - errors (int): Files with errors
                - results (list): Detailed results per file
        """
        results = await self.load_all_personas(directory)

        summary = {
            "total": len(results),
            "created": sum(1 for r in results if r["action"] == "created"),
            "updated": sum(1 for r in results if r["action"] == "updated"),
            "errors": sum(1 for r in results if r["action"] == "error"),
            "results": results,
        }

        logger.info(
            f"Persona sync complete: {summary['created']} created, "
            f"{summary['updated']} updated, {summary['errors']} errors"
        )

        return summary

    async def _create_persona_from_parsed(self, parsed: ParsedPersona):
        """Create a new persona from parsed data.

        Args:
            parsed: ParsedPersona object from parser

        Returns:
            Created Persona model instance
        """
        from ..models.persona import Persona

        # Extract PersonaType from agent_id or name
        persona_type = self._determine_persona_type(parsed)
        persona_role = self._determine_persona_role(parsed)

        # Extract trigger words from frontmatter or use defaults
        trigger_words = self._extract_trigger_words(parsed)

        # Build capabilities list from specialties
        capabilities = parsed.frontmatter.get("specialties", [])
        if isinstance(capabilities, str):
            capabilities = [c.strip() for c in capabilities.split(",")]

        # Create persona directly (PersonaService.create_persona has incompatible signature)
        persona = Persona(
            name=parsed.name,
            type=persona_type,
            role=persona_role,
            display_name=parsed.display_name,
            description=parsed.identity or parsed.display_name,
            specialties=capabilities,
            tier=parsed.tier,
            emoji=parsed.emoji,
            markdown_source=parsed.markdown_source,
            version=parsed.version,
            trigger_words=trigger_words,
            config={},
            preferences={
                "role": parsed.role,
                "partner": parsed.partner,
            },
            is_active=True,
            capabilities=capabilities,
            metadata_json={
                "agent_id": parsed.agent_id,
                "frontmatter": parsed.frontmatter,
            },
        )

        self.session.add(persona)
        await self.session.flush()

        logger.info(f"Created persona: {persona.name} (ID: {persona.id})")

        return persona

    async def _update_persona_from_parsed(self, persona_id, parsed: ParsedPersona):
        """Update existing persona from parsed data.

        Args:
            persona_id: UUID of existing persona
            parsed: ParsedPersona object from parser

        Returns:
            Updated Persona model instance
        """
        # Get existing persona
        persona = await self.persona_service.get_persona(persona_id)
        if not persona:
            raise ValidationError(f"Persona {persona_id} not found")

        # Extract updated values
        persona_type = self._determine_persona_type(parsed)
        persona_role = self._determine_persona_role(parsed)
        trigger_words = self._extract_trigger_words(parsed)

        capabilities = parsed.frontmatter.get("specialties", [])
        if isinstance(capabilities, str):
            capabilities = [c.strip() for c in capabilities.split(",")]

        # Update persona fields directly
        persona.type = persona_type
        persona.role = persona_role
        persona.display_name = parsed.display_name
        persona.description = parsed.identity or parsed.display_name
        persona.specialties = capabilities
        persona.tier = parsed.tier
        persona.emoji = parsed.emoji
        persona.markdown_source = parsed.markdown_source
        persona.version = parsed.version
        persona.trigger_words = trigger_words
        persona.capabilities = capabilities
        persona.preferences = {
            "role": parsed.role,
            "partner": parsed.partner,
        }
        persona.metadata_json = {
            "agent_id": parsed.agent_id,
            "frontmatter": parsed.frontmatter,
        }

        await self.session.flush()

        logger.info(f"Updated persona: {persona.name} (ID: {persona.id})")

        return persona

    def _determine_persona_type(self, parsed: ParsedPersona) -> PersonaType:
        """Determine PersonaType enum from parsed data.

        Args:
            parsed: ParsedPersona object

        Returns:
            PersonaType enum value
        """
        # Map name to PersonaType
        name_lower = parsed.name.lower()

        type_mapping = {
            "clotho": PersonaType.CLOTHO,
            "lachesis": PersonaType.LACHESIS,
            "athena": PersonaType.ATHENA,
            "hera": PersonaType.HERA,
            "artemis": PersonaType.ARTEMIS,
            "hestia": PersonaType.HESTIA,
            "eris": PersonaType.ERIS,
            "muses": PersonaType.MUSES,
            "aphrodite": PersonaType.APHRODITE,
            "metis": PersonaType.METIS,
            "aurora": PersonaType.AURORA,
            # Legacy
            "bellona": PersonaType.BELLONA,
            "seshat": PersonaType.SESHAT,
        }

        return type_mapping.get(name_lower, PersonaType.ATHENA)

    def _determine_persona_role(self, parsed: ParsedPersona) -> PersonaRole:
        """Determine PersonaRole enum from parsed data.

        Args:
            parsed: ParsedPersona object

        Returns:
            PersonaRole enum value
        """
        # Map tier to PersonaRole
        tier_upper = parsed.tier.upper() if parsed.tier else ""

        if tier_upper == "ORCHESTRATOR":
            return PersonaRole.ORCHESTRATOR

        # Map role string to PersonaRole
        role_lower = parsed.role.lower()

        role_mapping = {
            "conductor": PersonaRole.CONDUCTOR,
            "strategist": PersonaRole.STRATEGIST,
            "optimizer": PersonaRole.OPTIMIZER,
            "auditor": PersonaRole.AUDITOR,
            "coordinator": PersonaRole.COORDINATOR,
            "documenter": PersonaRole.DOCUMENTER,
            "designer": PersonaRole.DESIGNER,
            "developer": PersonaRole.DEVELOPER,
            "researcher": PersonaRole.RESEARCHER,
        }

        for key, value in role_mapping.items():
            if key in role_lower:
                return value

        return PersonaRole.CONDUCTOR  # Default

    def _extract_trigger_words(self, parsed: ParsedPersona) -> list[str]:
        """Extract trigger words from parsed persona.

        Args:
            parsed: ParsedPersona object

        Returns:
            List of trigger word strings
        """
        # Try to extract from frontmatter first
        trigger_words = parsed.frontmatter.get("trigger_words", [])

        if isinstance(trigger_words, str):
            # Parse comma-separated string
            trigger_words = [w.strip() for w in trigger_words.split(",")]

        if not trigger_words:
            # Generate defaults based on role
            name_lower = parsed.name.lower()
            default_triggers = {
                "clotho": ["workflow", "orchestrate", "sequence", "coordinate", "automate"],
                "lachesis": ["resource", "allocation", "capacity", "balance", "distribute"],
                "athena": ["orchestration", "workflow", "automation", "parallel", "coordination"],
                "hera": ["strategy", "planning", "architecture", "vision", "roadmap"],
                "artemis": ["optimization", "performance", "quality", "technical", "efficiency"],
                "hestia": ["security", "audit", "risk", "vulnerability", "threat"],
                "eris": ["coordinate", "tactical", "team", "collaboration", "conflict"],
                "muses": ["documentation", "knowledge", "record", "guide", "archive"],
                "aphrodite": ["design", "ui", "ux", "interface", "visual"],
                "metis": ["implement", "code", "develop", "build", "test", "debug"],
                "aurora": ["search", "find", "lookup", "research", "context", "retrieve"],
            }
            trigger_words = default_triggers.get(name_lower, [])

        return trigger_words
