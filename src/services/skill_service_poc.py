"""POC implementation for Skills System (Phase 5A Hour 6-12).

This module contains minimal POC code to validate Progressive Disclosure architecture:
- POC 1: Metadata layer query (< 10ms P95)
- POC 2: Core instructions layer query (< 30ms P95)
- POC 3: Memory integration (< 100ms P95)

Phase 5B Security Enhancements:
- S-3-M1: Input size validation (255 char limit)
- S-3-M2: Null byte sanitization
- S-3-M3: Configurable core instructions length

NOT production-ready. For validation purposes only.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import get_settings
from src.core.exceptions import ValidationError
from src.models.skill import Skill, SkillVersion, AccessLevel
from src.models.memory import Memory


class SkillServicePOC:
    """POC implementation for Skills system validation.

    Phase 5B Security Enhancements:
    - Input validation (S-3-M1)
    - Null byte sanitization (S-3-M2)
    - Configurable core instructions length (S-3-M3)
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.settings = get_settings()

    # ===== Phase 5B: Security Helpers =====

    def _sanitize_text_input(self, text: str | None) -> str | None:
        """S-3-M2: Remove null bytes from text input.

        Null bytes can cause data corruption in SQLite and other databases.

        Args:
            text: Input text to sanitize

        Returns:
            Sanitized text with null bytes removed, or None if input is None
        """
        if text is None:
            return None
        return text.replace('\x00', '')

    def _validate_input_length(self, value: str | None, field_name: str, max_length: int | None = None) -> None:
        """S-3-M1: Validate input length against configured maximum.

        Args:
            value: Input value to validate
            field_name: Name of the field (for error messages)
            max_length: Maximum allowed length (defaults to skills_max_field_length from settings)

        Raises:
            ValidationError: If input exceeds maximum length
        """
        if value is None:
            return

        max_len = max_length or self.settings.skills_max_field_length

        if len(value) > max_len:
            raise ValidationError(
                f"Input validation failed: {field_name} exceeds maximum length",
                details={
                    "field": field_name,
                    "max_length": max_len,
                    "actual_length": len(value),
                    "error_code": "S-3-M1",
                }
            )

    def _get_core_instructions(self, content: str | None) -> str:
        """S-3-M3: Extract core instructions with configurable length.

        Args:
            content: Full skill content

        Returns:
            Truncated core instructions (first N characters, where N is configurable)
        """
        if not content:
            return ""

        max_length = self.settings.skills_core_instructions_max_length
        return content[:max_length]

    # POC 1: Metadata Layer (<10ms P95)
    async def list_skills_metadata(
        self,
        namespace: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """POC 1: Metadata layer query (Layer 1 only).

        Target: < 10ms P95 for 10,000 skills

        Phase 5B Security: Input validation and sanitization
        """
        # S-3-M2: Sanitize namespace input
        namespace = self._sanitize_text_input(namespace) or ""

        # S-3-M1: Validate namespace length
        self._validate_input_length(namespace, "namespace")

        stmt = (
            select(
                Skill.id,
                Skill.name,
                Skill.namespace,
                Skill.created_by,
                Skill.persona,
                Skill.created_at,
                Skill.updated_at,
            )
            .where(
                Skill.namespace == namespace,
                Skill.is_deleted == False,
            )
            .limit(limit)
            .offset(offset)
        )

        result = await self.session.execute(stmt)
        return [
            {
                "id": str(row.id),
                "name": row.name,
                "namespace": row.namespace,
                "created_by": row.created_by,
                "persona": row.persona,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            }
            for row in result
        ]

    # POC 2: Core Instructions Layer (<30ms P95)
    async def get_skill_core_instructions(
        self,
        skill_id: UUID,
        agent_id: str,
        namespace: str,
    ) -> Optional[dict]:
        """POC 2: Core instructions layer query (Layer 1 + 2).

        Target: < 30ms P95

        Phase 5B Security: Input validation and sanitization
        """
        # S-3-M2: Sanitize namespace input
        namespace = self._sanitize_text_input(namespace) or ""

        # S-3-M1: Validate namespace length
        self._validate_input_length(namespace, "namespace")

        stmt = (
            select(Skill, SkillVersion.core_instructions)
            .join(
                SkillVersion,
                (Skill.id == SkillVersion.skill_id) & (SkillVersion.version == Skill.active_version)
            )
            .where(
                Skill.id == skill_id,
                Skill.namespace == namespace,
                Skill.is_deleted == False,
            )
        )

        result = await self.session.execute(stmt)
        row = result.one_or_none()

        if not row:
            return None

        skill, core_instructions = row

        # P0-1 pattern: Access control check
        if not skill.is_accessible_by(agent_id, namespace):
            raise PermissionError(f"Access denied to skill {skill_id}")

        return {
            "id": str(skill.id),
            "name": skill.name,
            "persona": skill.persona,
            "core_instructions": core_instructions,
            "metadata": {
                "namespace": skill.namespace,
                "created_by": skill.created_by,
                "access_level": skill.access_level.value,
            },
        }

    # POC 3: Memory Integration (<100ms P95)
    async def create_skill_from_memory(
        self,
        memory_id: UUID,
        agent_id: str,
        namespace: str,
        skill_name: str,
        persona: str | None = None,
    ) -> dict:
        """POC 3: Memory integration (Layer 1 + 2 + 3).

        Target: < 100ms P95

        Phase 5B Security: Input validation, sanitization, and configurable core instructions
        """
        # S-3-M2: Sanitize all text inputs
        namespace = self._sanitize_text_input(namespace) or ""
        skill_name = self._sanitize_text_input(skill_name) or ""
        persona = self._sanitize_text_input(persona)

        # S-3-M1: Validate input lengths
        self._validate_input_length(namespace, "namespace")
        self._validate_input_length(skill_name, "skill_name")
        self._validate_input_length(persona, "persona")

        # Step 1: Fetch Memory (20-40ms)
        memory_stmt = select(Memory).where(
            Memory.id == memory_id,
            Memory.namespace == namespace,
        )
        memory_result = await self.session.execute(memory_stmt)
        memory = memory_result.scalar_one_or_none()

        if not memory:
            raise ValueError(f"Memory {memory_id} not found")

        # P0-1 pattern: Access control check
        if not memory.is_accessible_by(agent_id, namespace):
            raise PermissionError(f"Access denied to memory {memory_id}")

        # Step 2: Parse Memory content (5-10ms)
        skill_content = memory.content

        # S-3-M3: Extract core instructions with configurable length
        core_instructions = self._get_core_instructions(skill_content)

        # Step 3: Create Skill + SkillVersion (10-20ms)
        skill_id = str(uuid4())
        version_id = str(uuid4())
        now = datetime.now(timezone.utc)

        skill = Skill(
            id=skill_id,
            name=skill_name,
            persona=persona,
            namespace=namespace,
            created_by=agent_id,
            access_level=AccessLevel.PRIVATE,
            is_deleted=False,
            created_at=now,
            updated_at=now,
        )

        skill_version = SkillVersion(
            id=version_id,
            skill_id=skill_id,
            version=1,
            content=skill_content,
            core_instructions=core_instructions,
            content_hash=SkillVersion.compute_content_hash(skill_content) if skill_content else "",
            created_by=agent_id,
            created_at=now,
        )

        self.session.add(skill)
        self.session.add(skill_version)
        await self.session.commit()
        await self.session.refresh(skill)

        return {
            "skill_id": str(skill.id),
            "version_id": str(skill_version.id),
            "name": skill.name,
            "persona": skill.persona,
            "source_memory_id": str(memory_id),
        }
