"""Persona Service for TMWS
Handles Trinitas persona management
"""

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..core.exceptions import NotFoundError, ValidationError
from ..models import Memory, Persona
from .base_service import BaseService

logger = logging.getLogger(__name__)


class PersonaService(BaseService):
    """Service for managing Trinitas personas."""

    def __init__(self, session: AsyncSession):
        super().__init__(session)

    async def create_persona(
        self,
        name: str,
        description: str,
        capabilities: list[str],
        personality_traits: dict[str, Any] = None,
        metadata: dict[str, Any] = None,
    ) -> Persona:
        """Create a new persona."""
        # Check if persona with same name exists
        existing = await self.get_persona_by_name(name)
        if existing:
            raise ValidationError(f"Persona with name '{name}' already exists")

        persona = await self.create_record(
            Persona,
            name=name,
            description=description,
            capabilities=capabilities,
            personality_traits=personality_traits or {},
            metadata_json=metadata or {},
            is_active=True,
        )

        await self.commit()
        logger.info(f"Created persona {persona.id}: {name}")
        return persona

    async def get_persona(self, persona_id: UUID) -> Persona | None:
        """Get a persona by ID."""
        result = await self.session.execute(
            select(Persona).where(Persona.id == persona_id),
        )
        return result.scalar_one_or_none()

    async def get_persona_by_name(self, name: str) -> Persona | None:
        """Get a persona by name."""
        result = await self.session.execute(select(Persona).where(Persona.name == name))
        return result.scalar_one_or_none()

    async def update_persona(self, persona_id: UUID, updates: dict[str, Any]) -> Persona:
        """Update an existing persona."""
        persona = await self.get_persona(persona_id)
        if not persona:
            raise NotFoundError(f"Persona {persona_id} not found")

        # Update allowed fields only
        allowed_fields = [
            "description",
            "capabilities",
            "personality_traits",
            "metadata_json",
            "is_active",
        ]

        filtered_updates = {k: v for k, v in updates.items() if k in allowed_fields}
        filtered_updates["updated_at"] = datetime.utcnow()

        persona = await self.update_record(persona, **filtered_updates)
        await self.commit()

        logger.info(f"Updated persona {persona_id}")
        return persona

    async def delete_persona(self, persona_id: UUID) -> bool:
        """Soft delete a persona (sets is_active to False)."""
        persona = await self.get_persona(persona_id)
        if not persona:
            raise NotFoundError(f"Persona {persona_id} not found")

        await self.update_record(
            persona,
            is_active=False,
            updated_at=datetime.utcnow(),
        )
        await self.commit()

        logger.info(f"Deactivated persona {persona_id}")
        return True

    async def list_personas(
        self,
        active_only: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Persona]:
        """List all personas."""
        stmt = select(Persona)

        if active_only:
            stmt = stmt.where(Persona.is_active)

        stmt = stmt.order_by(Persona.created_at.desc())
        stmt = stmt.limit(limit).offset(offset)

        result = await self.session.execute(stmt)
        personas = result.scalars().all()

        logger.info(f"Listed {len(personas)} personas")
        return personas

    async def get_persona_memories(
        self,
        persona_id: UUID,
        memory_type: str = None,
        limit: int = 100,
    ) -> list[Memory]:
        """Get memories associated with a persona."""
        stmt = select(Memory).where(Memory.persona_id == persona_id)

        if memory_type:
            stmt = stmt.where(Memory.memory_type == memory_type)

        stmt = stmt.order_by(Memory.importance.desc(), Memory.created_at.desc())
        stmt = stmt.limit(limit)

        result = await self.session.execute(stmt)
        memories = result.scalars().all()

        return memories

    async def count_personas(self, active_only: bool = True) -> int:
        """Count personas."""
        if active_only:
            return await self.count_records(Persona, is_active=True)
        return await self.count_records(Persona)

    async def get_persona_stats(self, persona_id: UUID) -> dict[str, Any]:
        """Get statistics for a specific persona."""
        persona = await self.get_persona(persona_id)
        if not persona:
            raise NotFoundError(f"Persona {persona_id} not found")

        # Count memories
        memory_count_stmt = select(func.count(Memory.id)).where(Memory.persona_id == persona_id)
        memory_count_result = await self.session.execute(memory_count_stmt)
        memory_count = memory_count_result.scalar() or 0

        # Count memories by type
        memory_type_stmt = (
            select(Memory.memory_type, func.count(Memory.id).label("count"))
            .where(Memory.persona_id == persona_id)
            .group_by(Memory.memory_type)
        )

        memory_type_result = await self.session.execute(memory_type_stmt)
        memory_types = {row.memory_type: row.count for row in memory_type_result}

        return {
            "persona_id": str(persona_id),
            "name": persona.name,
            "is_active": persona.is_active,
            "total_memories": memory_count,
            "memories_by_type": memory_types,
            "capabilities": persona.capabilities,
            "created_at": persona.created_at.isoformat(),
            "updated_at": persona.updated_at.isoformat(),
        }

    async def activate_persona(self, persona_id: UUID) -> Persona:
        """Activate a deactivated persona."""
        persona = await self.get_persona(persona_id)
        if not persona:
            raise NotFoundError(f"Persona {persona_id} not found")

        persona = await self.update_record(
            persona,
            is_active=True,
            updated_at=datetime.utcnow(),
        )
        await self.commit()

        logger.info(f"Activated persona {persona_id}")
        return persona

    async def deactivate_persona(self, persona_id: UUID) -> Persona:
        """Deactivate an active persona."""
        persona = await self.get_persona(persona_id)
        if not persona:
            raise NotFoundError(f"Persona {persona_id} not found")

        persona = await self.update_record(
            persona,
            is_active=False,
            updated_at=datetime.utcnow(),
        )
        await self.commit()

        logger.info(f"Deactivated persona {persona_id}")
        return persona
