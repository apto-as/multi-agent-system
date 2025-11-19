"""AgentRepository for retrieving Agent aggregates.

This repository provides namespace verification capabilities for Application Service Layer.
It's a thin wrapper around database queries to maintain consistency with DDD patterns.

Author: Artemis (Technical Perfectionist)
Created: 2025-11-12 (Phase 1-2-D: Application Service Implementation)
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.repositories.agent_repository import AgentRepository as AgentRepositoryInterface
from src.infrastructure.exceptions import RepositoryError
from src.models.agent import Agent


class SQLAlchemyAgentRepository(AgentRepositoryInterface):
    """SQLAlchemy implementation of AgentRepository."""

    def __init__(self, session: AsyncSession):
        """Initialize repository with database session.

        Args:
            session: SQLAlchemy async session for database operations
        """
        self._session = session

    async def get_by_id(self, agent_id: UUID | str) -> Agent | None:
        """Retrieve Agent by ID.

        Args:
            agent_id: Agent identifier (UUID or string agent_id)

        Returns:
            Agent model or None if not found

        Note:
            This method is primarily used for namespace verification in use cases.
            It returns the database model directly, not a domain aggregate.
        """
        try:
            # Convert UUID to string if needed
            agent_id_str = str(agent_id) if isinstance(agent_id, UUID) else agent_id

            stmt = select(Agent).where(Agent.agent_id == agent_id_str)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()

        except (KeyboardInterrupt, SystemExit):
            raise  # Never suppress system signals
        except Exception as e:
            raise RepositoryError(
                message=f"Failed to retrieve Agent: {e}",
                details={"agent_id": agent_id_str},
            ) from e

    async def get_by_full_id(self, full_id: str) -> Agent | None:
        """Get an agent by full ID.

        Args:
            full_id: The agent's full identifier

        Returns:
            Agent if found, None otherwise
        """
        try:
            stmt = select(Agent).where(Agent.full_id == full_id)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            raise RepositoryError(
                message=f"Failed to retrieve Agent by full_id: {e}",
                details={"full_id": full_id},
            ) from e

    async def list_all(self, namespace: str | None = None) -> list[Agent]:
        """List all agents, optionally filtered by namespace.

        Args:
            namespace: Optional namespace filter

        Returns:
            List of agents
        """
        try:
            stmt = select(Agent)
            if namespace:
                stmt = stmt.where(Agent.namespace == namespace)

            result = await self._session.execute(stmt)
            return list(result.scalars().all())

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            raise RepositoryError(
                message=f"Failed to list agents: {e}",
                details={"namespace": namespace},
            ) from e


# Maintain backwards compatibility
AgentRepository = SQLAlchemyAgentRepository
