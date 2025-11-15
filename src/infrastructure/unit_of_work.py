"""Unit of Work pattern implementation."""

from abc import ABC, abstractmethod
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.repositories.agent_repository import AgentRepository
from src.domain.repositories.mcp_connection_repository import MCPConnectionRepository


class UnitOfWork(ABC):
    """Abstract Unit of Work for managing database transactions.

    The Unit of Work pattern provides a way to group related operations
    into a single transaction that can be committed or rolled back as a unit.
    """

    agent_repository: AgentRepository
    mcp_connection_repository: MCPConnectionRepository

    @abstractmethod
    async def __aenter__(self):
        """Enter async context manager."""
        pass

    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context manager."""
        pass

    @abstractmethod
    async def commit(self) -> None:
        """Commit the current transaction."""
        pass

    @abstractmethod
    async def rollback(self) -> None:
        """Rollback the current transaction."""
        pass


class SQLAlchemyUnitOfWork(UnitOfWork):
    """SQLAlchemy implementation of Unit of Work pattern."""

    def __init__(self, session_factory):
        """Initialize with a session factory.

        Args:
            session_factory: Callable that returns an AsyncSession
        """
        self.session_factory = session_factory
        self._session: Optional[AsyncSession] = None

    async def __aenter__(self):
        """Enter async context manager and create session."""
        from src.infrastructure.repositories.agent_repository import (
            SQLAlchemyAgentRepository,
        )
        from src.infrastructure.repositories.mcp_connection_repository import (
            SQLAlchemyMCPConnectionRepository,
        )

        self._session = self.session_factory()

        # Initialize repositories with the session
        self.agent_repository = SQLAlchemyAgentRepository(self._session)
        self.mcp_connection_repository = SQLAlchemyMCPConnectionRepository(
            self._session
        )

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context manager and close session."""
        if self._session:
            await self._session.close()

    async def commit(self) -> None:
        """Commit the current transaction."""
        if self._session:
            await self._session.commit()

    async def rollback(self) -> None:
        """Rollback the current transaction."""
        if self._session:
            await self._session.rollback()
