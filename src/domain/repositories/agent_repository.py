"""Agent repository interface."""

from abc import ABC, abstractmethod
from uuid import UUID

from src.models.agent import Agent


class AgentRepository(ABC):
    """Abstract base class for Agent repository operations."""

    @abstractmethod
    async def get_by_id(self, agent_id: UUID | str) -> Agent | None:
        """Get an agent by ID.

        Args:
            agent_id: The agent UUID or string ID

        Returns:
            Agent if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_by_full_id(self, full_id: str) -> Agent | None:
        """Get an agent by full ID.

        Args:
            full_id: The agent's full identifier

        Returns:
            Agent if found, None otherwise
        """
        pass

    @abstractmethod
    async def list_all(self, namespace: str | None = None) -> list[Agent]:
        """List all agents, optionally filtered by namespace.

        Args:
            namespace: Optional namespace filter

        Returns:
            List of agents
        """
        pass
