"""MCP connection repository interface."""

from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

from src.domain.aggregates.mcp_connection import MCPConnection


class MCPConnectionRepository(ABC):
    """Abstract base class for MCP connection repository operations."""

    @abstractmethod
    async def get_by_id(self, connection_id: UUID) -> Optional[MCPConnection]:
        """Get a connection by ID.

        Args:
            connection_id: The connection UUID

        Returns:
            MCPConnection if found, None otherwise
        """
        pass

    @abstractmethod
    async def save(self, connection: MCPConnection) -> None:
        """Save or update a connection.

        Args:
            connection: The connection to save
        """
        pass

    @abstractmethod
    async def delete(self, connection_id: UUID) -> None:
        """Delete a connection.

        Args:
            connection_id: The connection UUID to delete
        """
        pass

    @abstractmethod
    async def list_by_agent(self, agent_id: UUID) -> list[MCPConnection]:
        """List all connections for an agent.

        Args:
            agent_id: The agent UUID

        Returns:
            List of connections
        """
        pass

    @abstractmethod
    async def find_by_server_name(
        self,
        agent_id: UUID,
        server_name: str,
    ) -> Optional[MCPConnection]:
        """Find a connection by server name for an agent.

        Args:
            agent_id: The agent UUID
            server_name: The MCP server name

        Returns:
            MCPConnection if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_by_server_name_and_namespace(
        self, server_name: str, namespace: str
    ) -> Optional[MCPConnection]:
        """Find connection by server name and namespace.

        Args:
            server_name: Server name to search for
            namespace: Verified namespace from database

        Returns:
            MCPConnection if found, None otherwise
        """
        pass
