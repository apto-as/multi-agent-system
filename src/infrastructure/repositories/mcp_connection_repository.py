"""MCPConnectionRepository for persistence of MCPConnection aggregates.

This repository implements the DDD Repository pattern for MCPConnection aggregates.
It handles translation between domain aggregates and database models, enforces
namespace isolation, and manages transaction boundaries.

Responsibilities:
- Persist MCPConnection aggregates to SQLite database
- Retrieve aggregates by various criteria
- Enforce namespace isolation (security)
- Handle database transactions with proper rollback
- Translate between domain and persistence models

Author: Artemis (Technical Perfectionist)
Created: 2025-11-12 (Phase 1-1-B: Infrastructure Implementation)
"""

from dataclasses import asdict
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.aggregates.mcp_connection import MCPConnection
from src.domain.entities.tool import Tool
from src.domain.repositories.mcp_connection_repository import (
    MCPConnectionRepository as MCPConnectionRepositoryInterface,
)
from src.domain.value_objects.connection_config import ConnectionConfig
from src.domain.value_objects.connection_status import ConnectionStatus
from src.domain.value_objects.tool_category import ToolCategory
from src.infrastructure.exceptions import AggregateNotFoundError, RepositoryError
from src.models.mcp_connection import MCPConnectionModel


class SQLAlchemyMCPConnectionRepository(MCPConnectionRepositoryInterface):
    """Repository for MCPConnection aggregate persistence.

    This repository follows DDD repository pattern:
    - Provides collection-like interface for aggregates
    - Encapsulates all data access logic
    - Maintains aggregate consistency boundaries
    - Does NOT persist domain events (they are transient)

    Example:
        >>> async with get_async_session() as session:
        ...     repo = MCPConnectionRepository(session)
        ...     connection = MCPConnection(...)
        ...     await repo.save(connection)
        ...     retrieved = await repo.get_by_id(connection.id)
    """

    def __init__(self, session: AsyncSession):
        """Initialize repository with database session.

        Args:
            session: SQLAlchemy async session for database operations
        """
        self._session = session

    async def save(self, connection: MCPConnection) -> MCPConnection:
        """Save or update MCPConnection aggregate.

        This method handles both insert (new aggregate) and update (existing aggregate).

        Args:
            connection: MCPConnection aggregate to persist

        Returns:
            The same aggregate (with updated metadata if applicable)

        Raises:
            RepositoryError: If persistence fails

        Example:
            >>> connection = MCPConnection(id=uuid4(), server_name="test", config=config)
            >>> saved = await repo.save(connection)
            >>> assert saved.id == connection.id
        """
        try:
            # Check if connection already exists
            stmt = select(MCPConnectionModel).where(MCPConnectionModel.id == str(connection.id))
            result = await self._session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing record
                self._update_model_from_domain(existing, connection)
            else:
                # Create new record
                model = self._to_model(connection)
                self._session.add(model)

            # Commit transaction
            await self._session.commit()

            # Note: Domain events are NOT persisted (they are transient)
            # Application service should dispatch events before calling save()

            return connection

        except (KeyboardInterrupt, SystemExit):
            raise  # Never suppress system signals
        except Exception as e:
            await self._session.rollback()
            raise RepositoryError(
                message=f"Failed to save MCPConnection: {e}",
                details={
                    "connection_id": str(connection.id),
                    "server_name": connection.server_name,
                },
            ) from e

    async def get_by_id(self, connection_id: UUID, namespace: str) -> MCPConnection:
        """Retrieve MCPConnection by ID with namespace verification.

        SECURITY: Enforces namespace isolation (P0-1). The namespace parameter
        must be verified from database, NOT from JWT claims or user input.

        Args:
            connection_id: UUID of the connection
            namespace: Verified namespace from database (not JWT claims)

        Returns:
            MCPConnection aggregate

        Raises:
            AggregateNotFoundError: If connection not found OR in different namespace

        Example:
            >>> # CORRECT: Verify namespace from database
            >>> agent = await get_agent_from_db(agent_id)
            >>> connection = await repo.get_by_id(uuid4(), agent.namespace)
            >>> assert isinstance(connection, MCPConnection)
        """
        try:
            stmt = select(MCPConnectionModel).where(
                MCPConnectionModel.id == str(connection_id),
                MCPConnectionModel.namespace == namespace,  # ✅ Namespace isolation
            )
            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            if not model:
                raise AggregateNotFoundError(
                    aggregate_type="MCPConnection",
                    identifier=str(connection_id),
                )

            return self._to_domain(model)

        except (KeyboardInterrupt, SystemExit):
            raise  # Never suppress system signals
        except AggregateNotFoundError:
            raise
        except Exception as e:
            raise RepositoryError(
                message=f"Failed to retrieve MCPConnection: {e}",
                details={"connection_id": str(connection_id)},
            ) from e

    async def find_by_namespace_and_agent(
        self, namespace: str, agent_id: str
    ) -> list[MCPConnection]:
        """Find all connections for a specific namespace and agent.

        SECURITY: This method enforces namespace isolation by filtering on namespace.

        Args:
            namespace: Namespace to filter by
            agent_id: Agent ID to filter by

        Returns:
            List of MCPConnection aggregates (may be empty)

        Example:
            >>> connections = await repo.find_by_namespace_and_agent("project-x", "agent-1")
            >>> assert all(c.namespace == "project-x" for c in connections)
            >>> assert all(c.agent_id == "agent-1" for c in connections)
        """
        try:
            stmt = (
                select(MCPConnectionModel)
                .where(MCPConnectionModel.namespace == namespace)
                .where(MCPConnectionModel.agent_id == agent_id)
                .order_by(MCPConnectionModel.created_at.desc())
            )

            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._to_domain(model) for model in models]

        except (KeyboardInterrupt, SystemExit):
            raise  # Never suppress system signals
        except Exception as e:
            raise RepositoryError(
                message=f"Failed to find connections by namespace and agent: {e}",
                details={"namespace": namespace, "agent_id": agent_id},
            ) from e

    async def find_by_status(self, status: ConnectionStatus) -> list[MCPConnection]:
        """Find all connections with a specific status.

        Args:
            status: ConnectionStatus enum value

        Returns:
            List of MCPConnection aggregates (may be empty)

        Example:
            >>> active_connections = await repo.find_by_status(ConnectionStatus.ACTIVE)
            >>> assert all(c.status == ConnectionStatus.ACTIVE for c in active_connections)
        """
        try:
            stmt = (
                select(MCPConnectionModel)
                .where(MCPConnectionModel.status == status.value)
                .order_by(MCPConnectionModel.created_at.desc())
            )

            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._to_domain(model) for model in models]

        except (KeyboardInterrupt, SystemExit):
            raise  # Never suppress system signals
        except Exception as e:
            raise RepositoryError(
                message=f"Failed to find connections by status: {e}",
                details={"status": status.value},
            ) from e

    async def get_by_server_name_and_namespace(
        self, server_name: str, namespace: str
    ) -> MCPConnection | None:
        """Find connection by server name and namespace.

        SECURITY: Enforces namespace isolation by filtering on namespace.

        Args:
            server_name: Server name to search for
            namespace: Verified namespace from database (not from user input)

        Returns:
            MCPConnection if found, None otherwise

        Example:
            >>> agent = await get_agent_from_db(agent_id)
            >>> connection = await repo.get_by_server_name_and_namespace(
            ...     "test_server", agent.namespace
            ... )
        """
        try:
            stmt = (
                select(MCPConnectionModel)
                .where(MCPConnectionModel.server_name == server_name)
                .where(MCPConnectionModel.namespace == namespace)  # ✅ Namespace isolation
            )

            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            if not model:
                return None

            return self._to_domain(model)

        except (KeyboardInterrupt, SystemExit):
            raise  # Never suppress system signals
        except Exception as e:
            raise RepositoryError(
                message=f"Failed to get connection by server name and namespace: {e}",
                details={"server_name": server_name, "namespace": namespace},
            ) from e

    async def delete(self, connection_id: UUID, namespace: str, agent_id: str) -> None:
        """Delete MCPConnection with namespace and ownership verification.

        SECURITY: Enforces namespace isolation AND ownership verification (P0-1).
        Both namespace and agent_id must be verified from database.

        Args:
            connection_id: UUID of the connection to delete
            namespace: Verified namespace from database (not JWT claims)
            agent_id: Agent requesting deletion (must be owner)

        Raises:
            AggregateNotFoundError: If connection not found, in different namespace, or not owned by agent
            RepositoryError: If deletion fails

        Example:
            >>> # CORRECT: Verify namespace and agent_id from database
            >>> agent = await get_agent_from_db(agent_id)
            >>> await repo.delete(connection_id, agent.namespace, agent.id)
        """
        try:
            stmt = select(MCPConnectionModel).where(
                MCPConnectionModel.id == str(connection_id),
                MCPConnectionModel.namespace == namespace,  # ✅ Namespace isolation
                MCPConnectionModel.agent_id == agent_id,  # ✅ Ownership verification
            )
            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            if not model:
                raise AggregateNotFoundError(
                    aggregate_type="MCPConnection",
                    identifier=str(connection_id),
                )

            await self._session.delete(model)
            await self._session.commit()

        except (KeyboardInterrupt, SystemExit):
            raise  # Never suppress system signals
        except AggregateNotFoundError:
            raise
        except Exception as e:
            await self._session.rollback()
            raise RepositoryError(
                message=f"Failed to delete MCPConnection: {e}",
                details={"connection_id": str(connection_id)},
            ) from e

    # Private mapping methods

    def _to_model(self, domain: MCPConnection) -> MCPConnectionModel:
        """Convert domain aggregate to database model.

        Args:
            domain: MCPConnection aggregate

        Returns:
            MCPConnectionModel for persistence

        Note:
            - config is converted to dict using asdict()
            - tools are converted to list of dicts
            - domain_events are NOT persisted (transient)
        """
        # Convert config to dict
        config_dict = asdict(domain.config)

        # Convert tools to list of dicts
        tools_list = [self._tool_to_dict(tool) for tool in domain.tools]

        return MCPConnectionModel(
            id=str(domain.id),
            server_name=domain.server_name,
            namespace=domain.namespace or "",
            agent_id=domain.agent_id or "",
            status=domain.status.value,
            config_json=config_dict,
            tools_json=tools_list,
            error_message=domain.error_message,
            error_at=domain.error_at,
            connected_at=domain.connected_at,
            disconnected_at=domain.disconnected_at,
            created_at=domain.created_at,
            updated_at=datetime.utcnow(),
        )

    def _update_model_from_domain(self, model: MCPConnectionModel, domain: MCPConnection) -> None:
        """Update existing model from domain aggregate.

        Args:
            model: Database model to update
            domain: Domain aggregate with new values

        Note:
            - ID is NOT updated (immutable)
            - created_at is NOT updated (immutable)
            - updated_at is set automatically by SQLAlchemy
        """
        config_dict = asdict(domain.config)
        tools_list = [self._tool_to_dict(tool) for tool in domain.tools]

        model.server_name = domain.server_name
        model.namespace = domain.namespace or ""
        model.agent_id = domain.agent_id or ""
        model.status = domain.status.value
        model.config_json = config_dict
        model.tools_json = tools_list
        model.error_message = domain.error_message
        model.error_at = domain.error_at
        model.connected_at = domain.connected_at
        model.disconnected_at = domain.disconnected_at

    def _to_domain(self, model: MCPConnectionModel) -> MCPConnection:
        """Convert database model to domain aggregate.

        Args:
            model: MCPConnectionModel from database

        Returns:
            Reconstructed MCPConnection aggregate

        Note:
            - domain_events list is empty (events are transient)
        """
        # Reconstruct ConnectionConfig
        config = ConnectionConfig(**model.config_json)

        # Reconstruct Tools
        tools = [self._dict_to_tool(tool_dict) for tool_dict in model.tools_json]

        # Reconstruct MCPConnection
        return MCPConnection(
            id=UUID(model.id),
            server_name=model.server_name,
            config=config,
            status=ConnectionStatus(model.status),
            tools=tools,
            created_at=model.created_at,
            connected_at=model.connected_at,
            disconnected_at=model.disconnected_at,
            error_message=model.error_message,
            error_at=model.error_at,
            namespace=model.namespace,
            agent_id=model.agent_id,
            domain_events=[],  # Domain events are not persisted
        )

    @staticmethod
    def _tool_to_dict(tool: Tool) -> dict[str, Any]:
        """Convert Tool entity to dictionary for JSON storage.

        Args:
            tool: Tool entity

        Returns:
            Dictionary representation of tool
        """
        return {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "category": tool.category.value,
        }

    @staticmethod
    def _dict_to_tool(tool_dict: dict[str, Any]) -> Tool:
        """Convert dictionary to Tool entity.

        Args:
            tool_dict: Dictionary from JSON storage

        Returns:
            Reconstructed Tool entity
        """
        return Tool(
            name=tool_dict["name"],
            description=tool_dict["description"],
            input_schema=tool_dict["input_schema"],
            category=ToolCategory(tool_dict["category"]),
        )

    # Interface-compliant methods (wrappers around existing methods)

    async def list_by_agent(self, agent_id: UUID) -> list[MCPConnection]:
        """List all connections for an agent.

        Args:
            agent_id: The agent UUID

        Returns:
            List of connections
        """
        # Implementation needed - for now return empty list
        return []

    async def find_by_server_name(
        self,
        agent_id: UUID,
        server_name: str,
    ) -> MCPConnection | None:
        """Find a connection by server name for an agent.

        Args:
            agent_id: The agent UUID
            server_name: The MCP server name

        Returns:
            MCPConnection if found, None otherwise
        """
        # Implementation needed - for now return None
        return None


# Maintain backwards compatibility
MCPConnectionRepository = SQLAlchemyMCPConnectionRepository
