"""Base Tool Class for TMWS MCP Tools
Provides common functionality and database session management
"""

from abc import ABC, abstractmethod
from typing import Any, TypeVar

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import get_db_session
from ..services import get_embedding_service
from ..services.memory_service import HybridMemoryService
from ..services.persona_service import PersonaService
from ..services.task_service import TaskService
from ..services.workflow_service import WorkflowService

T = TypeVar("T", bound=BaseModel)


class BaseTool(ABC):
    """Base class for all TMWS MCP tools.

    Provides:
    - Database session management
    - Service initialization
    - Common error handling
    - Response formatting
    - Type validation
    """

    def __init__(self):
        """Initialize base tool with service references."""
        self._memory_service: HybridMemoryService | None = None
        self._persona_service: PersonaService | None = None
        self._task_service: TaskService | None = None
        self._workflow_service: WorkflowService | None = None

    async def get_services(self, session: AsyncSession) -> dict[str, Any]:
        """Initialize and return all services with session."""
        return {
            "memory_service": HybridMemoryService(session),
            "persona_service": PersonaService(session),
            "task_service": TaskService(session),
            "workflow_service": WorkflowService(session),
            "embedding_service": get_embedding_service(),
        }

    async def execute_with_session(self, func, *args, **kwargs) -> dict[str, Any]:
        """Execute a function with database session management.

        Args:
            func: Async function to execute
            *args: Positional arguments for func
            **kwargs: Keyword arguments for func

        Returns:
            Dict containing execution result or error

        """
        try:
            async with get_db_session() as session:
                services = await self.get_services(session)
                return await func(session, services, *args, **kwargs)
        except Exception as e:
            return self.format_error(str(e))

    def format_success(
        self, data: Any, message: str = "Operation completed successfully",
    ) -> dict[str, Any]:
        """Format successful response."""
        return {"success": True, "message": message, "data": data}

    def format_error(self, error: str, error_type: str = "general") -> dict[str, Any]:
        """Format error response."""
        return {"success": False, "error": error, "error_type": error_type}

    def validate_input(self, data: dict[str, Any], model_class: type[T]) -> T:
        """Validate input data against Pydantic model.

        Args:
            data: Input data to validate
            model_class: Pydantic model class for validation

        Returns:
            Validated model instance

        Raises:
            ValueError: If validation fails

        """
        try:
            return model_class(**data)
        except Exception as e:
            raise ValueError(f"Input validation failed: {e}")

    @abstractmethod
    async def register_tools(self, mcp_instance) -> None:
        """Register tools with FastMCP instance."""
        pass
