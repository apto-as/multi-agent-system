"""Database transaction decorator for automatic commit/rollback handling."""

import logging
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar, cast

from src.infrastructure.exceptions import RepositoryError

P = ParamSpec("P")
R = TypeVar("R")
logger = logging.getLogger(__name__)


def db_transaction(
    error_class: type[Exception] = RepositoryError,
    error_message: str = "Database operation failed",
    auto_commit: bool = True,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Decorator for database transaction handling.

    Provides:
    - Automatic commit after successful operation
    - Automatic rollback on exception
    - Consistent error wrapping with context
    - System signal passthrough (KeyboardInterrupt, SystemExit)

    Args:
        error_class: Exception class to raise on failure (default: RepositoryError)
        error_message: Base error message for failures
        auto_commit: Whether to auto-commit on success (default: True)

    Returns:
        Decorated async function with transaction handling

    Usage:
        @db_transaction(error_message="Failed to save entity")
        async def save(self, entity: Entity) -> Entity:
            self._session.add(entity)
            return entity

        @db_transaction(auto_commit=False, error_message="Query failed")
        async def find_by_id(self, entity_id: str) -> Entity | None:
            stmt = select(Entity).where(Entity.id == entity_id)
            result = await self._session.execute(stmt)
            return result.scalar_one_or_none()
    """

    def decorator(func: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Extract self from args - must be first parameter
            instance: Any = args[0] if args else None
            if instance is None or not hasattr(instance, "_session"):
                msg = "Decorator requires instance method with _session attribute"
                raise TypeError(msg)

            try:
                result = await func(*args, **kwargs)
                if auto_commit:
                    await instance._session.commit()
                return result
            except (KeyboardInterrupt, SystemExit):
                raise  # Never suppress system signals
            except Exception as e:
                await instance._session.rollback()
                logger.error(
                    f"{error_message}: {e}",
                    extra={"function": func.__name__, "error": str(e)},
                    exc_info=True,
                )
                raise error_class(f"{error_message}: {e}") from e

        return cast(Callable[P, Awaitable[R]], wrapper)

    return decorator
