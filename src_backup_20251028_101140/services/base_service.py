"""
Base Service for TMWS
Provides common functionality for all service classes
"""

import logging
from typing import Any, TypeVar
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import NotFoundError, ValidationError

logger = logging.getLogger(__name__)

T = TypeVar("T")


class BaseService:
    """Base service class with common database operations."""

    def __init__(self, session: AsyncSession):
        """Initialize service with database session."""
        self.session = session

    async def get_by_id(self, model: type[T], record_id: UUID) -> T:
        """
        Get a record by ID.

        Args:
            model: SQLAlchemy model class
            record_id: Record UUID

        Returns:
            The record instance

        Raises:
            NotFoundError: If record not found
        """
        result = await self.session.execute(select(model).where(model.id == record_id))
        record = result.scalar_one_or_none()
        if not record:
            raise NotFoundError(f"{model.__name__} with ID {record_id} not found")
        return record

    async def create_record(self, model: type[T], **kwargs) -> T:
        """
        Create a new record.

        Args:
            model: SQLAlchemy model class
            **kwargs: Field values

        Returns:
            Created record instance
        """
        try:
            record = model(**kwargs)
            self.session.add(record)
            await self.session.flush()  # Get the ID without committing
            await self.session.refresh(record)
            return record
        except (KeyboardInterrupt, SystemExit):
            logger.critical(f"🚨 User interrupt during {model.__name__} creation")
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Error creating {model.__name__}: {e}",
                exc_info=True,
                extra={"model": model.__name__, "kwargs": kwargs}
            )
            raise ValidationError(f"Failed to create {model.__name__}: {str(e)}")

    async def update_record(self, record: T, **kwargs) -> T:
        """
        Update an existing record.

        Args:
            record: Record instance to update
            **kwargs: Field values to update

        Returns:
            Updated record instance
        """
        try:
            for key, value in kwargs.items():
                if hasattr(record, key):
                    setattr(record, key, value)
            await self.session.flush()
            await self.session.refresh(record)
            return record
        except (KeyboardInterrupt, SystemExit):
            logger.critical("🚨 User interrupt during record update")
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Error updating record: {e}",
                exc_info=True,
                extra={"record_type": type(record).__name__, "updates": kwargs}
            )
            raise ValidationError(f"Failed to update record: {str(e)}")

    async def delete_record(self, record: T) -> bool:
        """
        Delete a record.

        Args:
            record: Record instance to delete

        Returns:
            True if successful
        """
        try:
            await self.session.delete(record)
            await self.session.flush()
            return True
        except (KeyboardInterrupt, SystemExit):
            logger.critical("🚨 User interrupt during record deletion")
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Error deleting record: {e}",
                exc_info=True,
                extra={"record_type": type(record).__name__, "record_id": getattr(record, 'id', None)}
            )
            raise ValidationError(f"Failed to delete record: {str(e)}")

    async def exists(self, model: type[T], record_id: UUID) -> bool:
        """
        Check if a record exists by ID.

        Args:
            model: SQLAlchemy model class
            record_id: Record UUID

        Returns:
            True if record exists
        """
        result = await self.session.execute(select(model.id).where(model.id == record_id))
        return result.scalar_one_or_none() is not None

    async def count_records(self, model: type[T], **filters) -> int:
        """
        Count records with optional filters.

        Args:
            model: SQLAlchemy model class
            **filters: Filter conditions

        Returns:
            Number of matching records
        """
        query = select(model)
        for key, value in filters.items():
            if hasattr(model, key):
                query = query.where(getattr(model, key) == value)

        result = await self.session.execute(query)
        return len(result.scalars().all())

    def validate_required_fields(self, data: dict[str, Any], required_fields: list[str]):
        """
        Validate that required fields are present.

        Args:
            data: Data dictionary to validate
            required_fields: List of required field names

        Raises:
            ValidationError: If any required fields are missing
        """
        missing_fields = [
            field for field in required_fields if field not in data or data[field] is None
        ]
        if missing_fields:
            raise ValidationError(f"Missing required fields: {', '.join(missing_fields)}")

    def validate_enum_field(self, value: Any, enum_class: type, field_name: str):
        """
        Validate an enum field value.

        Args:
            value: Value to validate
            enum_class: Enum class
            field_name: Field name for error messages

        Raises:
            ValidationError: If value is not valid for the enum
        """
        if value not in [e.value for e in enum_class]:
            valid_values = [e.value for e in enum_class]
            raise ValidationError(f"Invalid {field_name}: {value}. Must be one of {valid_values}")

    async def commit(self):
        """Commit the current transaction."""
        try:
            await self.session.commit()
        except (KeyboardInterrupt, SystemExit):
            logger.critical("🚨 User interrupt during transaction commit")
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(
                f"Error committing transaction: {e}",
                exc_info=True,
                extra={"service": self.__class__.__name__}
            )
            raise

    async def rollback(self):
        """Rollback the current transaction."""
        await self.session.rollback()

    def get_logger(self) -> logging.Logger:
        """Get a logger for the service."""
        return logging.getLogger(self.__class__.__name__)
