"""Unit tests for @db_transaction decorator."""

import pytest
from unittest.mock import AsyncMock, Mock, patch

from src.infrastructure.decorators import db_transaction
from src.infrastructure.exceptions import RepositoryError


class CustomError(Exception):
    """Custom exception for testing."""

    pass


class MockRepository:
    """Mock repository for testing decorator."""

    def __init__(self, session: AsyncMock):
        self._session = session

    @db_transaction(error_message="Save operation failed")
    async def save(self, data: str) -> str:
        """Test method that commits on success."""
        return f"saved_{data}"

    @db_transaction(auto_commit=False, error_message="Query operation failed")
    async def query(self, query: str) -> str:
        """Test method that doesn't auto-commit."""
        return f"result_{query}"

    @db_transaction(error_message="Operation will fail")
    async def fail_operation(self) -> None:
        """Test method that raises an exception."""
        raise ValueError("Intentional failure")

    @db_transaction(error_message="Keyboard interrupt test")
    async def keyboard_interrupt(self) -> None:
        """Test method that raises KeyboardInterrupt."""
        raise KeyboardInterrupt()

    @db_transaction(error_message="System exit test")
    async def system_exit(self) -> None:
        """Test method that raises SystemExit."""
        raise SystemExit(1)

    @db_transaction(
        error_class=CustomError,
        error_message="Custom error test",
    )
    async def custom_error_operation(self) -> None:
        """Test method with custom error class."""
        raise ValueError("Wrapped in CustomError")


@pytest.mark.asyncio
class TestDbTransactionDecorator:
    """Test suite for @db_transaction decorator."""

    async def test_successful_operation_with_commit(self):
        """Test that successful operation commits transaction."""
        # Arrange
        session = AsyncMock()
        repo = MockRepository(session)

        # Act
        result = await repo.save("test_data")

        # Assert
        assert result == "saved_test_data"
        session.commit.assert_awaited_once()
        session.rollback.assert_not_awaited()

    async def test_successful_operation_without_commit(self):
        """Test that auto_commit=False skips commit."""
        # Arrange
        session = AsyncMock()
        repo = MockRepository(session)

        # Act
        result = await repo.query("SELECT *")

        # Assert
        assert result == "result_SELECT *"
        session.commit.assert_not_awaited()
        session.rollback.assert_not_awaited()

    async def test_failed_operation_rolls_back(self):
        """Test that failed operation rolls back transaction."""
        # Arrange
        session = AsyncMock()
        repo = MockRepository(session)

        # Act & Assert
        with pytest.raises(RepositoryError, match="Operation will fail: Intentional failure"):
            await repo.fail_operation()

        session.rollback.assert_awaited_once()
        session.commit.assert_not_awaited()

    async def test_keyboard_interrupt_passthrough(self):
        """Test that KeyboardInterrupt is not caught."""
        # Arrange
        session = AsyncMock()
        repo = MockRepository(session)

        # Act & Assert
        with pytest.raises(KeyboardInterrupt):
            await repo.keyboard_interrupt()

        # Rollback should not occur for system signals
        session.rollback.assert_not_awaited()
        session.commit.assert_not_awaited()

    async def test_system_exit_passthrough(self):
        """Test that SystemExit is not caught."""
        # Arrange
        session = AsyncMock()
        repo = MockRepository(session)

        # Act & Assert
        with pytest.raises(SystemExit):
            await repo.system_exit()

        # Rollback should not occur for system signals
        session.rollback.assert_not_awaited()
        session.commit.assert_not_awaited()

    async def test_custom_error_class(self):
        """Test that custom error class is used."""
        # Arrange
        session = AsyncMock()
        repo = MockRepository(session)

        # Act & Assert
        with pytest.raises(CustomError, match="Custom error test: Wrapped in CustomError"):
            await repo.custom_error_operation()

        session.rollback.assert_awaited_once()
        session.commit.assert_not_awaited()

    async def test_error_logging(self):
        """Test that errors are logged with structured data."""
        # Arrange
        session = AsyncMock()
        repo = MockRepository(session)

        # Act
        with patch("src.infrastructure.decorators.db_transaction.logger") as mock_logger:
            with pytest.raises(RepositoryError):
                await repo.fail_operation()

            # Assert
            mock_logger.error.assert_called_once()
            call_args = mock_logger.error.call_args
            assert "Operation will fail: Intentional failure" in call_args[0][0]
            assert call_args[1]["extra"]["function"] == "fail_operation"
            assert "Intentional failure" in call_args[1]["extra"]["error"]
            assert call_args[1]["exc_info"] is True

    async def test_function_metadata_preserved(self):
        """Test that @wraps preserves function metadata."""
        # Arrange
        session = AsyncMock()
        repo = MockRepository(session)

        # Assert
        assert repo.save.__name__ == "save"
        assert "Test method that commits on success" in repo.save.__doc__
        assert repo.query.__name__ == "query"
        assert "Test method that doesn't auto-commit" in repo.query.__doc__

    async def test_exception_chain_preserved(self):
        """Test that original exception is preserved in chain."""
        # Arrange
        session = AsyncMock()
        repo = MockRepository(session)

        # Act & Assert
        try:
            await repo.fail_operation()
        except RepositoryError as e:
            assert isinstance(e.__cause__, ValueError)
            assert str(e.__cause__) == "Intentional failure"

    async def test_multiple_operations_in_sequence(self):
        """Test multiple decorated operations in sequence."""
        # Arrange
        session = AsyncMock()
        repo = MockRepository(session)

        # Act
        result1 = await repo.save("data1")
        result2 = await repo.save("data2")
        result3 = await repo.query("SELECT COUNT(*)")

        # Assert
        assert result1 == "saved_data1"
        assert result2 == "saved_data2"
        assert result3 == "result_SELECT COUNT(*)"
        assert session.commit.await_count == 2  # Only save operations commit
        assert session.rollback.await_count == 0

    async def test_rollback_error_handling(self):
        """Test that rollback errors are propagated correctly."""
        # Arrange
        session = AsyncMock()
        session.rollback.side_effect = Exception("Rollback failed")
        repo = MockRepository(session)

        # Act & Assert
        with pytest.raises(Exception, match="Rollback failed"):
            await repo.fail_operation()


@pytest.mark.asyncio
class TestDbTransactionPerformance:
    """Performance tests for @db_transaction decorator."""

    @pytest.mark.benchmark
    async def test_minimal_overhead(self):
        """Test that decorator adds minimal overhead."""
        # Arrange
        session = AsyncMock()

        class PerformanceRepo:
            def __init__(self, session):
                self._session = session

            @db_transaction()
            async def fast_operation(self) -> int:
                return 42

        repo = PerformanceRepo(session)

        # Act & Assert - Should complete quickly
        result = await repo.fast_operation()
        assert result == 42
        session.commit.assert_awaited_once()
