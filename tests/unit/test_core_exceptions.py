"""
Unit tests for TMWS core exceptions
Testing all custom exception classes
"""

import pytest
import sys
import os

# Add source path for direct imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from core.exceptions import (
    TMWSException,
    DatabaseException,
    DatabaseError,
    MemoryException,
    WorkflowException,
    ValidationException,
    ValidationError,
    AuthenticationException,
    AuthorizationException,
    RateLimitException,
    VectorizationException,
    NotFoundError
)


class TestTMWSException:
    """Test base TMWSException class."""

    def test_basic_initialization(self):
        """Test basic exception creation."""
        message = "Test error message"
        exc = TMWSException(message)

        assert str(exc) == message
        assert exc.message == message
        assert exc.details == {}

    def test_initialization_with_details(self):
        """Test exception creation with details."""
        message = "Test error with details"
        details = {"error_code": 500, "context": "test_context"}
        exc = TMWSException(message, details)

        assert str(exc) == message
        assert exc.message == message
        assert exc.details == details

    def test_initialization_with_none_details(self):
        """Test exception creation with None details."""
        message = "Test error with None details"
        exc = TMWSException(message, None)

        assert str(exc) == message
        assert exc.message == message
        assert exc.details == {}

    def test_inheritance(self):
        """Test that TMWSException inherits from Exception."""
        exc = TMWSException("test")
        assert isinstance(exc, Exception)

    def test_empty_message(self):
        """Test exception with empty message."""
        exc = TMWSException("")
        assert str(exc) == ""
        assert exc.message == ""

    def test_complex_details(self):
        """Test exception with complex details structure."""
        message = "Complex error"
        details = {
            "nested": {"level": 1, "data": [1, 2, 3]},
            "timestamp": "2024-01-01T00:00:00Z",
            "severity": "high"
        }
        exc = TMWSException(message, details)

        assert exc.details["nested"]["level"] == 1
        assert exc.details["timestamp"] == "2024-01-01T00:00:00Z"
        assert exc.details["severity"] == "high"


class TestDatabaseException:
    """Test DatabaseException class."""

    def test_database_exception_creation(self):
        """Test DatabaseException creation."""
        message = "Database connection failed"
        exc = DatabaseException(message)

        assert isinstance(exc, TMWSException)
        assert str(exc) == message
        assert exc.message == message

    def test_database_exception_with_details(self):
        """Test DatabaseException with details."""
        message = "SQL query failed"
        details = {"table": "users", "query": "SELECT * FROM users"}
        exc = DatabaseException(message, details)

        assert exc.details["table"] == "users"
        assert exc.details["query"] == "SELECT * FROM users"

    def test_database_error_alias(self):
        """Test DatabaseError alias."""
        message = "Database error"
        exc = DatabaseError(message)

        assert isinstance(exc, DatabaseException)
        assert isinstance(exc, TMWSException)
        assert str(exc) == message


class TestMemoryException:
    """Test MemoryException class."""

    def test_memory_exception_creation(self):
        """Test MemoryException creation."""
        message = "Memory allocation failed"
        exc = MemoryException(message)

        assert isinstance(exc, TMWSException)
        assert str(exc) == message

    def test_memory_exception_with_details(self):
        """Test MemoryException with memory-specific details."""
        message = "Vector embedding failed"
        details = {"memory_id": "mem_123", "vector_size": 384}
        exc = MemoryException(message, details)

        assert exc.details["memory_id"] == "mem_123"
        assert exc.details["vector_size"] == 384


class TestWorkflowException:
    """Test WorkflowException class."""

    def test_workflow_exception_creation(self):
        """Test WorkflowException creation."""
        message = "Workflow execution failed"
        exc = WorkflowException(message)

        assert isinstance(exc, TMWSException)
        assert str(exc) == message

    def test_workflow_exception_with_details(self):
        """Test WorkflowException with workflow details."""
        message = "Step execution failed"
        details = {"workflow_id": "wf_456", "step": 3, "total_steps": 5}
        exc = WorkflowException(message, details)

        assert exc.details["workflow_id"] == "wf_456"
        assert exc.details["step"] == 3


class TestValidationException:
    """Test ValidationException class."""

    def test_validation_exception_creation(self):
        """Test ValidationException creation."""
        message = "Input validation failed"
        exc = ValidationException(message)

        assert isinstance(exc, TMWSException)
        assert str(exc) == message

    def test_validation_exception_with_details(self):
        """Test ValidationException with validation details."""
        message = "Required field missing"
        details = {"field": "email", "value": None, "required": True}
        exc = ValidationException(message, details)

        assert exc.details["field"] == "email"
        assert exc.details["required"] is True

    def test_validation_error_alias(self):
        """Test ValidationError alias."""
        message = "Validation error"
        exc = ValidationError(message)

        assert isinstance(exc, ValidationException)
        assert isinstance(exc, TMWSException)
        assert str(exc) == message


class TestAuthenticationException:
    """Test AuthenticationException class."""

    def test_authentication_exception_creation(self):
        """Test AuthenticationException creation."""
        message = "Authentication failed"
        exc = AuthenticationException(message)

        assert isinstance(exc, TMWSException)
        assert str(exc) == message

    def test_authentication_exception_with_details(self):
        """Test AuthenticationException with auth details."""
        message = "Invalid token"
        details = {"token_type": "Bearer", "expired": True, "user_id": "user_123"}
        exc = AuthenticationException(message, details)

        assert exc.details["token_type"] == "Bearer"
        assert exc.details["expired"] is True


class TestAuthorizationException:
    """Test AuthorizationException class."""

    def test_authorization_exception_creation(self):
        """Test AuthorizationException creation."""
        message = "Insufficient permissions"
        exc = AuthorizationException(message)

        assert isinstance(exc, TMWSException)
        assert str(exc) == message

    def test_authorization_exception_with_details(self):
        """Test AuthorizationException with permission details."""
        message = "Access denied to resource"
        details = {"resource": "/api/admin", "required_role": "admin", "user_role": "user"}
        exc = AuthorizationException(message, details)

        assert exc.details["resource"] == "/api/admin"
        assert exc.details["required_role"] == "admin"
        assert exc.details["user_role"] == "user"


class TestRateLimitException:
    """Test RateLimitException class."""

    def test_rate_limit_exception_creation(self):
        """Test RateLimitException creation."""
        message = "Rate limit exceeded"
        exc = RateLimitException(message)

        assert isinstance(exc, TMWSException)
        assert str(exc) == message

    def test_rate_limit_exception_with_details(self):
        """Test RateLimitException with rate limit details."""
        message = "Too many requests"
        details = {"limit": 100, "period": 60, "current_count": 150, "reset_time": 1640995200}
        exc = RateLimitException(message, details)

        assert exc.details["limit"] == 100
        assert exc.details["period"] == 60
        assert exc.details["current_count"] == 150


class TestVectorizationException:
    """Test VectorizationException class."""

    def test_vectorization_exception_creation(self):
        """Test VectorizationException creation."""
        message = "Vector embedding failed"
        exc = VectorizationException(message)

        assert isinstance(exc, TMWSException)
        assert str(exc) == message

    def test_vectorization_exception_with_details(self):
        """Test VectorizationException with vectorization details."""
        message = "Embedding model unavailable"
        details = {"model": "all-MiniLM-L6-v2", "dimension": 384, "text_length": 1000}
        exc = VectorizationException(message, details)

        assert exc.details["model"] == "all-MiniLM-L6-v2"
        assert exc.details["dimension"] == 384


class TestNotFoundError:
    """Test NotFoundError class."""

    def test_not_found_error_creation(self):
        """Test NotFoundError creation with resource info."""
        resource_type = "User"
        resource_id = "user_123"
        exc = NotFoundError(resource_type, resource_id)

        expected_message = "User with id 'user_123' not found"
        assert str(exc) == expected_message
        assert exc.message == expected_message
        assert exc.details["resource_type"] == resource_type
        assert exc.details["resource_id"] == resource_id

    def test_not_found_error_inheritance(self):
        """Test NotFoundError inheritance."""
        exc = NotFoundError("Task", "task_456")
        assert isinstance(exc, TMWSException)

    def test_not_found_error_different_resources(self):
        """Test NotFoundError with different resource types."""
        test_cases = [
            ("Memory", "mem_789"),
            ("Workflow", "wf_101"),
            ("Agent", "agent_202"),
            ("Persona", "persona_303")
        ]

        for resource_type, resource_id in test_cases:
            exc = NotFoundError(resource_type, resource_id)
            expected_message = f"{resource_type} with id '{resource_id}' not found"
            assert str(exc) == expected_message
            assert exc.details["resource_type"] == resource_type
            assert exc.details["resource_id"] == resource_id

    def test_not_found_error_empty_values(self):
        """Test NotFoundError with empty values."""
        exc = NotFoundError("", "")
        expected_message = " with id '' not found"
        assert str(exc) == expected_message
        assert exc.details["resource_type"] == ""
        assert exc.details["resource_id"] == ""


class TestExceptionHierarchy:
    """Test exception inheritance hierarchy."""

    def test_all_exceptions_inherit_from_tmws_exception(self):
        """Test that all custom exceptions inherit from TMWSException."""
        exception_classes = [
            DatabaseException,
            DatabaseError,
            MemoryException,
            WorkflowException,
            ValidationException,
            ValidationError,
            AuthenticationException,
            AuthorizationException,
            RateLimitException,
            VectorizationException,
            NotFoundError
        ]

        for exc_class in exception_classes:
            exc = exc_class("test message") if exc_class != NotFoundError else exc_class("type", "id")
            assert isinstance(exc, TMWSException)
            assert isinstance(exc, Exception)

    def test_exception_aliases(self):
        """Test that aliases point to correct classes."""
        # Test DatabaseError is alias for DatabaseException
        db_exc = DatabaseError("test")
        assert isinstance(db_exc, DatabaseException)

        # Test ValidationError is alias for ValidationException
        val_exc = ValidationError("test")
        assert isinstance(val_exc, ValidationException)


class TestExceptionEdgeCases:
    """Test edge cases and unusual scenarios."""

    def test_exception_with_none_message(self):
        """Test exception handling with None message."""
        # This should be handled gracefully by Python's exception system
        try:
            exc = TMWSException(None)
            assert str(exc) == "None"
        except TypeError:
            # If TypeError is raised, that's also acceptable behavior
            pass

    def test_exception_pickling(self):
        """Test that exceptions can be pickled and unpickled."""
        import pickle

        exc = TMWSException("Test message", {"key": "value"})
        pickled = pickle.dumps(exc)
        unpickled = pickle.loads(pickled)

        assert str(unpickled) == str(exc)
        assert unpickled.message == exc.message
        assert unpickled.details == exc.details

    def test_exception_repr(self):
        """Test string representation of exceptions."""
        exc = TMWSException("Test message", {"key": "value"})
        repr_str = repr(exc)

        # Should contain the class name and message
        assert "TMWSException" in repr_str
        assert "Test message" in repr_str

    def test_nested_exception_raising(self):
        """Test raising exceptions within exception handlers."""
        try:
            try:
                raise DatabaseException("Inner exception")
            except DatabaseException:
                raise MemoryException("Outer exception")
        except MemoryException as e:
            assert str(e) == "Outer exception"
            assert isinstance(e, TMWSException)


class TestExceptionIntegration:
    """Test exception usage in realistic scenarios."""

    def test_database_operation_failure(self):
        """Test database operation failure scenario."""
        try:
            # Simulate database operation
            raise DatabaseException(
                "Failed to insert record",
                {
                    "table": "memories",
                    "operation": "INSERT",
                    "error_code": "23505",  # Unique constraint violation
                    "constraint": "memories_pkey"
                }
            )
        except DatabaseException as e:
            assert "Failed to insert record" in str(e)
            assert e.details["table"] == "memories"
            assert e.details["error_code"] == "23505"

    def test_authentication_flow(self):
        """Test authentication failure scenario."""
        try:
            # Simulate authentication check
            raise AuthenticationException(
                "Invalid JWT token",
                {
                    "token_expired": True,
                    "expiry_time": "2024-01-01T00:00:00Z",
                    "current_time": "2024-01-01T01:00:00Z"
                }
            )
        except AuthenticationException as e:
            assert "Invalid JWT token" in str(e)
            assert e.details["token_expired"] is True

    def test_workflow_execution_failure(self):
        """Test workflow execution failure scenario."""
        try:
            # Simulate workflow step failure
            raise WorkflowException(
                "Step execution timeout",
                {
                    "workflow_id": "wf_critical_process",
                    "step_name": "data_validation",
                    "timeout_seconds": 300,
                    "actual_duration": 450
                }
            )
        except WorkflowException as e:
            assert "Step execution timeout" in str(e)
            assert e.details["workflow_id"] == "wf_critical_process"
            assert e.details["actual_duration"] > e.details["timeout_seconds"]