"""
Unit tests for BaseTool class
Testing common functionality without database dependencies
"""

from unittest.mock import Mock

import pytest
from pydantic import BaseModel

from src.tools.base_tool import BaseTool


class TestModel(BaseModel):
    """Test Pydantic model for validation testing."""
    name: str
    value: int


class TestBaseTool(BaseTool):
    """Concrete implementation of BaseTool for testing."""

    async def register_tools(self, mcp_instance) -> None:
        """Mock implementation."""
        pass


class TestBaseToolInitialization:
    """Test BaseTool initialization."""

    def test_base_tool_initialization(self):
        """Test that BaseTool initializes with None services."""
        tool = TestBaseTool()

        assert tool._memory_service is None
        assert tool._persona_service is None
        assert tool._task_service is None
        assert tool._workflow_service is None
        assert tool._vectorization_service is None


class TestBaseToolFormatting:
    """Test response formatting methods."""

    def test_format_success_basic(self):
        """Test basic success formatting."""
        tool = TestBaseTool()
        result = tool.format_success("test_data")

        assert result["success"] is True
        assert result["message"] == "Operation completed successfully"
        assert result["data"] == "test_data"

    def test_format_success_custom_message(self):
        """Test success formatting with custom message."""
        tool = TestBaseTool()
        result = tool.format_success("test_data", "Custom success message")

        assert result["success"] is True
        assert result["message"] == "Custom success message"
        assert result["data"] == "test_data"

    def test_format_success_complex_data(self):
        """Test success formatting with complex data."""
        tool = TestBaseTool()
        complex_data = {
            "users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}],
            "count": 2
        }
        result = tool.format_success(complex_data)

        assert result["success"] is True
        assert result["data"] == complex_data

    def test_format_error_basic(self):
        """Test basic error formatting."""
        tool = TestBaseTool()
        result = tool.format_error("Something went wrong")

        assert result["success"] is False
        assert result["error"] == "Something went wrong"
        assert result["error_type"] == "general"

    def test_format_error_custom_type(self):
        """Test error formatting with custom error type."""
        tool = TestBaseTool()
        result = tool.format_error("Invalid input", "validation")

        assert result["success"] is False
        assert result["error"] == "Invalid input"
        assert result["error_type"] == "validation"


class TestBaseToolValidation:
    """Test input validation methods."""

    def test_validate_input_success(self):
        """Test successful input validation."""
        tool = TestBaseTool()
        data = {"name": "test", "value": 42}

        result = tool.validate_input(data, TestModel)

        assert isinstance(result, TestModel)
        assert result.name == "test"
        assert result.value == 42

    def test_validate_input_missing_field(self):
        """Test validation failure with missing field."""
        tool = TestBaseTool()
        data = {"name": "test"}  # Missing 'value' field

        with pytest.raises(ValueError) as exc_info:
            tool.validate_input(data, TestModel)

        assert "Input validation failed" in str(exc_info.value)

    def test_validate_input_wrong_type(self):
        """Test validation failure with wrong field type."""
        tool = TestBaseTool()
        data = {"name": "test", "value": "not_an_int"}

        with pytest.raises(ValueError) as exc_info:
            tool.validate_input(data, TestModel)

        assert "Input validation failed" in str(exc_info.value)

    def test_validate_input_extra_fields(self):
        """Test validation with extra fields (should be ignored)."""
        tool = TestBaseTool()
        data = {"name": "test", "value": 42, "extra": "ignored"}

        result = tool.validate_input(data, TestModel)

        assert isinstance(result, TestModel)
        assert result.name == "test"
        assert result.value == 42
        # Extra field should be ignored by Pydantic


class TestBaseToolServiceInitialization:
    """Test service initialization without actual database."""

    @pytest.mark.asyncio
    async def test_get_services_mock(self):
        """Test service initialization with mocked session."""
        from unittest.mock import patch

        tool = TestBaseTool()
        mock_session = Mock()

        # Mock all service classes to avoid database dependency
        with patch('src.tools.base_tool.MemoryService'), \
             patch('src.tools.base_tool.PersonaService'), \
             patch('src.tools.base_tool.TaskService'), \
             patch('src.tools.base_tool.WorkflowService'), \
             patch('src.tools.base_tool.VectorizationService'):

            services = await tool.get_services(mock_session)

            # Verify all expected services are returned
            expected_keys = {
                'memory_service', 'persona_service', 'task_service',
                'workflow_service', 'vectorization_service'
            }
            assert set(services.keys()) == expected_keys


class TestBaseToolAbstractMethod:
    """Test abstract method enforcement."""

    def test_cannot_instantiate_base_tool_directly(self):
        """Test that BaseTool cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseTool()  # Should fail because it's abstract

    def test_concrete_implementation_works(self):
        """Test that concrete implementation can be instantiated."""
        tool = TestBaseTool()
        assert isinstance(tool, BaseTool)


class TestBaseToolEdgeCases:
    """Test edge cases and error conditions."""

    def test_format_success_none_data(self):
        """Test formatting success with None data."""
        tool = TestBaseTool()
        result = tool.format_success(None)

        assert result["success"] is True
        assert result["data"] is None

    def test_format_success_empty_data(self):
        """Test formatting success with empty data."""
        tool = TestBaseTool()
        result = tool.format_success({})

        assert result["success"] is True
        assert result["data"] == {}

    def test_format_error_empty_message(self):
        """Test formatting error with empty message."""
        tool = TestBaseTool()
        result = tool.format_error("")

        assert result["success"] is False
        assert result["error"] == ""

    def test_validate_input_empty_dict(self):
        """Test validation with empty dict."""
        tool = TestBaseTool()

        with pytest.raises(ValueError):
            tool.validate_input({}, TestModel)


class TestBaseToolTypeHints:
    """Test type hints and generic behavior."""

    def test_validate_input_returns_correct_type(self):
        """Test that validate_input returns the correct model type."""
        tool = TestBaseTool()
        data = {"name": "test", "value": 42}

        result = tool.validate_input(data, TestModel)

        # Check that the returned object is exactly the expected type
        assert type(result) is TestModel
        assert hasattr(result, 'name')
        assert hasattr(result, 'value')


class TestBaseToolIntegration:
    """Integration tests for multiple BaseTool methods."""

    def test_validation_and_formatting_integration(self):
        """Test validation followed by success formatting."""
        tool = TestBaseTool()
        data = {"name": "integration_test", "value": 100}

        # Validate input
        validated = tool.validate_input(data, TestModel)

        # Format success response
        result = tool.format_success(
            {"validated": validated.model_dump()},
            "Validation and formatting successful"
        )

        assert result["success"] is True
        assert result["message"] == "Validation and formatting successful"
        assert result["data"]["validated"]["name"] == "integration_test"
        assert result["data"]["validated"]["value"] == 100

    def test_validation_error_and_formatting_integration(self):
        """Test validation error followed by error formatting."""
        tool = TestBaseTool()
        invalid_data = {"name": "test"}  # Missing required field

        try:
            tool.validate_input(invalid_data, TestModel)
        except ValueError as e:
            error_result = tool.format_error(str(e), "validation")

        assert error_result["success"] is False
        assert error_result["error_type"] == "validation"
        assert "Input validation failed" in error_result["error"]
