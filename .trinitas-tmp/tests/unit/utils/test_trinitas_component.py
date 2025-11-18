"""
Unit tests for shared.utils.trinitas_component module

Tests the TrinitasComponent base class for standardized initialization.
Architecture testing by Athena: "調和的なコンポーネント設計のテストです♪"
"""

import json
from pathlib import Path

import pytest

from shared.utils import TrinitasComponent


class TestComponentExample(TrinitasComponent):
    """Example component for testing"""
    DEFAULT_CONFIG_FILE = "test_config.json"
    COMPONENT_NAME = "TestComponent"


class TestTrinitasComponent:
    """Test cases for TrinitasComponent base class"""

    def test_initialization_auto(self, tmp_path, sample_json_data):
        """Test automatic initialization"""
        # Arrange
        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "test_config.json"

        with open(config_file, "w") as f:
            json.dump(sample_json_data, f)

        # Create component with temp directory as project root
        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=True
        )

        # Assert
        assert component.is_initialized is True
        assert component.config == sample_json_data
        assert component.project_root == Path(tmp_path)

    def test_initialization_manual(self, tmp_path):
        """Test manual initialization"""
        # Arrange & Act
        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=False
        )

        # Assert
        assert component.is_initialized is False
        assert component.config == {}

        # Manually initialize
        component.ensure_initialized()
        assert component.is_initialized is True

    def test_initialization_custom_config_path(self, tmp_path, sample_json_data):
        """Test initialization with custom config path"""
        # Arrange
        custom_config = tmp_path / "custom" / "my_config.json"
        custom_config.parent.mkdir(parents=True)

        with open(custom_config, "w") as f:
            json.dump(sample_json_data, f)

        # Act
        component = TestComponentExample(
            config_path=custom_config,
            auto_init=True
        )

        # Assert
        assert component.config == sample_json_data
        assert component.config_path == custom_config

    def test_project_root_detection(self):
        """Test automatic project root detection"""
        # Act
        component = TestComponentExample(auto_init=False)

        # Assert
        assert component.project_root is not None
        assert component.project_root.exists()
        # Should find a .git directory or similar marker

    def test_get_config_simple(self, tmp_path):
        """Test get_config with simple key"""
        # Arrange
        config_data = {"version": "1.0", "enabled": True}
        config_file = tmp_path / ".opencode" / "config" / "test_config.json"
        config_file.parent.mkdir(parents=True)

        with open(config_file, "w") as f:
            json.dump(config_data, f)

        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=True
        )

        # Act & Assert
        assert component.get_config("version") == "1.0"
        assert component.get_config("enabled") is True

    def test_get_config_nested(self, tmp_path):
        """Test get_config with nested key"""
        # Arrange
        config_data = {
            "server": {
                "host": "localhost",
                "port": 8000,
                "ssl": {
                    "enabled": True,
                    "cert_path": "/path/to/cert"
                }
            }
        }
        config_file = tmp_path / ".opencode" / "config" / "test_config.json"
        config_file.parent.mkdir(parents=True)

        with open(config_file, "w") as f:
            json.dump(config_data, f)

        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=True
        )

        # Act & Assert
        assert component.get_config("server.host") == "localhost"
        assert component.get_config("server.port") == 8000
        assert component.get_config("server.ssl.enabled") is True
        assert component.get_config("server.ssl.cert_path") == "/path/to/cert"

    def test_get_config_with_default(self, tmp_path):
        """Test get_config with default value"""
        # Arrange
        config_data = {"existing": "value"}
        config_file = tmp_path / ".opencode" / "config" / "test_config.json"
        config_file.parent.mkdir(parents=True)

        with open(config_file, "w") as f:
            json.dump(config_data, f)

        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=True
        )

        # Act & Assert
        assert component.get_config("existing") == "value"
        assert component.get_config("missing", default="default") == "default"
        assert component.get_config("missing") is None

    def test_set_config_simple(self, tmp_path):
        """Test set_config with simple key"""
        # Arrange
        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=False
        )
        component._config = {}

        # Act
        component.set_config("version", "2.0")

        # Assert
        assert component.config["version"] == "2.0"

    def test_set_config_nested(self, tmp_path):
        """Test set_config with nested key"""
        # Arrange
        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=False
        )
        component._config = {}

        # Act
        component.set_config("server.host", "0.0.0.0")
        component.set_config("server.port", 9000)

        # Assert
        assert component.config["server"]["host"] == "0.0.0.0"
        assert component.config["server"]["port"] == 9000

    def test_ensure_initialized_idempotent(self, tmp_path, sample_json_data):
        """Test that ensure_initialized is idempotent"""
        # Arrange
        config_file = tmp_path / ".opencode" / "config" / "test_config.json"
        config_file.parent.mkdir(parents=True)

        with open(config_file, "w") as f:
            json.dump(sample_json_data, f)

        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=True
        )

        # Act - call multiple times
        component.ensure_initialized()
        component.ensure_initialized()
        component.ensure_initialized()

        # Assert - should still be initialized once
        assert component.is_initialized is True
        assert component.config == sample_json_data

    def test_config_missing_file(self, tmp_path):
        """Test behavior when config file is missing"""
        # Arrange & Act
        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=True
        )

        # Assert - should handle gracefully
        assert component.config == {}
        assert component.is_initialized is True

    def test_config_invalid_json(self, tmp_path):
        """Test behavior with invalid JSON config"""
        # Arrange
        config_file = tmp_path / ".opencode" / "config" / "test_config.json"
        config_file.parent.mkdir(parents=True)
        config_file.write_text("{ invalid json }")

        # Act
        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=True
        )

        # Assert - should fall back to empty config
        assert component.config == {}
        assert component.is_initialized is True


class TestComponentInheritance:
    """Test component inheritance patterns"""

    def test_multiple_components_isolated(self, tmp_path):
        """Test that multiple component instances are isolated"""
        # Arrange
        class ComponentA(TrinitasComponent):
            DEFAULT_CONFIG_FILE = "config_a.json"
            COMPONENT_NAME = "ComponentA"

        class ComponentB(TrinitasComponent):
            DEFAULT_CONFIG_FILE = "config_b.json"
            COMPONENT_NAME = "ComponentB"

        config_a = {"component": "A"}
        config_b = {"component": "B"}

        config_dir = tmp_path / ".opencode" / "config"
        config_dir.mkdir(parents=True)

        (config_dir / "config_a.json").write_text(json.dumps(config_a))
        (config_dir / "config_b.json").write_text(json.dumps(config_b))

        # Act
        comp_a = ComponentA(project_root=tmp_path, auto_init=True)
        comp_b = ComponentB(project_root=tmp_path, auto_init=True)

        # Assert
        assert comp_a.config == config_a
        assert comp_b.config == config_b
        assert comp_a.config != comp_b.config

    def test_component_with_custom_initialization(self, tmp_path):
        """Test component with custom _initialize method"""
        # Arrange
        class CustomComponent(TrinitasComponent):
            DEFAULT_CONFIG_FILE = "custom.json"
            COMPONENT_NAME = "CustomComponent"

            def _initialize(self):
                super()._initialize()
                self.custom_value = "initialized"

        config_file = tmp_path / ".opencode" / "config" / "custom.json"
        config_file.parent.mkdir(parents=True)
        config_file.write_text(json.dumps({"test": "value"}))

        # Act
        component = CustomComponent(project_root=tmp_path, auto_init=True)

        # Assert
        assert component.is_initialized is True
        assert hasattr(component, "custom_value")
        assert component.custom_value == "initialized"
        assert component.config == {"test": "value"}


class TestConfigHelpers:
    """Test configuration helper methods"""

    def test_get_config_dot_notation(self, tmp_path):
        """Test dot notation for nested config"""
        # Arrange
        config_data = {
            "level1": {
                "level2": {
                    "level3": "deep_value"
                }
            }
        }
        config_file = tmp_path / ".opencode" / "config" / "test_config.json"
        config_file.parent.mkdir(parents=True)

        with open(config_file, "w") as f:
            json.dump(config_data, f)

        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=True
        )

        # Act & Assert
        assert component.get_config("level1.level2.level3") == "deep_value"

    def test_set_config_creates_nested_structure(self, tmp_path):
        """Test that set_config creates nested dict structure"""
        # Arrange
        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=False
        )
        component._config = {}

        # Act
        component.set_config("a.b.c.d", "nested_value")

        # Assert
        assert component.config["a"]["b"]["c"]["d"] == "nested_value"

    def test_config_with_list_values(self, tmp_path):
        """Test configuration with list values"""
        # Arrange
        config_data = {
            "personas": ["athena", "artemis", "hestia"],
            "settings": {
                "priorities": [1, 2, 3]
            }
        }
        config_file = tmp_path / ".opencode" / "config" / "test_config.json"
        config_file.parent.mkdir(parents=True)

        with open(config_file, "w") as f:
            json.dump(config_data, f)

        component = TestComponentExample(
            project_root=tmp_path,
            auto_init=True
        )

        # Act & Assert
        assert component.get_config("personas") == ["athena", "artemis", "hestia"]
        assert component.get_config("settings.priorities") == [1, 2, 3]


@pytest.mark.parametrize("config_path,expected_result", [
    ("simple_key", "value"),
    ("nested.key", "nested_value"),
    ("deeply.nested.key", "deep_value"),
    ("missing.key", None),
])
def test_get_config_parametrized(config_path, expected_result, tmp_path):
    """Parametrized tests for get_config"""
    config_data = {
        "simple_key": "value",
        "nested": {"key": "nested_value"},
        "deeply": {"nested": {"key": "deep_value"}}
    }

    config_file = tmp_path / ".opencode" / "config" / "test_config.json"
    config_file.parent.mkdir(parents=True)

    with open(config_file, "w") as f:
        json.dump(config_data, f)

    component = TestComponentExample(
        project_root=tmp_path,
        auto_init=True
    )

    assert component.get_config(config_path) == expected_result
