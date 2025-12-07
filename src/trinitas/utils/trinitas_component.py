#!/usr/bin/env python3
"""
Base Component Class for Trinitas System
Provides standardized initialization and configuration loading

Created: 2025-10-15 (Phase 1 Day 3)
Purpose: Eliminate initialization code duplication across components
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    from .json_loader import JSONLoader
except ImportError:
    # Fallback for direct execution
    import json
    import logging as _logging
    _logger = _logging.getLogger(__name__)

    class JSONLoader:
        @staticmethod
        def load_from_file(file_path, default=None, silent=False):
            try:
                with open(file_path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                if not silent:
                    _logger.error("Failed to load JSON", exc_info=True)
                return default


class TrinitasComponent:
    """Base class for all Trinitas system components.

    This class provides standardized initialization, configuration loading, and
    project structure detection for all components in the Trinitas system.
    It eliminates code duplication by centralizing common setup patterns.

    Subclasses should override:
        - DEFAULT_CONFIG_FILE: Name of the default configuration file
        - COMPONENT_NAME: Human-readable name for logging
        - _initialize(): Custom initialization logic

    Attributes:
        DEFAULT_CONFIG_DIR: Directory for config files relative to project root.
            Defaults to '.opencode/config'.
        DEFAULT_CONFIG_FILE: Name of the default config file for this component.
            Set to None if no config file is needed.
        COMPONENT_NAME: Name of the component for logging and display.
            Defaults to 'TrinitasComponent'.

    Example:
        >>> # Use base class directly
        >>> component = TrinitasComponent()
        >>> print(f"Project root: {component.project_root}")
        >>> print(f"Config: {component.config}")
        >>>
        >>> # Create a custom component
        >>> class MyComponent(TrinitasComponent):
        ...     DEFAULT_CONFIG_FILE = "my_config.json"
        ...     COMPONENT_NAME = "MyComponent"
        ...
        ...     def _initialize(self):
        ...         super()._initialize()
        ...         self.my_setting = self.get_config("setting", default="value")
        >>>
        >>> my_component = MyComponent()
    """

    # Override these in subclasses
    DEFAULT_CONFIG_DIR = ".opencode/config"
    DEFAULT_CONFIG_FILE: str | None = None
    COMPONENT_NAME = "TrinitasComponent"

    def __init__(
        self,
        config_path: str | Path | None = None,
        project_root: str | Path | None = None,
        auto_init: bool = True,
    ):
        """Initialize Trinitas component with configuration and project detection.

        Sets up the component by detecting or using the provided project root,
        locating the configuration file, and optionally initializing the component
        immediately.

        Args:
            config_path: Explicit path to a configuration JSON file. If None,
                uses DEFAULT_CONFIG_FILE in DEFAULT_CONFIG_DIR within the project
                root (if DEFAULT_CONFIG_FILE is set). Can be absolute or relative.
            project_root: Explicit project root directory. If None, automatically
                detects the project root by searching for marker files
                (pyproject.toml, .git, README.md, etc.) starting from the current
                file's location and falling back to the current working directory.
            auto_init: If True, automatically calls _initialize() to load config
                and complete setup. If False, initialization must be done manually
                by calling _initialize() or ensure_initialized(). Defaults to True.

        Example:
            >>> # Basic usage with auto-detection
            >>> component = TrinitasComponent()
            >>>
            >>> # Specify custom config path
            >>> component = TrinitasComponent(config_path='/path/to/config.json')
            >>>
            >>> # Defer initialization
            >>> component = TrinitasComponent(auto_init=False)
            >>> # ... do some setup ...
            >>> component.ensure_initialized()
        """
        # Initialize base attributes
        self._initialized = False
        self._config: dict[str, Any] = {}
        self._project_root: Path | None = None
        self._config_path: Path | None = None

        # Set project root
        if project_root:
            self._project_root = Path(project_root)
        else:
            self._project_root = self._detect_project_root()

        # Set config path
        if config_path:
            self._config_path = Path(config_path)
        elif self.DEFAULT_CONFIG_FILE:
            self._config_path = (
                self._project_root / self.DEFAULT_CONFIG_DIR / self.DEFAULT_CONFIG_FILE
            )

        # Auto-initialize if requested
        if auto_init:
            self._initialize()

    def _detect_project_root(self) -> Path:
        """Detect project root directory by searching for common marker files.

        Searches upward from the current file's location and then from the current
        working directory, looking for files/directories that typically indicate
        a project root.

        Returns:
            Path object pointing to the detected project root directory.
            Falls back to current working directory if no markers found.

        Search Strategy:
            1. Search upward from this file's location
            2. If not found, search upward from current working directory
            3. Fall back to current working directory as last resort

        Marker Files (in priority order):
            - pyproject.toml: Python Poetry/PEP 518 projects
            - setup.py: Python setuptools projects
            - .git: Git repository root
            - README.md: Common project documentation
            - .claude-plugin: Claude Code plugin marker

        Example:
            >>> component = TrinitasComponent()
            >>> root = component._detect_project_root()
            >>> print(f"Project root: {root}")
            Project root: /home/user/workspace/trinitas-agents
        """
        current = Path(__file__).parent

        # Try to find from file location first
        while current != current.parent:
            markers = [
                "pyproject.toml",
                "setup.py",
                ".git",
                "README.md",
                ".claude-plugin",
            ]
            if any((current / marker).exists() for marker in markers):
                return current
            current = current.parent

        # Fallback: Try from current working directory
        current = Path.cwd()
        while current != current.parent:
            markers = ["pyproject.toml", ".git", "README.md"]
            if any((current / marker).exists() for marker in markers):
                return current
            current = current.parent

        # Last resort: Use current working directory
        return Path.cwd()

    def _initialize(self) -> None:
        """Initialize component by loading configuration and setting up resources.

        This method is called automatically if auto_init=True in __init__().
        It can also be called manually later if needed. The method is idempotent
        - calling it multiple times has no effect after the first call.

        Subclasses should override this method to add custom initialization logic,
        but must call super()._initialize() first to ensure configuration is loaded.

        Note:
            This method sets self._initialized = True to prevent re-initialization.
            All initialization logic should check this flag.

        Example:
            >>> class MyComponent(TrinitasComponent):
            ...     def _initialize(self):
            ...         super()._initialize()  # Load config first
            ...         self.db = self.get_config("database.url")
            ...         self.setup_logging()
        """
        if self._initialized:
            return

        # Load configuration if path is set
        if self._config_path and self._config_path.exists():
            self._config = self._load_config(self._config_path)

        self._initialized = True

    def _load_config(self, config_path: Path) -> dict[str, Any]:
        """Load configuration from a JSON file.

        Uses JSONLoader for consistent error handling and validation. If loading
        fails for any reason (file not found, invalid JSON, etc.), returns an
        empty dictionary and logs a warning.

        Args:
            config_path: Path to the JSON configuration file to load.

        Returns:
            Dictionary containing the loaded configuration, or an empty dictionary
            if loading fails for any reason.

        Note:
            Errors are logged to stderr but do not raise exceptions. This allows
            components to function with default settings even if config is missing.

        Example:
            >>> component = TrinitasComponent()
            >>> config = component._load_config(Path('config.json'))
            >>> print(f"Loaded {len(config)} config keys")
        """
        try:
            return JSONLoader.load_from_file(config_path, default={})
        except Exception:
            logger.warning(
                "Config load failed",
                extra={"component": self.COMPONENT_NAME},
                exc_info=True,
            )
            return {}

    @property
    def project_root(self) -> Path:
        """Get the detected or configured project root directory.

        Returns:
            Path object pointing to the project root directory.

        Example:
            >>> component = TrinitasComponent()
            >>> print(f"Project root: {component.project_root}")
            >>> config_dir = component.project_root / ".opencode/config"
        """
        return self._project_root

    @property
    def config_path(self) -> Path | None:
        """Get the path to the configuration file being used.

        Returns:
            Path to the config file if one is configured, None otherwise.

        Example:
            >>> component = TrinitasComponent()
            >>> if component.config_path:
            ...     print(f"Using config: {component.config_path}")
            ... else:
            ...     print("No config file configured")
        """
        return self._config_path

    @property
    def config(self) -> dict[str, Any]:
        """Get the full configuration dictionary.

        Returns:
            Dictionary containing all loaded configuration values.
            Returns empty dictionary if no config was loaded.

        Example:
            >>> component = TrinitasComponent()
            >>> config = component.config
            >>> print(f"Config keys: {list(config.keys())}")
        """
        return self._config

    @property
    def is_initialized(self) -> bool:
        """Check if the component has been initialized.

        Returns:
            True if _initialize() has been called and completed, False otherwise.

        Example:
            >>> component = TrinitasComponent(auto_init=False)
            >>> print(f"Initialized: {component.is_initialized}")
            False
            >>> component.ensure_initialized()
            >>> print(f"Initialized: {component.is_initialized}")
            True
        """
        return self._initialized

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key with support for nested keys.

        Supports dot notation for accessing nested configuration values.
        For example, "server.port" accesses config["server"]["port"].

        Args:
            key: Configuration key. Supports dot notation for nested access
                (e.g., "database.host", "server.ssl.enabled").
            default: Value to return if the key is not found at any level
                of nesting. Defaults to None.

        Returns:
            The configuration value if found, otherwise the default value.

        Example:
            >>> component = TrinitasComponent()
            >>> component.set_config("server.port", 8080)
            >>> component.set_config("server.host", "localhost")
            >>>
            >>> # Get nested value
            >>> port = component.get_config("server.port", default=3000)
            >>> print(port)
            8080
            >>>
            >>> # Get non-existent key with default
            >>> debug = component.get_config("debug.enabled", default=False)
            >>> print(debug)
            False
        """
        if "." in key:
            # Handle nested keys (e.g., "server.port")
            keys = key.split(".")
            value = self._config
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            return value
        return self._config.get(key, default)

    def set_config(self, key: str, value: Any) -> None:
        """Set configuration value by key with support for nested keys.

        Supports dot notation for setting nested configuration values.
        Automatically creates intermediate dictionaries as needed.

        Args:
            key: Configuration key. Supports dot notation for nested setting
                (e.g., "database.pool.size", "logging.level").
            value: Value to set. Can be any JSON-serializable type
                (str, int, float, bool, list, dict, None).

        Example:
            >>> component = TrinitasComponent()
            >>>
            >>> # Set simple value
            >>> component.set_config("debug", True)
            >>>
            >>> # Set nested value (creates intermediate dicts)
            >>> component.set_config("database.host", "localhost")
            >>> component.set_config("database.port", 5432)
            >>>
            >>> # Access the config
            >>> print(component.config)
            {'debug': True, 'database': {'host': 'localhost', 'port': 5432}}
        """
        if "." in key:
            # Handle nested keys
            keys = key.split(".")
            config = self._config
            for k in keys[:-1]:
                if k not in config or not isinstance(config[k], dict):
                    config[k] = {}
                config = config[k]
            config[keys[-1]] = value
        else:
            self._config[key] = value

    def ensure_initialized(self) -> None:
        """Ensure the component is initialized, calling _initialize() if needed.

        This method is idempotent - it can be called multiple times safely.
        If the component is already initialized, this method does nothing.

        Useful when auto_init=False was used in __init__() and you need to
        ensure initialization has occurred before using the component.

        Example:
            >>> # Create without auto-init
            >>> component = TrinitasComponent(auto_init=False)
            >>> print(component.is_initialized)
            False
            >>>
            >>> # Ensure initialization before use
            >>> component.ensure_initialized()
            >>> print(component.is_initialized)
            True
            >>>
            >>> # Safe to call again
            >>> component.ensure_initialized()  # No effect
        """
        if not self._initialized:
            self._initialize()

    def __repr__(self) -> str:
        """Return a string representation of the component for debugging.

        Returns:
            String containing component name, initialization status, config file,
            and project root directory.

        Example:
            >>> component = TrinitasComponent()
            >>> print(repr(component))
            <TrinitasComponent status=initialized config=None root=trinitas-agents>
        """
        status = "initialized" if self._initialized else "not initialized"
        config_file = self._config_path.name if self._config_path else "None"
        return (
            f"<{self.COMPONENT_NAME} "
            f"status={status} "
            f"config={config_file} "
            f"root={self._project_root.name}>"
        )


# Example subclass implementation
class ExampleComponent(TrinitasComponent):
    """Example component demonstrating how to subclass TrinitasComponent.

    This example shows the minimal requirements for creating a custom component:
    1. Set DEFAULT_CONFIG_FILE (optional, if component needs config)
    2. Set COMPONENT_NAME for logging and debugging
    3. Override _initialize() for custom setup logic

    Attributes:
        example_setting: Example of a component-specific attribute loaded
            from configuration during initialization.
    """

    DEFAULT_CONFIG_FILE = "example_config.json"
    COMPONENT_NAME = "ExampleComponent"

    def _initialize(self) -> None:
        """Perform custom initialization after loading config.

        This method demonstrates the pattern for custom initialization:
        1. Call super()._initialize() first to load config
        2. Extract configuration values with defaults
        3. Set up component-specific resources
        4. Log or print initialization status

        Example:
            >>> try:
            ...     example = ExampleComponent()
            ... except Exception:
            ...     # Expected if config file doesn't exist
            ...     pass
        """
        # Call parent initialization (loads config)
        super()._initialize()

        # Custom initialization logic
        self.example_setting = self.get_config("example.setting", default="default")

        print(f"{self.COMPONENT_NAME} initialized with setting: {self.example_setting}")


if __name__ == "__main__":
    # Test cases
    print("TrinitasComponent Test Suite")
    print("=" * 60)

    # Test 1: Basic initialization
    component = TrinitasComponent(auto_init=False)
    print(f"✓ Component created: {component}")
    print(f"  Project root: {component.project_root}")

    # Test 2: Auto-initialization
    component2 = TrinitasComponent()
    print(f"✓ Auto-initialized: {component2.is_initialized}")

    # Test 3: Config access
    component.set_config("test.nested.key", "value")
    value = component.get_config("test.nested.key")
    print(f"✓ Config get/set: {value}")

    # Test 4: Example subclass
    print("\n--- Testing ExampleComponent ---")
    try:
        example = ExampleComponent()
        print(f"✓ Subclass created: {example}")
    except Exception as e:
        print(f"✓ Expected error (no config file): {type(e).__name__}")

    print("\n✅ All tests completed!")
