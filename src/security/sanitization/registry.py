"""Validator registry for sanitization module.

Provides extensible registry pattern for validator discovery and management.
Allows registration of custom validators at runtime.

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

import logging
from typing import Any, ClassVar

from .base import BaseValidator
from .exceptions import ValidatorNotFoundError

logger = logging.getLogger(__name__)


class ValidatorRegistry:
    """Registry for validator discovery and instantiation.

    Provides a central registry for all validators, enabling:
    - Dynamic validator discovery
    - Runtime registration of custom validators
    - Type-safe validator retrieval

    Example:
        >>> registry = ValidatorRegistry()
        >>> registry.register("custom", CustomValidator)
        >>> validator_class = registry.get("custom")
        >>> validator = validator_class()
    """

    _instance: ClassVar["ValidatorRegistry | None"] = None

    def __init__(self) -> None:
        """Initialize the registry with empty validator dict."""
        self._validators: dict[str, type[BaseValidator[Any]]] = {}

    @classmethod
    def get_instance(cls) -> "ValidatorRegistry":
        """Get singleton registry instance.

        Returns:
            The global ValidatorRegistry instance
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(
        self,
        name: str,
        validator_class: type[BaseValidator[Any]],
        override: bool = False,
    ) -> None:
        """Register a validator class.

        Args:
            name: Unique name for the validator
            validator_class: The validator class to register
            override: Allow overriding existing registration (default False)

        Raises:
            TypeError: If validator_class is not a BaseValidator subclass
            ValueError: If name is already registered and override is False
        """
        # Type check
        if not isinstance(validator_class, type) or not issubclass(
            validator_class, BaseValidator
        ):
            raise TypeError(
                f"{validator_class} must be a subclass of BaseValidator"
            )

        # Check for existing registration
        if name in self._validators and not override:
            raise ValueError(
                f"Validator '{name}' is already registered. "
                f"Use override=True to replace."
            )

        self._validators[name] = validator_class
        logger.debug(f"Registered validator: {name} -> {validator_class.__name__}")

    def unregister(self, name: str) -> bool:
        """Unregister a validator.

        Args:
            name: Name of the validator to unregister

        Returns:
            True if validator was unregistered, False if not found
        """
        if name in self._validators:
            del self._validators[name]
            logger.debug(f"Unregistered validator: {name}")
            return True
        return False

    def get(self, name: str) -> type[BaseValidator[Any]]:
        """Retrieve validator class by name.

        Args:
            name: Name of the validator to retrieve

        Returns:
            The validator class

        Raises:
            ValidatorNotFoundError: If validator is not registered
        """
        if name not in self._validators:
            raise ValidatorNotFoundError(name)
        return self._validators[name]

    def has(self, name: str) -> bool:
        """Check if a validator is registered.

        Args:
            name: Name of the validator to check

        Returns:
            True if validator is registered, False otherwise
        """
        return name in self._validators

    def list_validators(self) -> list[str]:
        """List all registered validator names.

        Returns:
            Sorted list of validator names
        """
        return sorted(self._validators.keys())

    def get_validator_info(self) -> dict[str, dict[str, Any]]:
        """Get information about all registered validators.

        Returns:
            Dictionary mapping validator names to their rules
        """
        info = {}
        for name, validator_class in self._validators.items():
            try:
                # Instantiate with defaults to get rules
                validator = validator_class()
                info[name] = {
                    "class": validator_class.__name__,
                    "module": validator_class.__module__,
                    "rules": validator.get_validation_rules(),
                }
            except Exception as e:
                info[name] = {
                    "class": validator_class.__name__,
                    "module": validator_class.__module__,
                    "error": str(e),
                }
        return info

    def clear(self) -> None:
        """Clear all registered validators.

        Warning: This removes ALL validators including built-ins.
        """
        self._validators.clear()
        logger.warning("All validators cleared from registry")


def get_registry() -> ValidatorRegistry:
    """Get the global validator registry.

    Returns:
        The singleton ValidatorRegistry instance
    """
    return ValidatorRegistry.get_instance()
