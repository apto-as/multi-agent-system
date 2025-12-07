"""Command injection prevention validator.

Provides comprehensive command injection detection:
- Shell metacharacter detection
- Command substitution detection
- Pipe and redirect detection
- Dangerous command detection

Security:
- V-VERIFY-1: Command injection prevention
- Defense-in-depth with multiple detection layers
- Conservative detection for security-critical contexts

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

import re
import shlex
from typing import Any

from ..base import BaseValidator, Severity, ValidationResult
from ..core.patterns import get_pattern_registry
from ..exceptions import CommandInjectionError


class CommandValidator(BaseValidator[str]):
    """Validator for command injection prevention.

    Detects and prevents command injection attacks by:
    - Checking for shell metacharacters
    - Detecting command substitution
    - Detecting pipe and redirect operators
    - Checking for dangerous commands

    Example:
        >>> validator = CommandValidator()
        >>> result = validator.validate("; rm -rf /")
        >>> result.is_valid
        False
        >>> result.severity
        <Severity.CRITICAL: 'critical'>
    """

    # Allowed commands for verification system (V-VERIFY-1)
    ALLOWED_VERIFICATION_COMMANDS: set[str] = {
        "pytest",
        "python",
        "npm",
        "node",
        "ruff",
        "mypy",
        "black",
        "isort",
        "cargo",
        "go",
        "make",
        "echo",
        "cat",
        "grep",
        "wc",
        "head",
        "tail",
        "ls",
        "find",
        "diff",
    }

    def __init__(
        self,
        max_length: int = 1000,
        allowed_commands: set[str] | None = None,
        strict_mode: bool = True,
    ):
        """Initialize command validator.

        Args:
            max_length: Maximum command length (default 1000)
            allowed_commands: Set of allowed command names (default: verification commands)
            strict_mode: Use strict detection (default True)
        """
        self.max_length = max_length
        self.allowed_commands = allowed_commands or self.ALLOWED_VERIFICATION_COMMANDS
        self.strict_mode = strict_mode
        self._patterns = get_pattern_registry()

    def validate(self, value: Any, **kwargs: Any) -> ValidationResult[str]:
        """Validate input for command injection patterns.

        Args:
            value: The command string to validate
            **kwargs: Override options

        Returns:
            ValidationResult indicating if command is safe
        """
        # Type check
        if not isinstance(value, str):
            return ValidationResult.failure(
                f"Command must be string, got {type(value).__name__}",
                severity=Severity.CRITICAL,
            )

        # Length check
        max_length = kwargs.get("max_length", self.max_length)
        if len(value) > max_length:
            return ValidationResult.failure(
                f"Command exceeds maximum length of {max_length}",
                severity=Severity.WARNING,
                details={"original_length": len(value)},
            )

        # NULL byte check
        if self._patterns.test("null_bytes", value):
            return ValidationResult.failure(
                "NULL byte detected in command",
                severity=Severity.CRITICAL,
                details={"security_event": "null_byte_injection"},
            )

        # Command injection pattern check
        if self._patterns.test("command_injection", value):
            return ValidationResult.failure(
                "Potential command injection pattern detected",
                severity=Severity.CRITICAL,
                details={
                    "security_event": "command_injection_attempt",
                    "pattern_matched": "command_injection",
                },
            )

        # Extract base command
        base_command = self._extract_base_command(value)
        if base_command is None:
            return ValidationResult.failure(
                "Could not parse command",
                severity=Severity.WARNING,
            )

        # Check if command is allowed
        allowed_commands = kwargs.get("allowed_commands", self.allowed_commands)
        if base_command not in allowed_commands:
            return ValidationResult.failure(
                f"Command '{base_command}' is not in allowed list",
                severity=Severity.CRITICAL,
                details={
                    "command": base_command,
                    "allowed_commands": sorted(allowed_commands),
                },
            )

        # Additional strict mode checks
        if self.strict_mode:
            # Check for suspicious patterns even in allowed commands
            suspicious_args = [
                r"--help\s*;",  # Help followed by semicolon
                r"-[a-z]+\s*&&",  # Flag followed by &&
                r">\s*/",  # Redirect to root
                r"<\s*/etc",  # Read from /etc
            ]
            for pattern in suspicious_args:
                if re.search(pattern, value, re.IGNORECASE):
                    return ValidationResult.failure(
                        "Suspicious argument pattern detected",
                        severity=Severity.CRITICAL,
                        details={"pattern": pattern},
                    )

        return ValidationResult.success(value)

    def _extract_base_command(self, command: str) -> str | None:
        """Extract the base command name from a command string.

        Args:
            command: Full command string

        Returns:
            Base command name or None if parsing fails
        """
        try:
            # Use shlex for safe parsing
            parts = shlex.split(command)
            if not parts:
                return None
            # Get the command name (may be a path)
            cmd = parts[0]
            # Extract just the command name from path
            if "/" in cmd:
                cmd = cmd.rsplit("/", 1)[-1]
            return cmd
        except ValueError:
            # shlex.split failed, try simple split
            parts = command.strip().split()
            if not parts:
                return None
            cmd = parts[0]
            if "/" in cmd:
                cmd = cmd.rsplit("/", 1)[-1]
            return cmd

    def get_validation_rules(self) -> dict[str, Any]:
        """Return validation rules for documentation/audit.

        Returns:
            Dictionary describing the validation rules
        """
        return {
            "type": "command",
            "max_length": self.max_length,
            "strict_mode": self.strict_mode,
            "allowed_commands": sorted(self.allowed_commands),
            "blocked_patterns": [
                "Shell metacharacters (; & | ` $)",
                "Command substitution ($() and ``)",
                "Pipe and redirect operators",
                "Dangerous functions (eval, exec, system)",
            ],
        }


def validate_command_safe(
    command: str,
    allowed_commands: set[str] | None = None,
    raise_on_injection: bool = True,
) -> str:
    """Convenience function for quick command validation.

    Args:
        command: Command string to validate
        allowed_commands: Set of allowed commands (default: verification commands)
        raise_on_injection: Raise exception on injection (default True)

    Returns:
        The original command if safe

    Raises:
        CommandInjectionError: If injection detected and raise_on_injection is True
    """
    validator = CommandValidator(allowed_commands=allowed_commands)
    result = validator.validate(command)

    if not result.is_valid:
        if raise_on_injection and result.severity == Severity.CRITICAL:
            raise CommandInjectionError(result.error_message or "Command injection detected")
        # Commands can't be sanitized safely - fail closed
        raise CommandInjectionError(result.error_message or "Invalid command")

    return command
