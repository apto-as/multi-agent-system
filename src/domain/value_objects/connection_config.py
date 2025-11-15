"""ConnectionConfig value object for MCP Integration.

ConnectionConfig is an immutable value object that represents
the configuration for an MCP server connection.

As a value object:
- It is immutable (frozen=True)
- Equality is based on values, not identity
- It can be freely copied and passed around
- It validates itself on construction

Author: Athena (TDD) + Hera (DDD)
Created: 2025-11-12 (Phase 1-1: Day 1)
"""

from dataclasses import dataclass
from urllib.parse import urlparse

from src.domain.exceptions import InvalidConnectionError


@dataclass(frozen=True)
class ConnectionConfig:
    """Immutable configuration for MCP server connection.

    This value object encapsulates all configuration needed to establish
    and maintain a connection to an MCP server.

    Attributes:
        server_name: Unique identifier for the MCP server
        url: HTTP/HTTPS URL of the MCP server
        timeout: Connection timeout in seconds (must be positive)
        retry_attempts: Number of retry attempts on failure (must be non-negative)
        auth_required: Whether authentication is required
        api_key: Optional API key for authentication (should be kept secure)

    Raises:
        InvalidConnectionError: If any validation fails

    Example:
        >>> config = ConnectionConfig(
        ...     server_name="production_mcp",
        ...     url="https://mcp.example.com",
        ...     timeout=30,
        ...     retry_attempts=3
        ... )
        >>> config.server_name
        'production_mcp'
        >>> config.timeout
        30
    """

    server_name: str
    url: str
    timeout: int = 30
    retry_attempts: int = 3
    auth_required: bool = False
    api_key: str | None = None

    def __post_init__(self):
        """Validate configuration after initialization.

        This method is called automatically by dataclass after __init__.
        Since the object is frozen, we use object.__setattr__ for validation errors.
        """
        # Validate server_name
        if not self.server_name or not self.server_name.strip():
            raise InvalidConnectionError(
                field="server_name",
                value=self.server_name,
                reason="Server name cannot be empty",
            )

        # Validate URL format
        self._validate_url()

        # Validate timeout
        if self.timeout <= 0:
            raise InvalidConnectionError(
                field="timeout",
                value=str(self.timeout),
                reason="Timeout must be positive",
            )

        # Validate retry_attempts
        if self.retry_attempts < 0:
            raise InvalidConnectionError(
                field="retry_attempts",
                value=str(self.retry_attempts),
                reason="Retry attempts must be non-negative",
            )

        # Validate auth configuration
        if self.auth_required and not self.api_key:
            raise InvalidConnectionError(
                field="api_key",
                value=None,
                reason="API key is required when auth_required is True",
            )

    def _validate_url(self):
        """Validate URL format.

        Raises:
            InvalidConnectionError: If URL is invalid
        """
        try:
            parsed = urlparse(self.url)

            # Must have scheme (http or https)
            if parsed.scheme not in ("http", "https"):
                raise InvalidConnectionError(
                    field="url",
                    value=self.url,
                    reason=f"Invalid URL scheme: {parsed.scheme}. Must be http or https",
                )

            # Must have netloc (hostname)
            if not parsed.netloc:
                raise InvalidConnectionError(
                    field="url", value=self.url, reason="Invalid URL format: missing hostname"
                )

        except ValueError as e:
            raise InvalidConnectionError(
                field="url", value=self.url, reason=f"Invalid URL format: {e}"
            ) from e

    def __repr__(self) -> str:
        """String representation that doesn't expose API key.

        Security: API key is masked in repr to prevent accidental logging.
        """
        api_key_repr = "***" if self.api_key else None
        return (
            f"ConnectionConfig("
            f"server_name='{self.server_name}', "
            f"url='{self.url}', "
            f"timeout={self.timeout}, "
            f"retry_attempts={self.retry_attempts}, "
            f"auth_required={self.auth_required}, "
            f"api_key={api_key_repr}"
            f")"
        )

    def __str__(self) -> str:
        """User-friendly string representation.

        Security: API key is not included in str representation.
        """
        return f"MCP Connection to {self.server_name} ({self.url})"
