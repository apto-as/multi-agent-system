"""Server name value object."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ServerName:
    """Value object representing an MCP server name.

    Enforces naming conventions for MCP servers.

    Attributes:
        value: The server name string

    Raises:
        ValueError: If the server name is invalid
    """

    value: str

    def __post_init__(self):
        """Validate server name after initialization."""
        if not self.value or not self.value.strip():
            raise ValueError("Server name cannot be empty")

        if len(self.value) > 255:
            raise ValueError("Server name cannot exceed 255 characters")

        # Allow alphanumeric, hyphens, underscores, and dots
        import re

        if not re.match(r"^[a-zA-Z0-9_.-]+$", self.value):
            raise ValueError(
                "Server name can only contain alphanumeric characters, "
                "hyphens, underscores, and dots"
            )

    def __str__(self) -> str:
        """Return string representation."""
        return self.value

    def __repr__(self) -> str:
        """Return repr representation."""
        return f"ServerName('{self.value}')"
