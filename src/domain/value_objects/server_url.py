"""Server URL value object."""

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ServerURL:
    """Value object representing an MCP server URL.

    Enforces valid URL format for MCP servers.

    Attributes:
        value: The URL string

    Raises:
        ValueError: If the URL is invalid
    """

    value: str

    def __post_init__(self):
        """Validate URL after initialization."""
        if not self.value or not self.value.strip():
            raise ValueError("Server URL cannot be empty")

        # Parse URL to validate format
        try:
            parsed = urlparse(self.value)
            if not parsed.scheme:
                raise ValueError("URL must include a scheme (http, https, etc.)")
            if not parsed.netloc and not parsed.path:
                raise ValueError("URL must include a host or path")
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}") from e

    def __str__(self) -> str:
        """Return string representation."""
        return self.value

    def __repr__(self) -> str:
        """Return repr representation."""
        return f"ServerURL('{self.value}')"

    @property
    def scheme(self) -> str:
        """Get URL scheme (http, https, etc.)."""
        return urlparse(self.value).scheme

    @property
    def host(self) -> str:
        """Get URL host."""
        return urlparse(self.value).netloc

    @property
    def path(self) -> str:
        """Get URL path."""
        return urlparse(self.value).path
