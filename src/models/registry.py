"""Registry data models for sparse MCP server/tool metadata.

Designed for minimal memory footprint:
- ServerRegistryEntry: ~100 bytes
- ToolRegistryEntry: ~50 bytes
- Enables O(1) lookup without loading full schemas

Security Notes:
- Server IDs and tool IDs are validated against injection attacks
- Commands are restricted to an allowlist
- Environment variables are sanitized
- JSON size is limited to prevent DoS

Security Review: Hestia (2025-12-09) - CRITICAL fixes applied
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Final

# Security: Maximum registry size to prevent DoS
MAX_REGISTRY_SIZE_MB: Final[int] = 10

# Security: Allowlisted commands for server spawning
ALLOWED_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "python",
        "python3",
        "node",
        "npx",
        "uvx",
        "uv",
        "deno",
        "bun",
        "cargo",
        "go",
    }
)

# Security: Forbidden environment variables that could enable code injection
FORBIDDEN_ENV_VARS: Final[frozenset[str]] = frozenset(
    {
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "LD_LIBRARY_PATH",
        "PYTHONPATH",
        "NODE_PATH",
        "PYTHONSTARTUP",
    }
)

# Security: Patterns for valid IDs
SERVER_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
TOOL_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_-]+::[a-zA-Z0-9_-]+$")


class RegistrySecurityError(Exception):
    """Raised when registry security validation fails."""

    pass


def validate_server_id(server_id: str) -> str:
    """Validate server ID format.

    Args:
        server_id: Server identifier to validate

    Returns:
        Validated server ID

    Raises:
        RegistrySecurityError: If server_id is invalid
    """
    if not server_id:
        raise RegistrySecurityError("Server ID cannot be empty")
    if not SERVER_ID_PATTERN.match(server_id):
        raise RegistrySecurityError(
            f"Invalid server_id format: '{server_id}'. "
            "Must be alphanumeric with hyphens/underscores, 1-64 chars"
        )
    return server_id


def validate_tool_id(tool_id: str) -> str:
    """Validate tool ID format.

    Args:
        tool_id: Tool identifier to validate (format: server_id::tool_name)

    Returns:
        Validated tool ID

    Raises:
        RegistrySecurityError: If tool_id is invalid
    """
    if not tool_id:
        raise RegistrySecurityError("Tool ID cannot be empty")
    if not TOOL_ID_PATTERN.match(tool_id):
        raise RegistrySecurityError(
            f"Invalid tool_id format: '{tool_id}'. "
            "Must be 'server_id::tool_name' with alphanumeric chars"
        )
    return tool_id


def validate_server_command(command: str, args: list[str], env: dict[str, str] | None) -> None:
    """Validate server command for security.

    Args:
        command: Command to spawn server
        args: Command arguments
        env: Environment variables

    Raises:
        RegistrySecurityError: If command/args/env contain unsafe values
    """
    # Validate command against allowlist
    cmd_name = command.split("/")[-1]  # Handle full paths like /usr/bin/python
    if cmd_name not in ALLOWED_COMMANDS:
        raise RegistrySecurityError(
            f"Command not allowed: '{command}'. Allowed: {sorted(ALLOWED_COMMANDS)}"
        )

    # Validate args don't contain shell metacharacters
    dangerous_chars = {";", "|", "&", "`", "$", "(", ")", "\n", "\r", "\x00"}
    for arg in args:
        if any(c in arg for c in dangerous_chars):
            raise RegistrySecurityError(f"Dangerous characters in args: '{arg}'")

    # Validate environment variables
    if env:
        for key in env:
            if key.upper() in FORBIDDEN_ENV_VARS:
                raise RegistrySecurityError(f"Forbidden environment variable: '{key}'")


class ToolCategory(str, Enum):
    """Tool/Server category for classification and filtering."""

    MEMORY = "memory"
    SEARCH = "search"
    BROWSER = "browser"
    CODE = "code"
    FILE = "file"
    DATA = "data"
    OTHER = "other"


@dataclass
class ToolRegistryEntry:
    """Minimal metadata for a single MCP tool.

    Size target: ~50 bytes
    - tool_id: ~20 bytes
    - name: ~15 bytes
    - server_id: ~10 bytes
    - category: ~10 bytes
    - description: ~100 chars (truncated)
    - keywords: ~5 keywords
    """

    tool_id: str  # Format: "server_id::tool_name"
    name: str
    server_id: str
    category: ToolCategory
    description: str  # Truncated to ~100 chars for memory efficiency
    keywords: list[str] = field(default_factory=list)  # For semantic search

    def matches_query(self, query: str) -> bool:
        """Check if tool matches search query (case-insensitive)."""
        query_lower = query.lower()
        return (
            query_lower in self.name.lower()
            or query_lower in self.description.lower()
            or any(query_lower in kw.lower() for kw in self.keywords)
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "server_id": self.server_id,
            "category": self.category.value,
            "description": self.description,
            "keywords": self.keywords,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolRegistryEntry":
        """Create from JSON dict with security validation.

        Args:
            data: Dictionary with tool data

        Returns:
            ToolRegistryEntry instance

        Raises:
            RegistrySecurityError: If IDs are invalid
        """
        # Security: Validate IDs
        tool_id = validate_tool_id(data["tool_id"])
        server_id = validate_server_id(data["server_id"])

        return cls(
            tool_id=tool_id,
            name=data["name"],
            server_id=server_id,
            category=ToolCategory(data["category"]),
            description=data["description"],
            keywords=data.get("keywords", []),
        )


@dataclass
class ServerRegistryEntry:
    """Minimal metadata for an MCP server.

    Size target: ~120 bytes (extended for versioning)
    - server_id: ~10 bytes
    - name: ~20 bytes
    - command: ~30 bytes
    - args: ~20 bytes (serialized)
    - env: ~20 bytes (serialized, optional)
    - Counters/scores: ~20 bytes
    - Version info: ~20 bytes (Phase 4.2)
    """

    server_id: str
    name: str
    command: str  # For spawning (e.g., "python")
    args: list[str]  # For spawning (e.g., ["-m", "tmws.server"])
    env: dict[str, str] | None = None
    tool_count: int = 0
    category: ToolCategory = ToolCategory.OTHER
    popularity_score: float = 0.0  # 0.0 - 1.0, updated on tool usage
    last_connected: datetime | None = None
    estimated_memory_mb: int = 50  # Estimated memory usage when loaded
    cold_start_ms: int = 100  # Estimated cold start time
    # Phase 4.2: Version Management
    version: str = "1.0.0"  # Semantic version (MAJOR.MINOR.PATCH)
    min_compatible_version: str = "1.0.0"  # Minimum compatible client version
    deprecated: bool = False  # Whether server is deprecated
    deprecation_message: str | None = None  # Message if deprecated

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "server_id": self.server_id,
            "name": self.name,
            "command": self.command,
            "args": self.args,
            "env": self.env,
            "tool_count": self.tool_count,
            "category": self.category.value,
            "popularity_score": self.popularity_score,
            "last_connected": (self.last_connected.isoformat() if self.last_connected else None),
            "estimated_memory_mb": self.estimated_memory_mb,
            "cold_start_ms": self.cold_start_ms,
            # Phase 4.2: Version Management
            "version": self.version,
            "min_compatible_version": self.min_compatible_version,
            "deprecated": self.deprecated,
            "deprecation_message": self.deprecation_message,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServerRegistryEntry":
        """Create from JSON dict with security validation.

        Args:
            data: Dictionary with server data

        Returns:
            ServerRegistryEntry instance

        Raises:
            RegistrySecurityError: If server_id, command, args, or env are invalid
        """
        # Security: Validate server_id
        server_id = validate_server_id(data["server_id"])

        # Security: Validate command, args, env
        command = data["command"]
        args = data["args"]
        env = data.get("env")
        validate_server_command(command, args, env)

        last_connected_str = data.get("last_connected")
        last_connected = datetime.fromisoformat(last_connected_str) if last_connected_str else None

        return cls(
            server_id=server_id,
            name=data["name"],
            command=command,
            args=args,
            env=env,
            tool_count=data.get("tool_count", 0),
            category=ToolCategory(data.get("category", "other")),
            popularity_score=data.get("popularity_score", 0.0),
            last_connected=last_connected,
            estimated_memory_mb=data.get("estimated_memory_mb", 50),
            cold_start_ms=data.get("cold_start_ms", 100),
            # Phase 4.2: Version Management
            version=data.get("version", "1.0.0"),
            min_compatible_version=data.get("min_compatible_version", "1.0.0"),
            deprecated=data.get("deprecated", False),
            deprecation_message=data.get("deprecation_message"),
        )


@dataclass
class RegistryMetadata:
    """Metadata about the entire registry.

    Stored at top level of registry JSON for quick stats.
    """

    version: str  # Schema version (e.g., "1.0.0")
    created_at: datetime
    server_count: int
    tool_count: int
    total_size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "server_count": self.server_count,
            "tool_count": self.tool_count,
            "total_size_bytes": self.total_size_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegistryMetadata":
        """Create from JSON dict."""
        return cls(
            version=data["version"],
            created_at=datetime.fromisoformat(data["created_at"]),
            server_count=data["server_count"],
            tool_count=data["tool_count"],
            total_size_bytes=data["total_size_bytes"],
        )


@dataclass
class SparseRegistry:
    """Complete sparse registry structure.

    This is the top-level object serialized to JSON.
    """

    metadata: RegistryMetadata
    servers: dict[str, ServerRegistryEntry]  # server_id -> entry
    tools: dict[str, ToolRegistryEntry]  # tool_id -> entry
    tool_by_server: dict[str, list[str]]  # server_id -> [tool_ids]

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "metadata": self.metadata.to_dict(),
            "servers": {sid: entry.to_dict() for sid, entry in self.servers.items()},
            "tools": {tid: entry.to_dict() for tid, entry in self.tools.items()},
            "tool_by_server": self.tool_by_server,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SparseRegistry":
        """Create from JSON dict."""
        return cls(
            metadata=RegistryMetadata.from_dict(data["metadata"]),
            servers={
                sid: ServerRegistryEntry.from_dict(entry) for sid, entry in data["servers"].items()
            },
            tools={tid: ToolRegistryEntry.from_dict(entry) for tid, entry in data["tools"].items()},
            tool_by_server=data["tool_by_server"],
        )

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> "SparseRegistry":
        """Deserialize from JSON string.

        Args:
            json_str: JSON string to deserialize

        Returns:
            SparseRegistry instance

        Raises:
            RegistrySecurityError: If JSON exceeds size limit
        """
        # Security: Limit JSON size to prevent DoS
        size_mb = len(json_str.encode("utf-8")) / (1024 * 1024)
        if size_mb > MAX_REGISTRY_SIZE_MB:
            raise RegistrySecurityError(
                f"Registry JSON too large: {size_mb:.2f}MB > {MAX_REGISTRY_SIZE_MB}MB"
            )

        data = json.loads(json_str)
        return cls.from_dict(data)
