"""
Memory scope definitions for hybrid cloud-local architecture.
"""

from enum import Enum


class MemoryScope(str, Enum):
    """Memory storage scope classification."""

    GLOBAL = "global"  # Cloud: Universal knowledge across all projects
    SHARED = "shared"  # Cloud: Team/organization shared knowledge
    PROJECT = "project"  # Local: Project-specific implementation details
    PRIVATE = "private"  # Local: Confidential/sensitive information (never cloud)

    def is_cloud(self) -> bool:
        """Check if this scope should be stored in cloud."""
        return self in (MemoryScope.GLOBAL, MemoryScope.SHARED)

    def is_local(self) -> bool:
        """Check if this scope should be stored locally."""
        return self in (MemoryScope.PROJECT, MemoryScope.PRIVATE)

    def requires_encryption(self) -> bool:
        """Check if this scope requires E2EE."""
        return self in (MemoryScope.SHARED, MemoryScope.PRIVATE)

    @classmethod
    def get_default(cls) -> "MemoryScope":
        """Get default scope (most restrictive)."""
        return cls.PROJECT

    def __str__(self) -> str:
        return self.value


class StorageLocation(str, Enum):
    """Physical storage location."""

    CLOUD = "cloud"
    LOCAL = "local"
    BOTH = "both"  # Synced to both locations


def get_storage_location(scope: MemoryScope) -> StorageLocation:
    """Determine storage location based on scope."""
    if scope == MemoryScope.GLOBAL or scope == MemoryScope.SHARED:
        return StorageLocation.CLOUD
    elif scope == MemoryScope.PROJECT or scope == MemoryScope.PRIVATE:
        return StorageLocation.LOCAL
    else:
        # Default to local for unknown scopes (security first)
        return StorageLocation.LOCAL
