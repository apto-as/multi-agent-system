"""Compatibility Checker for MCP Server integration.

Validates version compatibility before server connection:
- Pre-connection validation
- Deprecation warnings
- Migration path suggestions

Phase 4.2: MCP Server Versioning (#46)

Example:
    >>> checker = CompatibilityChecker()
    >>> result = checker.check_server("tmws", "2.4.16", "2.4.0")
    >>> result.is_compatible
    True
    >>> result.warnings
    []
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Final

from src.infrastructure.mcp.version_resolver import (
    CompatibilityLevel,
    SemanticVersion,
    VersionResolver,
)
from src.models.registry import ServerRegistryEntry

logger = logging.getLogger(__name__)

# Maximum version age before warning (minor versions)
MAX_MINOR_VERSION_LAG: Final[int] = 3
# Maximum version age before error (major versions)
MAX_MAJOR_VERSION_LAG: Final[int] = 1


class CheckSeverity(str, Enum):
    """Severity level for compatibility checks."""

    INFO = "info"  # Informational only
    WARNING = "warning"  # Non-blocking issue
    ERROR = "error"  # Blocking issue
    CRITICAL = "critical"  # Security or stability risk


@dataclass
class CompatibilityIssue:
    """Single compatibility issue found during check.

    Attributes:
        severity: Issue severity level
        code: Machine-readable issue code
        message: Human-readable description
        suggestion: Optional remediation suggestion
    """

    severity: CheckSeverity
    code: str
    message: str
    suggestion: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
            "suggestion": self.suggestion,
        }


@dataclass
class CompatibilityResult:
    """Result of compatibility check.

    Attributes:
        server_id: Server identifier
        server_version: Server's reported version
        client_version: Client's required version
        is_compatible: Whether versions are compatible
        compatibility_level: Level of compatibility
        issues: List of issues found
    """

    server_id: str
    server_version: SemanticVersion
    client_version: SemanticVersion
    is_compatible: bool
    compatibility_level: CompatibilityLevel
    issues: list[CompatibilityIssue] = field(default_factory=list)

    @property
    def has_warnings(self) -> bool:
        """Check if result has any warnings."""
        return any(i.severity == CheckSeverity.WARNING for i in self.issues)

    @property
    def has_errors(self) -> bool:
        """Check if result has any errors."""
        return any(i.severity in (CheckSeverity.ERROR, CheckSeverity.CRITICAL) for i in self.issues)

    @property
    def warnings(self) -> list[str]:
        """Get warning messages."""
        return [i.message for i in self.issues if i.severity == CheckSeverity.WARNING]

    @property
    def errors(self) -> list[str]:
        """Get error messages."""
        return [
            i.message
            for i in self.issues
            if i.severity in (CheckSeverity.ERROR, CheckSeverity.CRITICAL)
        ]

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "server_id": self.server_id,
            "server_version": str(self.server_version),
            "client_version": str(self.client_version),
            "is_compatible": self.is_compatible,
            "compatibility_level": self.compatibility_level.value,
            "issues": [i.to_dict() for i in self.issues],
        }


class CompatibilityChecker:
    """Validates MCP server version compatibility.

    Performs comprehensive compatibility checks including:
    - Version compatibility (SemVer rules)
    - Deprecation status
    - Version lag warnings
    - Security advisories (future)

    Example:
        >>> checker = CompatibilityChecker()
        >>> result = checker.check_server("tmws", "2.4.16", "2.4.0")
        >>> if not result.is_compatible:
        ...     logger.error(f"Incompatible: {result.errors}")
        >>> elif result.has_warnings:
        ...     logger.warning(f"Warnings: {result.warnings}")
    """

    def __init__(self, resolver: VersionResolver | None = None):
        """Initialize compatibility checker.

        Args:
            resolver: Optional version resolver instance
        """
        self._resolver = resolver or VersionResolver()

    def check_server(
        self,
        server_id: str,
        server_version: str | SemanticVersion,
        min_version: str | SemanticVersion,
        deprecated: bool = False,
        deprecation_message: str | None = None,
    ) -> CompatibilityResult:
        """Check compatibility for a server.

        Args:
            server_id: Server identifier
            server_version: Server's reported version
            min_version: Minimum required version
            deprecated: Whether server is deprecated
            deprecation_message: Optional deprecation message

        Returns:
            CompatibilityResult with check details
        """
        # Parse versions
        server_ver = (
            self._resolver.parse(server_version)
            if isinstance(server_version, str)
            else server_version
        )
        min_ver = self._resolver.parse(min_version) if isinstance(min_version, str) else min_version

        issues: list[CompatibilityIssue] = []

        # Check basic compatibility
        is_compatible = self._resolver.is_compatible(server_ver, min_ver)
        compat_level = self._resolver.get_compatibility_level(min_ver, server_ver)

        # Version incompatibility
        if not is_compatible:
            if server_ver.major < min_ver.major:
                issues.append(
                    CompatibilityIssue(
                        severity=CheckSeverity.ERROR,
                        code="VERSION_MAJOR_MISMATCH",
                        message=(
                            f"Server '{server_id}' version {server_ver} is incompatible. "
                            f"Minimum required: {min_ver}"
                        ),
                        suggestion=f"Upgrade server to version {min_ver.major}.x.x or higher",
                    )
                )
            elif server_ver.major > min_ver.major:
                issues.append(
                    CompatibilityIssue(
                        severity=CheckSeverity.WARNING,
                        code="VERSION_MAJOR_AHEAD",
                        message=(
                            f"Server '{server_id}' version {server_ver} is ahead of "
                            f"expected version {min_ver}. Compatibility not guaranteed."
                        ),
                        suggestion="Consider updating client to match server version",
                    )
                )
            else:
                issues.append(
                    CompatibilityIssue(
                        severity=CheckSeverity.ERROR,
                        code="VERSION_TOO_OLD",
                        message=(
                            f"Server '{server_id}' version {server_ver} is below "
                            f"minimum required {min_ver}"
                        ),
                        suggestion=f"Upgrade server to version {min_ver} or higher",
                    )
                )

        # Deprecation check
        if deprecated:
            msg = deprecation_message or f"Server '{server_id}' is deprecated"
            issues.append(
                CompatibilityIssue(
                    severity=CheckSeverity.WARNING,
                    code="SERVER_DEPRECATED",
                    message=msg,
                    suggestion="Consider migrating to recommended alternative",
                )
            )

        # Version lag check
        if is_compatible:
            minor_lag = server_ver.minor - min_ver.minor
            if server_ver.major == min_ver.major and minor_lag >= MAX_MINOR_VERSION_LAG:
                issues.append(
                    CompatibilityIssue(
                        severity=CheckSeverity.INFO,
                        code="VERSION_LAG",
                        message=(
                            f"Server '{server_id}' is {minor_lag} minor versions ahead. "
                            "Consider updating minimum version requirement."
                        ),
                        suggestion=f"Update min_compatible_version to {server_ver.major}.{server_ver.minor - 1}.0",
                    )
                )

        # Prerelease warning
        if server_ver.is_prerelease():
            issues.append(
                CompatibilityIssue(
                    severity=CheckSeverity.WARNING,
                    code="PRERELEASE_VERSION",
                    message=(
                        f"Server '{server_id}' is running prerelease version {server_ver}. "
                        "Stability not guaranteed."
                    ),
                    suggestion="Use stable release for production environments",
                )
            )

        return CompatibilityResult(
            server_id=server_id,
            server_version=server_ver,
            client_version=min_ver,
            is_compatible=is_compatible,
            compatibility_level=compat_level,
            issues=issues,
        )

    def check_registry_entry(
        self,
        entry: ServerRegistryEntry,
        client_version: str | SemanticVersion,
    ) -> CompatibilityResult:
        """Check compatibility using registry entry.

        Args:
            entry: Server registry entry
            client_version: Client's version

        Returns:
            CompatibilityResult with check details
        """
        return self.check_server(
            server_id=entry.server_id,
            server_version=entry.version,
            min_version=client_version,
            deprecated=entry.deprecated,
            deprecation_message=entry.deprecation_message,
        )

    def check_multiple(
        self,
        servers: list[tuple[str, str, str]],
    ) -> dict[str, CompatibilityResult]:
        """Check compatibility for multiple servers.

        Args:
            servers: List of (server_id, server_version, min_version) tuples

        Returns:
            Dict mapping server_id to CompatibilityResult
        """
        results = {}
        for server_id, server_version, min_version in servers:
            results[server_id] = self.check_server(
                server_id=server_id,
                server_version=server_version,
                min_version=min_version,
            )
        return results

    def validate_upgrade_path(
        self,
        current_version: str | SemanticVersion,
        target_version: str | SemanticVersion,
    ) -> list[CompatibilityIssue]:
        """Validate if upgrade path is safe.

        Args:
            current_version: Current installed version
            target_version: Target version to upgrade to

        Returns:
            List of issues with upgrade path
        """
        current = (
            self._resolver.parse(current_version)
            if isinstance(current_version, str)
            else current_version
        )
        target = (
            self._resolver.parse(target_version)
            if isinstance(target_version, str)
            else target_version
        )

        issues: list[CompatibilityIssue] = []

        # Downgrade detection
        if self._resolver.compare(current, target) > 0:
            issues.append(
                CompatibilityIssue(
                    severity=CheckSeverity.WARNING,
                    code="DOWNGRADE_DETECTED",
                    message=f"Downgrading from {current} to {target}. Data loss possible.",
                    suggestion="Ensure backup before downgrading",
                )
            )

        # Major version jump
        major_diff = abs(target.major - current.major)
        if major_diff > MAX_MAJOR_VERSION_LAG:
            issues.append(
                CompatibilityIssue(
                    severity=CheckSeverity.WARNING,
                    code="LARGE_VERSION_JUMP",
                    message=(
                        f"Large version jump detected: {current} -> {target}. "
                        "Consider incremental upgrades."
                    ),
                    suggestion="Upgrade through intermediate major versions",
                )
            )

        # Prerelease to stable
        if current.is_prerelease() and target.is_stable():
            issues.append(
                CompatibilityIssue(
                    severity=CheckSeverity.INFO,
                    code="PRERELEASE_TO_STABLE",
                    message=f"Upgrading from prerelease {current} to stable {target}",
                    suggestion=None,
                )
            )

        # Stable to prerelease
        if current.is_stable() and target.is_prerelease():
            issues.append(
                CompatibilityIssue(
                    severity=CheckSeverity.WARNING,
                    code="STABLE_TO_PRERELEASE",
                    message=(
                        f"Upgrading from stable {current} to prerelease {target}. "
                        "Not recommended for production."
                    ),
                    suggestion="Wait for stable release",
                )
            )

        return issues


# Module-level singleton
_checker = CompatibilityChecker()


def check_server_compatibility(
    server_id: str,
    server_version: str,
    min_version: str,
) -> CompatibilityResult:
    """Check server compatibility (module-level convenience function)."""
    return _checker.check_server(server_id, server_version, min_version)
