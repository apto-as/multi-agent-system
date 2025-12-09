"""Version Resolver for MCP Server versioning.

Provides semantic versioning support for MCP servers:
- Version parsing and comparison (SemVer 2.0.0)
- Version range resolution
- Compatibility checking between server versions

Phase 4.2: MCP Server Versioning (#46)

Example:
    >>> resolver = VersionResolver()
    >>> resolver.parse("2.1.0")
    SemanticVersion(major=2, minor=1, patch=0)
    >>> resolver.is_compatible("2.1.0", "2.0.0")
    True
    >>> resolver.compare("2.1.0", "2.0.0")
    1  # 2.1.0 > 2.0.0
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Final

logger = logging.getLogger(__name__)

# SemVer regex pattern (strict)
SEMVER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

# Simplified pattern for common cases
SIMPLE_VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?$"
)


class VersionParseError(Exception):
    """Raised when version string cannot be parsed."""

    pass


class CompatibilityLevel(str, Enum):
    """Compatibility level between versions."""

    COMPATIBLE = "compatible"  # Full compatibility
    MINOR_UPDATE = "minor_update"  # New features, backward compatible
    MAJOR_UPDATE = "major_update"  # Breaking changes possible
    INCOMPATIBLE = "incompatible"  # Not compatible


@dataclass(frozen=True, order=True)
class SemanticVersion:
    """Semantic version representation (SemVer 2.0.0).

    Attributes:
        major: Major version (breaking changes)
        minor: Minor version (new features, backward compatible)
        patch: Patch version (bug fixes)
        prerelease: Optional prerelease tag (e.g., "alpha", "beta.1")
        build_metadata: Optional build metadata (ignored in comparison)
    """

    major: int
    minor: int
    patch: int
    prerelease: str | None = None
    build_metadata: str | None = None

    def __str__(self) -> str:
        """Format as SemVer string."""
        version = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            version += f"-{self.prerelease}"
        if self.build_metadata:
            version += f"+{self.build_metadata}"
        return version

    def is_prerelease(self) -> bool:
        """Check if this is a prerelease version."""
        return self.prerelease is not None

    def is_stable(self) -> bool:
        """Check if this is a stable release (major >= 1, no prerelease)."""
        return self.major >= 1 and not self.is_prerelease()

    def next_major(self) -> "SemanticVersion":
        """Return next major version."""
        return SemanticVersion(self.major + 1, 0, 0)

    def next_minor(self) -> "SemanticVersion":
        """Return next minor version."""
        return SemanticVersion(self.major, self.minor + 1, 0)

    def next_patch(self) -> "SemanticVersion":
        """Return next patch version."""
        return SemanticVersion(self.major, self.minor, self.patch + 1)


class VersionResolver:
    """Resolves and compares semantic versions.

    Thread-safe, stateless resolver for version operations.

    Example:
        >>> resolver = VersionResolver()
        >>> v1 = resolver.parse("2.1.0")
        >>> v2 = resolver.parse("2.0.0")
        >>> resolver.compare(v1, v2)
        1
        >>> resolver.is_compatible("2.1.0", "2.0.0")
        True
    """

    def parse(self, version_str: str) -> SemanticVersion:
        """Parse version string into SemanticVersion.

        Supports both strict SemVer and simplified formats:
        - "2.1.0" -> SemanticVersion(2, 1, 0)
        - "2.1" -> SemanticVersion(2, 1, 0)
        - "2.1.0-beta.1" -> SemanticVersion(2, 1, 0, prerelease="beta.1")
        - "2.1.0+build.123" -> SemanticVersion(2, 1, 0, build_metadata="build.123")

        Args:
            version_str: Version string to parse

        Returns:
            Parsed SemanticVersion

        Raises:
            VersionParseError: If version string is invalid
        """
        if not version_str:
            raise VersionParseError("Version string cannot be empty")

        version_str = version_str.strip()

        # Try strict SemVer first
        match = SEMVER_PATTERN.match(version_str)
        if match:
            return SemanticVersion(
                major=int(match.group("major")),
                minor=int(match.group("minor")),
                patch=int(match.group("patch")),
                prerelease=match.group("prerelease"),
                build_metadata=match.group("buildmetadata"),
            )

        # Try simplified format (e.g., "2.1" without patch)
        simple_match = SIMPLE_VERSION_PATTERN.match(version_str)
        if simple_match:
            patch = simple_match.group("patch")
            return SemanticVersion(
                major=int(simple_match.group("major")),
                minor=int(simple_match.group("minor")),
                patch=int(patch) if patch else 0,
            )

        raise VersionParseError(f"Invalid version format: '{version_str}'")

    def compare(self, v1: str | SemanticVersion, v2: str | SemanticVersion) -> int:
        """Compare two versions.

        Args:
            v1: First version
            v2: Second version

        Returns:
            -1 if v1 < v2
             0 if v1 == v2
             1 if v1 > v2
        """
        ver1 = self.parse(v1) if isinstance(v1, str) else v1
        ver2 = self.parse(v2) if isinstance(v2, str) else v2

        # Compare major.minor.patch
        for attr in ("major", "minor", "patch"):
            val1 = getattr(ver1, attr)
            val2 = getattr(ver2, attr)
            if val1 < val2:
                return -1
            if val1 > val2:
                return 1

        # Prerelease has lower precedence than normal version
        # e.g., 1.0.0-alpha < 1.0.0
        if ver1.prerelease and not ver2.prerelease:
            return -1
        if not ver1.prerelease and ver2.prerelease:
            return 1

        # Compare prerelease identifiers
        if ver1.prerelease and ver2.prerelease:
            return self._compare_prerelease(ver1.prerelease, ver2.prerelease)

        return 0

    def _compare_prerelease(self, pre1: str, pre2: str) -> int:
        """Compare prerelease identifiers.

        Rules (per SemVer spec):
        - Numeric identifiers compared as integers
        - Alphanumeric identifiers compared lexically
        - Numeric < Alphanumeric
        - More identifiers > fewer identifiers (if all equal)
        """
        ids1 = pre1.split(".")
        ids2 = pre2.split(".")

        for i in range(max(len(ids1), len(ids2))):
            if i >= len(ids1):
                return -1  # Fewer identifiers = lower precedence
            if i >= len(ids2):
                return 1

            id1, id2 = ids1[i], ids2[i]

            # Check if numeric
            is_num1 = id1.isdigit()
            is_num2 = id2.isdigit()

            if is_num1 and is_num2:
                # Both numeric: compare as integers
                n1, n2 = int(id1), int(id2)
                if n1 < n2:
                    return -1
                if n1 > n2:
                    return 1
            elif is_num1:
                return -1  # Numeric < Alphanumeric
            elif is_num2:
                return 1
            else:
                # Both alphanumeric: lexical comparison
                if id1 < id2:
                    return -1
                if id1 > id2:
                    return 1

        return 0

    def is_compatible(
        self,
        server_version: str | SemanticVersion,
        min_version: str | SemanticVersion,
    ) -> bool:
        """Check if server version is compatible with minimum required version.

        A server version is compatible if:
        - Same major version AND
        - Minor version >= minimum minor AND
        - (If same minor) Patch version >= minimum patch

        Args:
            server_version: Current server version
            min_version: Minimum required version

        Returns:
            True if compatible, False otherwise
        """
        server = self.parse(server_version) if isinstance(server_version, str) else server_version
        minimum = self.parse(min_version) if isinstance(min_version, str) else min_version

        # Major version must match for compatibility
        if server.major != minimum.major:
            return False

        # Compare minor.patch
        return self.compare(server, minimum) >= 0

    def get_compatibility_level(
        self,
        current: str | SemanticVersion,
        target: str | SemanticVersion,
    ) -> CompatibilityLevel:
        """Determine compatibility level between two versions.

        Args:
            current: Current version
            target: Target version to upgrade/downgrade to

        Returns:
            CompatibilityLevel indicating upgrade type
        """
        cur = self.parse(current) if isinstance(current, str) else current
        tgt = self.parse(target) if isinstance(target, str) else target

        # Same version
        if self.compare(cur, tgt) == 0:
            return CompatibilityLevel.COMPATIBLE

        # Different major version = potential breaking changes
        if cur.major != tgt.major:
            return CompatibilityLevel.MAJOR_UPDATE

        # Same major, different minor = new features
        if cur.minor != tgt.minor:
            return CompatibilityLevel.MINOR_UPDATE

        # Same major.minor, different patch = bug fixes
        return CompatibilityLevel.COMPATIBLE

    def satisfies_range(
        self,
        version: str | SemanticVersion,
        range_spec: str,
    ) -> bool:
        """Check if version satisfies a version range specification.

        Supports common range formats:
        - ">=1.0.0" - Greater than or equal
        - "<=2.0.0" - Less than or equal
        - ">1.0.0" - Greater than
        - "<2.0.0" - Less than
        - "^1.2.0" - Compatible with (same major, >= minor.patch)
        - "~1.2.0" - Approximately (same major.minor, >= patch)
        - "1.0.0 - 2.0.0" - Range (inclusive)
        - "1.x" or "1.*" - Wildcard (any 1.x.x)

        Args:
            version: Version to check
            range_spec: Range specification

        Returns:
            True if version satisfies range

        Raises:
            VersionParseError: If range_spec is invalid
        """
        ver = self.parse(version) if isinstance(version, str) else version
        range_spec = range_spec.strip()

        # Wildcard: "1.x", "1.*", "1.x.x"
        wildcard_match = re.match(r"^(\d+)\.(?:x|\*|x\.x|\*\.\*)$", range_spec)
        if wildcard_match:
            return ver.major == int(wildcard_match.group(1))

        # Range: "1.0.0 - 2.0.0"
        range_match = re.match(r"^(.+?)\s*-\s*(.+)$", range_spec)
        if range_match:
            min_ver = self.parse(range_match.group(1))
            max_ver = self.parse(range_match.group(2))
            return self.compare(ver, min_ver) >= 0 and self.compare(ver, max_ver) <= 0

        # Caret: "^1.2.0" - Compatible with (same major)
        if range_spec.startswith("^"):
            base = self.parse(range_spec[1:])
            return ver.major == base.major and self.compare(ver, base) >= 0

        # Tilde: "~1.2.0" - Approximately (same major.minor)
        if range_spec.startswith("~"):
            base = self.parse(range_spec[1:])
            return (
                ver.major == base.major and ver.minor == base.minor and self.compare(ver, base) >= 0
            )

        # Comparison operators
        for op, compare_result in [
            (">=", lambda r: r >= 0),
            ("<=", lambda r: r <= 0),
            (">", lambda r: r > 0),
            ("<", lambda r: r < 0),
            ("=", lambda r: r == 0),
        ]:
            if range_spec.startswith(op):
                target = self.parse(range_spec[len(op) :].strip())
                return compare_result(self.compare(ver, target))

        # Exact match
        target = self.parse(range_spec)
        return self.compare(ver, target) == 0

    def find_latest_compatible(
        self,
        available_versions: list[str | SemanticVersion],
        min_version: str | SemanticVersion,
    ) -> SemanticVersion | None:
        """Find the latest version compatible with minimum requirement.

        Args:
            available_versions: List of available versions
            min_version: Minimum required version

        Returns:
            Latest compatible version, or None if none found
        """
        minimum = self.parse(min_version) if isinstance(min_version, str) else min_version

        compatible = []
        for ver_str in available_versions:
            ver = self.parse(ver_str) if isinstance(ver_str, str) else ver_str
            if self.is_compatible(ver, minimum):
                compatible.append(ver)

        if not compatible:
            return None

        # Sort and return latest
        compatible.sort(reverse=True)
        return compatible[0]


# Module-level singleton for convenience
_resolver = VersionResolver()


def parse_version(version_str: str) -> SemanticVersion:
    """Parse version string (module-level convenience function)."""
    return _resolver.parse(version_str)


def compare_versions(v1: str, v2: str) -> int:
    """Compare two versions (module-level convenience function)."""
    return _resolver.compare(v1, v2)


def is_version_compatible(server_version: str, min_version: str) -> bool:
    """Check version compatibility (module-level convenience function)."""
    return _resolver.is_compatible(server_version, min_version)
