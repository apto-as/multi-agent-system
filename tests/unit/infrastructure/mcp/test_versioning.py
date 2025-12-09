"""Unit tests for MCP Server versioning (Phase 4.2 Issue #46).

Tests version parsing, comparison, compatibility checking, and
integration with the sparse registry.
"""

import pytest

from src.infrastructure.mcp.compatibility_checker import (
    CheckSeverity,
    CompatibilityChecker,
    CompatibilityIssue,
    CompatibilityResult,
    check_server_compatibility,
)
from src.infrastructure.mcp.version_resolver import (
    CompatibilityLevel,
    SemanticVersion,
    VersionParseError,
    VersionResolver,
    compare_versions,
    is_version_compatible,
    parse_version,
)
from src.models.registry import ServerRegistryEntry, ToolCategory


class TestSemanticVersion:
    """Test SemanticVersion dataclass."""

    def test_str_representation(self) -> None:
        """Test string representation of versions."""
        v = SemanticVersion(2, 1, 0)
        assert str(v) == "2.1.0"

        v_pre = SemanticVersion(2, 1, 0, prerelease="beta.1")
        assert str(v_pre) == "2.1.0-beta.1"

        v_build = SemanticVersion(2, 1, 0, build_metadata="build.123")
        assert str(v_build) == "2.1.0+build.123"

        v_full = SemanticVersion(2, 1, 0, prerelease="rc.1", build_metadata="git.abc123")
        assert str(v_full) == "2.1.0-rc.1+git.abc123"

    def test_is_prerelease(self) -> None:
        """Test prerelease detection."""
        assert not SemanticVersion(1, 0, 0).is_prerelease()
        assert SemanticVersion(1, 0, 0, prerelease="alpha").is_prerelease()

    def test_is_stable(self) -> None:
        """Test stable version detection."""
        assert SemanticVersion(1, 0, 0).is_stable()
        assert SemanticVersion(2, 5, 3).is_stable()
        assert not SemanticVersion(0, 9, 0).is_stable()  # Major < 1
        assert not SemanticVersion(1, 0, 0, prerelease="beta").is_stable()

    def test_next_versions(self) -> None:
        """Test next version generation."""
        v = SemanticVersion(1, 2, 3)
        assert v.next_major() == SemanticVersion(2, 0, 0)
        assert v.next_minor() == SemanticVersion(1, 3, 0)
        assert v.next_patch() == SemanticVersion(1, 2, 4)

    def test_ordering(self) -> None:
        """Test version ordering (frozen dataclass comparison)."""
        v1 = SemanticVersion(1, 0, 0)
        v2 = SemanticVersion(2, 0, 0)
        v3 = SemanticVersion(1, 1, 0)

        assert v1 < v2
        assert v1 < v3
        assert v3 < v2

        versions = [v2, v1, v3]
        assert sorted(versions) == [v1, v3, v2]


class TestVersionResolver:
    """Test VersionResolver class."""

    @pytest.fixture
    def resolver(self) -> VersionResolver:
        """Create resolver instance."""
        return VersionResolver()

    # --- Parsing Tests ---

    def test_parse_simple_version(self, resolver: VersionResolver) -> None:
        """Test parsing simple versions."""
        v = resolver.parse("2.1.0")
        assert v.major == 2
        assert v.minor == 1
        assert v.patch == 0
        assert v.prerelease is None
        assert v.build_metadata is None

    def test_parse_two_part_version(self, resolver: VersionResolver) -> None:
        """Test parsing two-part versions (major.minor)."""
        v = resolver.parse("2.1")
        assert v.major == 2
        assert v.minor == 1
        assert v.patch == 0

    def test_parse_prerelease(self, resolver: VersionResolver) -> None:
        """Test parsing prerelease versions."""
        v = resolver.parse("1.0.0-alpha")
        assert v.prerelease == "alpha"

        v2 = resolver.parse("1.0.0-beta.2")
        assert v2.prerelease == "beta.2"

        v3 = resolver.parse("1.0.0-rc.1.test")
        assert v3.prerelease == "rc.1.test"

    def test_parse_build_metadata(self, resolver: VersionResolver) -> None:
        """Test parsing build metadata."""
        v = resolver.parse("1.0.0+build.123")
        assert v.build_metadata == "build.123"

        v2 = resolver.parse("1.0.0-beta+git.abc123")
        assert v2.prerelease == "beta"
        assert v2.build_metadata == "git.abc123"

    def test_parse_invalid_version(self, resolver: VersionResolver) -> None:
        """Test parsing invalid versions raises error."""
        with pytest.raises(VersionParseError):
            resolver.parse("")

        with pytest.raises(VersionParseError):
            resolver.parse("invalid")

        with pytest.raises(VersionParseError):
            resolver.parse("1")

        with pytest.raises(VersionParseError):
            resolver.parse("1.2.3.4")

    def test_parse_whitespace_handling(self, resolver: VersionResolver) -> None:
        """Test whitespace is stripped."""
        v = resolver.parse("  2.1.0  ")
        assert v == SemanticVersion(2, 1, 0)

    # --- Comparison Tests ---

    def test_compare_equal(self, resolver: VersionResolver) -> None:
        """Test comparing equal versions."""
        assert resolver.compare("1.0.0", "1.0.0") == 0
        assert resolver.compare("2.5.3", "2.5.3") == 0

    def test_compare_major_diff(self, resolver: VersionResolver) -> None:
        """Test comparing versions with different major."""
        assert resolver.compare("2.0.0", "1.0.0") == 1
        assert resolver.compare("1.0.0", "2.0.0") == -1

    def test_compare_minor_diff(self, resolver: VersionResolver) -> None:
        """Test comparing versions with different minor."""
        assert resolver.compare("1.2.0", "1.1.0") == 1
        assert resolver.compare("1.1.0", "1.2.0") == -1

    def test_compare_patch_diff(self, resolver: VersionResolver) -> None:
        """Test comparing versions with different patch."""
        assert resolver.compare("1.0.2", "1.0.1") == 1
        assert resolver.compare("1.0.1", "1.0.2") == -1

    def test_compare_prerelease(self, resolver: VersionResolver) -> None:
        """Test prerelease has lower precedence than release."""
        # 1.0.0-alpha < 1.0.0
        assert resolver.compare("1.0.0-alpha", "1.0.0") == -1
        assert resolver.compare("1.0.0", "1.0.0-alpha") == 1

    def test_compare_prerelease_ordering(self, resolver: VersionResolver) -> None:
        """Test prerelease identifier ordering."""
        # alpha < beta < rc
        assert resolver.compare("1.0.0-alpha", "1.0.0-beta") == -1
        assert resolver.compare("1.0.0-beta", "1.0.0-rc") == -1

        # Numeric comparison
        assert resolver.compare("1.0.0-beta.1", "1.0.0-beta.2") == -1
        assert resolver.compare("1.0.0-beta.10", "1.0.0-beta.2") == 1

    def test_compare_with_semantic_version_objects(self, resolver: VersionResolver) -> None:
        """Test comparison with SemanticVersion objects."""
        v1 = SemanticVersion(1, 0, 0)
        v2 = SemanticVersion(2, 0, 0)
        assert resolver.compare(v1, v2) == -1
        assert resolver.compare(v2, v1) == 1
        assert resolver.compare(v1, "1.0.0") == 0

    # --- Compatibility Tests ---

    def test_is_compatible_same_version(self, resolver: VersionResolver) -> None:
        """Test same version is compatible."""
        assert resolver.is_compatible("2.0.0", "2.0.0")

    def test_is_compatible_higher_minor(self, resolver: VersionResolver) -> None:
        """Test higher minor version is compatible."""
        assert resolver.is_compatible("2.1.0", "2.0.0")
        assert resolver.is_compatible("2.5.3", "2.0.0")

    def test_is_compatible_higher_patch(self, resolver: VersionResolver) -> None:
        """Test higher patch version is compatible."""
        assert resolver.is_compatible("2.0.1", "2.0.0")

    def test_is_incompatible_different_major(self, resolver: VersionResolver) -> None:
        """Test different major version is incompatible."""
        assert not resolver.is_compatible("3.0.0", "2.0.0")
        assert not resolver.is_compatible("1.0.0", "2.0.0")

    def test_is_incompatible_lower_version(self, resolver: VersionResolver) -> None:
        """Test lower version is incompatible."""
        assert not resolver.is_compatible("2.0.0", "2.1.0")
        assert not resolver.is_compatible("2.0.5", "2.1.0")

    # --- Compatibility Level Tests ---

    def test_get_compatibility_level_same(self, resolver: VersionResolver) -> None:
        """Test compatibility level for same version."""
        level = resolver.get_compatibility_level("2.0.0", "2.0.0")
        assert level == CompatibilityLevel.COMPATIBLE

    def test_get_compatibility_level_patch(self, resolver: VersionResolver) -> None:
        """Test compatibility level for patch difference."""
        level = resolver.get_compatibility_level("2.0.0", "2.0.1")
        assert level == CompatibilityLevel.COMPATIBLE

    def test_get_compatibility_level_minor(self, resolver: VersionResolver) -> None:
        """Test compatibility level for minor difference."""
        level = resolver.get_compatibility_level("2.0.0", "2.1.0")
        assert level == CompatibilityLevel.MINOR_UPDATE

    def test_get_compatibility_level_major(self, resolver: VersionResolver) -> None:
        """Test compatibility level for major difference."""
        level = resolver.get_compatibility_level("2.0.0", "3.0.0")
        assert level == CompatibilityLevel.MAJOR_UPDATE

    # --- Range Tests ---

    def test_satisfies_range_greater_equal(self, resolver: VersionResolver) -> None:
        """Test >= range operator."""
        assert resolver.satisfies_range("2.0.0", ">=1.0.0")
        assert resolver.satisfies_range("1.0.0", ">=1.0.0")
        assert not resolver.satisfies_range("0.9.0", ">=1.0.0")

    def test_satisfies_range_less_equal(self, resolver: VersionResolver) -> None:
        """Test <= range operator."""
        assert resolver.satisfies_range("1.0.0", "<=2.0.0")
        assert resolver.satisfies_range("2.0.0", "<=2.0.0")
        assert not resolver.satisfies_range("2.1.0", "<=2.0.0")

    def test_satisfies_range_caret(self, resolver: VersionResolver) -> None:
        """Test ^x.y.z (caret) range - same major."""
        assert resolver.satisfies_range("1.2.3", "^1.0.0")
        assert resolver.satisfies_range("1.9.9", "^1.0.0")
        assert not resolver.satisfies_range("2.0.0", "^1.0.0")
        assert not resolver.satisfies_range("0.9.0", "^1.0.0")

    def test_satisfies_range_tilde(self, resolver: VersionResolver) -> None:
        """Test ~x.y.z (tilde) range - same major.minor."""
        assert resolver.satisfies_range("1.2.3", "~1.2.0")
        assert resolver.satisfies_range("1.2.9", "~1.2.0")
        assert not resolver.satisfies_range("1.3.0", "~1.2.0")
        assert not resolver.satisfies_range("1.1.0", "~1.2.0")

    def test_satisfies_range_hyphen(self, resolver: VersionResolver) -> None:
        """Test x.y.z - a.b.c (hyphen) range."""
        assert resolver.satisfies_range("1.5.0", "1.0.0 - 2.0.0")
        assert resolver.satisfies_range("1.0.0", "1.0.0 - 2.0.0")
        assert resolver.satisfies_range("2.0.0", "1.0.0 - 2.0.0")
        assert not resolver.satisfies_range("0.9.0", "1.0.0 - 2.0.0")
        assert not resolver.satisfies_range("2.0.1", "1.0.0 - 2.0.0")

    def test_satisfies_range_wildcard(self, resolver: VersionResolver) -> None:
        """Test x.* wildcard range."""
        assert resolver.satisfies_range("1.0.0", "1.x")
        assert resolver.satisfies_range("1.9.9", "1.x")
        assert resolver.satisfies_range("1.5.3", "1.*")
        assert not resolver.satisfies_range("2.0.0", "1.x")

    # --- Find Latest Compatible Tests ---

    def test_find_latest_compatible(self, resolver: VersionResolver) -> None:
        """Test finding latest compatible version."""
        versions = ["1.0.0", "1.1.0", "1.2.0", "2.0.0"]
        result = resolver.find_latest_compatible(versions, "1.0.0")
        assert result == SemanticVersion(1, 2, 0)

    def test_find_latest_compatible_none(self, resolver: VersionResolver) -> None:
        """Test when no compatible version exists."""
        versions = ["1.0.0", "1.1.0"]
        result = resolver.find_latest_compatible(versions, "2.0.0")
        assert result is None


class TestCompatibilityChecker:
    """Test CompatibilityChecker class."""

    @pytest.fixture
    def checker(self) -> CompatibilityChecker:
        """Create checker instance."""
        return CompatibilityChecker()

    def test_check_server_compatible(self, checker: CompatibilityChecker) -> None:
        """Test checking compatible server."""
        result = checker.check_server("tmws", "2.4.16", "2.4.0")

        assert result.is_compatible
        assert result.server_id == "tmws"
        assert result.server_version == SemanticVersion(2, 4, 16)
        assert result.client_version == SemanticVersion(2, 4, 0)
        assert not result.has_errors

    def test_check_server_incompatible_major(self, checker: CompatibilityChecker) -> None:
        """Test checking server with incompatible major version."""
        result = checker.check_server("tmws", "1.0.0", "2.0.0")

        assert not result.is_compatible
        assert result.has_errors
        assert any("VERSION_MAJOR_MISMATCH" in i.code for i in result.issues)

    def test_check_server_incompatible_minor(self, checker: CompatibilityChecker) -> None:
        """Test checking server with incompatible minor version."""
        result = checker.check_server("tmws", "2.0.0", "2.1.0")

        assert not result.is_compatible
        assert result.has_errors
        assert any("VERSION_TOO_OLD" in i.code for i in result.issues)

    def test_check_server_deprecated(self, checker: CompatibilityChecker) -> None:
        """Test checking deprecated server."""
        result = checker.check_server(
            "old-server",
            "2.0.0",
            "2.0.0",
            deprecated=True,
            deprecation_message="Use new-server instead",
        )

        assert result.is_compatible  # Still compatible
        assert result.has_warnings
        assert any("SERVER_DEPRECATED" in i.code for i in result.issues)
        assert "Use new-server instead" in result.warnings[0]

    def test_check_server_prerelease(self, checker: CompatibilityChecker) -> None:
        """Test checking prerelease server."""
        result = checker.check_server("dev-server", "2.0.0-beta.1", "2.0.0-beta.1")

        assert result.has_warnings
        assert any("PRERELEASE_VERSION" in i.code for i in result.issues)

    def test_check_server_version_lag(self, checker: CompatibilityChecker) -> None:
        """Test version lag detection."""
        result = checker.check_server("tmws", "2.5.0", "2.0.0")

        assert result.is_compatible
        assert any("VERSION_LAG" in i.code for i in result.issues)

    def test_check_registry_entry(self, checker: CompatibilityChecker) -> None:
        """Test checking with registry entry."""
        entry = ServerRegistryEntry(
            server_id="tmws",
            name="TMWS Server",
            command="python",
            args=["-m", "tmws.server"],
            version="2.4.16",
            min_compatible_version="2.4.0",
            deprecated=False,
        )

        result = checker.check_registry_entry(entry, "2.4.0")

        assert result.is_compatible
        assert result.server_id == "tmws"

    def test_check_registry_entry_deprecated(self, checker: CompatibilityChecker) -> None:
        """Test checking deprecated registry entry."""
        entry = ServerRegistryEntry(
            server_id="legacy",
            name="Legacy Server",
            command="python",
            args=["-m", "legacy"],
            version="1.0.0",
            deprecated=True,
            deprecation_message="Migrate to modern server",
        )

        result = checker.check_registry_entry(entry, "1.0.0")

        assert result.is_compatible
        assert result.has_warnings
        assert "Migrate to modern server" in result.warnings[0]

    def test_check_multiple_servers(self, checker: CompatibilityChecker) -> None:
        """Test checking multiple servers at once."""
        servers = [
            ("tmws", "2.4.16", "2.4.0"),
            ("serena", "1.0.0", "1.0.0"),
            ("legacy", "0.9.0", "1.0.0"),
        ]

        results = checker.check_multiple(servers)

        assert len(results) == 3
        assert results["tmws"].is_compatible
        assert results["serena"].is_compatible
        assert not results["legacy"].is_compatible

    def test_validate_upgrade_path_normal(self, checker: CompatibilityChecker) -> None:
        """Test validating normal upgrade path."""
        issues = checker.validate_upgrade_path("2.0.0", "2.1.0")
        assert len(issues) == 0

    def test_validate_upgrade_path_downgrade(self, checker: CompatibilityChecker) -> None:
        """Test detecting downgrade."""
        issues = checker.validate_upgrade_path("2.1.0", "2.0.0")

        assert len(issues) > 0
        assert any("DOWNGRADE_DETECTED" in i.code for i in issues)

    def test_validate_upgrade_path_large_jump(self, checker: CompatibilityChecker) -> None:
        """Test detecting large version jump."""
        issues = checker.validate_upgrade_path("1.0.0", "4.0.0")

        assert any("LARGE_VERSION_JUMP" in i.code for i in issues)

    def test_validate_upgrade_prerelease_to_stable(self, checker: CompatibilityChecker) -> None:
        """Test prerelease to stable upgrade."""
        issues = checker.validate_upgrade_path("1.0.0-beta", "1.0.0")

        assert any("PRERELEASE_TO_STABLE" in i.code for i in issues)

    def test_validate_upgrade_stable_to_prerelease(self, checker: CompatibilityChecker) -> None:
        """Test stable to prerelease upgrade (warned)."""
        issues = checker.validate_upgrade_path("1.0.0", "2.0.0-beta")

        assert any("STABLE_TO_PRERELEASE" in i.code for i in issues)


class TestModuleLevelFunctions:
    """Test module-level convenience functions."""

    def test_parse_version(self) -> None:
        """Test module-level parse_version."""
        v = parse_version("2.1.0")
        assert v == SemanticVersion(2, 1, 0)

    def test_compare_versions(self) -> None:
        """Test module-level compare_versions."""
        assert compare_versions("2.0.0", "1.0.0") == 1
        assert compare_versions("1.0.0", "2.0.0") == -1
        assert compare_versions("1.0.0", "1.0.0") == 0

    def test_is_version_compatible(self) -> None:
        """Test module-level is_version_compatible."""
        assert is_version_compatible("2.1.0", "2.0.0")
        assert not is_version_compatible("1.0.0", "2.0.0")

    def test_check_server_compatibility(self) -> None:
        """Test module-level check_server_compatibility."""
        result = check_server_compatibility("tmws", "2.4.16", "2.4.0")
        assert result.is_compatible


class TestCompatibilityResult:
    """Test CompatibilityResult properties and methods."""

    def test_has_warnings_property(self) -> None:
        """Test has_warnings property."""
        result_no_warn = CompatibilityResult(
            server_id="test",
            server_version=SemanticVersion(1, 0, 0),
            client_version=SemanticVersion(1, 0, 0),
            is_compatible=True,
            compatibility_level=CompatibilityLevel.COMPATIBLE,
            issues=[],
        )
        assert not result_no_warn.has_warnings

        result_with_warn = CompatibilityResult(
            server_id="test",
            server_version=SemanticVersion(1, 0, 0),
            client_version=SemanticVersion(1, 0, 0),
            is_compatible=True,
            compatibility_level=CompatibilityLevel.COMPATIBLE,
            issues=[
                CompatibilityIssue(
                    severity=CheckSeverity.WARNING,
                    code="TEST",
                    message="Test warning",
                )
            ],
        )
        assert result_with_warn.has_warnings

    def test_to_dict_serialization(self) -> None:
        """Test to_dict serialization."""
        result = CompatibilityResult(
            server_id="tmws",
            server_version=SemanticVersion(2, 4, 16),
            client_version=SemanticVersion(2, 4, 0),
            is_compatible=True,
            compatibility_level=CompatibilityLevel.COMPATIBLE,
            issues=[],
        )

        d = result.to_dict()
        assert d["server_id"] == "tmws"
        assert d["server_version"] == "2.4.16"
        assert d["client_version"] == "2.4.0"
        assert d["is_compatible"] is True
        assert d["compatibility_level"] == "compatible"


class TestServerRegistryEntryVersionFields:
    """Test version fields in ServerRegistryEntry model."""

    def test_default_version_fields(self) -> None:
        """Test default values for version fields."""
        entry = ServerRegistryEntry(
            server_id="test",
            name="Test Server",
            command="python",
            args=["-m", "test"],
        )

        assert entry.version == "1.0.0"
        assert entry.min_compatible_version == "1.0.0"
        assert entry.deprecated is False
        assert entry.deprecation_message is None

    def test_custom_version_fields(self) -> None:
        """Test custom values for version fields."""
        entry = ServerRegistryEntry(
            server_id="test",
            name="Test Server",
            command="python",
            args=["-m", "test"],
            version="2.4.16",
            min_compatible_version="2.4.0",
            deprecated=True,
            deprecation_message="Use v3 instead",
        )

        assert entry.version == "2.4.16"
        assert entry.min_compatible_version == "2.4.0"
        assert entry.deprecated is True
        assert entry.deprecation_message == "Use v3 instead"

    def test_to_dict_includes_version_fields(self) -> None:
        """Test to_dict includes version fields."""
        entry = ServerRegistryEntry(
            server_id="test",
            name="Test Server",
            command="python",
            args=["-m", "test"],
            version="2.4.16",
            deprecated=True,
        )

        d = entry.to_dict()
        assert d["version"] == "2.4.16"
        assert d["min_compatible_version"] == "1.0.0"
        assert d["deprecated"] is True
        assert d["deprecation_message"] is None

    def test_from_dict_parses_version_fields(self) -> None:
        """Test from_dict parses version fields."""
        data = {
            "server_id": "test",
            "name": "Test Server",
            "command": "python",
            "args": ["-m", "test"],
            "version": "2.4.16",
            "min_compatible_version": "2.4.0",
            "deprecated": True,
            "deprecation_message": "Migrate now",
        }

        entry = ServerRegistryEntry.from_dict(data)
        assert entry.version == "2.4.16"
        assert entry.min_compatible_version == "2.4.0"
        assert entry.deprecated is True
        assert entry.deprecation_message == "Migrate now"

    def test_from_dict_with_missing_version_fields(self) -> None:
        """Test from_dict handles missing version fields (backward compat)."""
        data = {
            "server_id": "legacy",
            "name": "Legacy Server",
            "command": "python",
            "args": ["-m", "legacy"],
            # No version fields - simulates old registry format
        }

        entry = ServerRegistryEntry.from_dict(data)
        assert entry.version == "1.0.0"  # Default
        assert entry.min_compatible_version == "1.0.0"  # Default
        assert entry.deprecated is False  # Default
        assert entry.deprecation_message is None  # Default
