"""V-3 SQL Injection Prevention Tests.

Validates SecureQueryBuilder prevents:
1. SQL Injection (UNION attacks) - SQLAlchemy built-in
2. LIKE Pattern Injection (DoS) - Wildcard escaping
3. Column Name Injection - Schema validation

Test Coverage:
- Category A: Basic wildcard escaping (5 tests)
- Category B: DoS attack patterns (5 tests)
- Category C: Unicode and edge cases (5 tests)
- Category D: SQLAlchemy integration (4 tests)
- Category E: Service layer migration validation (4 tests)
- Category F: Performance validation (3 tests)
- Category G: Security guarantees (3 tests)

Total: 29 tests

Author: Artemis (artemis-optimizer)
Created: 2025-11-24
Version: 1.0.0
"""

import time

import pytest
from sqlalchemy import select

from src.models.agent import Agent
from src.models.memory import Memory
from src.security.query_builder import SecureQueryBuilder

# ============================================================================
# Category A: Basic Wildcard Escaping (5 tests)
# ============================================================================


class TestBasicEscaping:
    """Test basic wildcard escaping functionality."""

    def test_escape_percent(self):
        """Single % wildcard should be escaped."""
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern("50%")
        assert escaped == "50\\%", f"Expected '50\\%', got '{escaped}'"
        assert escape_char == "\\", f"Expected '\\', got '{escape_char}'"

    def test_escape_underscore(self):
        """Single _ wildcard should be escaped."""
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern("foo_bar")
        assert escaped == "foo\\_bar", f"Expected 'foo\\_bar', got '{escaped}'"
        assert escape_char == "\\"

    def test_escape_backslash(self):
        """Backslash escape character should be escaped."""
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern("C:\\folder")
        assert escaped == "C:\\\\folder", f"Expected 'C:\\\\folder', got '{escaped}'"
        assert escape_char == "\\"

    def test_escape_combined(self):
        """Mix of %, _, \\ should be escaped correctly."""
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern("50%_off\\sale")
        # Expected: 50\%\_off\\sale
        assert escaped == "50\\%\\_off\\\\sale", f"Got '{escaped}'"
        assert escape_char == "\\"

    def test_escape_empty_string(self):
        """Empty string should be handled gracefully."""
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern("")
        assert escaped == "", "Empty string should remain empty"
        assert escape_char == "\\"


# ============================================================================
# Category B: DoS Attack Patterns (5 tests)
# ============================================================================


class TestAttackPatterns:
    """Test DoS attack patterns with wildcards."""

    def test_multiple_percent(self):
        """16 consecutive % wildcards (DoS attack)."""
        malicious = "%" * 16
        escaped, _ = SecureQueryBuilder.safe_like_pattern(malicious)
        # Each % should be escaped to \%
        expected = "\\%" * 16
        assert escaped == expected, f"Expected '{expected}', got '{escaped}'"

    def test_multiple_underscore(self):
        """16 consecutive _ wildcards (DoS attack)."""
        malicious = "_" * 16
        escaped, _ = SecureQueryBuilder.safe_like_pattern(malicious)
        expected = "\\_" * 16
        assert escaped == expected, f"Expected '{expected}', got '{escaped}'"

    def test_alternating_wildcards(self):
        """Alternating % and _ pattern."""
        malicious = "%_%_%_%_"
        escaped, _ = SecureQueryBuilder.safe_like_pattern(malicious)
        # Expected: \%\_\%\_\%\_\%\_
        expected = "\\%\\_\\%\\_\\%\\_\\%\\_"
        assert escaped == expected, f"Expected '{expected}', got '{escaped}'"

    def test_double_escape_attack(self):
        """Double escaping bypass attempt (\\%)."""
        malicious = "\\\\%"
        escaped, _ = SecureQueryBuilder.safe_like_pattern(malicious)
        # First \\ → \\\\, then % → \%
        # Result: \\\\\%
        expected = "\\\\\\\\\\%"
        assert escaped == expected, f"Expected '{expected}', got '{escaped}'"

    def test_null_byte_injection(self):
        """NULL byte injection attempt."""
        malicious = "test\x00%%%%%"
        escaped, _ = SecureQueryBuilder.safe_like_pattern(malicious)
        # NULL byte should be preserved, wildcards escaped
        assert "\\%" in escaped, "Wildcards should be escaped"
        assert "\x00" in escaped, "NULL byte should be preserved"


# ============================================================================
# Category C: Unicode and Edge Cases (5 tests)
# ============================================================================


class TestUnicodeAndEdgeCases:
    """Test Unicode characters and edge cases."""

    def test_unicode_emoji(self):
        """Unicode emoji should be preserved."""
        escaped, _ = SecureQueryBuilder.safe_like_pattern("test 🚀 rocket")
        assert escaped == "test 🚀 rocket", "Emoji should be preserved"

    def test_unicode_japanese(self):
        """Japanese characters should be preserved."""
        escaped, _ = SecureQueryBuilder.safe_like_pattern("テスト_%完了")
        # Only % and _ should be escaped, Japanese preserved
        assert "テスト" in escaped, "Japanese should be preserved"
        assert "\\%" in escaped, "% should be escaped"
        assert "\\_" in escaped, "_ should be escaped"
        assert "完了" in escaped, "Japanese should be preserved"

    def test_unicode_mixed(self):
        """Mix of ASCII, emoji, and Japanese."""
        escaped, _ = SecureQueryBuilder.safe_like_pattern("Test%🚀テスト_完了")
        assert "Test" in escaped
        assert "🚀" in escaped
        assert "テスト" in escaped
        assert "完了" in escaped
        assert "\\%" in escaped
        assert "\\_" in escaped

    def test_allow_wildcards_flag(self):
        """allow_wildcards=True should skip escaping."""
        user_input = "test%%%%%_____"
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern(
            user_input, allow_wildcards=True
        )
        # Should NOT escape when allow_wildcards=True
        assert escaped == user_input, "Wildcards should NOT be escaped"
        assert escape_char == "\\"

    def test_custom_escape_char(self):
        """Custom escape character should work."""
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern("test%", escape_char="!")
        # Should use ! instead of \\
        assert escaped == "test!%", f"Expected 'test!%', got '{escaped}'"
        assert escape_char == "!", f"Expected '!', got '{escape_char}'"


# ============================================================================
# Category D: SQLAlchemy Integration (4 tests)
# ============================================================================


class TestSQLAlchemyIntegration:
    """Test SQLAlchemy integration with ESCAPE clause."""

    @pytest.mark.asyncio
    async def test_ilike_with_escape(self, test_session):
        """Test .ilike() with ESCAPE clause."""
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern("50%")
        query = select(Memory).where(Memory.content.ilike(f"%{escaped}%", escape=escape_char))
        # Should generate: WHERE content ILIKE '%50\\%%' ESCAPE '\\'
        result = await test_session.execute(query)
        # Verify query executes without error
        assert result is not None, "Query should execute successfully"

    @pytest.mark.asyncio
    async def test_like_with_escape(self, test_session):
        """Test .like() with ESCAPE clause (case-sensitive)."""
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern("Test_")
        query = select(Agent).where(Agent.display_name.like(f"%{escaped}%", escape=escape_char))
        result = await test_session.execute(query)
        assert result is not None

    @pytest.mark.asyncio
    async def test_multiple_columns_search(self, test_session):
        """Test OR search across multiple columns."""
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern("test%")
        query = select(Agent).where(
            (Agent.display_name.ilike(f"%{escaped}%", escape=escape_char))
            | (Agent.agent_id.ilike(f"%{escaped}%", escape=escape_char))
        )
        result = await test_session.execute(query)
        assert result is not None

    @pytest.mark.asyncio
    async def test_build_search_query_helper(self, test_session):
        """Test build_search_query() helper method."""
        # This tests the high-level helper function
        result = await SecureQueryBuilder.build_search_query(
            model=Agent,
            search_columns=["display_name", "agent_id"],
            search_term="test%%%%%",  # DoS attempt
            session=test_session,
            case_insensitive=True,
        )
        # Should NOT cause DoS (wildcards escaped)
        assert isinstance(result, list), "Should return list of results"


# ============================================================================
# Category E: Service Layer Migration Validation (4 tests)
# ============================================================================


class TestServiceLayerMigration:
    """Validate service layer uses SecureQueryBuilder."""

    def test_learning_service_uses_secure_query_builder(self):
        """LearningService code contains SecureQueryBuilder import."""
        import inspect

        from src.services.learning_service import LearningService

        # Verify the service file contains the V-3 mitigation
        source = inspect.getsource(LearningService.search_patterns)
        assert "SecureQueryBuilder" in source, (
            "LearningService.search_patterns() should use SecureQueryBuilder"
        )
        assert "safe_like_pattern" in source, (
            "LearningService.search_patterns() should escape wildcards"
        )

    def test_agent_service_uses_secure_query_builder(self):
        """AgentService code contains SecureQueryBuilder import."""
        import inspect

        from src.services.agent_service import AgentService

        # Verify the service file contains the V-3 mitigation
        source = inspect.getsource(AgentService.search_agents)
        assert "SecureQueryBuilder" in source, (
            "AgentService.search_agents() should use SecureQueryBuilder"
        )
        assert "safe_like_pattern" in source, "AgentService.search_agents() should escape wildcards"

    def test_pattern_execution_service_uses_secure_query_builder(self):
        """PatternExecutionService code contains SecureQueryBuilder import."""
        import inspect

        # Import the module to check its methods
        from src.services import pattern_execution_service

        # Get the source code of the module
        source = inspect.getsource(pattern_execution_service)

        # Verify the service file contains the V-3 mitigation
        assert "SecureQueryBuilder" in source, (
            "pattern_execution_service should use SecureQueryBuilder"
        )
        assert "safe_like_pattern" in source, "pattern_execution_service should escape wildcards"
        assert "_execute_memory" in source, "_execute_memory method should exist"

    @pytest.mark.asyncio
    async def test_agent_service_integration(self, test_session):
        """AgentService.search_agents() integration test."""
        from src.services.agent_service import AgentService

        service = AgentService(test_session)

        # DoS attack: 16 consecutive wildcards
        malicious_query = "%%%%%%%%%%%%%%%%%"

        # Should NOT cause DoS
        results = await service.search_agents(query=malicious_query)

        assert isinstance(results, list), "Should return list"


# ============================================================================
# Category F: Performance Validation (3 tests)
# ============================================================================


class TestPerformance:
    """Validate performance targets are met."""

    @pytest.mark.asyncio
    async def test_performance_normal_query(self, test_session):
        """Normal query should be fast (<50ms in test env, <20ms P95 in prod)."""
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern("test")

        start = time.perf_counter()
        query = select(Memory).where(Memory.content.ilike(f"%{escaped}%", escape=escape_char))
        await test_session.execute(query)
        duration = (time.perf_counter() - start) * 1000  # ms

        # Should be fast even with escaping (test env overhead: ~30-40ms)
        assert duration < 50, f"Query too slow: {duration:.2f}ms (target: <50ms test, <20ms prod)"

    @pytest.mark.asyncio
    async def test_performance_wildcard_heavy_query(self, test_session):
        """Wildcard-heavy query should be acceptable (<100ms P95)."""
        # 16 wildcards (worst case for escaping)
        malicious = "%" * 16
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern(malicious)

        start = time.perf_counter()
        query = select(Memory).where(Memory.content.ilike(f"%{escaped}%", escape=escape_char))
        await test_session.execute(query)
        duration = (time.perf_counter() - start) * 1000  # ms

        assert duration < 100, f"Query too slow: {duration:.2f}ms (target: <100ms)"

    def test_performance_escaping_function(self):
        """safe_like_pattern() should be fast (<5ms for heavy input)."""
        # 100 character input with many wildcards
        heavy_input = "test%" * 20  # 100 chars

        start = time.perf_counter()
        for _ in range(100):  # Run 100 times
            SecureQueryBuilder.safe_like_pattern(heavy_input)
        duration = (time.perf_counter() - start) * 1000  # ms

        avg_duration = duration / 100
        assert avg_duration < 5, f"Escaping too slow: {avg_duration:.2f}ms (target: <5ms)"


# ============================================================================
# Category G: Security Guarantees (3 tests)
# ============================================================================


class TestSecurityValidation:
    """Validate security guarantees."""

    @pytest.mark.asyncio
    async def test_sql_injection_union_attack(self, test_session):
        """UNION attack should be prevented by parameterization."""
        malicious = "test%' UNION SELECT password FROM users WHERE '1'='1"

        escaped, escape_char = SecureQueryBuilder.safe_like_pattern(malicious)
        query = select(Memory).where(Memory.content.ilike(f"%{escaped}%", escape=escape_char))

        # SQLAlchemy should parameterize, preventing injection
        result = await test_session.execute(query)

        # Should return 0 results (malicious SQL not executed)
        memories = result.scalars().all()
        assert len(memories) == 0, "UNION attack should not return data"

    @pytest.mark.asyncio
    async def test_column_name_injection_prevention(self, test_session):
        """build_filter_query() should reject invalid column names."""
        from src.security.query_builder import SecureQueryBuilder

        # Try to inject malicious column name
        malicious_filters = {"agent_id": "test", "'; DROP TABLE memories; --": "malicious"}

        with pytest.raises(ValueError, match="Invalid column name"):
            await SecureQueryBuilder.build_filter_query(Memory, malicious_filters, test_session)

    @pytest.mark.asyncio
    async def test_build_search_query_column_validation(self, test_session):
        """build_search_query() should reject invalid column names."""
        # Try to search non-existent column
        malicious_columns = ["content", "'; DROP TABLE memories; --"]

        with pytest.raises(ValueError, match="Invalid column name"):
            await SecureQueryBuilder.build_search_query(
                model=Memory,
                search_columns=malicious_columns,
                search_term="test",
                session=test_session,
            )


# ============================================================================
# Additional Edge Case Tests (Bonus)
# ============================================================================


class TestAdditionalEdgeCases:
    """Additional edge cases beyond the 29 required tests."""

    def test_very_long_input(self):
        """Very long input (10,000 chars) should be handled."""
        long_input = "a" * 10000
        escaped, _ = SecureQueryBuilder.safe_like_pattern(long_input)
        assert len(escaped) == 10000, "Length should be preserved"

    def test_special_sql_characters(self):
        """Special SQL characters should be preserved (not escaped)."""
        # These are NOT LIKE wildcards, should be preserved
        special = "test'value\"with;special--chars"
        escaped, _ = SecureQueryBuilder.safe_like_pattern(special)
        # SQLAlchemy handles SQL injection, we only escape LIKE wildcards
        assert "'" in escaped, "Single quote should be preserved"
        assert '"' in escaped, "Double quote should be preserved"
        assert ";" in escaped, "Semicolon should be preserved"

    def test_newlines_and_whitespace(self):
        """Newlines and whitespace should be preserved."""
        multiline = "line1\nline2\tline3   line4"
        escaped, _ = SecureQueryBuilder.safe_like_pattern(multiline)
        assert "\n" in escaped, "Newline should be preserved"
        assert "\t" in escaped, "Tab should be preserved"
        assert "   " in escaped, "Multiple spaces should be preserved"
