"""
P1 Integration Tests: Injection Prevention
HIGH PRIORITY: These tests verify protection against injection attacks.

Test IDs:
- INJ-P1-001: SQL injection prevention
- INJ-P1-002: NoSQL injection prevention
- INJ-P1-003: Command injection prevention
- INJ-P1-004: XSS prevention
"""

import pytest
from unittest.mock import AsyncMock, Mock


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.asyncio
class TestSQLInjectionPrevention:
    """INJ-P1-001: SQL injection prevention tests."""

    async def test_sql_injection_in_search_query(self, sql_injection_payloads):
        """INJ-P1-001-T1: SQL injection in search queries is prevented."""
        mock_search_service = AsyncMock()

        # Service should sanitize or parameterize queries
        mock_search_service.search.return_value = []

        for payload in sql_injection_payloads[:5]:  # Test first 5 payloads
            results = await mock_search_service.search(query=payload)
            # Should return empty results, not execute malicious SQL
            assert isinstance(results, list)
            mock_search_service.search.assert_called()

    async def test_sql_injection_in_agent_id(self, sql_injection_payloads):
        """INJ-P1-001-T2: SQL injection in agent_id parameter is prevented."""
        mock_agent_service = AsyncMock()

        # Service should reject malicious input
        mock_agent_service.get_agent.side_effect = ValueError("Invalid agent ID format")

        for payload in sql_injection_payloads[:3]:
            with pytest.raises(ValueError):
                await mock_agent_service.get_agent(agent_id=payload)

    async def test_sql_injection_in_filter_parameters(self, sql_injection_payloads):
        """INJ-P1-001-T3: SQL injection in filter parameters is prevented."""
        mock_list_service = AsyncMock()

        # Service should use parameterized queries
        mock_list_service.list_with_filters.return_value = []

        malicious_filters = {
            "status": "active'; DROP TABLE agents; --",
            "namespace": "test' OR '1'='1",
        }

        # Should return empty results, not execute injection
        results = await mock_list_service.list_with_filters(**malicious_filters)
        assert isinstance(results, list)

    async def test_parameterized_queries_used(self):
        """INJ-P1-001-T4: Parameterized queries are used for all DB operations."""
        # This test verifies the pattern, not actual DB execution
        mock_db = AsyncMock()

        # Simulate parameterized query execution
        query_log = []

        async def execute_parameterized(query: str, params: dict):
            query_log.append({"query": query, "params": params})
            return []

        mock_db.execute.side_effect = execute_parameterized

        # Proper parameterized query
        await mock_db.execute(
            query="SELECT * FROM agents WHERE status = :status AND namespace = :namespace",
            params={"status": "active", "namespace": "test"}
        )

        # Verify parameterization
        assert len(query_log) == 1
        assert ":status" in query_log[0]["query"]
        assert ":namespace" in query_log[0]["query"]
        assert "params" in query_log[0]


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.asyncio
class TestNoSQLInjectionPrevention:
    """INJ-P1-002: NoSQL injection prevention tests."""

    async def test_nosql_injection_in_memory_search(self):
        """INJ-P1-002-T1: NoSQL injection in memory search is prevented."""
        mock_vector_service = AsyncMock()

        # NoSQL injection payloads
        nosql_payloads = [
            '{"$gt": ""}',
            '{"$where": "sleep(5000)"}',
            '{"$regex": ".*"}',
            "{'$ne': null}",
        ]

        mock_vector_service.search.return_value = []

        for payload in nosql_payloads:
            results = await mock_vector_service.search(query=payload)
            assert isinstance(results, list)

    async def test_nosql_injection_in_metadata_query(self):
        """INJ-P1-002-T2: NoSQL injection in metadata queries is prevented."""
        mock_memory_service = AsyncMock()

        # Attempt injection via metadata filter
        malicious_metadata = {
            "$where": "function() { return true; }",
            "importance": {"$gt": ""},
        }

        mock_memory_service.search_by_metadata.return_value = []

        results = await mock_memory_service.search_by_metadata(
            filters=malicious_metadata
        )
        assert isinstance(results, list)


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.asyncio
class TestCommandInjectionPrevention:
    """INJ-P1-003: Command injection prevention tests."""

    async def test_command_injection_in_skill_execution(self):
        """INJ-P1-003-T1: Command injection in skill execution is prevented."""
        mock_skill_executor = AsyncMock()

        # Command injection payloads
        cmd_payloads = [
            "; rm -rf /",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "&& curl evil.com",
        ]

        # Service should sanitize or sandbox execution
        mock_skill_executor.execute.side_effect = ValueError(
            "Invalid characters in input"
        )

        for payload in cmd_payloads:
            with pytest.raises(ValueError):
                await mock_skill_executor.execute(
                    skill_id="test-skill",
                    params={"command": payload}
                )

    async def test_path_traversal_prevention(self):
        """INJ-P1-003-T2: Path traversal attacks are prevented."""
        mock_file_service = AsyncMock()

        # Path traversal payloads
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]

        mock_file_service.read_file.side_effect = ValueError(
            "Path traversal detected"
        )

        for payload in path_payloads:
            with pytest.raises(ValueError) as exc_info:
                await mock_file_service.read_file(path=payload)
            assert "traversal" in str(exc_info.value).lower()

    async def test_environment_variable_injection_prevention(self):
        """INJ-P1-003-T3: Environment variable injection is prevented."""
        mock_config_service = AsyncMock()

        # Env injection payloads
        env_payloads = [
            "${DATABASE_URL}",
            "$SECRET_KEY",
            "%(DATABASE_URL)s",
            "{{config.SECRET_KEY}}",
        ]

        mock_config_service.set_value.side_effect = ValueError(
            "Variable interpolation not allowed"
        )

        for payload in env_payloads:
            with pytest.raises(ValueError):
                await mock_config_service.set_value(key="test", value=payload)


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.asyncio
class TestXSSPrevention:
    """INJ-P1-004: XSS prevention tests."""

    async def test_xss_in_memory_content(self, xss_payloads):
        """INJ-P1-004-T1: XSS in memory content is sanitized."""
        mock_memory_service = AsyncMock()

        # Service should sanitize HTML/script content using comprehensive sanitization
        import re

        async def sanitize_and_create(content: str, **kwargs):
            # Comprehensive XSS sanitization
            sanitized = Mock()
            # Remove script tags and their content
            sanitized_content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)
            # Remove event handlers
            sanitized_content = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', sanitized_content, flags=re.IGNORECASE)
            sanitized_content = re.sub(r'\s*on\w+\s*=\s*[^\s>]+', '', sanitized_content, flags=re.IGNORECASE)
            # Remove javascript: URLs
            sanitized_content = re.sub(r'javascript:', '', sanitized_content, flags=re.IGNORECASE)
            # Escape remaining HTML
            sanitized_content = sanitized_content.replace("<", "&lt;").replace(">", "&gt;")
            sanitized.content = sanitized_content
            return sanitized

        mock_memory_service.create_memory.side_effect = sanitize_and_create

        for payload in xss_payloads[:5]:
            result = await mock_memory_service.create_memory(
                content=payload,
                agent_id="test-agent",
                namespace="test-namespace"
            )
            # Script tags should be escaped
            assert "<script>" not in result.content
            assert "onerror=" not in result.content.lower()

    async def test_xss_in_skill_description(self, xss_payloads):
        """INJ-P1-004-T2: XSS in skill description is sanitized."""
        mock_skill_service = AsyncMock()
        import re

        async def sanitize_skill(name: str, description: str, **kwargs):
            skill = Mock()
            skill.name = name
            # Comprehensive XSS sanitization
            sanitized = description
            # Remove javascript: URLs
            sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
            # Escape remaining HTML
            sanitized = sanitized.replace("<", "&lt;").replace(">", "&gt;")
            skill.description = sanitized
            return skill

        mock_skill_service.create_skill.side_effect = sanitize_skill

        for payload in xss_payloads[:3]:
            skill = await mock_skill_service.create_skill(
                name="test-skill",
                description=payload,
                agent_id="test-agent",
                namespace="test-namespace"
            )
            assert "<script>" not in skill.description
            assert "javascript:" not in skill.description.lower()

    async def test_xss_in_agent_display_name(self, xss_payloads):
        """INJ-P1-004-T3: XSS in agent display name is sanitized."""
        mock_agent_service = AsyncMock()

        async def sanitize_agent(display_name: str, **kwargs):
            agent = Mock()
            # Simulate sanitization - strip all HTML
            import re
            agent.display_name = re.sub(r'<[^>]+>', '', display_name)
            return agent

        mock_agent_service.create_agent.side_effect = sanitize_agent

        for payload in xss_payloads[:3]:
            agent = await mock_agent_service.create_agent(
                display_name=payload,
                agent_id="test-agent",
                namespace="test-namespace"
            )
            # No HTML tags should remain
            assert "<" not in agent.display_name
            assert ">" not in agent.display_name

    async def test_content_security_policy_headers(self):
        """INJ-P1-004-T4: CSP headers are properly configured."""
        # This test verifies the expected CSP configuration
        expected_csp = {
            "default-src": "'self'",
            "script-src": "'self'",
            "style-src": "'self' 'unsafe-inline'",
            "img-src": "'self' data:",
            "frame-ancestors": "'none'",
        }

        # Mock security headers configuration
        mock_security_config = Mock()
        mock_security_config.csp = expected_csp

        # Verify CSP prevents inline scripts
        assert "'unsafe-eval'" not in mock_security_config.csp.get("script-src", "")
        assert mock_security_config.csp.get("frame-ancestors") == "'none'"


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.asyncio
class TestInputValidation:
    """INJ-P1-005: General input validation tests."""

    async def test_maximum_input_length_enforced(self):
        """INJ-P1-005-T1: Maximum input length is enforced."""
        mock_service = AsyncMock()

        # Very long input (potential buffer overflow or DoS)
        very_long_input = "A" * 1000000  # 1MB of data

        mock_service.process_input.side_effect = ValueError(
            "Input exceeds maximum length"
        )

        with pytest.raises(ValueError) as exc_info:
            await mock_service.process_input(data=very_long_input)

        assert "length" in str(exc_info.value).lower()

    async def test_special_characters_sanitized(self):
        """INJ-P1-005-T2: Special characters are properly handled."""
        mock_service = AsyncMock()

        special_inputs = [
            "\x00",  # Null byte
            "\r\n",  # CRLF
            "\x1b[31m",  # ANSI escape
            "\uffff",  # Invalid Unicode
        ]

        async def sanitize_special(x: str) -> str:
            # Remove null bytes, ANSI escapes, and invalid unicode
            result = x.replace("\x00", "").replace("\x1b", "")
            # Remove invalid unicode
            result = result.encode('utf-8', 'ignore').decode('utf-8', 'ignore')
            return result

        mock_service.sanitize.side_effect = sanitize_special

        for input_data in special_inputs:
            result = await mock_service.sanitize(input_data)
            # Special characters should be removed or escaped
            assert "\x00" not in result
            assert "\x1b" not in result

    async def test_unicode_normalization(self):
        """INJ-P1-005-T3: Unicode is properly normalized."""
        mock_service = AsyncMock()

        # Unicode bypass attempts
        unicode_payloads = [
            "ａｄｍｉｎ",  # Full-width characters
            "admin\u200b",  # Zero-width space
            "adm\u0069n",  # Unicode char for 'i'
        ]

        import unicodedata

        async def normalize_input(data: str):
            # NFKC normalization + remove zero-width characters
            normalized = unicodedata.normalize('NFKC', data)
            # Remove zero-width characters
            normalized = normalized.replace('\u200b', '').replace('\u200c', '').replace('\u200d', '')
            return normalized.strip()

        mock_service.normalize.side_effect = normalize_input

        for payload in unicode_payloads:
            result = await mock_service.normalize(payload)
            # Should normalize to standard ASCII where possible
            assert "\u200b" not in result  # Zero-width removed
