"""
Pattern Data Validation and Sanitization
Addresses Hestia's CRITICAL findings:
- Pattern injection (arbitrary code execution)
- SQL injection (malicious queries)

Security Strategy:
- Whitelist-based validation
- Template sanitization
- Parameterized query enforcement
- Regular expression safety checks
"""

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of pattern validation"""

    is_valid: bool
    errors: list[str]
    warnings: list[str]


class PatternDataValidator:
    """
    Validates pattern data to prevent injection attacks

    Security Measures:
    1. Whitelist allowed pattern fields
    2. Sanitize template strings
    3. Validate SQL queries for parameterization
    4. Check regex patterns for ReDoS vulnerabilities
    """

    # Allowed pattern fields (whitelist approach)
    ALLOWED_PATTERN_FIELDS = {
        "name",
        "pattern_type",
        "trigger_pattern",
        "cost_tokens",
        "priority",
        "cache_ttl",
        "metadata",
        "description",
        "required_permissions",
        "rate_limit",
    }

    # Allowed metadata keys
    ALLOWED_METADATA_KEYS = {
        "category",
        "author",
        "version",
        "tags",
        "documentation",
        "performance_target",
        "token_budget",
    }

    # Dangerous SQL keywords that should only appear in parameterized contexts
    DANGEROUS_SQL_KEYWORDS = {
        "DROP",
        "DELETE",
        "TRUNCATE",
        "ALTER",
        "CREATE",
        "EXEC",
        "EXECUTE",
        "UNION",
        "INSERT",
        "UPDATE",
        "--",
        ";--",
        "/*",
        "*/",
    }

    # Dangerous Python functions/keywords
    DANGEROUS_PYTHON_PATTERNS = [
        r"\bexec\s*\(",
        r"\beval\s*\(",
        r"__import__",
        r"\bcompile\s*\(",
        r"subprocess",
        r"os\.system",
        r"os\.popen",
    ]

    def __init__(self):
        self.dangerous_python_regex = re.compile(
            "|".join(self.DANGEROUS_PYTHON_PATTERNS), re.IGNORECASE
        )

    def validate_pattern_definition(self, pattern_data: dict[str, Any]) -> ValidationResult:
        """
        Comprehensive validation of pattern definition

        Args:
            pattern_data: Pattern configuration dictionary

        Returns:
            ValidationResult with validation status and any errors
        """
        errors = []
        warnings = []

        # 1. Check for unknown fields (potential injection vector)
        unknown_fields = set(pattern_data.keys()) - self.ALLOWED_PATTERN_FIELDS
        if unknown_fields:
            errors.append(
                f"Unknown fields detected: {unknown_fields}. "
                f"Only allowed: {self.ALLOWED_PATTERN_FIELDS}"
            )

        # 2. Validate required fields
        required_fields = {"name", "pattern_type", "trigger_pattern", "cost_tokens"}
        missing_fields = required_fields - set(pattern_data.keys())
        if missing_fields:
            errors.append(f"Missing required fields: {missing_fields}")

        # 3. Validate pattern name (alphanumeric + underscore only)
        if "name" in pattern_data and not re.match(r"^[a-zA-Z0-9_]+$", pattern_data["name"]):
            errors.append(
                f"Invalid pattern name '{pattern_data['name']}'. "
                f"Only alphanumeric and underscore allowed."
            )

        # 4. Validate trigger pattern for ReDoS vulnerabilities
        if "trigger_pattern" in pattern_data:
            redos_result = self._check_redos_vulnerability(pattern_data["trigger_pattern"])
            if not redos_result["safe"]:
                warnings.append(
                    f"Potential ReDoS vulnerability in trigger pattern: {redos_result['reason']}"
                )

        # 5. Validate metadata
        if "metadata" in pattern_data:
            metadata_result = self._validate_metadata(pattern_data["metadata"])
            errors.extend(metadata_result["errors"])
            warnings.extend(metadata_result["warnings"])

        # 6. Check for code injection patterns
        pattern_str = str(pattern_data)
        if self.dangerous_python_regex.search(pattern_str):
            errors.append(
                "Dangerous Python code detected in pattern definition. "
                "Patterns cannot contain exec, eval, __import__, etc."
            )

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)

    def _validate_metadata(self, metadata: dict[str, Any]) -> dict[str, list[str]]:
        """Validate metadata dictionary"""
        errors = []
        warnings = []

        # Check for unknown metadata keys
        unknown_keys = set(metadata.keys()) - self.ALLOWED_METADATA_KEYS
        if unknown_keys:
            warnings.append(
                f"Unknown metadata keys: {unknown_keys}. Allowed: {self.ALLOWED_METADATA_KEYS}"
            )

        # Check metadata values for dangerous content
        for key, value in metadata.items():
            if isinstance(value, str) and self.dangerous_python_regex.search(value):
                errors.append(f"Dangerous code detected in metadata['{key}']: {value}")

        return {"errors": errors, "warnings": warnings}

    def _check_redos_vulnerability(self, regex_pattern: str) -> dict[str, Any]:
        """
        Check regex pattern for ReDoS (Regular Expression Denial of Service) vulnerabilities

        Common ReDoS patterns:
        - (a+)+
        - (a*)*
        - (a|a)*
        - (a|ab)+
        """
        # Simple heuristics for common ReDoS patterns
        redos_patterns = [
            (r"\([^)]*\+\)\+", "Nested quantifiers (x+)+"),
            (r"\([^)]*\*\)\*", "Nested quantifiers (x*)*"),
            (r"\([^)]*\+\)\*", "Nested quantifiers (x+)*"),
            (r"\([^)]*\|\1\)", "Alternation with same pattern"),
        ]

        for pattern, reason in redos_patterns:
            if re.search(pattern, regex_pattern):
                return {"safe": False, "reason": reason}

        return {"safe": True, "reason": None}

    def sanitize_sql_query(self, query: str) -> ValidationResult:
        """
        Validate and sanitize SQL query to prevent SQL injection

        Only allows SELECT queries with parameterized placeholders
        """
        errors = []
        warnings = []

        # 1. Only allow SELECT statements
        query_upper = query.upper().strip()
        if not query_upper.startswith("SELECT"):
            errors.append("Only SELECT queries are allowed in patterns")

        # 2. Check for dangerous keywords
        for keyword in self.DANGEROUS_SQL_KEYWORDS:
            if keyword in query_upper:
                errors.append(f"Dangerous SQL keyword '{keyword}' not allowed in patterns")

        # 3. Ensure parameterized queries (look for placeholders)
        if ("'" in query or '"' in query) and not ("$" in query or "?" in query):
            # Check if quotes are used for string literals (dangerous)
            # Should use $1, $2 (PostgreSQL) or ? (SQLite) placeholders
            errors.append(
                "SQL query appears to use string literals. "
                "Use parameterized queries with $1, $2, etc."
            )

        # 4. Check for comment attacks (-- or /* */)
        if "--" in query or "/*" in query:
            warnings.append("SQL comments detected - review for injection attempts")

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)

    def validate_template_string(self, template: str) -> ValidationResult:
        """
        Validate template string to prevent template injection

        Templates should only use safe variable substitution:
        - ${variable_name}
        - {variable_name}

        Not allowed:
        - eval() or exec()
        - __import__
        - file operations
        """
        errors = []
        warnings = []

        # Check for dangerous code patterns
        if self.dangerous_python_regex.search(template):
            errors.append(
                "Dangerous code detected in template. Templates cannot execute arbitrary code."
            )

        # Check template syntax
        # Allow ${var} or {var} style templates
        invalid_templates = re.findall(r"\$\{[^}]*[^a-zA-Z0-9_][^}]*\}", template)
        if invalid_templates:
            errors.append(
                f"Invalid template syntax: {invalid_templates}. "
                f"Only alphanumeric and underscore allowed in variable names."
            )

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)


# Singleton instance
pattern_validator = PatternDataValidator()
