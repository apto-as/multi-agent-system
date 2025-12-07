"""HTML/XSS sanitization validator.

Provides comprehensive XSS prevention:
- Dangerous tag detection
- Event handler detection
- JavaScript URL detection
- CSS expression detection

Security:
- V-XSS-1: XSS prevention
- Multiple detection patterns for defense-in-depth
- Configurable sanitization levels

Author: Artemis (Implementation)
Created: 2025-12-07 (Issue #22: Unified Sanitization)
"""

import html
import re
from typing import Any

from ..base import BaseValidator, Severity, ValidationResult
from ..core.patterns import get_pattern_registry
from ..exceptions import XSSError


class HTMLValidator(BaseValidator[str]):
    """Validator for HTML/XSS sanitization.

    Detects and prevents XSS attacks by:
    - Checking for dangerous HTML tags
    - Detecting event handlers
    - Detecting JavaScript URLs
    - Checking for CSS expressions

    Example:
        >>> validator = HTMLValidator()
        >>> result = validator.validate("<script>alert('xss')</script>")
        >>> result.is_valid
        False
        >>> result.severity
        <Severity.CRITICAL: 'critical'>
    """

    # Safe tags that don't need escaping (basic set)
    SAFE_TAGS_BASIC: set[str] = {
        "p", "br", "hr", "b", "i", "u", "s", "em", "strong",
        "span", "div", "a", "ul", "ol", "li", "blockquote",
    }

    # Markdown-safe tags
    SAFE_TAGS_MARKDOWN: set[str] = SAFE_TAGS_BASIC | {
        "h1", "h2", "h3", "h4", "h5", "h6",
        "code", "pre", "table", "thead", "tbody", "tr", "th", "td",
        "img", "sup", "sub", "del", "ins",
    }

    # Rich content tags
    SAFE_TAGS_RICH: set[str] = SAFE_TAGS_MARKDOWN | {
        "figure", "figcaption", "details", "summary",
        "abbr", "cite", "q", "dfn", "time",
    }

    def __init__(
        self,
        max_length: int = 50000,
        preset: str = "strict",
        allowed_tags: set[str] | None = None,
        escape_output: bool = True,
    ):
        """Initialize HTML validator.

        Args:
            max_length: Maximum content length (default 50000)
            preset: Sanitization preset (strict, basic, markdown, rich)
            allowed_tags: Custom set of allowed tags (overrides preset)
            escape_output: HTML-escape output (default True)
        """
        self.max_length = max_length
        self.preset = preset
        self.escape_output = escape_output
        self._patterns = get_pattern_registry()

        # Set allowed tags based on preset or custom
        if allowed_tags is not None:
            self.allowed_tags = allowed_tags
        elif preset == "basic":
            self.allowed_tags = self.SAFE_TAGS_BASIC
        elif preset == "markdown":
            self.allowed_tags = self.SAFE_TAGS_MARKDOWN
        elif preset == "rich":
            self.allowed_tags = self.SAFE_TAGS_RICH
        else:  # strict
            self.allowed_tags = set()  # No tags allowed

    def validate(self, value: Any, **kwargs: Any) -> ValidationResult[str]:
        """Validate and sanitize HTML content.

        Args:
            value: The HTML content to validate
            **kwargs: Override options

        Returns:
            ValidationResult with sanitized content
        """
        # Type check
        if not isinstance(value, str):
            return ValidationResult.failure(
                f"HTML content must be string, got {type(value).__name__}",
                severity=Severity.CRITICAL,
            )

        # Length check
        max_length = kwargs.get("max_length", self.max_length)
        if len(value) > max_length:
            return ValidationResult.failure(
                f"Content exceeds maximum length of {max_length}",
                severity=Severity.WARNING,
                sanitized_value=value[:max_length],
                details={"original_length": len(value)},
            )

        # XSS pattern check
        if self._patterns.test("xss", value):
            sanitized = self._sanitize_html(value)
            return ValidationResult.failure(
                "Potential XSS pattern detected",
                severity=Severity.CRITICAL,
                sanitized_value=sanitized,
                details={
                    "security_event": "xss_attempt",
                    "pattern_matched": "xss",
                },
            )

        # Dangerous tags check
        if self._patterns.test("dangerous_html_tags", value):
            sanitized = self._sanitize_html(value)
            return ValidationResult.failure(
                "Dangerous HTML tag detected",
                severity=Severity.CRITICAL,
                sanitized_value=sanitized,
                details={
                    "security_event": "dangerous_tag",
                },
            )

        # Dangerous attributes check
        if self._patterns.test("dangerous_html_attrs", value):
            sanitized = self._sanitize_html(value)
            return ValidationResult.failure(
                "Dangerous HTML attribute detected",
                severity=Severity.CRITICAL,
                sanitized_value=sanitized,
                details={
                    "security_event": "dangerous_attribute",
                },
            )

        # If strict mode and any HTML tags present
        if self.preset == "strict" and re.search(r"<[a-zA-Z]", value):
            sanitized = self._sanitize_html(value)
            return ValidationResult.failure(
                "HTML tags not allowed in strict mode",
                severity=Severity.WARNING,
                sanitized_value=sanitized,
            )

        # Sanitize output if requested
        sanitized = self._sanitize_html(value) if self.escape_output else value

        return ValidationResult.success(sanitized)

    def _sanitize_html(self, value: str) -> str:
        """Sanitize HTML content by escaping dangerous characters.

        Args:
            value: HTML content to sanitize

        Returns:
            Sanitized HTML content
        """
        # For strict mode, escape everything
        if self.preset == "strict" or not self.allowed_tags:
            return html.escape(value)

        # For other modes, selectively process
        # This is a simplified implementation - production would use
        # a proper HTML parser like bleach or lxml
        sanitized = value

        # Remove dangerous tags entirely
        dangerous_tags = [
            "script", "iframe", "object", "embed", "form",
            "input", "button", "textarea", "select", "style",
            "link", "meta", "base", "frame", "frameset", "applet",
        ]
        for tag in dangerous_tags:
            # Remove opening tags
            sanitized = re.sub(
                rf"<\s*{tag}[^>]*>",
                "",
                sanitized,
                flags=re.IGNORECASE,
            )
            # Remove closing tags
            sanitized = re.sub(
                rf"<\s*/\s*{tag}\s*>",
                "",
                sanitized,
                flags=re.IGNORECASE,
            )

        # Remove dangerous attributes
        sanitized = re.sub(
            r"\s+on\w+\s*=\s*['\"][^'\"]*['\"]",
            "",
            sanitized,
            flags=re.IGNORECASE,
        )
        sanitized = re.sub(
            r"javascript:",
            "",
            sanitized,
            flags=re.IGNORECASE,
        )

        return sanitized

    def get_validation_rules(self) -> dict[str, Any]:
        """Return validation rules for documentation/audit.

        Returns:
            Dictionary describing the validation rules
        """
        return {
            "type": "html",
            "max_length": self.max_length,
            "preset": self.preset,
            "allowed_tags": sorted(self.allowed_tags) if self.allowed_tags else [],
            "escape_output": self.escape_output,
            "blocked_patterns": [
                "Script tags",
                "Event handlers (onclick, onerror, etc.)",
                "JavaScript URLs",
                "CSS expressions",
                "Iframe/object/embed tags",
            ],
        }


def sanitize_html(
    content: str,
    preset: str = "strict",
    raise_on_xss: bool = False,
) -> str:
    """Convenience function for HTML sanitization.

    Args:
        content: HTML content to sanitize
        preset: Sanitization preset (strict, basic, markdown, rich)
        raise_on_xss: Raise exception on XSS detection (default False)

    Returns:
        Sanitized HTML content

    Raises:
        XSSError: If XSS detected and raise_on_xss is True
    """
    validator = HTMLValidator(preset=preset)
    result = validator.validate(content)

    if not result.is_valid:
        if raise_on_xss and result.severity == Severity.CRITICAL:
            raise XSSError(result.error_message or "XSS detected")
        return result.sanitized_value or ""

    return result.sanitized_value or content
