"""Tool Metadata Schema - V-DISC-2 Security Fix

Pydantic schema for validating tool metadata to prevent:
- JSON injection attacks (CWE-20)
- XSS via stored metadata (CWE-79)
- Arbitrary field injection

Security Requirements:
- All fields must be explicitly defined (no arbitrary JSON)
- HTML/script tags must be sanitized
- Field lengths must be bounded
- Unknown fields must be rejected

Phase: 4-Day1 (TMWS v2.3.0)
Vulnerability: V-DISC-2 (CVSS 8.1 HIGH)
Fix Date: 2025-11-22
"""

import bleach
from pydantic import BaseModel, Field, constr, field_validator


class ToolMetadata(BaseModel):
    """
    Validated tool metadata schema (V-DISC-2 fix).

    Enforces strict validation and HTML sanitization to prevent
    JSON injection and XSS attacks.

    Security Features:
    - Bounded string lengths (DoS prevention)
    - HTML sanitization (XSS prevention)
    - Tag count limits (DoS prevention)
    - Unknown field rejection (injection prevention)

    Example:
        metadata = ToolMetadata(
            description="A tool for data processing",
            author="Artemis",
            license="MIT",
            tags=["data", "processing", "analytics"]
        )
    """

    description: constr(max_length=500)
    """Tool description (max 500 chars, HTML sanitized)"""

    author: constr(max_length=100) | None = None
    """Tool author name (max 100 chars, HTML sanitized)"""

    license: constr(max_length=50) | None = None
    """License identifier (max 50 chars, HTML sanitized)"""

    tags: list[constr(max_length=30)] = Field(default_factory=list, max_length=10)
    """Tool tags (max 10 tags, 30 chars each, HTML sanitized)"""

    @field_validator("description", "author", "license")
    @classmethod
    def sanitize_html(cls, v: str | None) -> str | None:
        """
        Escape all HTML tags to prevent XSS attacks.

        Security: V-DISC-2 - XSS prevention via HTML entity escaping

        Args:
            v: Input string (may contain malicious HTML/JavaScript)

        Returns:
            Sanitized string with HTML tags escaped as entities

        Example:
            Input:  "<script>alert('XSS')</script>Hello"
            Output: "&lt;script&gt;alert('XSS')&lt;/script&gt;Hello"

        Note: strip=False (default) escapes tags as HTML entities,
              which is safe to store and display in web browsers.
        """
        if v is None:
            return v
        # bleach.clean with tags=[] and strip=False (default) escapes all HTML
        # This prevents XSS by converting < and > to &lt; and &gt;
        return bleach.clean(
            v,
            tags=[],  # No tags allowed
            attributes={},  # No attributes allowed
            strip=False,  # Escape tags (don't remove content)
        )

    @field_validator("tags")
    @classmethod
    def sanitize_tags(cls, v: list[str]) -> list[str]:
        """
        Escape HTML in each tag.

        Security: V-DISC-2 - XSS prevention in tag arrays

        Args:
            v: List of tags (may contain malicious HTML)

        Returns:
            List of sanitized tags with HTML escaped

        Example:
            Input:  ["<script>alert(1)</script>", "valid-tag"]
            Output: ["&lt;script&gt;alert(1)&lt;/script&gt;", "valid-tag"]
        """
        return [bleach.clean(tag, tags=[], attributes={}, strip=False) for tag in v]

    model_config = {
        "extra": "forbid",  # Reject unknown fields (injection prevention)
        "str_strip_whitespace": True,  # Strip leading/trailing whitespace
        "validate_assignment": True,  # Validate on attribute assignment
    }
