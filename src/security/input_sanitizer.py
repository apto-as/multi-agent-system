"""Input Sanitization Utilities for TMWS v2.4.12

Provides security utilities for input validation and sanitization:
- V-REDOS-1: Regex pattern validation (prevent ReDoS)
- V-REDOS-2: Regex complexity limits
- V-XSS-1: HTML/Markdown content sanitization
- V-INJECT-1: General input sanitization

Security:
- CWE-1333: ReDoS prevention
- CWE-79: XSS prevention
- CWE-20: Input validation

Performance:
- Pattern validation: < 1ms
- Content sanitization: < 5ms for 10KB content
"""

import html
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# V-REDOS-1/2: Regex Validation Constants
# =============================================================================

# Maximum allowed pattern length
MAX_PATTERN_LENGTH = 200

# Maximum allowed repetition count in patterns
MAX_REPETITION = 20

# Disallowed dangerous patterns (ReDoS vectors)
DANGEROUS_PATTERNS = frozenset(
    [
        r".*",  # Unbounded wildcard
        r".+",  # Unbounded one-or-more
        r"[\s\S]*",  # Match everything
        r"[\s\S]+",  # Match everything one-or-more
        r"(?:.*)*",  # Nested unbounded
        r"(?:.+)+",  # Nested unbounded
        r"(a+)+",  # Exponential backtracking
        r"(a*)*",  # Exponential backtracking
        r"([a-zA-Z]+)*",  # Exponential on word boundaries
    ]
)

# Patterns that indicate potential ReDoS
REDOS_INDICATORS = [
    r"\(\?:[^)]*\*\)\*",  # (?:...*)*
    r"\(\?:[^)]*\+\)\+",  # (?:...+)+
    r"\([^)]*\*\)\*",  # (...*)*
    r"\([^)]*\+\)\+",  # (...+)+
    r"\[[^\]]*\]\*\*",  # [...]**
    r"\[[^\]]*\]\+\+",  # [...]+++
]


# =============================================================================
# V-XSS-1: Content Sanitization Constants
# =============================================================================

# HTML tags to strip (not escape)
DANGEROUS_HTML_TAGS = [
    "script",
    "iframe",
    "object",
    "embed",
    "form",
    "input",
    "button",
    "textarea",
    "select",
    "style",
    "link",
    "meta",
    "base",
    "applet",
    "frame",
    "frameset",
]

# Dangerous attributes to remove
DANGEROUS_ATTRIBUTES = [
    "onclick",
    "onload",
    "onerror",
    "onmouseover",
    "onfocus",
    "onblur",
    "onchange",
    "onsubmit",
    "onreset",
    "onselect",
    "onkeydown",
    "onkeyup",
    "onkeypress",
    "ondblclick",
    "javascript:",
    "vbscript:",
    "data:",
    "expression",
]


# =============================================================================
# V-REDOS-1: Regex Pattern Validation
# =============================================================================


class RegexValidationError(Exception):
    """Raised when a regex pattern fails validation."""

    pass


def validate_regex_pattern(
    pattern: str,
    max_length: int = MAX_PATTERN_LENGTH,
    allow_unbounded: bool = False,
) -> tuple[bool, str | None]:
    """Validate a regex pattern for safety (ReDoS prevention).

    Args:
        pattern: Regex pattern string to validate
        max_length: Maximum allowed pattern length
        allow_unbounded: Whether to allow unbounded quantifiers (dangerous)

    Returns:
        Tuple of (is_valid, error_message)

    Security:
        - CWE-1333: Prevents ReDoS via pattern complexity limits
        - V-REDOS-1: Blocks dangerous wildcard patterns
        - V-REDOS-2: Enforces complexity limits
    """
    # Length check
    if len(pattern) > max_length:
        return False, f"Pattern exceeds maximum length ({len(pattern)} > {max_length})"

    # Empty pattern check
    if not pattern or not pattern.strip():
        return False, "Pattern cannot be empty"

    # Check for dangerous patterns
    if pattern in DANGEROUS_PATTERNS:
        return False, f"Pattern '{pattern}' is a known ReDoS vector"

    # Check for unbounded quantifiers without allow flag
    if not allow_unbounded:
        # Check for .* or .+ without length limits
        if re.search(r"(?<!\\)\.\*(?!\?)(?!\{)", pattern):
            return False, "Unbounded .* pattern detected. Use .{0,N} with explicit limit"
        if re.search(r"(?<!\\)\.\+(?!\?)(?!\{)", pattern):
            return False, "Unbounded .+ pattern detected. Use .{1,N} with explicit limit"

    # Check for nested quantifiers (exponential backtracking)
    for indicator in REDOS_INDICATORS:
        if re.search(indicator, pattern):
            return False, "Nested quantifier pattern detected (potential ReDoS)"

    # Try to compile the pattern
    try:
        compiled = re.compile(pattern)
        # Check for excessive groups
        if compiled.groups > 10:
            return False, f"Too many capture groups ({compiled.groups} > 10)"
    except re.error as e:
        return False, f"Invalid regex syntax: {e}"

    return True, None


def compile_safe_regex(
    pattern: str,
    flags: int = 0,
    timeout_hint: bool = True,
) -> re.Pattern:
    """Compile a regex pattern after safety validation.

    Args:
        pattern: Regex pattern string
        flags: Regex flags (re.IGNORECASE, etc.)
        timeout_hint: Log warning about timeout consideration

    Returns:
        Compiled regex Pattern object

    Raises:
        RegexValidationError: If pattern fails validation

    Example:
        pattern = compile_safe_regex(r"\\b(optimize|improve)\\w{0,10}\\b", re.IGNORECASE)
        if pattern.search(user_input):
            # Safe to use
    """
    is_valid, error = validate_regex_pattern(pattern)
    if not is_valid:
        raise RegexValidationError(error)

    compiled = re.compile(pattern, flags)

    if timeout_hint:
        logger.debug(f"Compiled safe regex: {pattern[:50]}...")

    return compiled


def sanitize_regex_input(
    pattern: str,
    max_length: int = MAX_PATTERN_LENGTH,
) -> str:
    """Sanitize a user-provided regex pattern.

    Converts dangerous patterns to safer alternatives:
    - .* -> .{0,100}
    - .+ -> .{1,100}
    - Escapes special characters in suspicious contexts

    Args:
        pattern: User-provided pattern
        max_length: Maximum pattern length

    Returns:
        Sanitized pattern string
    """
    # Truncate if too long
    if len(pattern) > max_length:
        pattern = pattern[:max_length]
        logger.warning(f"Truncated regex pattern to {max_length} chars")

    # Replace unbounded .* with bounded version
    pattern = re.sub(r"(?<!\\)\.\*(?!\?)", ".{0,100}", pattern)

    # Replace unbounded .+ with bounded version
    pattern = re.sub(r"(?<!\\)\.\+(?!\?)", ".{1,100}", pattern)

    # Replace [\s\S]* with bounded version
    pattern = re.sub(r"\[\\s\\S\]\*", r"[\\s\\S]{0,100}", pattern)

    return pattern


# =============================================================================
# V-XSS-1: Content Sanitization
# =============================================================================


def sanitize_html(content: str, allow_basic_formatting: bool = True) -> str:
    """Sanitize HTML content to prevent XSS.

    Args:
        content: HTML content to sanitize
        allow_basic_formatting: Keep safe tags like <b>, <i>, <code>

    Returns:
        Sanitized HTML string

    Security:
        - CWE-79: Prevents XSS via tag/attribute stripping
        - V-XSS-1: Sanitizes generated skill content
    """
    if not content:
        return content

    # First, escape all HTML entities
    sanitized = html.escape(content)

    # If allowing basic formatting, unescape safe tags
    if allow_basic_formatting:
        safe_tags = ["b", "i", "u", "em", "strong", "code", "pre", "br"]
        for tag in safe_tags:
            # Restore opening tags
            sanitized = sanitized.replace(f"&lt;{tag}&gt;", f"<{tag}>")
            sanitized = sanitized.replace(f"&lt;/{tag}&gt;", f"</{tag}>")

    return sanitized


def sanitize_markdown(content: str) -> str:
    """Sanitize Markdown content for safe rendering.

    Args:
        content: Markdown content to sanitize

    Returns:
        Sanitized Markdown string

    Security:
        - Removes HTML tags embedded in Markdown
        - Prevents script injection via links
        - V-XSS-1: For generated skill content
    """
    if not content:
        return content

    sanitized = content

    # Remove HTML tags (Markdown should use Markdown syntax)
    for tag in DANGEROUS_HTML_TAGS:
        # Remove opening and closing tags
        sanitized = re.sub(
            rf"<{tag}[^>]*>.*?</{tag}>", "", sanitized, flags=re.IGNORECASE | re.DOTALL
        )
        # Remove self-closing tags
        sanitized = re.sub(rf"<{tag}[^>]*/?>", "", sanitized, flags=re.IGNORECASE)

    # Remove javascript: links
    sanitized = re.sub(
        r"\[([^\]]*)\]\(javascript:[^)]*\)", r"[\1](#removed)", sanitized, flags=re.IGNORECASE
    )

    # Remove data: links (potential XSS vector)
    sanitized = re.sub(
        r"\[([^\]]*)\]\(data:[^)]*\)", r"[\1](#removed)", sanitized, flags=re.IGNORECASE
    )

    # Remove on* event handlers in any remaining HTML-like content
    for attr in DANGEROUS_ATTRIBUTES:
        sanitized = re.sub(rf'{attr}\s*=\s*["\'][^"\']*["\']', "", sanitized, flags=re.IGNORECASE)

    return sanitized


# =============================================================================
# V-INJECT-1: General Input Sanitization
# =============================================================================


def sanitize_string(
    value: str,
    max_length: int = 1000,
    allow_newlines: bool = True,
    strip_control_chars: bool = True,
) -> str:
    """Sanitize a general string input.

    Args:
        value: String to sanitize
        max_length: Maximum allowed length
        allow_newlines: Whether to preserve newline characters
        strip_control_chars: Remove ASCII control characters

    Returns:
        Sanitized string

    Security:
        - V-INJECT-1: Prevents injection via control characters
        - Enforces length limits
    """
    if not value:
        return value

    sanitized = value

    # Truncate if too long
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
        logger.warning(f"Truncated input string to {max_length} chars")

    # Strip control characters (except newlines/tabs if allowed)
    if strip_control_chars:
        if allow_newlines:
            # Keep \n, \r, \t but remove other control chars
            sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", sanitized)
        else:
            # Remove all control characters including newlines
            sanitized = re.sub(r"[\x00-\x1f\x7f]", "", sanitized)

    # Normalize Unicode (prevent homograph attacks)
    import unicodedata

    sanitized = unicodedata.normalize("NFKC", sanitized)

    return sanitized


def sanitize_identifier(
    value: str,
    max_length: int = 100,
    allow_dots: bool = False,
    allow_hyphens: bool = True,
) -> str:
    """Sanitize an identifier (agent_id, namespace, etc.).

    Args:
        value: Identifier to sanitize
        max_length: Maximum allowed length
        allow_dots: Whether to allow dots in identifier
        allow_hyphens: Whether to allow hyphens in identifier

    Returns:
        Sanitized identifier

    Security:
        - V-INJECT-1: Prevents path traversal via identifiers
        - Enforces safe character set
    """
    if not value:
        return value

    # Build allowed character pattern
    allowed = r"a-zA-Z0-9_"
    if allow_hyphens:
        allowed += r"-"
    if allow_dots:
        allowed += r"."

    # Remove disallowed characters
    sanitized = re.sub(f"[^{allowed}]", "", value)

    # Truncate
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    # Prevent empty result
    if not sanitized:
        sanitized = "unnamed"

    return sanitized


def sanitize_dict(
    data: dict[str, Any],
    string_max_length: int = 1000,
    max_depth: int = 10,
    current_depth: int = 0,
) -> dict[str, Any]:
    """Recursively sanitize all string values in a dictionary.

    Args:
        data: Dictionary to sanitize
        string_max_length: Maximum length for string values
        max_depth: Maximum recursion depth
        current_depth: Current recursion depth (internal)

    Returns:
        Sanitized dictionary
    """
    if current_depth >= max_depth:
        logger.warning(f"Max sanitization depth reached ({max_depth})")
        return data

    result = {}
    for key, value in data.items():
        # Sanitize key
        safe_key = sanitize_identifier(str(key))

        # Sanitize value based on type
        if isinstance(value, str):
            result[safe_key] = sanitize_string(value, max_length=string_max_length)
        elif isinstance(value, dict):
            result[safe_key] = sanitize_dict(value, string_max_length, max_depth, current_depth + 1)
        elif isinstance(value, list):
            result[safe_key] = [
                sanitize_dict(item, string_max_length, max_depth, current_depth + 1)
                if isinstance(item, dict)
                else sanitize_string(str(item), max_length=string_max_length)
                if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            result[safe_key] = value

    return result
