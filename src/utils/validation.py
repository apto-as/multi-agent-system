"""
Unified Validation Utilities for TMWS
Centralized validation functions to avoid duplication

NOTE: sanitize_input and validate_agent_id have been moved to security.validators
for consolidation. Import from there instead.
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

NAMESPACE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")


def validate_namespace(namespace: str, allow_empty: bool = False) -> tuple[bool, list[str]]:
    """
    Validate namespace format.

    Args:
        namespace: Namespace to validate
        allow_empty: Whether to allow empty namespace

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []

    if not namespace:
        if allow_empty:
            return True, []
        issues.append("Namespace cannot be empty")
        return False, issues

    if not isinstance(namespace, str):
        issues.append("Namespace must be a string")
        return False, issues

    if len(namespace) > 32:
        issues.append("Namespace must be at most 32 characters")

    if not NAMESPACE_PATTERN.match(namespace):
        issues.append("Namespace must contain only letters, numbers, hyphens, and underscores")

    # Check for reserved namespaces
    reserved_namespaces = ["system", "admin", "api", "internal"]
    if namespace.lower() in reserved_namespaces:
        issues.append(f"Namespace '{namespace}' is reserved")

    return len(issues) == 0, issues


def validate_email(email: str) -> tuple[bool, list[str]]:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []

    if not email:
        issues.append("Email cannot be empty")
        return False, issues

    # Basic email pattern
    email_pattern = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    if not email_pattern.match(email):
        issues.append("Invalid email format")

    if len(email) > 320:  # RFC 5321 limit
        issues.append("Email address too long")

    return len(issues) == 0, issues


def validate_url(url: str, allowed_schemes: list[str] = None) -> tuple[bool, list[str]]:
    """
    Validate URL format and scheme.

    Args:
        url: URL to validate
        allowed_schemes: List of allowed schemes (default: ['http', 'https'])

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []

    if not url:
        issues.append("URL cannot be empty")
        return False, issues

    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]

    # Basic URL pattern
    url_pattern = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain...
        r"localhost|"  # localhost...
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    if not url_pattern.match(url):
        issues.append("Invalid URL format")

    # Check scheme
    scheme = url.split("://")[0].lower()
    if scheme not in allowed_schemes:
        issues.append(f"URL scheme must be one of: {', '.join(allowed_schemes)}")

    return len(issues) == 0, issues


def validate_json_object(
    obj: Any, max_depth: int = 10, current_depth: int = 0
) -> tuple[bool, list[str]]:
    """
    Validate JSON object structure and prevent deeply nested objects.

    Args:
        obj: Object to validate
        max_depth: Maximum allowed nesting depth
        current_depth: Current nesting depth (internal)

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []

    if current_depth > max_depth:
        issues.append(f"JSON object too deeply nested (max depth: {max_depth})")
        return False, issues

    if isinstance(obj, dict):
        if len(obj) > 100:  # Limit number of keys
            issues.append("Too many keys in JSON object (max: 100)")

        for key, value in obj.items():
            if not isinstance(key, str):
                issues.append("JSON object keys must be strings")
            elif len(key) > 100:  # Limit key length
                issues.append("JSON object key too long (max: 100 characters)")

            # Recursively validate nested objects
            is_valid, nested_issues = validate_json_object(value, max_depth, current_depth + 1)
            if not is_valid:
                issues.extend(nested_issues)

    elif isinstance(obj, list):
        if len(obj) > 1000:  # Limit array size
            issues.append("JSON array too large (max: 1000 items)")

        for item in obj:
            is_valid, nested_issues = validate_json_object(item, max_depth, current_depth + 1)
            if not is_valid:
                issues.extend(nested_issues)

    elif isinstance(obj, str):
        if len(obj) > 10000:  # Limit string length
            issues.append("JSON string too long (max: 10000 characters)")

    return len(issues) == 0, issues


def validate_importance_score(score: float) -> tuple[bool, list[str]]:
    """
    Validate importance score.

    Args:
        score: Importance score to validate

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []

    if not isinstance(score, (int, float)):
        issues.append("Importance score must be a number")
        return False, issues

    if score < 0.0 or score > 1.0:
        issues.append("Importance score must be between 0.0 and 1.0")

    return len(issues) == 0, issues


def validate_priority(priority: str) -> tuple[bool, list[str]]:
    """
    Validate priority value.

    Args:
        priority: Priority to validate

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    issues = []
    valid_priorities = ["low", "medium", "high", "urgent", "critical"]

    if not isinstance(priority, str):
        issues.append("Priority must be a string")
        return False, issues

    if priority.lower() not in valid_priorities:
        issues.append(f"Priority must be one of: {', '.join(valid_priorities)}")

    return len(issues) == 0, issues
