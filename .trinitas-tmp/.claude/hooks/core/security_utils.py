#!/usr/bin/env python3
"""
security_utils.py - Security Utility Functions
===============================================

Provides security validation functions for:
- Path traversal prevention (CWE-22)
- SSRF prevention (CWE-918)
- Input sanitization
- Secret redaction
- Log injection prevention (CWE-117)
"""

import re
import unicodedata
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
import ipaddress


class SecurityError(Exception):
    """Base exception for security violations"""
    pass


class PathTraversalError(SecurityError):
    """Path traversal attempt detected"""
    pass


class SSRFError(SecurityError):
    """SSRF attack attempt detected"""
    pass


def validate_decision_id(decision_id: str) -> str:
    """
    Validate decision ID for safe filesystem use

    Args:
        decision_id: Decision ID to validate

    Returns:
        str: Validated decision ID

    Raises:
        ValueError: If decision ID is invalid

    Security: CWE-22 (Path Traversal)
    """
    # 1. Only allow alphanumeric, dash, underscore
    if not re.match(r'^[a-zA-Z0-9_-]+$', decision_id):
        raise ValueError(f"Invalid decision ID: {decision_id}")

    # 2. Length limit
    if len(decision_id) > 64:
        raise ValueError(f"Decision ID too long: {len(decision_id)}")

    # 3. No path separators (redundant but explicit)
    if '/' in decision_id or '\\' in decision_id:
        raise ValueError(f"Path separators not allowed: {decision_id}")

    return decision_id


def validate_and_resolve_path(
    file_path: Path,
    base_dir: Path,
    allow_create: bool = False
) -> Path:
    """
    Validate file path and resolve to prevent traversal

    Args:
        file_path: Path to validate
        base_dir: Base directory (all paths must be under this)
        allow_create: Whether to create the path if it doesn't exist

    Returns:
        Path: Validated resolved path

    Raises:
        PathTraversalError: If path traversal detected
        SecurityError: If symlink detected

    Security: CWE-22, CWE-61
    """
    # 1. Resolve symlinks
    base_resolved = base_dir.resolve()

    # 2. Check if file_path is symlink (before resolution)
    if file_path.exists() and file_path.is_symlink():
        raise SecurityError(f"Symlink access denied (CWE-61): {file_path}")

    # 3. Resolve file path
    file_resolved = file_path.resolve()

    # 4. Ensure path is under base_dir
    try:
        file_resolved.relative_to(base_resolved)
    except ValueError:
        raise PathTraversalError(
            f"Path traversal attempt (CWE-22): {file_resolved} not under {base_resolved}"
        )

    # 5. Create if requested
    if allow_create and not file_resolved.exists():
        file_resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    return file_resolved


def validate_tmws_url(url: str, allow_localhost: bool = True) -> str:
    """
    Validate TMWS URL for SSRF protection

    Args:
        url: URL to validate
        allow_localhost: Whether to allow localhost URLs

    Returns:
        str: Validated URL

    Raises:
        SSRFError: If SSRF risk detected

    Security: CWE-918 (SSRF)
    """
    parsed = urlparse(url)

    # 1. Only allow http/https
    if parsed.scheme not in ('http', 'https'):
        raise SSRFError(f"Invalid scheme: {parsed.scheme}")

    # 2. Require hostname
    if not parsed.hostname:
        raise SSRFError("Hostname required")

    # 3. Block private IP ranges
    try:
        ip = ipaddress.ip_address(parsed.hostname)

        # Check for private/loopback/link-local
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            # Only allow localhost for development
            if allow_localhost and str(ip) in ('127.0.0.1', '::1'):
                pass  # Allow
            else:
                raise SSRFError(f"Private IP not allowed: {ip}")

        # Block reserved ranges
        if ip.is_reserved:
            raise SSRFError(f"Reserved IP not allowed: {ip}")

    except ValueError:
        # Hostname (not IP) - block suspicious hosts
        blocked_hosts = [
            'metadata.google.internal',
            '169.254.169.254',
            'metadata.goog',
            'metadata',
        ]

        if parsed.hostname in blocked_hosts:
            raise SSRFError(f"Blocked hostname: {parsed.hostname}")

        # Block localhost aliases
        if not allow_localhost and parsed.hostname in ('localhost', '127.0.0.1', '::1'):
            raise SSRFError("Localhost not allowed")

    # 4. Port whitelist (optional, can be relaxed)
    if parsed.port:
        allowed_ports = [80, 443, 8000, 8080]
        if parsed.port not in allowed_ports:
            raise SSRFError(f"Non-standard port: {parsed.port}")

    return url


def sanitize_prompt(prompt: str, max_length: int = 1000) -> str:
    """
    Comprehensive prompt sanitization

    Args:
        prompt: Raw prompt text
        max_length: Maximum length

    Returns:
        str: Sanitized prompt

    Security: Input validation, injection prevention
    """
    if not isinstance(prompt, str):
        return ""

    # 1. Remove all control characters (including \n, \r, \t, \0)
    sanitized = ''.join(
        char for char in prompt
        if unicodedata.category(char)[0] != 'C'  # Remove all control chars
    )

    # 2. Normalize Unicode (NFC form)
    sanitized = unicodedata.normalize('NFC', sanitized)

    # 3. Strip and collapse whitespace
    sanitized = ' '.join(sanitized.split())

    # 4. Length limit
    return sanitized[:max_length]


def redact_secrets(text: str) -> str:
    """
    Redact potential secrets from text

    Args:
        text: Text to redact

    Returns:
        str: Text with secrets redacted

    Security: Secret sanitization, information disclosure prevention
    """
    patterns = [
        # OpenAI API keys
        (r'\b(sk-[a-zA-Z0-9]{20,})\b', '[REDACTED_API_KEY]'),

        # Generic long tokens (32+ chars)
        (r'\b([a-zA-Z0-9]{32,})\b', '[REDACTED_TOKEN]'),

        # Passwords
        (r'\b(password|passwd|pwd)[\s:=]+\S+', r'\1=[REDACTED]'),

        # SHA256/SHA512 hashes
        (r'\b([a-f0-9]{64,})\b', '[REDACTED_HASH]'),

        # AWS access keys
        (r'\b(AKIA[0-9A-Z]{16})\b', '[REDACTED_AWS_KEY]'),

        # JWT tokens
        (r'\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b', '[REDACTED_JWT]'),

        # Generic secrets
        (r'\b(secret|token|key)[\s:=]+\S+', r'\1=[REDACTED]'),
    ]

    redacted = text
    for pattern, replacement in patterns:
        redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)

    return redacted


def sanitize_log_message(msg: str, max_length: int = 500) -> str:
    """
    Sanitize log message to prevent injection

    Args:
        msg: Log message
        max_length: Maximum length

    Returns:
        str: Sanitized log message

    Security: CWE-117 (Log Injection)
    """
    # Remove newlines and control characters
    sanitized = msg.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')

    # Remove other control characters
    sanitized = ''.join(
        char for char in sanitized
        if unicodedata.category(char)[0] != 'C'
    )

    # Length limit
    return sanitized[:max_length]


def safe_json_parse(json_str: str, max_size: int = 10_000, max_depth: int = 10) -> dict:
    """
    Safely parse JSON with size and depth limits

    Args:
        json_str: JSON string
        max_size: Maximum size in bytes
        max_depth: Maximum nesting depth

    Returns:
        dict: Parsed JSON

    Raises:
        ValueError: If JSON is too large, too deep, or invalid

    Security: CWE-502 (Deserialization), CWE-400 (Resource Exhaustion)
    """
    import json

    # 1. Size check
    if len(json_str) > max_size:
        raise ValueError(f"JSON too large: {len(json_str)} bytes (max: {max_size})")

    # 2. Parse
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")

    # 3. Depth check
    def check_depth(obj, depth=0):
        if depth > max_depth:
            raise ValueError(f"JSON too deeply nested: >{max_depth} levels")

        if isinstance(obj, dict):
            for v in obj.values():
                check_depth(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                check_depth(item, depth + 1)

    check_depth(data)
    return data
