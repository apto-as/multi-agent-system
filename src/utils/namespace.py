"""Namespace detection and validation utilities for TMWS.

Security: Implements automatic project namespace detection to prevent
cross-project memory leakage (addresses CVSS 9.8 vulnerability C-1).
"""

import hashlib
import logging
import os
import re
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


class NamespaceError(Exception):
    """Raised when namespace detection or validation fails."""
    pass


def sanitize_namespace(raw_namespace: str) -> str:
    """Sanitize namespace to ensure it's safe for storage.

    Rules:
    - Only alphanumeric, hyphens, underscores, dots, slashes
    - Max 128 characters
    - No leading/trailing whitespace
    - Lowercase only

    Args:
        raw_namespace: Raw namespace string to sanitize

    Returns:
        Sanitized namespace string

    Raises:
        NamespaceError: If namespace cannot be sanitized

    """
    if not raw_namespace or not raw_namespace.strip():
        raise NamespaceError("Namespace cannot be empty")

    # Security: Check for path traversal sequences BEFORE sanitization (V-1 fix)
    # This prevents bypass attacks like "../../../secrets" → "secrets"
    if ".." in raw_namespace:
        raise NamespaceError(
            f"Namespace '{raw_namespace}' contains path traversal pattern (..). "
            "This is not allowed for security reasons."
        )

    if "/" in raw_namespace:
        raise NamespaceError(
            f"Namespace '{raw_namespace}' contains path separator (/). "
            "This is not allowed for security reasons."
        )

    # Remove whitespace and convert to lowercase
    namespace = raw_namespace.strip().lower()

    # Replace invalid characters with hyphens
    # Security: Block . and / to prevent path traversal (V-1 fix)
    namespace = re.sub(r'[^a-z0-9\-_]', '-', namespace)

    # Remove consecutive hyphens
    namespace = re.sub(r'-+', '-', namespace)

    # Remove leading/trailing hyphens
    namespace = namespace.strip('-')

    # Enforce max length
    if len(namespace) > 128:
        namespace = namespace[:128]

    if not namespace:
        raise NamespaceError("Sanitized namespace is empty")

    return namespace


def validate_namespace(namespace: str) -> None:
    """Validate namespace for security requirements.

    Security checks:
    - Must not be "default" (prevents cross-project leakage)
    - Must be non-empty
    - Must be sanitized

    Args:
        namespace: Namespace to validate

    Raises:
        NamespaceError: If validation fails

    """
    if not namespace or not namespace.strip():
        raise NamespaceError("Namespace cannot be empty")

    if namespace.lower() == "default":
        raise NamespaceError(
            "Namespace 'default' is not allowed for security reasons. "
            "Use explicit project-specific namespace instead.",
        )

    # Security: Reject path traversal sequences (V-1 fix)
    if ".." in namespace or namespace.startswith("/"):
        raise NamespaceError(
            f"Namespace '{namespace}' contains invalid path sequences. "
            "Path traversal patterns (.., /) are not allowed for security reasons.",
        )

    # Check if sanitized (should match sanitize output)
    try:
        sanitized = sanitize_namespace(namespace)
        if sanitized != namespace:
            raise NamespaceError(
                f"Namespace '{namespace}' is not properly sanitized. "
                f"Use '{sanitized}' instead.",
            )
    except NamespaceError as e:
        raise NamespaceError(f"Invalid namespace: {e}")


async def detect_git_root(start_path: Path | None = None) -> Path | None:
    """Detect git repository root directory.

    Args:
        start_path: Starting directory (defaults to cwd)

    Returns:
        Path to git root, or None if not in git repo

    """
    if start_path is None:
        start_path = Path.cwd()

    current = start_path.resolve()

    # Walk up directory tree looking for .git
    while current != current.parent:
        git_dir = current / ".git"
        if git_dir.exists():
            return current
        current = current.parent

    return None


async def get_git_remote_url(git_root: Path) -> str | None:
    """Get git remote URL from repository.

    Args:
        git_root: Path to git repository root

    Returns:
        Remote URL, or None if not found

    """
    git_config = git_root / ".git" / "config"

    if not git_config.exists():
        return None

    try:
        with open(git_config) as f:
            content = f.read()

        # Extract remote origin URL
        match = re.search(r'url\s*=\s*(.+)', content)
        if match:
            return match.group(1).strip()
    except OSError as e:
        # File read errors (permissions, not found after check, etc.)
        logger.debug(f"Could not read git config {git_config}: {e}")

    return None


def namespace_from_git_url(git_url: str) -> str:
    """Convert git remote URL to namespace.

    Examples:
        git@github.com:apto-as/tmws.git -> github.com/apto-as/tmws
        https://github.com/apto-as/tmws -> github.com/apto-as/tmws

    Args:
        git_url: Git remote URL

    Returns:
        Namespace derived from URL

    """
    # Remove .git suffix
    url = git_url.rstrip("/").removesuffix(".git")

    # Handle SSH format: git@github.com:user/repo
    if url.startswith("git@"):
        url = url.replace("git@", "").replace(":", "/")

    # Handle HTTPS format: https://github.com/user/repo
    elif url.startswith("https://") or url.startswith("http://"):
        url = url.split("://", 1)[1]

    # Pre-process: Replace / with - BEFORE sanitize (V-1 fix)
    # This allows git URLs to work while still blocking path traversal
    url = url.replace("/", "-")

    return sanitize_namespace(url)


async def find_marker_file(filename: str = ".trinitas-project.yaml", start_path: Path | None = None) -> Path | None:
    """Find project marker file by walking up directory tree.

    Args:
        filename: Marker filename to search for
        start_path: Starting directory (defaults to cwd)

    Returns:
        Path to marker file, or None if not found

    """
    if start_path is None:
        start_path = Path.cwd()

    current = start_path.resolve()

    while current != current.parent:
        marker = current / filename
        if marker.exists():
            return marker
        current = current.parent

    return None


async def detect_project_namespace() -> str:
    """Auto-detect project namespace from environment.

    Detection priority (fastest → slowest):
    1. Environment variable TRINITAS_PROJECT_NAMESPACE (0.001ms)
    2. Git repository root + remote URL (1-5ms)
    3. Marker file .trinitas-project.yaml (5-10ms)
    4. Current working directory hash (0.01ms) - fallback

    Returns:
        Detected namespace string

    Raises:
        NamespaceError: If detection fails completely

    """
    # Priority 1: Environment variable
    if env_namespace := os.getenv("TRINITAS_PROJECT_NAMESPACE"):
        namespace = sanitize_namespace(env_namespace)
        validate_namespace(namespace)
        return namespace

    # Priority 2: Git repository
    if git_root := await detect_git_root():
        if git_url := await get_git_remote_url(git_root):
            namespace = namespace_from_git_url(git_url)
            validate_namespace(namespace)
            return namespace

        # Fallback: Use git root directory name
        namespace = sanitize_namespace(git_root.name)
        validate_namespace(namespace)
        return namespace

    # Priority 3: Marker file
    if marker := await find_marker_file():
        try:
            with open(marker) as f:
                config = yaml.safe_load(f)

            if namespace := config.get("namespace"):
                namespace = sanitize_namespace(namespace)
                validate_namespace(namespace)
                return namespace
        except (OSError, yaml.YAMLError, NamespaceError) as e:
            # File read errors, YAML parse errors, or validation errors
            logger.debug(f"Could not load namespace from marker file {marker}: {e}")

    # Priority 4: Current working directory hash (fallback)
    cwd = Path.cwd().resolve()
    cwd_hash = hashlib.sha256(str(cwd).encode()).hexdigest()[:16]
    namespace = f"project_{cwd_hash}"

    # Log warning for fallback
    logger.warning(
        f"No project namespace detected. Using cwd hash: {namespace}. "
        f"Set TRINITAS_PROJECT_NAMESPACE environment variable or create "
        f".trinitas-project.yaml for explicit namespace.",
    )

    return namespace
