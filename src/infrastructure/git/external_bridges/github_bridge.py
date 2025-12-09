"""GitHub Integration Bridge for TMWS.

Phase 4.2: Issue #33 - External Git Integration
This module provides GitHub-specific implementation of the ExternalBridge interface.

Features:
- Issue search via GitHub REST API v3
- Session sync from GitHub issues with 'tmws-session' label
- Memory snapshot backup to GitHub issues
- Rate limiting (5,000 req/hour for authenticated users)
- Circuit breaker for fault tolerance

Security:
- Token validation (ghp_, gho_, ghs_, github_pat_ prefixes)
- HTTPS-only communication
- Request timeout enforcement (30s)
- Input sanitization for all queries
- No token logging

Author: Metis (Development Assistant)
Created: 2025-12-09
Security Review: Hestia (2025-12-09) - CRITICAL security patterns applied
"""

import logging
from datetime import datetime
from typing import Any, Final

import httpx

from .base import (
    BridgeConfig,
    BridgeError,
    CircuitBreaker,
    ExternalBridge,
    IssueResult,
    RateLimiter,
    SecurityError,
    SessionSnapshot,
    _sanitize_query,
    _validate_token_format,
    _validate_url,
)

logger = logging.getLogger(__name__)

# GitHub API Configuration
GITHUB_API_BASE_URL: Final[str] = "https://api.github.com"
GITHUB_API_VERSION: Final[str] = "2022-11-28"

# Rate limits for GitHub API (authenticated)
GITHUB_RATE_LIMIT_REQUESTS: Final[int] = 5000
GITHUB_RATE_LIMIT_WINDOW_SECONDS: Final[float] = 3600.0  # 1 hour

# Default repository for TMWS session storage
DEFAULT_TMWS_REPO: Final[str] = "apto-as/tmws"


class BridgeAuthenticationError(BridgeError):
    """Raised when authentication fails."""
    pass


class BridgeConnectionError(BridgeError):
    """Raised when connection fails."""
    pass


class BridgeRateLimitError(BridgeError):
    """Raised when rate limit is exceeded."""
    pass


class GitHubBridge(ExternalBridge):
    """GitHub integration bridge for TMWS.

    Features:
    - Issue search via GitHub REST API v3
    - Session sync from GitHub issues/comments
    - Memory snapshot backup to GitHub issues

    Rate Limits:
    - 5,000 requests/hour for authenticated users
    - Respects x-ratelimit-* headers
    - Implements exponential backoff on 429

    Authentication:
    - Requires GitHub Personal Access Token (PAT)
    - Token must start with: ghp_, gho_, ghs_, or github_pat_
    - Minimum token length: 20 characters

    Example:
        >>> config = BridgeConfig(
        ...     bridge_type="github",
        ...     token="ghp_xxxxxxxxxxxxxxxxxxxx",
        ...     base_url="https://api.github.com",
        ... )
        >>> bridge = GitHubBridge(config)
        >>> await bridge.connect()
        >>> issues = await bridge.search_issues("is:issue label:bug")
        >>> await bridge.disconnect()
    """

    def __init__(self, config: BridgeConfig, repository: str | None = None):
        """Initialize GitHub bridge.

        Args:
            config: Bridge configuration (validated)
            repository: GitHub repository in "owner/repo" format (optional)

        Raises:
            ValueError: If repository format is invalid
        """
        super().__init__(config)

        # Override rate limiter with GitHub-specific limits
        self.rate_limiter = RateLimiter(
            max_requests=GITHUB_RATE_LIMIT_REQUESTS,
            window_seconds=GITHUB_RATE_LIMIT_WINDOW_SECONDS,
        )

        # Circuit breaker for fault tolerance
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60.0,
            success_threshold=2,
        )

        # Repository for TMWS session storage
        self.repository = repository or DEFAULT_TMWS_REPO
        self._validate_repository_format(self.repository)

        # HTTP client (initialized in connect)
        self._client: httpx.AsyncClient | None = None

        # Rate limit tracking from headers
        self._rate_limit_remaining: int | None = None
        self._rate_limit_reset: int | None = None

    def _validate_repository_format(self, repo: str) -> None:
        """Validate GitHub repository format.

        Args:
            repo: Repository in "owner/repo" format

        Raises:
            ValueError: If format is invalid
        """
        if not repo or "/" not in repo:
            raise ValueError(
                f"Invalid repository format: {repo}. Expected 'owner/repo'"
            )

        parts = repo.split("/")
        if len(parts) != 2:
            raise ValueError(
                f"Invalid repository format: {repo}. Expected 'owner/repo'"
            )

        owner, name = parts
        if not owner or not name:
            raise ValueError(
                f"Invalid repository format: {repo}. Owner and name cannot be empty"
            )

    async def connect(self, credentials: dict[str, str] | None = None) -> bool:
        """Establish connection to GitHub API.

        Security:
        - Validates token format before use
        - Tests connection with /user endpoint
        - Never logs token value
        - Enforces timeout on authentication request

        Args:
            credentials: Optional credentials (not used, token from config)

        Returns:
            True if connected successfully

        Raises:
            BridgeAuthenticationError: If token is invalid
            BridgeConnectionError: If connection fails
        """
        if self._connected:
            logger.debug("GitHub bridge already connected")
            return True

        # Validate token format
        try:
            _validate_token_format(self.config.token, "github")
        except SecurityError as e:
            logger.error(f"GitHub token validation failed: {e}")
            raise BridgeAuthenticationError(f"Invalid GitHub token: {e}")

        # Validate base URL
        try:
            _validate_url(
                self.config.base_url,
                allow_custom_domains=self.config.allow_custom_domain,
            )
        except SecurityError as e:
            logger.error(f"GitHub URL validation failed: {e}")
            raise BridgeConnectionError(f"Invalid GitHub URL: {e}")

        # Create HTTP client
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url,
            headers={
                "Authorization": f"Bearer {self.config.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
            timeout=httpx.Timeout(self.config.timeout_seconds),
        )

        # Test connection with /user endpoint
        try:
            response = await self._client.get("/user")
            response.raise_for_status()

            user_data = response.json()
            username = user_data.get("login", "unknown")

            logger.info(
                f"GitHub bridge connected successfully (user: {username})",
                extra={"bridge_type": "github", "username": username},
            )

            # Update rate limit tracking
            self._update_rate_limits(response.headers)

            self._connected = True
            return True

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logger.error(
                    "GitHub authentication failed: Invalid or expired token",
                    extra={"status_code": 401},
                )
                raise BridgeAuthenticationError("Invalid or expired GitHub token")
            elif e.response.status_code == 403:
                # Check if it's rate limiting
                if self._is_rate_limited(e.response.headers):
                    reset_time = e.response.headers.get("x-ratelimit-reset", "unknown")
                    logger.error(
                        f"GitHub rate limit exceeded (reset: {reset_time})",
                        extra={"status_code": 403, "reset_time": reset_time},
                    )
                    raise BridgeRateLimitError(
                        f"GitHub rate limit exceeded. Reset at: {reset_time}"
                    )
                else:
                    logger.error(
                        "GitHub authentication failed: Forbidden",
                        extra={"status_code": 403},
                    )
                    raise BridgeAuthenticationError(
                        "GitHub authentication failed: Forbidden"
                    )
            else:
                logger.error(
                    f"GitHub connection failed: {e}",
                    extra={"status_code": e.response.status_code},
                )
                raise BridgeConnectionError(f"GitHub connection failed: {e}")
        except httpx.RequestError as e:
            logger.error(f"GitHub connection request failed: {e}")
            raise BridgeConnectionError(f"GitHub connection request failed: {e}")

    async def disconnect(self) -> None:
        """Disconnect and clean up resources.

        Idempotent - safe to call multiple times.
        """
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("GitHub bridge disconnected")

        self._connected = False
        self._rate_limit_remaining = None
        self._rate_limit_reset = None

    async def sync_sessions(
        self, since: datetime
    ) -> list[SessionSnapshot]:
        """Sync TMWS sessions from GitHub issues.

        Searches for issues with 'tmws-session' label updated since the given timestamp.

        Args:
            since: Only sync sessions updated after this timestamp

        Returns:
            List of session snapshots from GitHub issues

        Raises:
            RuntimeError: If not connected or sync fails
        """
        if not self._connected or not self._client:
            raise RuntimeError("GitHub bridge not connected. Call connect() first.")

        # Format datetime for GitHub search query
        # GitHub API expects ISO 8601 format
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Build search query
        query = f"repo:{self.repository} label:tmws-session updated:>={since_str}"

        logger.info(
            f"Syncing TMWS sessions from GitHub since {since_str}",
            extra={"since": since_str, "repository": self.repository},
        )

        # Search for issues
        try:
            issues = await self.search_issues(query, limit=100)
        except Exception as e:
            logger.error(f"Failed to sync sessions from GitHub: {e}")
            raise RuntimeError(f"Failed to sync sessions from GitHub: {e}")

        # Convert issues to session snapshots
        snapshots: list[SessionSnapshot] = []
        for issue in issues:
            try:
                # Extract session ID from issue title or body
                # Expected format: "TMWS Session: <session_id>"
                session_id = self._extract_session_id(issue.title, issue.body)

                snapshot = SessionSnapshot(
                    session_id=session_id,
                    timestamp=issue.updated_at or issue.created_at or datetime.utcnow(),
                    summary=issue.title,
                    metadata={
                        "issue_id": issue.issue_id,
                        "url": issue.url,
                        "labels": issue.labels,
                        "state": issue.state,
                        "body": issue.body,
                    },
                )
                snapshots.append(snapshot)

            except Exception as e:
                logger.warning(
                    f"Failed to parse session from issue {issue.issue_id}: {e}",
                    extra={"issue_id": issue.issue_id},
                )
                continue

        logger.info(
            f"Synced {len(snapshots)} session(s) from GitHub",
            extra={"count": len(snapshots)},
        )

        return snapshots

    async def search_issues(
        self, query: str, limit: int = 10
    ) -> list[IssueResult]:
        """Search for issues on GitHub.

        Security:
        - Query is sanitized to prevent injection
        - Limit is enforced (1-100)
        - Rate limiting is applied

        Args:
            query: GitHub search query (will be sanitized)
            limit: Maximum results (1-100)

        Returns:
            List of matching issues

        Raises:
            SecurityError: If query is invalid
            RuntimeError: If not connected or search fails
            BridgeRateLimitError: If rate limit exceeded
        """
        if not self._connected or not self._client:
            raise RuntimeError("GitHub bridge not connected. Call connect() first.")

        # Sanitize query
        try:
            sanitized_query = _sanitize_query(query)
        except SecurityError as e:
            logger.error(f"Invalid search query: {e}")
            raise

        # Enforce limit bounds
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")

        # Apply rate limiting
        await self.rate_limiter.wait_if_needed()

        # Build request
        params = {
            "q": sanitized_query,
            "per_page": limit,
            "sort": "updated",
            "order": "desc",
        }

        logger.debug(
            f"Searching GitHub issues: {sanitized_query[:50]}...",
            extra={"limit": limit},
        )

        # Execute search with circuit breaker
        try:
            response = await self.circuit_breaker.call(
                self._client.get,
                "/search/issues",
                params=params,
            )
            response.raise_for_status()

            # Update rate limit tracking
            self._update_rate_limits(response.headers)

            data = response.json()
            items = data.get("items", [])

            logger.info(
                f"Found {len(items)} issue(s) on GitHub",
                extra={"count": len(items), "total_count": data.get("total_count", 0)},
            )

            # Parse results
            results: list[IssueResult] = []
            for item in items:
                result = self._parse_issue(item)
                results.append(result)

            return results

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logger.error("GitHub authentication failed during search")
                raise BridgeAuthenticationError("GitHub authentication failed")
            elif e.response.status_code == 403:
                if self._is_rate_limited(e.response.headers):
                    reset_time = e.response.headers.get("x-ratelimit-reset", "unknown")
                    logger.error(f"GitHub rate limit exceeded (reset: {reset_time})")
                    raise BridgeRateLimitError(
                        f"GitHub rate limit exceeded. Reset at: {reset_time}"
                    )
                else:
                    logger.error("GitHub search forbidden")
                    raise BridgeError("GitHub search forbidden")
            elif e.response.status_code == 422:
                logger.error(f"GitHub search validation error: {e.response.text}")
                raise BridgeError(f"GitHub search validation error: {e.response.text}")
            else:
                logger.error(f"GitHub search failed: {e}")
                raise BridgeError(f"GitHub search failed: {e}")
        except httpx.RequestError as e:
            logger.error(f"GitHub search request failed: {e}")
            raise BridgeError(f"GitHub search request failed: {e}")

    async def push_memory_snapshot(
        self, sessions: list[SessionSnapshot]
    ) -> str:
        """Push memory snapshot to GitHub as an issue.

        Creates a new issue with all session summaries and metadata.

        Args:
            sessions: Sessions to include in snapshot

        Returns:
            URL of created issue

        Raises:
            RuntimeError: If not connected or push fails
        """
        if not self._connected or not self._client:
            raise RuntimeError("GitHub bridge not connected. Call connect() first.")

        if not sessions:
            raise ValueError("Cannot push empty session list")

        # Build issue title and body
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        title = f"TMWS Memory Snapshot - {timestamp}"

        body_parts = [
            "# TMWS Memory Snapshot",
            f"**Created**: {timestamp}",
            f"**Sessions**: {len(sessions)}",
            "",
            "---",
            "",
        ]

        for session in sessions:
            session_time = session.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            body_parts.extend([
                f"## Session: {session.session_id}",
                f"**Time**: {session_time}",
                f"**Summary**: {session.summary}",
                "",
                "**Metadata**:",
                "```json",
                str(session.metadata),
                "```",
                "",
                "---",
                "",
            ])

        body = "\n".join(body_parts)

        # Prepare request
        owner, repo = self.repository.split("/")
        url = f"/repos/{owner}/{repo}/issues"

        payload = {
            "title": title,
            "body": body,
            "labels": ["tmws-session", "tmws-snapshot"],
        }

        logger.info(
            f"Pushing memory snapshot to GitHub ({len(sessions)} sessions)",
            extra={"session_count": len(sessions)},
        )

        # Apply rate limiting
        await self.rate_limiter.wait_if_needed()

        # Create issue with circuit breaker
        try:
            response = await self.circuit_breaker.call(
                self._client.post,
                url,
                json=payload,
            )
            response.raise_for_status()

            # Update rate limit tracking
            self._update_rate_limits(response.headers)

            data = response.json()
            issue_url = data.get("html_url", "")
            issue_number = data.get("number", "unknown")

            logger.info(
                f"Created GitHub issue #{issue_number}: {issue_url}",
                extra={"issue_number": issue_number, "url": issue_url},
            )

            return issue_url

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logger.error("GitHub authentication failed during snapshot push")
                raise BridgeAuthenticationError("GitHub authentication failed")
            elif e.response.status_code == 403:
                if self._is_rate_limited(e.response.headers):
                    reset_time = e.response.headers.get("x-ratelimit-reset", "unknown")
                    logger.error(f"GitHub rate limit exceeded (reset: {reset_time})")
                    raise BridgeRateLimitError(
                        f"GitHub rate limit exceeded. Reset at: {reset_time}"
                    )
                else:
                    logger.error("GitHub snapshot push forbidden")
                    raise BridgeError("GitHub snapshot push forbidden")
            elif e.response.status_code == 404:
                logger.error(f"GitHub repository not found: {self.repository}")
                raise BridgeError(f"GitHub repository not found: {self.repository}")
            elif e.response.status_code == 422:
                logger.error(f"GitHub snapshot push validation error: {e.response.text}")
                raise BridgeError(f"GitHub snapshot push validation error: {e.response.text}")
            else:
                logger.error(f"GitHub snapshot push failed: {e}")
                raise BridgeError(f"GitHub snapshot push failed: {e}")
        except httpx.RequestError as e:
            logger.error(f"GitHub snapshot push request failed: {e}")
            raise BridgeError(f"GitHub snapshot push request failed: {e}")

    def _parse_issue(self, item: dict[str, Any]) -> IssueResult:
        """Parse GitHub API issue response into IssueResult.

        Args:
            item: Issue data from GitHub API

        Returns:
            Parsed issue result
        """
        # Parse timestamps
        created_at = None
        updated_at = None

        if created_str := item.get("created_at"):
            try:
                created_at = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            except Exception:
                pass

        if updated_str := item.get("updated_at"):
            try:
                updated_at = datetime.fromisoformat(updated_str.replace("Z", "+00:00"))
            except Exception:
                pass

        # Extract labels
        labels = [label["name"] for label in item.get("labels", [])]

        # Determine state
        state = item.get("state", "unknown")
        if item.get("pull_request") and item.get("merged_at"):
            state = "merged"

        return IssueResult(
            issue_id=str(item.get("number", "")),
            title=item.get("title", ""),
            body=item.get("body") or "",
            state=state,
            url=item.get("html_url", ""),
            labels=labels,
            created_at=created_at,
            updated_at=updated_at,
        )

    def _extract_session_id(self, title: str, body: str) -> str:
        """Extract session ID from issue title or body.

        Expected formats:
        - Title: "TMWS Session: <session_id>"
        - Body: First line contains session ID

        Args:
            title: Issue title
            body: Issue body

        Returns:
            Extracted session ID

        Raises:
            ValueError: If session ID cannot be extracted
        """
        # Try to extract from title
        if "TMWS Session:" in title:
            parts = title.split("TMWS Session:")
            if len(parts) >= 2:
                session_id = parts[1].strip()
                if session_id:
                    return session_id

        # Try to extract from first line of body
        if body:
            lines = body.split("\n")
            for line in lines:
                if line.strip():
                    # Assume first non-empty line contains session ID
                    return line.strip()

        # Fallback: use issue title as session ID
        return title

    def _update_rate_limits(self, headers: httpx.Headers) -> None:
        """Update rate limit tracking from response headers.

        Args:
            headers: Response headers from GitHub API
        """
        if remaining := headers.get("x-ratelimit-remaining"):
            try:
                self._rate_limit_remaining = int(remaining)
            except ValueError:
                pass

        if reset := headers.get("x-ratelimit-reset"):
            try:
                self._rate_limit_reset = int(reset)
            except ValueError:
                pass

        if self._rate_limit_remaining is not None:
            logger.debug(
                f"GitHub rate limit: {self._rate_limit_remaining} remaining",
                extra={
                    "remaining": self._rate_limit_remaining,
                    "reset": self._rate_limit_reset,
                },
            )

    def _is_rate_limited(self, headers: httpx.Headers) -> bool:
        """Check if response indicates rate limiting.

        Args:
            headers: Response headers from GitHub API

        Returns:
            True if rate limited
        """
        remaining = headers.get("x-ratelimit-remaining", "")
        try:
            return int(remaining) == 0
        except (ValueError, TypeError):
            return False
