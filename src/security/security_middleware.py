"""Enhanced Security Middleware for TMWS.
Implements comprehensive security headers and enhanced CORS handling.
"""

from __future__ import annotations

import logging
import time

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from ..api.security import SecurityHeaders
from ..core.config import get_settings
from .rate_limiter import RateLimiter

# Phase 4.2: Use new Facade instead of monolithic logger
from .security_audit_facade import SecurityAuditFacade

logger = logging.getLogger(__name__)


class UnifiedSecurityMiddleware(BaseHTTPMiddleware):
    """Unified security middleware combining rate limiting, authentication, and audit logging.
    High-performance middleware optimized for <200ms response times.
    """

    def __init__(
        self,
        app: FastAPI,
        rate_limiter: RateLimiter | None = None,
        audit_logger: SecurityAuditFacade | None = None,
    ):
        super().__init__(app)
        self.settings = get_settings()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.audit_logger = audit_logger or SecurityAuditFacade()

        # Bypass paths that don't need security checks
        self.bypass_paths = {
            "/health",
            "/docs",
            "/openapi.json",
            "/redoc",
            "/favicon.ico",
            "/static",
        }

        # Public endpoints that don't require authentication
        self.public_endpoints = {
            "/health",
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh",
        }

    async def dispatch(self, request: Request, call_next) -> Response:
        """Unified security processing."""
        start_time = time.time()

        # Skip security checks for bypass paths
        if self._should_bypass(request):
            return await call_next(request)

        # Extract request metadata
        client_ip = self._get_client_ip(request)
        request.headers.get("User-Agent", "Unknown")

        try:
            # Rate limiting check (first line of defense)
            await self._check_rate_limits(request, client_ip)

            # Process request
            response = await call_next(request)

            # Add security headers if enabled
            if self.settings.security_headers_enabled:
                security_headers = SecurityHeaders.get_security_headers()
                for header_name, header_value in security_headers.items():
                    response.headers[header_name] = header_value

            # Audit successful requests (async, non-blocking)
            await self._audit_request(request, response, client_ip, start_time)

            return response

        except HTTPException as e:
            # Audit failed requests
            await self._audit_security_violation(request, e, client_ip, start_time)
            raise
        except Exception as e:
            # Audit unexpected errors
            await self._audit_system_error(request, e, client_ip, start_time)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error",
            )

    def _should_bypass(self, request: Request) -> bool:
        """Check if request should bypass security checks."""
        path = request.url.path
        return any(path.startswith(bypass) for bypass in self.bypass_paths)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address."""
        # Check X-Forwarded-For header first (for reverse proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fallback to request client IP
        return request.client.host if request.client else "unknown"

    async def _check_rate_limits(self, request: Request, client_ip: str) -> None:
        """Check rate limits for the request."""
        if not self.settings.auth_enabled:
            return  # Skip rate limiting in development mode

        # Determine endpoint type
        endpoint_type = self._get_endpoint_type(request)

        # Extract user context if available
        user_id = None
        user_roles = None
        api_key_scopes = None

        # Try to extract user info from Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                from ..security.jwt_service import verify_and_extract_user

                token = auth_header.split(" ", 1)[1]
                user_info = verify_and_extract_user(token)
                if user_info:
                    user_id = user_info.get("user_id")
                    user_roles = user_info.get("roles", [])
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                # JWT extraction failure - continue with IP-based limits only
                logger.warning(
                    f"⚠️  Failed to extract JWT user info (using IP-based limits): {type(e).__name__}: {str(e)}",
                    exc_info=False,  # Expected for invalid/expired tokens
                    extra={"client_ip": client_ip, "has_auth_header": True},
                )
                # Continue with IP-based limits

        # Try to extract API key info
        api_key = request.headers.get("X-API-Key")
        if api_key:
            try:
                from ..services.auth_service import auth_service

                user, key_record = await auth_service.validate_api_key(
                    api_key=api_key, ip_address=client_ip,
                )
                user_id = str(user.id)
                user_roles = [role.value for role in user.roles]
                api_key_scopes = [scope.value for scope in key_record.scopes]
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                # API key validation failure - continue with IP-based limits only
                logger.warning(
                    f"⚠️  Failed to validate API key (using IP-based limits): {type(e).__name__}: {str(e)}",
                    exc_info=False,  # Expected for invalid keys
                    extra={
                        "client_ip": client_ip,
                        "api_key_prefix": api_key[:8] + "..." if len(api_key) > 8 else "***",
                    },
                )
                # Continue with IP-based limits

        # Perform rate limit check
        await self.rate_limiter.check_rate_limit(
            request=request,
            endpoint_type=endpoint_type,
            user_id=user_id,
            user_roles=user_roles,
            api_key_scopes=api_key_scopes,
        )

    def _get_endpoint_type(self, request: Request) -> str:
        """Determine endpoint type for rate limiting."""
        path = request.url.path.lower()
        method = request.method.upper()

        # Authentication endpoints
        if "/auth/login" in path:
            return "login"
        elif "/auth/register" in path:
            return "register"

        # API endpoints
        elif "/api/v1/memory" in path and method == "POST":
            return "search" if "search" in path else "embedding"
        elif "/api/v1/tasks" in path:
            return "tasks"
        elif "/api/v1/workflows" in path:
            return "workflows"

        return "default"

    async def _audit_request(
        self, request: Request, response: Response, client_ip: str, start_time: float,
    ) -> None:
        """Audit successful request."""
        processing_time = time.time() - start_time

        # Only audit significant requests (skip health checks, etc.)
        if not self._should_audit(request):
            return

        await self.audit_logger.log_event(
            event_type="request_success",
            user_id=self._extract_user_id(request),
            resource=request.url.path,
            action=request.method,
            result="success",
            metadata={
                "client_ip": client_ip,
                "user_agent": request.headers.get("User-Agent", ""),
                "status_code": response.status_code,
                "processing_time_ms": round(processing_time * 1000, 2),
                "content_length": response.headers.get("content-length", "0"),
            },
        )

    async def _audit_security_violation(
        self, request: Request, exception: HTTPException, client_ip: str, start_time: float,
    ) -> None:
        """Audit security violations."""
        processing_time = time.time() - start_time

        await self.audit_logger.log_event(
            event_type="security_violation",
            user_id=self._extract_user_id(request) or "anonymous",
            resource=request.url.path,
            action=request.method,
            result="blocked",
            metadata={
                "client_ip": client_ip,
                "user_agent": request.headers.get("User-Agent", ""),
                "status_code": exception.status_code,
                "error_detail": exception.detail,
                "processing_time_ms": round(processing_time * 1000, 2),
            },
        )

    async def _audit_system_error(
        self, request: Request, exception: Exception, client_ip: str, start_time: float,
    ) -> None:
        """Audit system errors."""
        processing_time = time.time() - start_time

        await self.audit_logger.log_event(
            event_type="system_error",
            user_id=self._extract_user_id(request) or "anonymous",
            resource=request.url.path,
            action=request.method,
            result="error",
            metadata={
                "client_ip": client_ip,
                "user_agent": request.headers.get("User-Agent", ""),
                "error_type": type(exception).__name__,
                "error_message": str(exception)[:500],  # Truncate long errors
                "processing_time_ms": round(processing_time * 1000, 2),
            },
        )

    def _should_audit(self, request: Request) -> bool:
        """Check if request should be audited."""
        path = request.url.path

        # Skip auditing for these paths
        skip_audit = {"/health", "/docs", "/openapi.json", "/redoc", "/favicon.ico"}
        return not any(path.startswith(skip) for skip in skip_audit)

    def _extract_user_id(self, request: Request) -> str | None:
        """Extract user ID from request for auditing."""
        # Try to extract from JWT token
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                from ..security.jwt_service import verify_and_extract_user

                token = auth_header.split(" ", 1)[1]
                user_info = verify_and_extract_user(token)
                return user_info.get("user_id") if user_info else None
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                # Failed to extract - log at DEBUG (non-critical for auditing)
                logger.debug(
                    f"Failed to extract user ID from JWT: {type(e).__name__}: {str(e)}",
                    exc_info=False,
                )
                # Fall through to try API key

        # Try to extract from API key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            try:
                # Lightweight extraction - just use prefix for auditing
                return f"api_key:{api_key[:8]}"
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                # Failed to extract - log at DEBUG (non-critical for auditing)
                logger.debug(
                    f"Failed to extract user ID from API key: {type(e).__name__}: {str(e)}",
                    exc_info=False,
                )

        return None


class EnhancedCORSMiddleware:
    """Enhanced CORS middleware with security-first configuration."""

    @staticmethod
    def setup_cors(app: FastAPI, settings) -> None:
        """Configure CORS with security-appropriate settings."""

        if settings.TMWS_ENVIRONMENT == "development":
            # Development: Allow all origins for convenience
            allowed_origins = ["*"]
            allow_credentials = False  # Can't use credentials with wildcard
        else:
            # Production: Strict origin control
            allowed_origins = [
                "https://tmws.ai",
                "https://api.tmws.ai",
                "https://app.tmws.ai",
                # Add your production domains here
            ]
            allow_credentials = True

        # Allowed methods (be specific)
        allowed_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

        # Allowed headers
        allowed_headers = [
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Authorization",
            "X-API-Key",
            "X-Requested-With",
            "X-CSRF-Token",
            "Cache-Control",
            "Pragma",
        ]

        # Exposed headers (headers that client can access)
        exposed_headers = [
            "X-Total-Count",
            "X-Page-Count",
            "X-Rate-Limit-Remaining",
            "X-Rate-Limit-Reset",
            "X-Request-ID",
        ]

        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=allow_credentials,
            allow_methods=allowed_methods,
            allow_headers=allowed_headers,
            expose_headers=exposed_headers,
            max_age=86400,  # 24 hours preflight cache
        )


def setup_security_middleware(
    app: FastAPI,
    rate_limiter: RateLimiter | None = None,
    audit_logger: SecurityAuditFacade | None = None,
) -> None:
    """Set up all security middleware in the correct order.
    Order matters for security effectiveness.
    """
    settings = get_settings()

    # 1. CORS (must be first for preflight requests)
    EnhancedCORSMiddleware.setup_cors(app, settings)

    # 2. Security Headers (applied to all responses)
    # Security headers are now integrated into UnifiedSecurityMiddleware
    # See UnifiedSecurityMiddleware.dispatch() for implementation

    # 3. Unified Security (rate limiting + audit logging)
    app.add_middleware(
        UnifiedSecurityMiddleware, rate_limiter=rate_limiter, audit_logger=audit_logger,
    )
