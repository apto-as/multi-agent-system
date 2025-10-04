"""
JWT Service for TMWS Authentication System.
High-performance JWT token generation, validation, and refresh with comprehensive security.
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from ..core.config import get_settings
from ..models.user import RefreshToken, User
from ..utils.security import hash_password_with_salt, verify_password_with_salt

settings = get_settings()


class JWTService:
    """High-performance JWT service with production-grade security."""

    def __init__(self):
        """Initialize JWT service with secure defaults."""
        # Cryptographic settings
        self.secret_key = settings.secret_key
        if not self.secret_key or len(self.secret_key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters long")

        self.algorithm = "HS256"
        self.issuer = "tmws-auth-service"
        self.audience = "tmws-api"

        # Token lifetimes (optimized for performance vs security)
        self.access_token_expire_minutes = 15  # Short-lived for security
        self.refresh_token_expire_days = 30  # Longer-lived for UX
        self.api_key_token_expire_hours = 24  # Service tokens

        # Password hashing moved to utils.security for consistency

        # Performance optimization: pre-compute common claims
        self._base_claims = {
            "iss": self.issuer,
            "aud": self.audience,
        }

    def hash_password(self, password: str) -> tuple[str, str]:
        """Hash password with salt - delegates to unified security utils."""
        return hash_password_with_salt(password)

    def verify_password(self, password: str, hashed: str, salt: str) -> bool:
        """Verify password against hash with salt - delegates to unified security utils."""
        return verify_password_with_salt(password, hashed, salt)

    def create_access_token(
        self,
        user: User,
        additional_claims: dict[str, Any] | None = None,
        expires_delta: timedelta | None = None,
    ) -> str:
        """
        Create JWT access token for user.
        Optimized for <200ms performance requirement.
        """
        now = datetime.now(timezone.utc)
        expire = now + (expires_delta or timedelta(minutes=self.access_token_expire_minutes))

        # Build claims efficiently
        claims = self._base_claims.copy()
        claims.update(
            {
                "sub": str(user.id),  # Subject (user ID)
                "username": user.username,
                "email": user.email,
                "roles": [role.value for role in user.roles],
                "agent_namespace": user.agent_namespace,
                "preferred_agent_id": user.preferred_agent_id,
                "iat": now,  # Issued at
                "exp": expire,  # Expires
                "jti": secrets.token_urlsafe(16),  # JWT ID for revocation
                "session_timeout": user.session_timeout_minutes,
            }
        )

        # Add additional claims if provided
        if additional_claims:
            claims.update(additional_claims)

        # Generate token (performance critical)
        try:
            token = jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
            return token
        except Exception as e:
            raise ValueError(f"Failed to create access token: {str(e)}")

    def create_refresh_token(self, user: User) -> tuple[str, RefreshToken]:
        """
        Create refresh token for user.
        Returns (token, refresh_token_record) tuple.
        """
        token_id = secrets.token_urlsafe(32)
        raw_token = secrets.token_urlsafe(64)

        # Hash the token for storage
        token_hash = self.pwd_context.hash(raw_token)

        expires_at = datetime.now(timezone.utc) + timedelta(days=self.refresh_token_expire_days)

        # Create database record
        refresh_token = RefreshToken(
            token_id=token_id, token_hash=token_hash, expires_at=expires_at, user_id=user.id
        )

        # Return token and record
        full_token = f"{token_id}.{raw_token}"
        return full_token, refresh_token

    def create_api_key_token(
        self, api_key_id: str, user: User, scopes: list[str], expires_delta: timedelta | None = None
    ) -> str:
        """Create JWT token for API key authentication."""
        now = datetime.now(timezone.utc)
        expire = now + (expires_delta or timedelta(hours=self.api_key_token_expire_hours))

        claims = self._base_claims.copy()
        claims.update(
            {
                "sub": str(user.id),
                "username": user.username,
                "api_key_id": api_key_id,
                "scopes": scopes,
                "token_type": "api_key",
                "agent_namespace": user.agent_namespace,
                "iat": now,
                "exp": expire,
                "jti": secrets.token_urlsafe(16),
            }
        )

        return jwt.encode(claims, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> dict[str, Any] | None:
        """
        Verify and decode JWT token.
        Optimized for <200ms performance requirement.
        """
        try:
            # Fast path: decode and verify in one operation
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )

            # Additional validation
            if "sub" not in payload or "username" not in payload:
                return None

            return payload

        except ExpiredSignatureError:
            # Token expired - this is expected behavior
            return None
        except InvalidTokenError:
            # Invalid token format or signature
            return None
        except Exception as e:
            # Unexpected error - log but don't expose details
            import logging

            logger = logging.getLogger(__name__)
            logger.error(
                f"JWT verification failed with unexpected error: {type(e).__name__}: {str(e)}",
                exc_info=True,
            )
            return None

    def verify_refresh_token(self, token: str) -> str | None:
        """
        Verify refresh token and extract token_id.
        Returns token_id if valid, None otherwise.
        """
        try:
            # Parse token format: token_id.raw_token
            parts = token.split(".", 1)
            if len(parts) != 2:
                return None

            token_id, raw_token = parts

            # Validate token_id format (URL-safe base64)
            if len(token_id) < 32 or not token_id.replace("-", "").replace("_", "").isalnum():
                return None

            return token_id

        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.error(
                f"Refresh token verification failed: {type(e).__name__}: {str(e)}", exc_info=True
            )
            return None

    def verify_refresh_token_hash(self, raw_token: str, stored_hash: str) -> bool:
        """Verify raw refresh token against stored hash."""
        try:
            return self.pwd_context.verify(raw_token, stored_hash)
        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.error(
                f"Refresh token hash verification failed: {type(e).__name__}: {str(e)}",
                exc_info=True,
            )
            return False

    def decode_token_unsafe(self, token: str) -> dict[str, Any] | None:
        """
        Decode token without verification (for debugging/logging only).
        WARNING: Never use for authentication!
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(f"Token decode (unsafe) failed: {type(e).__name__}: {str(e)}")
            return None

    def get_token_expiry(self, token: str) -> datetime | None:
        """Get token expiration time without full verification."""
        try:
            payload = self.decode_token_unsafe(token)
            if payload and "exp" in payload:
                return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to extract token expiry: {type(e).__name__}: {str(e)}")
            pass
        return None

    def create_password_reset_token(self, user: User) -> str:
        """Create password reset token (short-lived)."""
        now = datetime.now(timezone.utc)
        expire = now + timedelta(minutes=30)  # 30-minute expiry

        claims = {
            "sub": str(user.id),
            "username": user.username,
            "token_type": "password_reset",
            "iat": now,
            "exp": expire,
            "jti": secrets.token_urlsafe(16),
        }

        return jwt.encode(claims, self.secret_key, algorithm=self.algorithm)

    def validate_token_claims(self, payload: dict[str, Any], required_claims: list[str]) -> bool:
        """Validate that token contains required claims."""
        return all(claim in payload for claim in required_claims)

    def extract_user_info(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Extract user information from token payload."""
        return {
            "user_id": payload.get("sub"),
            "username": payload.get("username"),
            "email": payload.get("email"),
            "roles": payload.get("roles", []),
            "agent_namespace": payload.get("agent_namespace", "default"),
            "preferred_agent_id": payload.get("preferred_agent_id"),
            "session_timeout": payload.get("session_timeout", 480),
        }

    def is_token_type(self, payload: dict[str, Any], token_type: str) -> bool:
        """Check if token is of specific type."""
        return payload.get("token_type") == token_type

    def get_token_scopes(self, payload: dict[str, Any]) -> list[str]:
        """Extract scopes from API key token."""
        return payload.get("scopes", [])


class TokenBlacklist:
    """In-memory token blacklist for revoked tokens (Redis in production)."""

    def __init__(self):
        self._blacklisted_tokens = set()
        self._blacklisted_jtis = set()

    def blacklist_token(self, jti: str) -> None:
        """Add token JTI to blacklist."""
        self._blacklisted_jtis.add(jti)

    def is_blacklisted(self, jti: str) -> bool:
        """Check if token JTI is blacklisted."""
        return jti in self._blacklisted_jtis

    def blacklist_user_tokens(self, user_id: str) -> None:
        """Blacklist all tokens for a user (logout all sessions)."""
        # In production, this would use Redis with user_id patterns
        pass

    def cleanup_expired(self) -> None:
        """Clean up expired blacklist entries (scheduled task)."""
        # In production, Redis TTL handles this automatically
        pass


# Global instances
jwt_service = JWTService()
token_blacklist = TokenBlacklist()


# Convenience functions for common operations
def create_tokens_for_user(user: User) -> tuple[str, str]:
    """Create both access and refresh tokens for user."""
    access_token = jwt_service.create_access_token(user)
    refresh_token, refresh_record = jwt_service.create_refresh_token(user)
    return access_token, refresh_token


def verify_and_extract_user(token: str) -> dict[str, Any] | None:
    """Verify token and extract user information."""
    payload = jwt_service.verify_token(token)
    if not payload:
        return None

    # Check blacklist
    jti = payload.get("jti")
    if jti and token_blacklist.is_blacklisted(jti):
        return None

    return jwt_service.extract_user_info(payload)


# Global password functions removed - use utils.security directly
# or access through jwt_service instance
