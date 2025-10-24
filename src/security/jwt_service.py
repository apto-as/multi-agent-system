"""
JWT Service for TMWS Authentication System.
High-performance JWT token generation, validation, and refresh with comprehensive security.
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext

from ..core.config import get_settings
from ..models.user import RefreshToken, User
from ..utils.security import hash_password_with_salt, verify_password_with_salt

logger = logging.getLogger(__name__)
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

        # M-1 fix: Initialize pwd_context for refresh token hashing
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

        # Password hashing for user passwords moved to utils.security for consistency

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

    def verify_token(self, token: str, client_ip: str | None = None) -> dict[str, Any] | None:
        """
        Verify and decode JWT token.
        Optimized for <200ms performance requirement.

        Args:
            token: JWT token to verify
            client_ip: Client IP address for security logging (optional)

        Returns:
            Decoded payload if valid, None if invalid/expired
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
                logger.error(
                    "⚠️  JWT token missing required claims",
                    extra={"client_ip": client_ip, "has_sub": "sub" in payload, "has_username": "username" in payload}
                )
                return None

            return payload

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except ExpiredSignatureError:
            # Token expired - this is EXPECTED behavior (not an error)
            # Only log if we have client IP (indicates actual auth attempt)
            if client_ip:
                logger.info(
                    f"Expired JWT token from {client_ip} (normal expiration)",
                    extra={"client_ip": client_ip, "error_type": "expired"}
                )
            return None
        except InvalidTokenError as e:
            # Invalid token format or signature - POSSIBLE ATTACK
            logger.error(
                f"🚨 Invalid JWT token detected{f' from {client_ip}' if client_ip else ''} (possible attack): {type(e).__name__}",
                exc_info=False,  # Don't spam with full traces for expected invalid tokens
                extra={
                    "client_ip": client_ip or "unknown",
                    "error_type": "invalid_token",
                    "error_class": type(e).__name__,
                    "token_prefix": token[:8] + "..." if len(token) > 8 else "***"  # Masked token
                }
            )
            return None
        except Exception as e:
            # Unexpected error - CRITICAL (should never happen)
            logger.critical(
                f"❌ CRITICAL: Unexpected JWT verification error: {type(e).__name__}: {str(e)}",
                exc_info=True,
                extra={
                    "client_ip": client_ip or "unknown",
                    "error_type": "unexpected",
                    "error_class": type(e).__name__
                }
            )
            return None

    def verify_refresh_token(self, token: str, client_ip: str | None = None) -> str | None:
        """
        Verify refresh token and extract token_id.

        Args:
            token: Refresh token in format "token_id.raw_token"
            client_ip: Client IP for security logging (optional)

        Returns:
            token_id if valid format, None otherwise
        """
        try:
            # Parse token format: token_id.raw_token
            parts = token.split(".", 1)
            if len(parts) != 2:
                logger.error(
                    "⚠️  Invalid refresh token format (missing delimiter)",
                    extra={"client_ip": client_ip or "unknown", "parts_count": len(parts)}
                )
                return None

            token_id, raw_token = parts

            # Validate token_id format (URL-safe base64)
            if len(token_id) < 32 or not token_id.replace("-", "").replace("_", "").isalnum():
                logger.error(
                    "🚨 Invalid refresh token_id format (possible attack)",
                    extra={
                        "client_ip": client_ip or "unknown",
                        "token_id_length": len(token_id),
                        "token_id_prefix": token_id[:8] + "..." if len(token_id) > 8 else "***"
                    }
                )
                return None

            return token_id

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.critical(
                f"❌ CRITICAL: Unexpected refresh token verification error: {type(e).__name__}: {str(e)}",
                exc_info=True,
                extra={"client_ip": client_ip or "unknown", "error_type": "unexpected"}
            )
            return None

    def verify_refresh_token_hash(self, raw_token: str, stored_hash: str, client_ip: str | None = None) -> bool:
        """
        Verify raw refresh token against stored hash.

        Args:
            raw_token: Raw refresh token from client
            stored_hash: Stored bcrypt hash from database
            client_ip: Client IP for security logging (optional)

        Returns:
            True if token matches hash, False otherwise
        """
        try:
            return self.pwd_context.verify(raw_token, stored_hash)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            # Hash verification failure could indicate attack or corrupted hash
            logger.error(
                f"❌ Refresh token hash verification failed{f' from {client_ip}' if client_ip else ''}: {type(e).__name__}: {str(e)}",
                exc_info=True,
                extra={
                    "client_ip": client_ip or "unknown",
                    "error_type": "hash_verification_failed",
                    "stored_hash_prefix": stored_hash[:10] + "..." if len(stored_hash) > 10 else "***"
                }
            )
            # FAIL-SECURE: On any error, deny access
            return False

    def decode_token_unsafe(self, token: str) -> dict[str, Any] | None:
        """
        Decode token without verification (for debugging/logging only).

        WARNING: NEVER use for authentication! This bypasses all security checks.
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.warning(
                f"⚠️  Unsafe token decode failed (debugging only): {type(e).__name__}: {str(e)}",
                exc_info=False,  # Don't spam logs for debugging function
                extra={"token_prefix": token[:8] + "..." if len(token) > 8 else "***"}
            )
            return None

    def get_token_expiry(self, token: str) -> datetime | None:
        """
        Get token expiration time without full verification.

        Note: This is a convenience function for displaying token lifetime.
        Do NOT use for security decisions.
        """
        try:
            payload = self.decode_token_unsafe(token)
            if payload and "exp" in payload:
                return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
            return None
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.warning(
                f"⚠️  Failed to extract token expiry: {type(e).__name__}: {str(e)}",
                exc_info=False,  # Non-critical operation
                extra={"token_prefix": token[:8] + "..." if len(token) > 8 else "***"}
            )
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
