"""HMAC Authentication for MCP Hub Unix Socket Communication.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 2.1 - Security Foundation
Requirement: S-P0-1 - HMAC Request Signing

Security Properties:
- SHA-256 HMAC for message authentication
- Constant-time comparison to prevent timing attacks
- Timestamp validation to prevent replay attacks
- Nonce tracking for additional replay protection

Usage:
    >>> auth = create_hmac_authenticator()
    >>> token = auth.generate_token("client_123", b"request_data")
    >>> is_valid = auth.verify_token(token, b"request_data")

Author: Artemis (Implementation) + Hestia (Security Review)
Created: 2025-12-05
"""

import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class HMACAuthError(Exception):
    """HMAC authentication error.

    Raised when authentication fails due to:
    - Invalid signature
    - Expired timestamp
    - Replayed nonce
    - Missing credentials
    """

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.details = details or {}


@dataclass
class HMACToken:
    """HMAC authentication token.

    Format: {client_id}:{timestamp}:{nonce}:{signature}
    """

    client_id: str
    timestamp: int
    nonce: str
    signature: str

    def to_string(self) -> str:
        """Serialize token to string format."""
        return f"{self.client_id}:{self.timestamp}:{self.nonce}:{self.signature}"

    @classmethod
    def from_string(cls, token_str: str) -> "HMACToken":
        """Parse token from string format.

        Args:
            token_str: Token in format {client_id}:{timestamp}:{nonce}:{signature}

        Returns:
            HMACToken instance

        Raises:
            HMACAuthError: If token format is invalid
        """
        parts = token_str.split(":")
        if len(parts) != 4:
            raise HMACAuthError(
                "Invalid token format",
                details={"expected_parts": 4, "actual_parts": len(parts)},
            )

        try:
            return cls(
                client_id=parts[0],
                timestamp=int(parts[1]),
                nonce=parts[2],
                signature=parts[3],
            )
        except ValueError as e:
            raise HMACAuthError(
                "Invalid token components",
                details={"error": str(e)},
            )


@dataclass
class HMACAuthenticator:
    """HMAC authenticator for MCP Hub communication.

    Security Features:
    - HMAC-SHA256 signature generation and verification
    - Constant-time signature comparison
    - Timestamp-based expiration (default: 5 minutes)
    - Nonce tracking to prevent replay attacks

    Thread Safety:
    - Nonce set should be accessed with external synchronization
      in multi-threaded environments
    """

    secret_key: bytes
    token_ttl_seconds: int = 300  # 5 minutes
    max_nonce_cache_size: int = 10000

    # Nonce cache for replay protection
    _used_nonces: set[str] = field(default_factory=set)

    def generate_token(
        self,
        client_id: str,
        message: bytes,
        timestamp: int | None = None,
    ) -> HMACToken:
        """Generate HMAC authentication token.

        Args:
            client_id: Unique client identifier
            message: Message to authenticate
            timestamp: Optional timestamp (uses current time if None)

        Returns:
            HMACToken with signature
        """
        if timestamp is None:
            timestamp = int(time.time())

        # Generate cryptographically secure nonce
        nonce = secrets.token_hex(16)

        # Create signature payload
        payload = self._create_payload(client_id, timestamp, nonce, message)

        # Generate HMAC-SHA256 signature
        signature = hmac.new(
            self.secret_key,
            payload,
            hashlib.sha256,
        ).hexdigest()

        return HMACToken(
            client_id=client_id,
            timestamp=timestamp,
            nonce=nonce,
            signature=signature,
        )

    def verify_token(
        self,
        token: HMACToken | str,
        message: bytes,
        current_time: int | None = None,
    ) -> bool:
        """Verify HMAC authentication token.

        Args:
            token: Token to verify (HMACToken or string)
            message: Original message that was signed
            current_time: Optional current timestamp for testing

        Returns:
            True if token is valid

        Raises:
            HMACAuthError: If verification fails
        """
        # Parse token if string
        if isinstance(token, str):
            token = HMACToken.from_string(token)

        if current_time is None:
            current_time = int(time.time())

        # Check timestamp expiration
        age = current_time - token.timestamp
        if age < 0 or age > self.token_ttl_seconds:
            raise HMACAuthError(
                "Token expired",
                details={
                    "token_age": age,
                    "max_age": self.token_ttl_seconds,
                },
            )

        # Check replay (nonce already used)
        if token.nonce in self._used_nonces:
            raise HMACAuthError(
                "Replay attack detected",
                details={"nonce": token.nonce[:8] + "..."},
            )

        # Recreate expected signature
        payload = self._create_payload(
            token.client_id,
            token.timestamp,
            token.nonce,
            message,
        )

        expected_signature = hmac.new(
            self.secret_key,
            payload,
            hashlib.sha256,
        ).hexdigest()

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(expected_signature, token.signature):
            raise HMACAuthError(
                "Invalid signature",
                details={"client_id": token.client_id},
            )

        # Record nonce to prevent replay
        self._record_nonce(token.nonce)

        logger.debug(f"HMAC verification successful for client: {token.client_id}")
        return True

    def _create_payload(
        self,
        client_id: str,
        timestamp: int,
        nonce: str,
        message: bytes,
    ) -> bytes:
        """Create payload for HMAC signing.

        Payload format: {client_id}|{timestamp}|{nonce}|{message_hash}
        """
        # Hash message to normalize length
        message_hash = hashlib.sha256(message).hexdigest()

        payload_str = f"{client_id}|{timestamp}|{nonce}|{message_hash}"
        return payload_str.encode("utf-8")

    def _record_nonce(self, nonce: str) -> None:
        """Record nonce to prevent replay attacks.

        Implements LRU-like cleanup when cache exceeds max size.
        """
        # Clean up if cache is too large
        if len(self._used_nonces) >= self.max_nonce_cache_size:
            # Remove oldest 10% of nonces
            # Note: set doesn't maintain order, so this is approximate
            # In production, consider using OrderedDict or LRU cache
            to_remove = len(self._used_nonces) // 10
            for _ in range(to_remove):
                self._used_nonces.pop()

        self._used_nonces.add(nonce)


# Environment variable for secret key
_ENV_SECRET_KEY = "TMWS_MCP_HMAC_SECRET"

# Singleton instance
_authenticator: HMACAuthenticator | None = None


def create_hmac_authenticator(
    secret_key: bytes | str | None = None,
    token_ttl_seconds: int = 300,
) -> HMACAuthenticator:
    """Create or get HMAC authenticator instance.

    Args:
        secret_key: Secret key for HMAC (uses env var if None)
        token_ttl_seconds: Token time-to-live in seconds

    Returns:
        HMACAuthenticator instance

    Raises:
        HMACAuthError: If no secret key is available
    """
    global _authenticator

    if _authenticator is not None:
        return _authenticator

    # Resolve secret key
    if secret_key is None:
        secret_key = os.environ.get(_ENV_SECRET_KEY)

    if secret_key is None:
        # Generate ephemeral key with warning
        logger.warning(
            f"No HMAC secret key configured ({_ENV_SECRET_KEY}). "
            "Generating ephemeral key - tokens will not persist across restarts."
        )
        secret_key = secrets.token_bytes(32)
    elif isinstance(secret_key, str):
        secret_key = secret_key.encode("utf-8")

    _authenticator = HMACAuthenticator(
        secret_key=secret_key,
        token_ttl_seconds=token_ttl_seconds,
    )

    logger.info("HMAC authenticator initialized (S-P0-1)")
    return _authenticator


def reset_authenticator() -> None:
    """Reset the singleton authenticator.

    Primarily for testing purposes.
    """
    global _authenticator
    _authenticator = None
