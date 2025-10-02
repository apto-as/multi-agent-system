"""
Authentication Service for TMWS.
Production-grade user authentication with comprehensive security features.
"""

import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import selectinload

from ..core.database import get_db_session
from ..models.user import APIKey, APIKeyScope, RefreshToken, User, UserRole, UserStatus
from ..security.audit_logger import get_audit_logger
from ..models.audit_log import SecurityEventType, SecurityEventSeverity
from ..security.jwt_service import jwt_service, token_blacklist
from ..utils.security import hash_password_with_salt, verify_password_with_salt


class AuthenticationError(Exception):
    """Base authentication error."""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Invalid username/password."""
    pass


class AccountLockedError(AuthenticationError):
    """Account is locked due to failed login attempts."""
    pass


class AccountDisabledError(AuthenticationError):
    """Account is disabled or suspended."""
    pass


class TokenExpiredError(AuthenticationError):
    """Token has expired."""
    pass


class InsufficientPermissionsError(AuthenticationError):
    """User lacks required permissions."""
    pass


class AuthService:
    """Comprehensive authentication service with high-performance requirements."""

    def __init__(self):
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30
        self.password_min_length = 8

    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
        roles: list[UserRole] | None = None,
        agent_namespace: str = "default",
        created_by: str | None = None
    ) -> User:
        """
        Create new user account with secure password hashing.
        """
        # Input validation
        if len(username) < 2 or len(username) > 64:
            raise ValueError("Username must be 2-64 characters long")

        if len(password) < self.password_min_length:
            raise ValueError(f"Password must be at least {self.password_min_length} characters long")

        # Hash password securely
        password_hash, password_salt = hash_password_with_salt(password)

        # Set default roles
        if roles is None:
            roles = [UserRole.USER]

        user = User(
            username=username,
            email=email,
            full_name=full_name,
            password_hash=password_hash,
            password_salt=password_salt,
            roles=roles,
            agent_namespace=agent_namespace,
            password_changed_at=datetime.now(timezone.utc),
            created_by=created_by,
            status=UserStatus.ACTIVE
        )

        # Save to database
        async with get_db_session() as session:
            # Check for existing username/email
            existing = await session.execute(
                select(User).where(
                    or_(User.username == username, User.email == email)
                )
            )
            if existing.scalar_one_or_none():
                raise ValueError("Username or email already exists")

            session.add(user)
            await session.commit()
            await session.refresh(user)

        # Audit log (temporarily disabled for testing)
        try:
            audit_logger = get_audit_logger()
            await audit_logger.log_event(
                event_type=SecurityEventType.ADMIN_ACTION,
                severity=SecurityEventSeverity.LOW,
                client_ip="127.0.0.1",
                message=f"User created: {user.username}",
                user_id=created_by or "system",
                details={"action": "user_creation", "new_user_id": str(user.id), "username": user.username}
            )
        except Exception as e:
            # Log audit error but don't fail the operation
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Audit logging failed: {e}")

        return user

    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str | None = None
    ) -> tuple[User, str, str]:
        """
        Authenticate user and return user object with tokens.
        Returns (user, access_token, refresh_token).
        Performance target: <200ms.
        """
        async with get_db_session() as session:
            # Fetch user with single query
            result = await session.execute(
                select(User).where(
                    or_(User.username == username, User.email == username)
                )
            )
            user = result.scalar_one_or_none()

            # Check if user exists
            if not user:
                await self._log_failed_login(username, ip_address, "user_not_found")
                raise InvalidCredentialsError("Invalid credentials")

            # Check account status
            if user.status == UserStatus.LOCKED:
                await self._log_failed_login(username, ip_address, "account_locked")
                raise AccountLockedError("Account is locked")

            if user.status in [UserStatus.SUSPENDED, UserStatus.INACTIVE]:
                await self._log_failed_login(username, ip_address, "account_disabled")
                raise AccountDisabledError("Account is disabled")

            # Verify password
            if not verify_password_with_salt(password, user.password_hash, user.password_salt):
                # Increment failed login attempts
                user.increment_failed_login()
                await session.commit()

                await self._log_failed_login(username, ip_address, "invalid_password")
                raise InvalidCredentialsError("Invalid credentials")

            # Successful authentication - reset failed attempts
            user.reset_failed_login()
            if ip_address:
                user.last_login_ip = ip_address

            await session.commit()

            # Generate tokens
            access_token = jwt_service.create_access_token(user)
            refresh_token, refresh_record = jwt_service.create_refresh_token(user)

            # Save refresh token
            session.add(refresh_record)
            await session.commit()

            # Audit successful login (temporarily disabled for testing)
            try:
                audit_logger = get_audit_logger()
                await audit_logger.log_event(
                    event_type=SecurityEventType.LOGIN_SUCCESS,
                    severity=SecurityEventSeverity.LOW,
                    client_ip=ip_address or "127.0.0.1",
                    message=f"User login successful: {user.username}",
                    user_id=user.username,
                    details={"login_method": "password"}
                )
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Audit logging failed: {e}")

            return user, access_token, refresh_token

    async def refresh_access_token(self, refresh_token: str) -> tuple[str, str]:
        """
        Refresh access token using refresh token.
        Returns (new_access_token, new_refresh_token).
        """
        # Verify refresh token format
        token_id = jwt_service.verify_refresh_token(refresh_token)
        if not token_id:
            raise TokenExpiredError("Invalid refresh token format")

        # Extract raw token
        parts = refresh_token.split(".", 1)
        raw_token = parts[1]

        async with get_db_session() as session:
            # Fetch refresh token record
            result = await session.execute(
                select(RefreshToken)
                .where(RefreshToken.token_id == token_id)
                .options(selectinload(RefreshToken.user))
            )
            refresh_record = result.scalar_one_or_none()

            if not refresh_record or not refresh_record.is_valid():
                raise TokenExpiredError("Refresh token expired or revoked")

            # Verify token hash
            if not jwt_service.verify_refresh_token_hash(raw_token, refresh_record.token_hash):
                raise TokenExpiredError("Invalid refresh token")

            # Check user status
            user = refresh_record.user
            if not user.is_active():
                raise AccountDisabledError("User account is disabled")

            # Revoke old refresh token
            refresh_record.revoke()

            # Generate new tokens
            new_access_token = jwt_service.create_access_token(user)
            new_refresh_token, new_refresh_record = jwt_service.create_refresh_token(user)

            # Save new refresh token
            session.add(new_refresh_record)
            await session.commit()

            return new_access_token, new_refresh_token

    async def create_api_key(
        self,
        user_id: UUID,
        name: str,
        description: str | None = None,
        scopes: list[APIKeyScope] | None = None,
        expires_days: int | None = None,
        allowed_ips: list[str] | None = None,
        rate_limit_per_hour: int | None = None
    ) -> tuple[str, APIKey]:
        """
        Create API key for user.
        Returns (raw_key, api_key_record).
        """
        # Generate secure API key
        raw_key = secrets.token_urlsafe(32)
        key_prefix = raw_key[:8]
        key_hash = jwt_service.pwd_context.hash(raw_key)
        key_id = secrets.token_urlsafe(16)

        # Set default scopes
        if scopes is None:
            scopes = [APIKeyScope.READ]

        # Calculate expiration
        expires_at = None
        if expires_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

        api_key = APIKey(
            key_id=key_id,
            name=name,
            description=description,
            key_hash=key_hash,
            key_prefix=key_prefix,
            scopes=scopes,
            allowed_ips=allowed_ips,
            rate_limit_per_hour=rate_limit_per_hour,
            expires_at=expires_at,
            user_id=user_id
        )

        async with get_db_session() as session:
            session.add(api_key)
            await session.commit()
            await session.refresh(api_key)

        # Format final key: key_id.raw_key
        final_key = f"{key_id}.{raw_key}"

        return final_key, api_key

    async def validate_api_key(
        self,
        api_key: str,
        required_scope: APIKeyScope | None = None,
        ip_address: str | None = None
    ) -> tuple[User, APIKey]:
        """
        Validate API key and return user and key objects.
        Performance target: <100ms.
        """
        # Parse key format: key_id.raw_key
        try:
            key_id, raw_key = api_key.split(".", 1)
        except ValueError:
            raise InvalidCredentialsError("Invalid API key format")

        async with get_db_session() as session:
            # Fetch API key with user in single query
            result = await session.execute(
                select(APIKey)
                .where(APIKey.key_id == key_id)
                .options(selectinload(APIKey.user))
            )
            key_record = result.scalar_one_or_none()

            if not key_record:
                raise InvalidCredentialsError("Invalid API key")

            # Verify key hash
            if not jwt_service.pwd_context.verify(raw_key, key_record.key_hash):
                raise InvalidCredentialsError("Invalid API key")

            # Check key validity
            if not key_record.is_valid():
                raise TokenExpiredError("API key expired or disabled")

            # Check IP restrictions
            if ip_address and not key_record.is_ip_allowed(ip_address):
                raise InsufficientPermissionsError("IP address not allowed")

            # Check required scope
            if required_scope and not key_record.has_scope(required_scope):
                raise InsufficientPermissionsError("Insufficient API key scope")

            # Check user status
            if not key_record.user.is_active():
                raise AccountDisabledError("User account disabled")

            # Record usage
            key_record.record_usage(ip_address or "unknown")
            await session.commit()

            return key_record.user, key_record

    async def logout_user(self, refresh_token: str, access_token: str | None = None) -> None:
        """Logout user by revoking refresh token and blacklisting access token."""
        # Revoke refresh token
        token_id = jwt_service.verify_refresh_token(refresh_token)
        if token_id:
            async with get_db_session() as session:
                await session.execute(
                    update(RefreshToken)
                    .where(RefreshToken.token_id == token_id)
                    .values(is_revoked=True)
                )
                await session.commit()

        # Blacklist access token
        if access_token:
            payload = jwt_service.decode_token_unsafe(access_token)
            if payload and "jti" in payload:
                token_blacklist.blacklist_token(payload["jti"])

    async def logout_all_sessions(self, user_id: UUID) -> None:
        """Logout user from all sessions."""
        async with get_db_session() as session:
            # Revoke all refresh tokens
            await session.execute(
                update(RefreshToken)
                .where(RefreshToken.user_id == user_id)
                .values(is_revoked=True)
            )
            await session.commit()

        # Blacklist user tokens
        token_blacklist.blacklist_user_tokens(str(user_id))

    async def change_password(
        self,
        user_id: UUID,
        current_password: str,
        new_password: str
    ) -> None:
        """Change user password with validation."""
        if len(new_password) < self.password_min_length:
            raise ValueError(f"Password must be at least {self.password_min_length} characters long")

        async with get_db_session() as session:
            user = await session.get(User, user_id)
            if not user:
                raise ValueError("User not found")

            # Verify current password
            if not verify_password_with_salt(current_password, user.password_hash, user.password_salt):
                raise InvalidCredentialsError("Current password is incorrect")

            # Hash new password
            password_hash, password_salt = hash_password_with_salt(new_password)

            # Update password
            user.password_hash = password_hash
            user.password_salt = password_salt
            user.password_changed_at = datetime.now(timezone.utc)
            user.force_password_change = False

            await session.commit()

        # Logout all sessions for security
        await self.logout_all_sessions(user_id)

    async def reset_password(self, user_id: UUID, new_password: str) -> None:
        """Reset user password (admin operation)."""
        if len(new_password) < self.password_min_length:
            raise ValueError(f"Password must be at least {self.password_min_length} characters long")

        password_hash, password_salt = hash_password(new_password)

        async with get_db_session() as session:
            await session.execute(
                update(User)
                .where(User.id == user_id)
                .values(
                    password_hash=password_hash,
                    password_salt=password_salt,
                    password_changed_at=datetime.now(timezone.utc),
                    force_password_change=True,
                    failed_login_attempts=0,
                    status=UserStatus.ACTIVE
                )
            )
            await session.commit()

        # Logout all sessions
        await self.logout_all_sessions(user_id)

    async def unlock_account(self, user_id: UUID) -> None:
        """Unlock locked user account."""
        async with get_db_session() as session:
            await session.execute(
                update(User)
                .where(User.id == user_id)
                .values(
                    status=UserStatus.ACTIVE,
                    failed_login_attempts=0,
                    last_failed_login_at=None
                )
            )
            await session.commit()

    async def disable_account(self, user_id: UUID) -> None:
        """Disable user account."""
        async with get_db_session() as session:
            await session.execute(
                update(User)
                .where(User.id == user_id)
                .values(status=UserStatus.SUSPENDED)
            )
            await session.commit()

        # Logout all sessions
        await self.logout_all_sessions(user_id)

    async def get_user_by_id(self, user_id: UUID) -> User | None:
        """Get user by ID."""
        async with get_db_session() as session:
            return await session.get(User, user_id)

    async def get_user_by_username(self, username: str) -> User | None:
        """Get user by username."""
        async with get_db_session() as session:
            result = await session.execute(
                select(User).where(User.username == username)
            )
            return result.scalar_one_or_none()

    async def list_user_api_keys(self, user_id: UUID) -> list[APIKey]:
        """List all API keys for user."""
        async with get_db_session() as session:
            result = await session.execute(
                select(APIKey)
                .where(APIKey.user_id == user_id)
                .order_by(APIKey.created_at.desc())
            )
            return result.scalars().all()

    async def revoke_api_key(self, key_id: str, user_id: UUID) -> bool:
        """Revoke API key for user."""
        async with get_db_session() as session:
            result = await session.execute(
                update(APIKey)
                .where(and_(APIKey.key_id == key_id, APIKey.user_id == user_id))
                .values(is_active=False)
            )
            await session.commit()
            return result.rowcount > 0

    async def _log_failed_login(
        self,
        username: str,
        ip_address: str | None,
        reason: str
    ) -> None:
        """Log failed login attempt."""
        try:
            audit_logger = get_audit_logger()
            await audit_logger.log_event(
                event_type=SecurityEventType.LOGIN_FAILED,
                severity=SecurityEventSeverity.MEDIUM,
                client_ip=ip_address or "127.0.0.1",
                message=f"Login failed for user: {username}",
                user_id=username,
                details={"reason": reason, "login_method": "password"}
            )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Audit logging failed: {e}")


# Global auth service instance
auth_service = AuthService()
