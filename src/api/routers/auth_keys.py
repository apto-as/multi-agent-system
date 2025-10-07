"""
API Key Management Endpoints for TMWS.
User self-service API key creation, listing, and revocation.

Security Note:
- These endpoints use JWT authentication (not API key auth)
- Users can only manage their own API keys
- Raw API keys are only shown once during creation
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from ...models.user import APIKeyScope
from ...services.auth_service import AuthService, auth_service
from ..security import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/api-keys", tags=["api-keys"])


# Pydantic request/response models
class CreateAPIKeyRequest(BaseModel):
    """Request model for creating API key."""

    name: str = Field(..., min_length=2, max_length=128, description="Human-readable key name")
    description: str | None = Field(None, max_length=500, description="Key purpose description")
    scopes: list[APIKeyScope] = Field(
        default_factory=lambda: [APIKeyScope.READ],
        description="API key access scopes",
    )
    expires_days: int | None = Field(
        None, gt=0, description="Optional expiration in days (null = unlimited)"
    )

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: list[APIKeyScope]) -> list[APIKeyScope]:
        """Ensure at least one scope is provided."""
        if not v:
            raise ValueError("At least one scope must be specified")
        # Remove duplicates
        return list(set(v))


class APIKeyInfo(BaseModel):
    """API key metadata (without sensitive data)."""

    key_id: str
    name: str
    description: str | None
    key_prefix: str
    scopes: list[str]
    is_active: bool
    expires_at: str | None
    last_used_at: str | None
    total_requests: int
    created_at: str


class CreateAPIKeyResponse(BaseModel):
    """Response model for API key creation."""

    api_key: str = Field(
        ...,
        description="Full API key (key_id.raw_key) - ONLY SHOWN ONCE, store securely!",
    )
    key_info: APIKeyInfo


class ListAPIKeysResponse(BaseModel):
    """Response model for listing API keys."""

    api_keys: list[APIKeyInfo]
    total: int


class RevokeAPIKeyResponse(BaseModel):
    """Response model for API key revocation."""

    message: str
    key_id: str


# Endpoints
@router.post("/", response_model=CreateAPIKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    request: CreateAPIKeyRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
    auth_service_instance: AuthService = Depends(lambda: auth_service),
) -> CreateAPIKeyResponse:
    """
    Create new API key for authenticated user.

    **Authentication**: Requires valid JWT token (NOT API key)

    **Important**: The raw API key is only shown once in the response.
    Store it securely - it cannot be retrieved later.

    **Response**:
    - `api_key`: Full key in format `{key_id}.{raw_key}` (store this!)
    - `key_info`: Metadata about the created key

    **Scopes**:
    - `read`: Read-only access
    - `write`: Read and write access
    - `full`: Full API access
    - `admin`: Administrative operations
    - `memory`: Memory operations only
    - `tasks`: Task operations only
    - `workflows`: Workflow operations only

    **Expiration**:
    - `null` (default): Key never expires
    - `N` days: Key expires after N days
    """
    try:
        user_id = current_user["id"]

        # Create API key using AuthService
        raw_api_key, api_key_record = await auth_service_instance.create_api_key(
            user_id=user_id,
            name=request.name,
            description=request.description,
            scopes=request.scopes,
            expires_days=request.expires_days,
            allowed_ips=None,  # IP restrictions disabled as per requirements
            rate_limit_per_hour=None,  # Unlimited rate limit as per requirements
        )

        logger.info(
            f"API key created: {api_key_record.key_id} for user {current_user['username']}"
        )

        # Build response
        key_info = APIKeyInfo(
            key_id=api_key_record.key_id,
            name=api_key_record.name,
            description=api_key_record.description,
            key_prefix=api_key_record.key_prefix,
            scopes=[scope.value for scope in api_key_record.scopes],
            is_active=api_key_record.is_active,
            expires_at=api_key_record.expires_at.isoformat() if api_key_record.expires_at else None,
            last_used_at=None,  # New key, never used
            total_requests=0,  # New key
            created_at=api_key_record.created_at.isoformat(),
        )

        return CreateAPIKeyResponse(api_key=raw_api_key, key_info=key_info)

    except ValueError as e:
        logger.warning(f"Invalid API key creation request: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    except Exception as e:
        logger.error(f"Failed to create API key: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key",
        )


@router.get("/", response_model=ListAPIKeysResponse)
async def list_api_keys(
    current_user: dict[str, Any] = Depends(get_current_user),
    auth_service_instance: AuthService = Depends(lambda: auth_service),
) -> ListAPIKeysResponse:
    """
    List all API keys for authenticated user.

    **Authentication**: Requires valid JWT token (NOT API key)

    **Security**:
    - Users can only see their own API keys
    - Raw API keys are NEVER returned (only key prefixes for identification)
    - Only metadata and usage statistics are shown

    **Returns**:
    - List of API key metadata
    - Total count of keys
    """
    try:
        user_id = current_user["id"]

        # Get all API keys for user
        api_keys = await auth_service_instance.list_user_api_keys(user_id)

        # Build response (exclude sensitive data)
        api_keys_info = []
        for key in api_keys:
            key_info = APIKeyInfo(
                key_id=key.key_id,
                name=key.name,
                description=key.description,
                key_prefix=key.key_prefix,
                scopes=[scope.value for scope in key.scopes],
                is_active=key.is_active,
                expires_at=key.expires_at.isoformat() if key.expires_at else None,
                last_used_at=key.last_used_at.isoformat() if key.last_used_at else None,
                total_requests=key.total_requests,
                created_at=key.created_at.isoformat(),
            )
            api_keys_info.append(key_info)

        logger.info(f"Listed {len(api_keys_info)} API keys for user {current_user['username']}")

        return ListAPIKeysResponse(api_keys=api_keys_info, total=len(api_keys_info))

    except Exception as e:
        logger.error(f"Failed to list API keys: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve API keys",
        )


@router.delete("/{key_id}", response_model=RevokeAPIKeyResponse)
async def revoke_api_key(
    key_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
    auth_service_instance: AuthService = Depends(lambda: auth_service),
) -> RevokeAPIKeyResponse:
    """
    Revoke (deactivate) an API key.

    **Authentication**: Requires valid JWT token (NOT API key)

    **Security**:
    - Users can only revoke their own API keys
    - Revoked keys cannot be reactivated (create new key instead)
    - Revocation is immediate

    **Parameters**:
    - `key_id`: The key_id to revoke (from list endpoint)

    **Errors**:
    - `404`: Key not found or belongs to different user
    - `403`: Attempting to revoke another user's key
    """
    try:
        user_id = current_user["id"]

        # Revoke API key (only if it belongs to this user)
        success = await auth_service_instance.revoke_api_key(key_id=key_id, user_id=user_id)

        if not success:
            logger.warning(
                f"API key revocation failed: key {key_id} not found or belongs to different user"
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found or access denied",
            )

        logger.info(f"API key revoked: {key_id} by user {current_user['username']}")

        return RevokeAPIKeyResponse(message="API key revoked successfully", key_id=key_id)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke API key {key_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke API key",
        )
