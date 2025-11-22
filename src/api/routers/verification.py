"""Verification Service FastAPI Router.

This module provides HTTP endpoints for claim verification and trust score management.
All endpoints follow Day 2 architecture patterns with thin controllers.

Endpoints:
- POST /api/v1/verification/verify-and-record - Verify claim and record evidence

Design Principles:
1. Thin controllers - delegate to VerificationService
2. Security-first - V-VERIFY-1/2 compliance
3. Pydantic validation - request/response models
4. Async-first - non-blocking I/O

Security:
- V-VERIFY-1: Command injection prevention (in VerificationService)
- V-VERIFY-2: RBAC authorization (verifier role check)
- V-VERIFY-3: Namespace isolation (verified from DB)
- V-TRUST-5: Self-verification prevention

Performance:
- <500ms P95 per verification (target)
- Non-blocking async operations
- Graceful error handling with proper HTTP status codes
"""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_current_user, get_db_session
from src.core.exceptions import (
    AgentNotFoundError,
    DatabaseError,
    ValidationError,
    VerificationError,
)
from src.models.user import User
from src.services.verification_service import VerificationService

router = APIRouter(prefix="/api/v1/verification", tags=["Verification"])


# ============================================================================
# Request/Response Models
# ============================================================================


class VerifyAndRecordRequest(BaseModel):
    """Request model for verify-and-record endpoint"""

    agent_id: str = Field(
        ...,
        description="Agent making the claim",
        examples=["artemis-optimizer"],
    )
    claim_type: str = Field(
        ...,
        description="Type of claim (test_result, performance_metric, etc.)",
        examples=["test_result"],
    )
    claim_content: dict[str, Any] = Field(
        ...,
        description="The claim to verify (structure depends on claim_type)",
        examples=[{"return_code": 0, "output_contains": "PASS"}],
    )
    verification_command: str = Field(
        ...,
        description="Shell command to execute for verification",
        examples=["pytest tests/unit/ -v"],
    )
    verified_by_agent_id: str | None = Field(
        None,
        description="Optional agent performing verification (defaults to current user's agent)",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "artemis-optimizer",
                "claim_type": "test_result",
                "claim_content": {
                    "return_code": 0,
                    "output_contains": ["100% PASSED", "370 passed"],
                },
                "verification_command": "pytest tests/unit/ -v",
                "verified_by_agent_id": "hestia-auditor",
            },
        }


class VerifyAndRecordResponse(BaseModel):
    """Response model for verify-and-record endpoint"""

    verification_id: UUID = Field(
        ...,
        description="Unique identifier for this verification",
    )
    accurate: bool = Field(
        ...,
        description="Whether the claim was accurate",
    )
    evidence_id: UUID = Field(
        ...,
        description="Memory ID containing verification evidence",
    )
    new_trust_score: float = Field(
        ...,
        description="Agent's trust score after verification",
        ge=0.0,
        le=1.0,
    )
    claim: dict[str, Any] = Field(
        ...,
        description="Original claim content",
    )
    actual: dict[str, Any] = Field(
        ...,
        description="Actual verification result",
    )
    pattern_linked: bool = Field(
        False,
        description="Whether verification was linked to a learning pattern (Phase 2A)",
    )
    pattern_id: str | None = Field(
        None,
        description="Linked pattern UUID (if pattern_linked=true)",
    )
    trust_delta: float | None = Field(
        None,
        description="Trust score change from pattern propagation (if linked)",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "verification_id": "123e4567-e89b-12d3-a456-426614174000",
                "accurate": True,
                "evidence_id": "223e4567-e89b-12d3-a456-426614174001",
                "new_trust_score": 0.55,
                "claim": {"return_code": 0, "output_contains": "PASS"},
                "actual": {
                    "return_code": 0,
                    "stdout": "100% PASSED\n370 passed",
                    "stderr": "",
                    "command": "pytest tests/unit/ -v",
                },
                "pattern_linked": False,
                "pattern_id": None,
                "trust_delta": None,
            },
        }


# ============================================================================
# Dependency Injection
# ============================================================================


async def get_verification_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> VerificationService:
    """Dependency: Get VerificationService instance

    Args:
        session: Database session (injected)

    Returns:
        VerificationService instance with shared session
    """
    return VerificationService(session)


# ============================================================================
# POST /api/v1/verification/verify-and-record
# ============================================================================


@router.post("/verify-and-record", response_model=VerifyAndRecordResponse)
async def verify_and_record_endpoint(
    request: VerifyAndRecordRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    verification_service: Annotated[VerificationService, Depends(get_verification_service)],
) -> VerifyAndRecordResponse:
    """Verify a claim and record evidence with Trust Score update

    This endpoint executes a verification command, compares the result with
    the claimed outcome, records evidence to memory, and updates the agent's
    trust score based on accuracy.

    Security:
    - Requires JWT/API Key authentication
    - V-VERIFY-1: Command injection prevention (allowlist in VerificationService)
    - V-VERIFY-2: Verifier authorization (requires AGENT/ADMIN role)
    - V-VERIFY-3: Namespace isolation (verified from DB)
    - V-TRUST-5: Self-verification prevention

    Performance:
    - Target: <500ms P95 per verification
    - Async execution: Non-blocking I/O
    - Pattern propagation: <35ms overhead (Phase 2A)

    Integration (Phase 2A):
    - If claim_content contains "pattern_id", verification result propagates
      to learning pattern trust scores (±0.02 additional delta)
    - Graceful degradation: Pattern failures don't block verification

    Args:
        request: Verification request with claim and command
        current_user: Authenticated user (from JWT/API Key)
        verification_service: Injected VerificationService

    Returns:
        VerifyAndRecordResponse with verification result and trust score

    Raises:
        HTTPException 400: Validation error (invalid command, self-verification, etc.)
        HTTPException 403: Authorization error (verifier lacks AGENT/ADMIN role)
        HTTPException 404: Agent not found
        HTTPException 500: Internal server error (verification execution failed)

    Example:
        ```bash
        curl -X POST http://localhost:8000/api/v1/verification/verify-and-record \\
          -H "Authorization: Bearer $TOKEN" \\
          -H "Content-Type: application/json" \\
          -d '{
            "agent_id": "artemis-optimizer",
            "claim_type": "test_result",
            "claim_content": {"return_code": 0, "output_contains": "PASS"},
            "verification_command": "echo PASS"
          }'
        ```
    """
    try:
        # Default verifier to current user's agent_id if not specified
        verifier_id = request.verified_by_agent_id or current_user.agent_id

        # Execute verification via VerificationService
        # Security checks (V-VERIFY-1/2/3, V-TRUST-5) happen in service layer
        result = await verification_service.verify_claim(
            agent_id=request.agent_id,
            claim_type=request.claim_type,
            claim_content=request.claim_content,
            verification_command=request.verification_command,
            verified_by_agent_id=verifier_id,
        )

        # Extract pattern linkage info (if present)
        pattern_id_str = request.claim_content.get("pattern_id")

        # Construct response
        return VerifyAndRecordResponse(
            verification_id=result.verification_id,
            accurate=result.accurate,
            evidence_id=result.evidence_id,
            new_trust_score=result.new_trust_score,
            claim=result.claim,
            actual=result.actual,
            pattern_linked=pattern_id_str is not None,
            pattern_id=pattern_id_str,
            trust_delta=None,  # TODO: Extract from propagation result (Phase 2A)
        )

    except ValidationError as e:
        # 400 Bad Request: Invalid input (command not allowed, self-verification, etc.)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    except PermissionError as e:
        # 403 Forbidden: Authorization failure (verifier lacks AGENT/ADMIN role)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        ) from e

    except AgentNotFoundError as e:
        # 404 Not Found: Agent doesn't exist
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e

    except VerificationError as e:
        # 500 Internal Server Error: Verification execution failed
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification execution failed: {str(e)}",
        ) from e

    except DatabaseError as e:
        # 500 Internal Server Error: Database operation failed
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}",
        ) from e

    except Exception as e:
        # 500 Internal Server Error: Unexpected error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}",
        ) from e
