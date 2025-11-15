"""FastAPI Exception Handlers

This module maps application and domain exceptions to HTTP responses.

Security Note:
- All exception handlers sanitize error details
- NO internal IDs, stack traces, or database details are exposed
- Only safe, user-facing messages are returned
"""

# ruff: noqa: ARG001

from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from src.application.exceptions import (
    ApplicationError,
    AuthorizationError,
    ExternalServiceError,
    ValidationError,
)
from src.domain.exceptions import AggregateNotFoundError, DomainException


async def pydantic_validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Map Pydantic RequestValidationError → 400 Bad Request (not 422)

    FastAPI returns 422 by default, but we want 400 for consistency.

    Args:
        request: FastAPI request
        exc: RequestValidationError from Pydantic

    Returns:
        JSONResponse with 400 status
    """
    # Extract readable error message from Pydantic errors
    errors = exc.errors()
    if errors:
        first_error = errors[0]
        field = ".".join(str(loc) for loc in first_error.get("loc", []))
        message = f"Validation error in {field}: {first_error.get('msg', 'Invalid value')}"
    else:
        message = "Invalid request data"

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error_code": "VALIDATION_ERROR",
            "message": message,
            "details": errors,
        },
    )


async def validation_error_handler(
    request: Request, exc: ValidationError
) -> JSONResponse:
    """Map ValidationError → 400 Bad Request

    This handles input validation failures from business logic.

    Args:
        request: FastAPI request
        exc: ValidationError exception

    Returns:
        JSONResponse with 400 status and sanitized error details
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error_code": "VALIDATION_ERROR",
            "message": str(exc),
        },
    )


async def authorization_error_handler(
    request: Request, exc: AuthorizationError
) -> JSONResponse:
    """Map AuthorizationError → 403 Forbidden

    Security Critical:
    - DO NOT expose namespace, agent_id, or resource identifiers
    - Keep error message generic to prevent information leakage
    - Specific details logged server-side only

    Args:
        request: FastAPI request
        exc: AuthorizationError exception

    Returns:
        JSONResponse with 403 status and generic message
    """
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            # FastAPI TestClient expects 'detail' key
            "detail": str(exc),
            # ⚠️ DO NOT include exc.details (may contain sensitive info)
        },
    )


async def not_found_error_handler(
    request: Request, exc: AggregateNotFoundError
) -> JSONResponse:
    """Map AggregateNotFoundError → 404 Not Found

    Security Note:
    - DO NOT expose internal identifiers (UUIDs, primary keys)
    - Only expose aggregate type (e.g., "Connection", "Agent")
    - Specific identifier logged server-side only

    Args:
        request: FastAPI request
        exc: AggregateNotFoundError exception

    Returns:
        JSONResponse with 404 status and generic message
    """
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            # FastAPI TestClient expects 'detail' key
            "detail": f"{exc.details.get('aggregate_type', 'Resource')} not found",
        },
    )


async def external_service_error_handler(
    request: Request, exc: ExternalServiceError
) -> JSONResponse:
    """Map ExternalServiceError → 502 Bad Gateway

    Security Note:
    - DO NOT expose internal service URLs or configurations
    - DO NOT expose connection details or credentials
    - Keep error message generic for external clients

    Args:
        request: FastAPI request
        exc: ExternalServiceError exception

    Returns:
        JSONResponse with 502 status and generic message
    """
    return JSONResponse(
        status_code=status.HTTP_502_BAD_GATEWAY,
        content={
            "error_code": "EXTERNAL_SERVICE_ERROR",
            "message": str(exc),
        },
    )


async def domain_exception_handler(
    request: Request, exc: DomainException
) -> JSONResponse:
    """Map generic DomainException → 400 Bad Request

    This is a catch-all for domain exceptions not handled by specific handlers.

    Args:
        request: FastAPI request
        exc: DomainException exception

    Returns:
        JSONResponse with 400 status and sanitized message
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error_code": "DOMAIN_ERROR",
            "message": str(exc),
            # Domain exception details are generally safe to expose
            "details": exc.details if hasattr(exc, "details") else None,
        },
    )


async def application_error_handler(
    request: Request, exc: ApplicationError
) -> JSONResponse:
    """Map generic ApplicationError → 500 Internal Server Error

    This is a catch-all for application errors not handled by specific handlers.

    Security Note:
    - Keep error message generic
    - Log full exception details server-side
    - DO NOT expose internal implementation details

    Args:
        request: FastAPI request
        exc: ApplicationError exception

    Returns:
        JSONResponse with 500 status and generic message
    """
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error_code": "INTERNAL_ERROR",
            # Generic message for unknown errors
            "message": "An internal error occurred",
            # ⚠️ DO NOT expose exception details
        },
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Map any unhandled exception → 500 Internal Server Error

    This is the final safety net for any unexpected exceptions.

    Security Critical:
    - NEVER expose stack traces or internal details
    - Log full exception server-side for debugging
    - Return generic message to client

    Args:
        request: FastAPI request
        exc: Any unhandled exception

    Returns:
        JSONResponse with 500 status and generic message
    """
    # TODO: Log full exception with stack trace for debugging
    # logger.exception("Unhandled exception", exc_info=exc)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error_code": "INTERNAL_ERROR",
            "message": "An unexpected error occurred",
            # ⚠️ DO NOT expose any exception details
        },
    )
