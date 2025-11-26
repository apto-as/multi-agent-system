"""FastAPI Application Initialization

This module initializes the FastAPI app with:
- CORS middleware
- Exception handlers
- API routers
- Health check endpoint

Security:
- All exceptions are sanitized before exposing to clients
- CORS configured for production (update for your domain)
- JWT authentication required for all /api endpoints
"""

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from src.api.exception_handlers import (
    application_error_handler,
    authorization_error_handler,
    domain_exception_handler,
    external_service_error_handler,
    generic_exception_handler,
    not_found_error_handler,
    pydantic_validation_error_handler,
    validation_error_handler,
)
from src.api.routers import mcp_connections, skills
from src.application.exceptions import (
    ApplicationError,
    AuthorizationError,
    ExternalServiceError,
    ValidationError,
)
from src.core.config import settings
from src.domain.exceptions import AggregateNotFoundError, DomainException
from src.infrastructure.exceptions import (
    AggregateNotFoundError as InfraAggregateNotFoundError,
)

# ============================================================================
# FastAPI App Initialization
# ============================================================================

app = FastAPI(
    title="TMWS MCP Connection API",
    version="2.3.0",
    description="Trinitas Memory & Workflow System - MCP Connection Management",
    docs_url="/api/docs",  # Swagger UI
    redoc_url="/api/redoc",  # ReDoc
)

# ============================================================================
# CORS Middleware
# ============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins or ["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# ============================================================================
# Exception Handlers (Security: Sanitize all errors)
# ============================================================================

# Pydantic validation errors (422 → 400)
app.add_exception_handler(RequestValidationError, pydantic_validation_error_handler)

# Application-layer exceptions
app.add_exception_handler(ValidationError, validation_error_handler)
app.add_exception_handler(AuthorizationError, authorization_error_handler)
app.add_exception_handler(ExternalServiceError, external_service_error_handler)
app.add_exception_handler(ApplicationError, application_error_handler)

# Domain-layer exceptions
app.add_exception_handler(AggregateNotFoundError, not_found_error_handler)
app.add_exception_handler(DomainException, domain_exception_handler)

# Infrastructure-layer exceptions (handle both domain and infrastructure versions)
app.add_exception_handler(InfraAggregateNotFoundError, not_found_error_handler)

# Catch-all for unexpected exceptions (security: never expose internals)
app.add_exception_handler(Exception, generic_exception_handler)

# ============================================================================
# API Routers
# ============================================================================

app.include_router(mcp_connections.router)
app.include_router(skills.router)

# ============================================================================
# Health Check
# ============================================================================


@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """Health check endpoint

    Returns:
        Dict with status indicating service is healthy
    """
    return {"status": "healthy", "service": "tmws-mcp-api", "version": "2.3.0"}


@app.get("/", tags=["Root"])
async def root() -> dict:
    """Root endpoint with API information

    Returns:
        Dict with API metadata and links
    """
    return {
        "service": "TMWS MCP Connection API",
        "version": "2.3.0",
        "docs": "/api/docs",
        "redoc": "/api/redoc",
        "health": "/health",
    }
