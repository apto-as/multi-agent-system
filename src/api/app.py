"""
Main FastAPI application for TMWS.
"""

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ..core.config import get_settings
from ..core.database import DatabaseHealthCheck, close_db_connections, create_tables
from .middleware_unified import setup_middleware
from .routers import auth_keys, health, memory, persona, task, websocket_mcp, workflow

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info("TMWS starting up...")

    try:
        # Initialize database
        await create_tables()
        logger.info("Database tables created/verified")

        # Verify database connection
        if not await DatabaseHealthCheck.check_connection():
            logger.error("Database health check failed during startup")
            raise Exception("Database connection failed")

        logger.info("TMWS startup completed successfully")

        # Application is ready
        yield

    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise

    # Shutdown
    logger.info("TMWS shutting down...")

    try:
        # Close database connections
        await close_db_connections()
        logger.info("Database connections closed")

        logger.info("TMWS shutdown completed successfully")

    except Exception as e:
        logger.error(f"Shutdown error: {e}")


def create_app() -> FastAPI:
    """
    Create and configure FastAPI application.

    Returns:
        Configured FastAPI application
    """

    # Enhanced API description with authentication information
    api_description = f"""{settings.api_description}

## Authentication

TMWS supports two authentication methods:

1. **JWT Token Authentication**: For user sessions and interactive applications
   - Obtain token via `/api/v1/auth/login`
   - Include in header: `Authorization: Bearer <token>`

2. **API Key Authentication**: For service integrations and automation
   - Create key via `/api/v1/auth/api-keys`
   - Include in header: `X-API-Key: <key>`

**Current Mode**: {'Production (Authentication Required)' if settings.auth_enabled else 'Development (No Authentication)'}

📚 [Full Authentication Guide](https://github.com/apto-as/tmws/blob/master/docs/API_AUTHENTICATION.md)
"""

    # Create FastAPI app with security-focused configuration
    app = FastAPI(
        title=settings.api_title,
        version=settings.api_version,
        description=api_description,
        lifespan=lifespan,
        # Security configurations
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        # Additional security settings
        swagger_ui_parameters={
            "persistAuthorization": False,
            "displayRequestDuration": True,
            "tryItOutEnabled": not settings.is_production,
        }
        if not settings.is_production
        else None,
    )

    # Setup unified middleware
    setup_middleware(app)

    # Define OpenAPI security schemes
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        from fastapi.openapi.utils import get_openapi

        openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )

        # Add security schemes
        openapi_schema["components"]["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT token obtained from /api/v1/auth/login endpoint",
            },
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "API key obtained from /api/v1/auth/api-keys endpoint",
            },
        }

        # Add security requirement to all endpoints by default
        # Individual endpoints can override this
        if settings.auth_enabled:
            openapi_schema["security"] = [{"BearerAuth": []}, {"ApiKeyAuth": []}]

        # Add authentication status to info
        openapi_schema["info"]["x-authentication"] = {
            "enabled": settings.auth_enabled,
            "mode": "production" if settings.auth_enabled else "development",
            "methods": ["JWT Bearer Token", "API Key"],
        }

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi

    # Include routers
    app.include_router(health.router, prefix="/health", tags=["health"])

    # Authentication and API key management
    app.include_router(auth_keys.router, prefix="/api/v1", tags=["authentication"])

    app.include_router(memory.router, prefix="/api/v1/memory", tags=["memory"])

    app.include_router(persona.router, prefix="/api/v1/personas", tags=["personas"])

    app.include_router(task.router, prefix="/api/v1/tasks", tags=["tasks"])

    app.include_router(workflow.router, prefix="/api/v1/workflows", tags=["workflows"])

    # WebSocket MCP endpoint - Elite real-time communication
    app.include_router(websocket_mcp.router, prefix="/ws", tags=["websocket", "mcp"])

    # Root endpoint
    @app.get("/")
    async def root() -> dict[str, Any]:
        """Root endpoint with basic API information."""
        return {
            "message": "TMWS - Trinitas Memory & Workflow Service",
            "version": settings.api_version,
            "environment": settings.environment,
            "status": "running",
            "docs_url": "/docs" if not settings.is_production else None,
        }

    # Global exception handlers
    @app.exception_handler(404)
    async def not_found_handler(request: Request, _exc: HTTPException):
        """Handle 404 errors."""
        return JSONResponse(
            status_code=404,
            content={
                "error": "Not Found",
                "message": "The requested resource was not found",
                "path": str(request.url.path),
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc: Exception):
        """Handle 500 errors."""
        request_id = getattr(request.state, "request_id", None)
        logger.error(f"Internal server error {request_id}: {str(exc)}", exc_info=True)

        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "message": "An unexpected error occurred" if settings.is_production else str(exc),
                "request_id": request_id,
            },
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.detail,
                "status_code": exc.status_code,
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    # Validation error handler
    from fastapi.exceptions import RequestValidationError
    from pydantic import ValidationError

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle request validation errors."""
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Validation Error",
                "message": "Request validation failed",
                "details": exc.errors(),
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(ValidationError)
    async def pydantic_validation_exception_handler(request: Request, exc: ValidationError):
        """Handle Pydantic validation errors."""
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Data Validation Error",
                "message": "Data validation failed",
                "details": exc.errors(),
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    # Add custom headers
    @app.middleware("http")
    async def add_api_headers(request: Request, call_next):
        """Add custom API headers."""
        response = await call_next(request)

        # API version header
        response.headers["X-API-Version"] = settings.api_version

        # Environment header (only in development)
        if settings.is_development:
            response.headers["X-Environment"] = settings.environment

        return response

    logger.info(f"FastAPI application created for {settings.environment} environment")

    return app


# Create application instance
app = create_app()


# Additional configuration for production
if settings.is_production:
    # Disable server header
    @app.middleware("http")
    async def remove_server_header(request: Request, call_next):
        response = await call_next(request)
        if "server" in response.headers:
            del response.headers["server"]
        return response

    logger.info("Production security configurations applied")


def get_app_info() -> dict[str, Any]:
    """Get application information."""
    return {
        "name": settings.api_title,
        "version": settings.api_version,
        "environment": settings.environment,
        "debug": settings.is_development,
        "docs_enabled": not settings.is_production,
        "security_headers": True,
        "rate_limiting": settings.rate_limit_enabled,
        "cors_enabled": bool(settings.cors_origins),
        "database_url": settings.database_url_async.split("@")[0]
        + "@[REDACTED]",  # Hide credentials
    }


# Create default app instance for uvicorn
app = create_app()
