"""Service manager for TMWS v2.0 - Universal Multi-Agent Platform.
Centralized service lifecycle management with dependency injection and health monitoring.
"""

import asyncio
import logging
import signal
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from typing import Any, TypeVar

from ..services.batch_service import batch_service
from ..services.learning_service import LearningService
from .database import get_db_session_dependency as db_manager
from .exceptions import ServiceError

logger = logging.getLogger(__name__)

T = TypeVar("T")


class ServiceRegistry:
    """Service registry for dependency injection and lifecycle management."""

    def __init__(self):
        self._services: dict[str, Any] = {}
        self._dependencies: dict[str, list[str]] = {}
        self._initialized: dict[str, bool] = {}
        self._health_status: dict[str, dict[str, Any]] = {}

    def register(self, name: str, service: Any, dependencies: list[str] | None = None) -> None:
        """Register a service with optional dependencies."""
        self._services[name] = service
        self._dependencies[name] = dependencies or []
        self._initialized[name] = False
        self._health_status[name] = {"status": "unknown", "last_check": None, "error": None}
        logger.debug(f"Registered service: {name}")

    def get(self, name: str) -> Any:
        """Get a service by name."""
        if name not in self._services:
            raise ServiceError(f"Service '{name}' not found")
        return self._services[name]

    def get_all(self) -> dict[str, Any]:
        """Get all registered services."""
        return self._services.copy()

    def is_initialized(self, name: str) -> bool:
        """Check if a service is initialized."""
        return self._initialized.get(name, False)

    def set_initialized(self, name: str, status: bool = True) -> None:
        """Set service initialization status."""
        self._initialized[name] = status

    def get_dependencies(self, name: str) -> list[str]:
        """Get service dependencies."""
        return self._dependencies.get(name, [])

    def get_health_status(self, name: str) -> dict[str, Any]:
        """Get service health status."""
        return self._health_status.get(name, {"status": "unknown"})

    def update_health_status(self, name: str, status: str, error: str | None = None) -> None:
        """Update service health status."""
        self._health_status[name] = {"status": status, "last_check": datetime.now(), "error": error}

    def get_service_names(self) -> list[str]:
        """Get all registered service names."""
        return list(self._services.keys())


class ServiceManager:
    """Centralized service manager for TMWS v2.0.

    Features:
    - Dependency-aware service initialization
    - Graceful service shutdown
    - Health monitoring and status reporting
    - Service discovery and injection
    - Configuration management
    - Error handling and recovery
    """

    def __init__(self):
        self.registry = ServiceRegistry()
        self._initialized = False
        self._shutdown_handlers: list[callable] = []
        self._health_check_interval = 30  # seconds
        self._health_check_task: asyncio.Task | None = None

    def register_core_services(self) -> None:
        """Register all core TMWS services."""

        # Database manager (no dependencies)
        self.registry.register("database", db_manager)

        # Batch service (depends on database)
        self.registry.register("batch", batch_service, ["database"])

        # Core services (depend on database)
        self.registry.register("agent", None, ["database"])  # Will be created with session
        self.registry.register("learning", LearningService(), ["database"])
        self.registry.register("memory", None, ["database"])  # Will be created with session
        self.registry.register("task", None, ["database"])  # Will be created with session

        logger.info("Core services registered")

    async def initialize_all(self) -> None:
        """Initialize all services in dependency order."""
        if self._initialized:
            logger.warning("Services already initialized")
            return

        try:
            # Get initialization order based on dependencies
            init_order = self._get_initialization_order()

            logger.info(f"Initializing services in order: {init_order}")

            for service_name in init_order:
                await self._initialize_service(service_name)

            # Setup signal handlers for graceful shutdown
            self._setup_signal_handlers()

            # Start health monitoring
            await self._start_health_monitoring()

            self._initialized = True
            logger.info("All services initialized successfully")

        except (KeyboardInterrupt, SystemExit):
            logger.critical("🚨 User interrupt during service initialization - shutting down")
            await self.shutdown_all()
            raise
        except Exception as e:
            logger.error(
                f"Service initialization failed: {e}",
                exc_info=True,
                extra={
                    "services_initialized": len(
                        [
                            s
                            for s in self.registry.get_service_names()
                            if self.registry.is_initialized(s)
                        ]
                    )
                },
            )
            await self.shutdown_all()
            raise ServiceError(f"Service initialization failed: {e}") from e

    async def shutdown_all(self, timeout: float = 60.0) -> None:
        """Shutdown all services gracefully."""
        if not self._initialized:
            logger.warning("Services not initialized or already shut down")
            return

        logger.info("Starting graceful shutdown...")

        try:
            # Stop health monitoring
            if self._health_check_task:
                self._health_check_task.cancel()
                with suppress(asyncio.TimeoutError, asyncio.CancelledError):
                    await asyncio.wait_for(self._health_check_task, timeout=5.0)

            # Run custom shutdown handlers
            for handler in reversed(self._shutdown_handlers):
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler()
                    else:
                        handler()
                except (KeyboardInterrupt, SystemExit):
                    logger.warning(f"User interrupt during shutdown handler {handler.__name__}")
                    raise
                except Exception as e:
                    logger.error(
                        f"Shutdown handler error: {e}",
                        exc_info=True,
                        extra={
                            "handler": handler.__name__
                            if hasattr(handler, "__name__")
                            else str(handler)
                        },
                    )

            # Shutdown services in reverse dependency order
            init_order = self._get_initialization_order()
            shutdown_order = list(reversed(init_order))

            for service_name in shutdown_order:
                await self._shutdown_service(service_name, timeout / len(shutdown_order))

            self._initialized = False
            logger.info("All services shut down successfully")

        except (KeyboardInterrupt, SystemExit):
            logger.critical("🚨 User interrupt during shutdown - forcing immediate stop")
            self._initialized = False
            raise
        except Exception as e:
            logger.error(
                f"Error during shutdown: {e}",
                exc_info=True,
                extra={
                    "services_remaining": len(
                        [
                            s
                            for s in self.registry.get_service_names()
                            if self.registry.is_initialized(s)
                        ]
                    )
                },
            )
            raise ServiceError(f"Shutdown failed: {e}") from e

    async def get_service(self, service_name: str) -> Any:
        """Get a service instance, creating session-dependent services as needed."""
        if not self._initialized:
            raise ServiceError("Services not initialized")

        service = self.registry.get(service_name)

        # Handle session-dependent services
        if service is None and service_name in ["agent", "memory", "task"]:
            from ..core.database import get_db_session

            async with get_db_session() as session:
                if service_name == "agent":
                    from ..services.agent_service import AgentService

                    return AgentService(session)
                elif service_name == "memory":
                    from ..services.memory_service import HybridMemoryService

                    return HybridMemoryService(session)
                elif service_name == "task":
                    from ..services.task_service import TaskService

                    return TaskService(session)

        return service

    @asynccontextmanager
    async def get_service_context(self, service_name: str):
        """Get service in an async context manager."""
        service = await self.get_service(service_name)
        try:
            yield service
        finally:
            # Cleanup if needed
            if hasattr(service, "close"):
                await service.close()

    async def health_check_all(self) -> dict[str, dict[str, Any]]:
        """Perform health check on all services."""
        health_results = {}

        for service_name in self.registry.get_service_names():
            try:
                health_result = await self._health_check_service(service_name)
                health_results[service_name] = health_result
                self.registry.update_health_status(
                    service_name,
                    health_result["status"],
                    health_result.get("error"),
                )
            except (KeyboardInterrupt, SystemExit):
                logger.warning(f"User interrupt during health check of {service_name}")
                raise
            except Exception as e:
                logger.error(
                    f"Health check failed for service '{service_name}': {e}",
                    exc_info=True,
                    extra={"service_name": service_name},
                )
                health_result = {
                    "status": "unhealthy",
                    "error": str(e),
                    "last_check": datetime.now(),
                }
                health_results[service_name] = health_result
                self.registry.update_health_status(service_name, "unhealthy", str(e))

        return health_results

    def add_shutdown_handler(self, handler: callable) -> None:
        """Add a custom shutdown handler."""
        self._shutdown_handlers.append(handler)

    def get_service_status(self) -> dict[str, Any]:
        """Get overall service status."""
        status = {
            "initialized": self._initialized,
            "total_services": len(self.registry.get_service_names()),
            "services": {},
        }

        for service_name in self.registry.get_service_names():
            status["services"][service_name] = {
                "initialized": self.registry.is_initialized(service_name),
                "health": self.registry.get_health_status(service_name),
                "dependencies": self.registry.get_dependencies(service_name),
            }

        return status

    def _get_initialization_order(self) -> list[str]:
        """Get service initialization order based on dependencies."""
        visited = set()
        temp_visited = set()
        order = []

        def dfs(service_name: str) -> None:
            if service_name in temp_visited:
                raise ServiceError(f"Circular dependency detected involving '{service_name}'")
            if service_name in visited:
                return

            temp_visited.add(service_name)

            # Visit all dependencies first
            for dependency in self.registry.get_dependencies(service_name):
                if dependency not in self.registry.get_service_names():
                    raise ServiceError(
                        f"Missing dependency '{dependency}' for service '{service_name}'",
                    )
                dfs(dependency)

            temp_visited.remove(service_name)
            visited.add(service_name)
            order.append(service_name)

        for service_name in self.registry.get_service_names():
            if service_name not in visited:
                dfs(service_name)

        return order

    async def _initialize_service(self, service_name: str) -> None:
        """Initialize a single service."""
        if self.registry.is_initialized(service_name):
            logger.debug(f"Service '{service_name}' already initialized")
            return

        logger.info(f"Initializing service: {service_name}")

        try:
            service = self.registry.get(service_name)

            # Special handling for different service types
            if service_name == "database":
                await service.initialize(workload_type="mixed")
            elif service_name == "batch":
                await service.start()
            elif hasattr(service, "initialize"):
                await service.initialize()
            elif hasattr(service, "start"):
                await service.start()

            self.registry.set_initialized(service_name, True)
            self.registry.update_health_status(service_name, "healthy")

            logger.info(f"Service '{service_name}' initialized successfully")

        except (KeyboardInterrupt, SystemExit):
            logger.critical(f"🚨 User interrupt during '{service_name}' initialization")
            self.registry.update_health_status(service_name, "interrupted", "User interrupt")
            raise
        except Exception as e:
            logger.error(
                f"Failed to initialize service '{service_name}': {e}",
                exc_info=True,
                extra={
                    "service_name": service_name,
                    "dependencies": self.registry.get_dependencies(service_name),
                },
            )
            self.registry.update_health_status(service_name, "unhealthy", str(e))
            raise ServiceError(f"Service '{service_name}' initialization failed: {e}") from e

    async def _shutdown_service(self, service_name: str, timeout: float) -> None:
        """Shutdown a single service."""
        if not self.registry.is_initialized(service_name):
            logger.debug(f"Service '{service_name}' not initialized, skipping shutdown")
            return

        logger.info(f"Shutting down service: {service_name}")

        try:
            service = self.registry.get(service_name)

            # Special handling for different service types
            if service_name == "database":
                await service.close()
            elif service_name == "batch":
                await service.stop(timeout)
            elif hasattr(service, "shutdown"):
                await service.shutdown(timeout)
            elif hasattr(service, "stop"):
                await service.stop(timeout)
            elif hasattr(service, "close"):
                await service.close()

            self.registry.set_initialized(service_name, False)
            self.registry.update_health_status(service_name, "shutdown")

            logger.info(f"Service '{service_name}' shut down successfully")

        except (KeyboardInterrupt, SystemExit):
            logger.warning(
                f"User interrupt during '{service_name}' shutdown - "
                f"service may be in inconsistent state"
            )
            self.registry.update_health_status(
                service_name, "interrupted", "User interrupt during shutdown"
            )
            raise
        except Exception as e:
            logger.error(
                f"Error shutting down service '{service_name}': {e}",
                exc_info=True,
                extra={"service_name": service_name},
            )
            self.registry.update_health_status(service_name, "error", str(e))

    async def _health_check_service(self, service_name: str) -> dict[str, Any]:
        """Perform health check on a single service."""
        if not self.registry.is_initialized(service_name):
            return {"status": "not_initialized", "last_check": datetime.now()}

        service = self.registry.get(service_name)

        try:
            # Service-specific health checks
            if service_name == "database":
                health_data = await service.health_check()
                return {
                    "status": health_data.get("status", "unknown"),
                    "details": health_data,
                    "last_check": datetime.now(),
                }
            elif service_name == "batch":
                metrics = await service.get_performance_metrics()
                return {
                    "status": "healthy" if metrics["active_jobs"] >= 0 else "unhealthy",
                    "details": metrics,
                    "last_check": datetime.now(),
                }
            elif hasattr(service, "health_check"):
                health_data = await service.health_check()
                return {
                    "status": "healthy" if health_data.get("healthy", True) else "unhealthy",
                    "details": health_data,
                    "last_check": datetime.now(),
                }
            else:
                # Basic service availability check
                return {
                    "status": "healthy",
                    "details": {"type": type(service).__name__},
                    "last_check": datetime.now(),
                }

        except (KeyboardInterrupt, SystemExit):
            # Health checks should not suppress user interrupts
            raise
        except Exception as e:
            logger.error(
                f"Health check exception for '{service_name}': {e}",
                exc_info=True,
                extra={"service_name": service_name},
            )
            return {"status": "unhealthy", "error": str(e), "last_check": datetime.now()}

    async def _start_health_monitoring(self) -> None:
        """Start background health monitoring."""

        async def health_monitor():
            while self._initialized:
                try:
                    await self.health_check_all()
                    await asyncio.sleep(self._health_check_interval)
                except asyncio.CancelledError:
                    logger.info("Health monitoring cancelled")
                    break
                except (KeyboardInterrupt, SystemExit):
                    logger.critical("🚨 User interrupt in health monitor - stopping")
                    break
                except Exception as e:
                    logger.error(
                        f"Health monitoring error: {e}",
                        exc_info=True,
                        extra={"health_check_interval": self._health_check_interval},
                    )
                    await asyncio.sleep(self._health_check_interval)

        self._health_check_task = asyncio.create_task(health_monitor())
        logger.info(f"Health monitoring started (interval: {self._health_check_interval}s)")

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""

        def signal_handler(signum, _frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(self.shutdown_all())

        # Setup handlers for common signals
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)


# Global service manager instance
service_manager = ServiceManager()


# Convenience functions
async def initialize_services() -> None:
    """Initialize all TMWS services."""
    service_manager.register_core_services()
    await service_manager.initialize_all()


async def shutdown_services(timeout: float = 60.0) -> None:
    """Shutdown all TMWS services."""
    await service_manager.shutdown_all(timeout)


async def get_service(service_name: str) -> Any:
    """Get a service instance."""
    return await service_manager.get_service(service_name)


async def health_check() -> dict[str, dict[str, Any]]:
    """Perform health check on all services."""
    return await service_manager.health_check_all()


def get_service_status() -> dict[str, Any]:
    """Get service status."""
    return service_manager.get_service_status()


# Context manager for service lifecycle
@asynccontextmanager
async def service_context():
    """Context manager for service lifecycle."""
    try:
        await initialize_services()
        yield service_manager
    finally:
        await shutdown_services()
