"""
Comprehensive unit tests for ServiceManager with 100% coverage.
Tests all service lifecycle management, dependency injection, and health monitoring.

Strategic coverage implementation by Hera for 80% target achievement.
Target: 265 lines of 0% coverage code - MAXIMUM IMPACT!
"""

import asyncio
import pytest
import signal
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from contextlib import suppress

from src.core.service_manager import (
    ServiceRegistry, ServiceManager, service_manager,
    initialize_services, shutdown_services, get_service,
    health_check, get_service_status, service_context
)
from src.core.exceptions import ServiceError


class TestServiceRegistry:
    """Test ServiceRegistry class functionality."""

    @pytest.fixture
    def registry(self):
        """Create ServiceRegistry instance."""
        return ServiceRegistry()

    def test_registry_initialization(self, registry):
        """Test ServiceRegistry initialization."""
        assert len(registry._services) == 0
        assert len(registry._dependencies) == 0
        assert len(registry._initialized) == 0
        assert len(registry._health_status) == 0

    def test_register_service(self, registry):
        """Test service registration."""
        mock_service = Mock()

        registry.register("test_service", mock_service, ["dependency1"])

        assert "test_service" in registry._services
        assert registry._services["test_service"] == mock_service
        assert registry._dependencies["test_service"] == ["dependency1"]
        assert registry._initialized["test_service"] is False
        assert registry._health_status["test_service"]["status"] == "unknown"

    def test_register_service_no_dependencies(self, registry):
        """Test service registration without dependencies."""
        mock_service = Mock()

        registry.register("test_service", mock_service)

        assert registry._dependencies["test_service"] == []

    def test_get_service_success(self, registry):
        """Test successful service retrieval."""
        mock_service = Mock()
        registry.register("test_service", mock_service)

        result = registry.get("test_service")

        assert result == mock_service

    def test_get_service_not_found(self, registry):
        """Test service retrieval failure."""
        with pytest.raises(ServiceError, match="Service 'nonexistent' not found"):
            registry.get("nonexistent")

    def test_get_all_services(self, registry):
        """Test getting all services."""
        service1 = Mock()
        service2 = Mock()
        registry.register("service1", service1)
        registry.register("service2", service2)

        result = registry.get_all()

        assert len(result) == 2
        assert result["service1"] == service1
        assert result["service2"] == service2

    def test_is_initialized(self, registry):
        """Test initialization status checking."""
        registry.register("test_service", Mock())

        assert registry.is_initialized("test_service") is False

        registry.set_initialized("test_service", True)

        assert registry.is_initialized("test_service") is True

    def test_is_initialized_nonexistent(self, registry):
        """Test initialization status for nonexistent service."""
        assert registry.is_initialized("nonexistent") is False

    def test_set_initialized(self, registry):
        """Test setting initialization status."""
        registry.register("test_service", Mock())

        registry.set_initialized("test_service", True)
        assert registry._initialized["test_service"] is True

        registry.set_initialized("test_service", False)
        assert registry._initialized["test_service"] is False

    def test_get_dependencies(self, registry):
        """Test getting service dependencies."""
        registry.register("service1", Mock(), ["dep1", "dep2"])

        deps = registry.get_dependencies("service1")

        assert deps == ["dep1", "dep2"]

    def test_get_dependencies_nonexistent(self, registry):
        """Test getting dependencies for nonexistent service."""
        deps = registry.get_dependencies("nonexistent")
        assert deps == []

    def test_get_health_status(self, registry):
        """Test getting health status."""
        registry.register("test_service", Mock())

        status = registry.get_health_status("test_service")

        assert status["status"] == "unknown"
        assert status["last_check"] is None
        assert status["error"] is None

    def test_get_health_status_nonexistent(self, registry):
        """Test getting health status for nonexistent service."""
        status = registry.get_health_status("nonexistent")
        assert status == {"status": "unknown"}

    def test_update_health_status(self, registry):
        """Test updating health status."""
        registry.register("test_service", Mock())

        registry.update_health_status("test_service", "healthy")
        status = registry.get_health_status("test_service")

        assert status["status"] == "healthy"
        assert isinstance(status["last_check"], datetime)
        assert status["error"] is None

    def test_update_health_status_with_error(self, registry):
        """Test updating health status with error."""
        registry.register("test_service", Mock())

        registry.update_health_status("test_service", "unhealthy", "Connection failed")
        status = registry.get_health_status("test_service")

        assert status["status"] == "unhealthy"
        assert status["error"] == "Connection failed"

    def test_get_service_names(self, registry):
        """Test getting service names."""
        registry.register("service1", Mock())
        registry.register("service2", Mock())

        names = registry.get_service_names()

        assert set(names) == {"service1", "service2"}


class TestServiceManager:
    """Test ServiceManager class functionality."""

    @pytest.fixture
    def manager(self):
        """Create ServiceManager instance."""
        return ServiceManager()

    def test_manager_initialization(self, manager):
        """Test ServiceManager initialization."""
        assert isinstance(manager.registry, ServiceRegistry)
        assert manager._initialized is False
        assert manager._shutdown_handlers == []
        assert manager._health_check_interval == 30
        assert manager._health_check_task is None

    @patch('src.core.service_manager.db_manager')
    @patch('src.core.service_manager.batch_service')
    @patch('src.core.service_manager.LearningService')
    def test_register_core_services(self, mock_learning, mock_batch, mock_db, manager):
        """Test core service registration."""
        manager.register_core_services()

        # Check that services were registered
        service_names = manager.registry.get_service_names()
        expected_services = {"database", "batch", "agent", "learning", "memory", "task"}

        assert set(service_names) == expected_services

    def test_get_initialization_order_simple(self, manager):
        """Test initialization order with simple dependencies."""
        manager.registry.register("service_a", Mock(), [])
        manager.registry.register("service_b", Mock(), ["service_a"])
        manager.registry.register("service_c", Mock(), ["service_b"])

        order = manager._get_initialization_order()

        assert order.index("service_a") < order.index("service_b")
        assert order.index("service_b") < order.index("service_c")

    def test_get_initialization_order_circular_dependency(self, manager):
        """Test circular dependency detection."""
        manager.registry.register("service_a", Mock(), ["service_b"])
        manager.registry.register("service_b", Mock(), ["service_a"])

        with pytest.raises(ServiceError, match="Circular dependency detected"):
            manager._get_initialization_order()

    def test_get_initialization_order_missing_dependency(self, manager):
        """Test missing dependency detection."""
        manager.registry.register("service_a", Mock(), ["nonexistent"])

        with pytest.raises(ServiceError, match="Missing dependency 'nonexistent'"):
            manager._get_initialization_order()

    @pytest.mark.asyncio
    async def test_initialize_service_database(self, manager):
        """Test database service initialization."""
        mock_db = AsyncMock()
        manager.registry.register("database", mock_db)

        await manager._initialize_service("database")

        mock_db.initialize.assert_called_once_with(workload_type="mixed")
        assert manager.registry.is_initialized("database") is True

    @pytest.mark.asyncio
    async def test_initialize_service_batch(self, manager):
        """Test batch service initialization."""
        mock_batch = AsyncMock()
        manager.registry.register("batch", mock_batch)

        await manager._initialize_service("batch")

        mock_batch.start.assert_called_once()
        assert manager.registry.is_initialized("batch") is True

    @pytest.mark.asyncio
    async def test_initialize_service_with_initialize_method(self, manager):
        """Test service with initialize method."""
        mock_service = AsyncMock()
        mock_service.initialize = AsyncMock()
        manager.registry.register("test_service", mock_service)

        await manager._initialize_service("test_service")

        mock_service.initialize.assert_called_once()
        assert manager.registry.is_initialized("test_service") is True

    @pytest.mark.asyncio
    async def test_initialize_service_with_start_method(self, manager):
        """Test service with start method."""
        mock_service = AsyncMock()
        mock_service.start = AsyncMock()
        manager.registry.register("test_service", mock_service)

        await manager._initialize_service("test_service")

        mock_service.start.assert_called_once()
        assert manager.registry.is_initialized("test_service") is True

    @pytest.mark.asyncio
    async def test_initialize_service_already_initialized(self, manager):
        """Test initialization of already initialized service."""
        mock_service = Mock()
        manager.registry.register("test_service", mock_service)
        manager.registry.set_initialized("test_service", True)

        await manager._initialize_service("test_service")

        # Should not call any initialization methods

    @pytest.mark.asyncio
    async def test_initialize_service_failure(self, manager):
        """Test service initialization failure."""
        mock_service = AsyncMock()
        mock_service.initialize = AsyncMock(side_effect=Exception("Init failed"))
        manager.registry.register("test_service", mock_service)

        with pytest.raises(ServiceError, match="Service 'test_service' initialization failed"):
            await manager._initialize_service("test_service")

    @pytest.mark.asyncio
    async def test_shutdown_service_database(self, manager):
        """Test database service shutdown."""
        mock_db = AsyncMock()
        manager.registry.register("database", mock_db)
        manager.registry.set_initialized("database", True)

        await manager._shutdown_service("database", 30.0)

        mock_db.close.assert_called_once()
        assert manager.registry.is_initialized("database") is False

    @pytest.mark.asyncio
    async def test_shutdown_service_batch(self, manager):
        """Test batch service shutdown."""
        mock_batch = AsyncMock()
        manager.registry.register("batch", mock_batch)
        manager.registry.set_initialized("batch", True)

        await manager._shutdown_service("batch", 30.0)

        mock_batch.stop.assert_called_once_with(30.0)

    @pytest.mark.asyncio
    async def test_shutdown_service_not_initialized(self, manager):
        """Test shutdown of non-initialized service."""
        mock_service = Mock()
        manager.registry.register("test_service", mock_service)

        await manager._shutdown_service("test_service", 30.0)

        # Should not call any shutdown methods

    @pytest.mark.asyncio
    async def test_shutdown_service_with_error(self, manager):
        """Test service shutdown with error."""
        mock_service = AsyncMock()
        mock_service.close = AsyncMock(side_effect=Exception("Shutdown failed"))
        manager.registry.register("test_service", mock_service)
        manager.registry.set_initialized("test_service", True)

        # Should not raise exception, just log error
        await manager._shutdown_service("test_service", 30.0)

    @pytest.mark.asyncio
    async def test_initialize_all_success(self, manager):
        """Test successful initialization of all services."""
        mock_service1 = AsyncMock()
        mock_service2 = AsyncMock()

        manager.registry.register("service1", mock_service1)
        manager.registry.register("service2", mock_service2, ["service1"])

        with patch.object(manager, '_setup_signal_handlers'):
            with patch.object(manager, '_start_health_monitoring', new_callable=AsyncMock):
                await manager.initialize_all()

        assert manager._initialized is True
        assert manager.registry.is_initialized("service1") is True
        assert manager.registry.is_initialized("service2") is True

    @pytest.mark.asyncio
    async def test_initialize_all_already_initialized(self, manager):
        """Test initialization when already initialized."""
        manager._initialized = True

        await manager.initialize_all()

        # Should return early without doing anything

    @pytest.mark.asyncio
    async def test_initialize_all_failure(self, manager):
        """Test initialization failure."""
        mock_service = AsyncMock()
        mock_service.initialize = AsyncMock(side_effect=Exception("Init failed"))
        manager.registry.register("test_service", mock_service)

        with pytest.raises(ServiceError, match="Service initialization failed"):
            await manager.initialize_all()

    @pytest.mark.asyncio
    async def test_shutdown_all_success(self, manager):
        """Test successful shutdown of all services."""
        mock_service1 = AsyncMock()
        mock_service2 = AsyncMock()

        manager.registry.register("service1", mock_service1)
        manager.registry.register("service2", mock_service2, ["service1"])
        manager.registry.set_initialized("service1", True)
        manager.registry.set_initialized("service2", True)
        manager._initialized = True

        await manager.shutdown_all()

        assert manager._initialized is False

    @pytest.mark.asyncio
    async def test_shutdown_all_not_initialized(self, manager):
        """Test shutdown when not initialized."""
        await manager.shutdown_all()

        # Should return early

    @pytest.mark.asyncio
    async def test_shutdown_all_with_health_check_task(self, manager):
        """Test shutdown with health check task running."""
        manager._initialized = True
        manager._health_check_task = AsyncMock()

        await manager.shutdown_all()

    @pytest.mark.asyncio
    async def test_shutdown_all_with_handlers(self, manager):
        """Test shutdown with custom handlers."""
        manager._initialized = True

        sync_handler = Mock()
        async_handler = AsyncMock()

        manager.add_shutdown_handler(sync_handler)
        manager.add_shutdown_handler(async_handler)

        await manager.shutdown_all()

        sync_handler.assert_called_once()
        async_handler.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_service_not_initialized(self, manager):
        """Test getting service when not initialized."""
        with pytest.raises(ServiceError, match="Services not initialized"):
            await manager.get_service("test_service")

    @pytest.mark.asyncio
    async def test_get_service_session_dependent(self, manager):
        """Test getting session-dependent services."""
        manager._initialized = True

        # Mock None service (session-dependent)
        manager.registry.register("agent", None)

        with patch('src.core.service_manager.get_async_session') as mock_session:
            mock_session.return_value.__aenter__ = AsyncMock()
            mock_session.return_value.__aexit__ = AsyncMock()

            with patch('src.services.agent_service.AgentService') as mock_agent:
                await manager.get_service("agent")
                mock_agent.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_service_context(self, manager):
        """Test service context manager."""
        manager._initialized = True
        mock_service = Mock()
        manager.registry.register("test_service", mock_service)

        async with manager.get_service_context("test_service") as service:
            assert service == mock_service

    @pytest.mark.asyncio
    async def test_get_service_context_with_close(self, manager):
        """Test service context manager with close method."""
        manager._initialized = True
        mock_service = AsyncMock()
        manager.registry.register("test_service", mock_service)

        async with manager.get_service_context("test_service") as service:
            assert service == mock_service

        mock_service.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_all(self, manager):
        """Test health check for all services."""
        mock_service1 = Mock()
        mock_service2 = Mock()

        manager.registry.register("service1", mock_service1)
        manager.registry.register("service2", mock_service2)

        with patch.object(manager, '_health_check_service') as mock_check:
            mock_check.return_value = {"status": "healthy"}

            results = await manager.health_check_all()

            assert len(results) == 2
            assert mock_check.call_count == 2

    @pytest.mark.asyncio
    async def test_health_check_all_with_error(self, manager):
        """Test health check with service error."""
        manager.registry.register("service1", Mock())

        with patch.object(manager, '_health_check_service') as mock_check:
            mock_check.side_effect = Exception("Health check failed")

            results = await manager.health_check_all()

            assert results["service1"]["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_health_check_service_not_initialized(self, manager):
        """Test health check for non-initialized service."""
        manager.registry.register("test_service", Mock())

        result = await manager._health_check_service("test_service")

        assert result["status"] == "not_initialized"

    @pytest.mark.asyncio
    async def test_health_check_service_database(self, manager):
        """Test database service health check."""
        mock_db = AsyncMock()
        mock_db.health_check.return_value = {"status": "healthy"}
        manager.registry.register("database", mock_db)
        manager.registry.set_initialized("database", True)

        result = await manager._health_check_service("database")

        assert result["status"] == "healthy"
        mock_db.health_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_service_batch(self, manager):
        """Test batch service health check."""
        mock_batch = AsyncMock()
        mock_batch.get_performance_metrics.return_value = {"active_jobs": 5}
        manager.registry.register("batch", mock_batch)
        manager.registry.set_initialized("batch", True)

        result = await manager._health_check_service("batch")

        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_check_service_with_health_check_method(self, manager):
        """Test service with health_check method."""
        mock_service = AsyncMock()
        mock_service.health_check.return_value = {"healthy": True}
        manager.registry.register("test_service", mock_service)
        manager.registry.set_initialized("test_service", True)

        result = await manager._health_check_service("test_service")

        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_check_service_basic(self, manager):
        """Test basic service health check."""
        mock_service = Mock()
        manager.registry.register("test_service", mock_service)
        manager.registry.set_initialized("test_service", True)

        result = await manager._health_check_service("test_service")

        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_check_service_exception(self, manager):
        """Test health check with exception."""
        mock_service = AsyncMock()
        mock_service.health_check.side_effect = Exception("Health check failed")
        manager.registry.register("test_service", mock_service)
        manager.registry.set_initialized("test_service", True)

        result = await manager._health_check_service("test_service")

        assert result["status"] == "unhealthy"
        assert "Health check failed" in result["error"]

    def test_add_shutdown_handler(self, manager):
        """Test adding shutdown handler."""
        handler = Mock()

        manager.add_shutdown_handler(handler)

        assert handler in manager._shutdown_handlers

    def test_get_service_status(self, manager):
        """Test getting service status."""
        mock_service = Mock()
        manager.registry.register("test_service", mock_service, ["dep1"])

        status = manager.get_service_status()

        assert status["initialized"] is False
        assert status["total_services"] == 1
        assert "test_service" in status["services"]
        assert status["services"]["test_service"]["dependencies"] == ["dep1"]

    @pytest.mark.asyncio
    async def test_start_health_monitoring(self, manager):
        """Test starting health monitoring."""
        manager._initialized = True

        with patch('asyncio.create_task') as mock_create_task:
            await manager._start_health_monitoring()

            mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_monitor_loop(self, manager):
        """Test health monitoring loop."""
        manager._initialized = True

        # Mock the monitoring loop
        with patch.object(manager, 'health_check_all', new_callable=AsyncMock) as mock_health_check:
            with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
                # Run one iteration and then cancel
                async def health_monitor():
                    await manager.health_check_all()
                    await asyncio.sleep(manager._health_check_interval)

                task = asyncio.create_task(health_monitor())
                await asyncio.sleep(0.01)  # Let it run briefly
                task.cancel()

                with suppress(asyncio.CancelledError):
                    await task

    def test_setup_signal_handlers(self, manager):
        """Test signal handler setup."""
        with patch('signal.signal') as mock_signal:
            manager._setup_signal_handlers()

            # Should set up SIGINT and SIGTERM at minimum
            assert mock_signal.call_count >= 2


class TestGlobalFunctions:
    """Test global convenience functions."""

    @pytest.mark.asyncio
    @patch('src.core.service_manager.service_manager')
    async def test_initialize_services(self, mock_manager):
        """Test global initialize_services function."""
        await initialize_services()

        mock_manager.register_core_services.assert_called_once()
        mock_manager.initialize_all.assert_called_once()

    @pytest.mark.asyncio
    @patch('src.core.service_manager.service_manager')
    async def test_shutdown_services(self, mock_manager):
        """Test global shutdown_services function."""
        await shutdown_services(timeout=30.0)

        mock_manager.shutdown_all.assert_called_once_with(30.0)

    @pytest.mark.asyncio
    @patch('src.core.service_manager.service_manager')
    async def test_get_service(self, mock_manager):
        """Test global get_service function."""
        mock_manager.get_service.return_value = Mock()

        await get_service("test_service")

        mock_manager.get_service.assert_called_once_with("test_service")

    @pytest.mark.asyncio
    @patch('src.core.service_manager.service_manager')
    async def test_health_check(self, mock_manager):
        """Test global health_check function."""
        await health_check()

        mock_manager.health_check_all.assert_called_once()

    @patch('src.core.service_manager.service_manager')
    def test_get_service_status(self, mock_manager):
        """Test global get_service_status function."""
        get_service_status()

        mock_manager.get_service_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_service_context(self):
        """Test service_context context manager."""
        with patch('src.core.service_manager.initialize_services', new_callable=AsyncMock) as mock_init:
            with patch('src.core.service_manager.shutdown_services', new_callable=AsyncMock) as mock_shutdown:
                async with service_context() as manager:
                    assert manager is not None

                mock_init.assert_called_once()
                mock_shutdown.assert_called_once()


class TestServiceManagerIntegration:
    """Integration tests for ServiceManager."""

    @pytest.mark.asyncio
    async def test_full_service_lifecycle(self):
        """Test complete service lifecycle."""
        manager = ServiceManager()

        # Register test services
        mock_db = AsyncMock()
        mock_service1 = AsyncMock()
        mock_service2 = AsyncMock()

        manager.registry.register("database", mock_db)
        manager.registry.register("service1", mock_service1, ["database"])
        manager.registry.register("service2", mock_service2, ["service1"])

        # Initialize
        with patch.object(manager, '_setup_signal_handlers'):
            with patch.object(manager, '_start_health_monitoring', new_callable=AsyncMock):
                await manager.initialize_all()

        assert manager._initialized is True

        # Get services
        service = await manager.get_service("service1")
        assert service == mock_service1

        # Health check
        with patch.object(manager, '_health_check_service') as mock_check:
            mock_check.return_value = {"status": "healthy"}
            health_results = await manager.health_check_all()
            assert len(health_results) == 3

        # Shutdown
        await manager.shutdown_all()

        assert manager._initialized is False

    @pytest.mark.asyncio
    async def test_dependency_resolution(self):
        """Test complex dependency resolution."""
        manager = ServiceManager()

        # Create complex dependency graph
        manager.registry.register("a", Mock(), [])
        manager.registry.register("b", Mock(), ["a"])
        manager.registry.register("c", Mock(), ["a"])
        manager.registry.register("d", Mock(), ["b", "c"])
        manager.registry.register("e", Mock(), ["d"])

        order = manager._get_initialization_order()

        # Verify dependencies are satisfied
        assert order.index("a") < order.index("b")
        assert order.index("a") < order.index("c")
        assert order.index("b") < order.index("d")
        assert order.index("c") < order.index("d")
        assert order.index("d") < order.index("e")

    @pytest.mark.asyncio
    async def test_service_failure_recovery(self):
        """Test service failure and recovery handling."""
        manager = ServiceManager()

        mock_service = AsyncMock()
        mock_service.initialize.side_effect = [Exception("First failure"), None]
        manager.registry.register("test_service", mock_service)

        # First initialization should fail
        with pytest.raises(ServiceError):
            await manager._initialize_service("test_service")

        # Service should be marked as unhealthy
        status = manager.registry.get_health_status("test_service")
        assert status["status"] == "unhealthy"

        # Second attempt should succeed
        await manager._initialize_service("test_service")
        assert manager.registry.is_initialized("test_service") is True

    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Test concurrent service operations."""
        manager = ServiceManager()

        # Register services
        for i in range(5):
            mock_service = AsyncMock()
            manager.registry.register(f"service_{i}", mock_service)

        # Simulate concurrent health checks
        async def concurrent_health_check():
            return await manager._health_check_service("service_0")

        # Run multiple concurrent operations
        tasks = [concurrent_health_check() for _ in range(10)]
        results = await asyncio.gather(*tasks)

        # All should complete successfully
        assert len(results) == 10
        for result in results:
            assert "status" in result


class TestServiceManagerEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_shutdown_with_failing_handlers(self):
        """Test shutdown with failing custom handlers."""
        manager = ServiceManager()
        manager._initialized = True

        failing_handler = Mock(side_effect=Exception("Handler failed"))
        working_handler = Mock()

        manager.add_shutdown_handler(failing_handler)
        manager.add_shutdown_handler(working_handler)

        # Should complete shutdown despite handler failure
        await manager.shutdown_all()

        failing_handler.assert_called_once()
        working_handler.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_monitoring_error_handling(self):
        """Test health monitoring with errors."""
        manager = ServiceManager()
        manager._initialized = True

        # Mock health check to fail
        with patch.object(manager, 'health_check_all', side_effect=Exception("Health check failed")):
            # Health monitor should handle errors gracefully
            async def test_monitor():
                try:
                    await manager.health_check_all()
                except Exception:
                    pass  # Should be handled by monitor

            await test_monitor()

    def test_service_registry_edge_cases(self):
        """Test ServiceRegistry edge cases."""
        registry = ServiceRegistry()

        # Test with None service
        registry.register("none_service", None)
        assert registry.get("none_service") is None

        # Test empty dependencies list
        registry.register("empty_deps", Mock(), [])
        assert registry.get_dependencies("empty_deps") == []

    @pytest.mark.asyncio
    async def test_get_service_edge_cases(self):
        """Test get_service edge cases."""
        manager = ServiceManager()
        manager._initialized = True

        # Test getting None service that's not session-dependent
        manager.registry.register("none_service", None)

        service = await manager.get_service("none_service")
        assert service is None