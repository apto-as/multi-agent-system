"""End-to-End Lazy Loading Validation Tests (Phase 4.1).

Tests the complete lazy loading behavior across both VectorSearchService
and ToolSearchService to validate Issue #34 implementation.

Test Categories:
1. Service Initialization Tests (5) - No ChromaDB on construction
2. First-Use Initialization Tests (5) - Lazy init on first search
3. Backward Compatibility Tests (3) - Existing patterns work
4. Integration Tests (2) - Full workflow validation

Issue: #35 - End-to-end lazy loading validation
Prerequisites: Issue #34 - ChromaDB Lazy Initialization
Author: Metis (E2E Testing)
Created: 2025-12-09
"""

import asyncio
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models.tool_search import ToolMetadata, ToolSearchQuery, ToolSourceType
from src.services.tool_search_service import ToolSearchService
from src.services.vector_search_service import VectorSearchService


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_persist_dir(tmp_path):
    """Create temporary ChromaDB persistence directory."""
    persist_dir = tmp_path / "chromadb"
    persist_dir.mkdir(exist_ok=True)
    return persist_dir


@pytest.fixture
def mock_chromadb():
    """Mock ChromaDB for both VectorSearchService and ToolSearchService.

    Note: Since VectorSearchService uses asyncio.to_thread(chromadb.PersistentClient, ...),
    we need to patch the chromadb module directly, not just the class.
    """
    with patch("src.services.vector_search_service.chromadb") as mock_vector_chromadb, \
         patch("src.services.tool_search_service.chromadb") as mock_tool_chromadb:

        # Create shared mock setup
        def create_mock_client():
            mock_client = MagicMock()
            mock_collection = MagicMock()
            mock_collection.count = MagicMock(return_value=0)
            mock_collection.add = MagicMock()
            mock_collection.query = MagicMock(return_value={
                "ids": [[]],
                "metadatas": [[]],
                "distances": [[]],
                "documents": [[]]
            })
            mock_collection.upsert = MagicMock()
            mock_collection.get = MagicMock(return_value={"ids": [], "metadatas": []})
            mock_client.get_or_create_collection = MagicMock(return_value=mock_collection)
            mock_client.delete_collection = MagicMock()
            return mock_client

        mock_vector_chromadb.PersistentClient.return_value = create_mock_client()
        mock_tool_chromadb.PersistentClient.return_value = create_mock_client()

        yield {
            "vector": mock_vector_chromadb.PersistentClient,
            "tool": mock_tool_chromadb.PersistentClient,
        }


# =============================================================================
# Category 1: Service Initialization Tests (5 tests)
# =============================================================================


@pytest.mark.e2e
class TestServiceInitialization:
    """Verify that services do NOT initialize ChromaDB on construction."""

    def test_vector_service_construction_no_chromadb(self, temp_persist_dir):
        """Test VectorSearchService construction creates no ChromaDB client.

        Expected: _client is None, _initialized is False
        """
        service = VectorSearchService(persist_directory=temp_persist_dir)

        assert service._client is None, "ChromaDB client should be None on construction"
        assert service._collection is None, "Collection should be None on construction"
        assert service._initialized is False, "Service should not be initialized"

    def test_tool_service_construction_no_chromadb(self, temp_persist_dir):
        """Test ToolSearchService construction creates no ChromaDB client.

        Expected: _client is None, _initialized is False
        """
        service = ToolSearchService(persist_directory=str(temp_persist_dir))

        assert service._client is None, "ChromaDB client should be None on construction"
        assert service._collection is None, "Collection should be None on construction"
        assert service._initialized is False, "Service should not be initialized"

    def test_multiple_vector_service_constructions_no_chromadb(self, temp_persist_dir):
        """Test that creating multiple VectorSearchService instances doesn't init ChromaDB.

        Expected: All instances have _client = None
        """
        services = [VectorSearchService(persist_directory=temp_persist_dir) for _ in range(5)]

        for i, service in enumerate(services):
            assert service._client is None, f"Service {i} should have no ChromaDB client"
            assert service._initialized is False, f"Service {i} should not be initialized"

    def test_multiple_tool_service_constructions_no_chromadb(self, temp_persist_dir):
        """Test that creating multiple ToolSearchService instances doesn't init ChromaDB.

        Expected: All instances have _client = None
        """
        services = [ToolSearchService(persist_directory=str(temp_persist_dir)) for _ in range(5)]

        for i, service in enumerate(services):
            assert service._client is None, f"Service {i} should have no ChromaDB client"
            assert service._initialized is False, f"Service {i} should not be initialized"

    @pytest.mark.asyncio
    async def test_stats_without_force_init_no_chromadb(self, mock_chromadb, temp_persist_dir):
        """Test that get_stats/get_collection_stats without force_init doesn't initialize ChromaDB.

        Expected: Returns metadata only, no ChromaDB initialization
        """
        vector_service = VectorSearchService(persist_directory=temp_persist_dir)
        tool_service = ToolSearchService(persist_directory=str(temp_persist_dir))

        # Get stats without forcing initialization
        vector_stats = await vector_service.get_collection_stats(force_init=False)
        tool_stats = await tool_service.get_stats(force_init=False)

        # ChromaDB should not have been initialized
        assert vector_service._client is None, "VectorService should not have ChromaDB client"
        assert tool_service._client is None, "ToolService should not have ChromaDB client"

        # Stats should return metadata with initialized=False
        assert vector_stats["initialized"] is False
        assert vector_stats["memory_count"] == 0
        assert tool_stats["initialized"] is False
        assert tool_stats["total_indexed"] == 0


# =============================================================================
# Category 2: First-Use Initialization Tests (5 tests)
# =============================================================================


@pytest.mark.e2e
class TestFirstUseInitialization:
    """Verify that ChromaDB is initialized on first actual use."""

    @pytest.mark.asyncio
    async def test_vector_service_search_triggers_init(self, mock_chromadb, temp_persist_dir):
        """Test that first search triggers ChromaDB initialization.

        Expected: _ensure_initialized is called, collection created
        """
        service = VectorSearchService(persist_directory=temp_persist_dir)

        # Verify not initialized
        assert service._initialized is False

        # Perform search (will call _ensure_initialized)
        query_embedding = [0.1] * 1024
        await service.search(query_embedding, top_k=5)

        # Should now be initialized
        assert service._initialized is True
        assert service._client is not None
        assert service._collection is not None
        mock_chromadb["vector"].assert_called_once()

    @pytest.mark.asyncio
    async def test_tool_service_search_triggers_init(self, mock_chromadb, temp_persist_dir):
        """Test that first tool search triggers ChromaDB initialization.

        Expected: _ensure_initialized is called, collection created
        """
        service = ToolSearchService(persist_directory=str(temp_persist_dir))
        service._get_embedding = AsyncMock(return_value=[0.1] * 1024)

        # Verify not initialized
        assert service._initialized is False

        # Perform search
        query = ToolSearchQuery(query="test", source="all", limit=5)
        await service.search(query)

        # Should now be initialized
        assert service._initialized is True
        assert service._client is not None
        assert service._collection is not None
        mock_chromadb["tool"].assert_called_once()

    @pytest.mark.asyncio
    async def test_vector_service_add_memory_triggers_init(self, mock_chromadb, temp_persist_dir):
        """Test that adding memory triggers ChromaDB initialization.

        Expected: _ensure_initialized is called before add
        """
        service = VectorSearchService(persist_directory=temp_persist_dir)

        assert service._initialized is False

        # Add memory
        await service.add_memory(
            memory_id="mem_123",
            embedding=[0.1] * 1024,
            metadata={"agent_id": "athena"}
        )

        # Should be initialized
        assert service._initialized is True
        mock_chromadb["vector"].assert_called_once()

    @pytest.mark.asyncio
    async def test_tool_service_register_tools_triggers_init(self, mock_chromadb, temp_persist_dir):
        """Test that registering tools triggers ChromaDB initialization.

        Expected: _ensure_initialized is called during indexing
        """
        service = ToolSearchService(persist_directory=str(temp_persist_dir))

        assert service._initialized is False

        # Register tools
        tools = [
            ToolMetadata(
                name="test_tool",
                description="A test tool",
                input_schema={"type": "object"},
                tags=["testing"]
            )
        ]
        await service.register_internal_tools(tools)

        # Should be initialized
        assert service._initialized is True
        mock_chromadb["tool"].assert_called_once()

    @pytest.mark.asyncio
    async def test_stats_with_force_init_triggers_init(self, mock_chromadb, temp_persist_dir):
        """Test that get_stats with force_init=True initializes ChromaDB.

        Expected: ChromaDB initialized when force_init=True
        """
        vector_service = VectorSearchService(persist_directory=temp_persist_dir)
        tool_service = ToolSearchService(persist_directory=str(temp_persist_dir))

        # Force initialization via stats
        vector_stats = await vector_service.get_collection_stats(force_init=True)
        tool_stats = await tool_service.get_stats(force_init=True)

        # Should be initialized
        assert vector_service._initialized is True
        assert tool_service._initialized is True
        assert vector_stats["initialized"] is True
        assert tool_stats["initialized"] is True


# =============================================================================
# Category 3: Backward Compatibility Tests (3 tests)
# =============================================================================


@pytest.mark.e2e
class TestBackwardCompatibility:
    """Verify that existing code patterns continue to work."""

    @pytest.mark.asyncio
    async def test_explicit_initialize_still_works(self, mock_chromadb, temp_persist_dir):
        """Test that calling initialize() explicitly still works.

        Expected: Service initializes normally, can perform operations
        """
        vector_service = VectorSearchService(persist_directory=temp_persist_dir)
        tool_service = ToolSearchService(persist_directory=str(temp_persist_dir))

        # Explicit initialize (old pattern)
        await vector_service.initialize()
        await tool_service.initialize()

        # Should be initialized
        assert vector_service._initialized is True
        assert tool_service._initialized is True

        # Operations should work
        await vector_service.add_memory(
            memory_id="mem_123",
            embedding=[0.1] * 1024,
            metadata={"agent_id": "athena"}
        )

        tool_service._get_embedding = AsyncMock(return_value=[0.1] * 1024)
        await tool_service.search_tools(query="test", limit=5)

    @pytest.mark.asyncio
    async def test_singleton_pattern_works(self, mock_chromadb):
        """Test that singleton pattern works with lazy initialization.

        Expected: Same instance, lazy init on first use
        """
        from src.services.vector_search_service import get_vector_search_service

        service1 = get_vector_search_service()
        service2 = get_vector_search_service()

        # Should be same instance
        assert service1 is service2

        # Should not be initialized yet
        assert service1._initialized is False

        # Initialize through one reference
        await service1.initialize()

        # Both references should see initialization
        assert service1._initialized is True
        assert service2._initialized is True
        assert service1._collection is not None
        assert service2._collection is not None

    @pytest.mark.asyncio
    async def test_double_initialize_is_safe(self, mock_chromadb, temp_persist_dir):
        """Test that calling initialize() multiple times is safe.

        Expected: Double-check locking prevents duplicate initialization
        """
        service = VectorSearchService(persist_directory=temp_persist_dir)

        # Initialize multiple times
        await service.initialize()
        await service.initialize()
        await service.initialize()

        # ChromaDB client created only once
        mock_chromadb["vector"].assert_called_once()

        # Service should be initialized
        assert service._initialized is True


# =============================================================================
# Category 4: Integration Tests (2 tests)
# =============================================================================


@pytest.mark.e2e
class TestFullWorkflow:
    """Test complete workflows with lazy loading."""

    @pytest.mark.asyncio
    async def test_vector_service_full_workflow(self, mock_chromadb, temp_persist_dir):
        """Test complete VectorSearchService workflow with lazy loading.

        Workflow:
        1. Construct service (no init)
        2. Get stats without init (metadata only)
        3. Add memory (triggers init)
        4. Search (uses initialized service)
        5. Get stats with init (real counts)
        """
        service = VectorSearchService(persist_directory=temp_persist_dir)

        # Step 1: Construct - no init
        assert service._initialized is False

        # Step 2: Get stats without init
        stats = await service.get_collection_stats(force_init=False)
        assert stats["initialized"] is False
        assert service._initialized is False

        # Step 3: Add memory - triggers init
        await service.add_memory(
            memory_id="mem_1",
            embedding=[0.1] * 1024,
            metadata={"agent_id": "athena", "namespace": "default"}
        )
        assert service._initialized is True

        # Mock collection count
        service._collection.count = MagicMock(return_value=1)

        # Step 4: Search - uses initialized service
        results = await service.search(
            query_embedding=[0.2] * 1024,
            top_k=5
        )

        # Step 5: Get stats with init
        stats = await service.get_collection_stats(force_init=True)
        assert stats["initialized"] is True
        assert stats["memory_count"] == 1

    @pytest.mark.asyncio
    async def test_tool_service_full_workflow(self, mock_chromadb, temp_persist_dir):
        """Test complete ToolSearchService workflow with lazy loading.

        Workflow:
        1. Construct service (no init)
        2. Get stats without init (metadata only)
        3. Register tools (triggers init)
        4. Search tools (uses initialized service)
        5. Get tool details
        """
        service = ToolSearchService(persist_directory=str(temp_persist_dir))
        service._get_embedding = AsyncMock(return_value=[0.1] * 1024)

        # Step 1: Construct - no init
        assert service._initialized is False

        # Step 2: Get stats without init
        stats = await service.get_stats(force_init=False)
        assert stats["initialized"] is False
        assert service._initialized is False

        # Step 3: Register tools - triggers init
        tools = [
            ToolMetadata(
                name="tool_1",
                description="First test tool",
                input_schema={"type": "object"},
                tags=["test"]
            ),
            ToolMetadata(
                name="tool_2",
                description="Second test tool",
                input_schema={"type": "object"},
                tags=["test"]
            )
        ]
        await service.register_internal_tools(tools)
        assert service._initialized is True

        # Mock search results
        service._collection.query = MagicMock(return_value={
            "ids": [["tmws:tool_1"]],
            "metadatas": [[{
                "tool_name": "tool_1",
                "server_id": "tmws",
                "description": "First test tool",
                "source_type": "internal",
                "tags": "test"
            }]],
            "distances": [[0.1]],
            "documents": [["tool_1 - First test tool"]]
        })

        # Step 4: Search tools
        results = await service.search_tools(query="test", limit=5)
        assert len(results) > 0

        # Step 5: Get tool details
        details = await service.get_tool_details(tool_name="tool_1", server_id="tmws")
        assert details is not None
        assert details["tool_name"] == "tool_1"


# =============================================================================
# Performance & Concurrency Tests
# =============================================================================


@pytest.mark.e2e
class TestConcurrencyAndPerformance:
    """Test thread safety and performance of lazy initialization."""

    @pytest.mark.asyncio
    async def test_concurrent_initialization_no_race_condition(self, temp_persist_dir):
        """Test that concurrent first-use doesn't cause race conditions.

        Expected: Double-check locking ensures single initialization
        """
        service = VectorSearchService(persist_directory=temp_persist_dir)

        # Simulate slow initialization with full chromadb module mock
        with patch("src.services.vector_search_service.chromadb") as mock_chromadb_module:
            call_count = 0

            # Create mock client with collection
            mock_client = MagicMock()
            mock_collection = MagicMock()
            mock_collection.count = MagicMock(return_value=0)
            mock_collection.query = MagicMock(return_value={
                "ids": [[]],
                "metadatas": [[]],
                "distances": [[]],
                "documents": [[]]
            })
            mock_client.get_or_create_collection = MagicMock(return_value=mock_collection)

            def slow_client_init(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                time.sleep(0.05)  # Simulate slow operation
                return mock_client

            mock_chromadb_module.PersistentClient.side_effect = slow_client_init

            # Trigger 10 concurrent operations
            tasks = [
                service.search([0.1] * 1024, top_k=5)
                for _ in range(10)
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # No exceptions
            assert all(not isinstance(r, Exception) for r in results)

            # Client created only once (double-check locking works)
            assert call_count == 1

    @pytest.mark.asyncio
    async def test_construction_performance(self, temp_persist_dir):
        """Test that service construction is fast (no ChromaDB overhead).

        Expected: Construction < 10ms (no I/O)
        """
        start = time.time()

        service = VectorSearchService(persist_directory=temp_persist_dir)

        elapsed_ms = (time.time() - start) * 1000

        # Construction should be very fast (no ChromaDB init)
        assert elapsed_ms < 10, f"Construction took {elapsed_ms:.2f}ms, expected < 10ms"
        assert service._initialized is False

    @pytest.mark.asyncio
    async def test_multiple_services_memory_efficient(self, temp_persist_dir):
        """Test that creating multiple service instances is memory-efficient.

        Expected: Multiple instances without ChromaDB clients consume minimal memory
        """
        # Create 100 service instances
        services = [
            VectorSearchService(persist_directory=temp_persist_dir)
            for _ in range(100)
        ]

        # All should be uninitialized (no ChromaDB clients)
        for service in services:
            assert service._client is None
            assert service._initialized is False

        # This test passes if no memory errors occur
        # and all services remain uninitialized


# =============================================================================
# Error Handling Tests
# =============================================================================


@pytest.mark.e2e
class TestErrorHandling:
    """Test error handling in lazy initialization."""

    @pytest.mark.asyncio
    async def test_concurrent_timeout_race_condition(self, temp_persist_dir):
        """Test race condition when multiple tasks timeout during initialization.

        Security (Hestia C-1): Prevents invalid state where _initialized=True but _client=None
        """
        from src.core.exceptions import ChromaInitializationError

        service = VectorSearchService(persist_directory=temp_persist_dir)

        with patch("src.services.vector_search_service.chromadb") as mock_chromadb:
            def hang(*args, **kwargs):
                time.sleep(10)  # Simulate hang (sync sleep for to_thread)
                raise Exception("Should not reach here")

            mock_chromadb.PersistentClient.side_effect = hang

            # Launch 5 tasks with 100ms timeout
            tasks = [
                service._ensure_initialized(timeout=0.1)
                for _ in range(5)
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # All should fail with timeout
            assert all(isinstance(r, ChromaInitializationError) for r in results)

            # SECURITY INVARIANT: Service must remain uninitialized
            assert service._initialized is False
            assert service._client is None
            assert service._collection is None

    @pytest.mark.asyncio
    async def test_timeout_during_collection_creation(self, temp_persist_dir):
        """Test timeout during get_or_create_collection phase.

        Security (Hestia C-2): Ensures cleanup even after client creation succeeds.
        """
        from src.core.exceptions import ChromaInitializationError

        service = VectorSearchService(persist_directory=temp_persist_dir)

        with patch("src.services.vector_search_service.chromadb") as mock_chromadb:
            mock_client = MagicMock()

            def hang_on_collection(*args, **kwargs):
                time.sleep(10)  # Hang on collection creation

            mock_client.get_or_create_collection.side_effect = hang_on_collection
            mock_chromadb.PersistentClient.return_value = mock_client

            with pytest.raises(ChromaInitializationError) as exc_info:
                await service._ensure_initialized(timeout=0.1)

            error_msg = str(exc_info.value).lower()
            assert "timed out" in error_msg or "timeout" in error_msg

            # SECURITY: Service should remain uninitialized
            assert service._initialized is False
            assert service._client is None
            assert service._collection is None

    @pytest.mark.asyncio
    async def test_initialization_timeout_protection(self, temp_persist_dir):
        """Test that initialization timeout protection works.

        Expected: ChromaInitializationError raised on timeout
        """
        from src.core.exceptions import ChromaInitializationError

        service = VectorSearchService(persist_directory=temp_persist_dir)

        # Mock ChromaDB to hang using a sync function (for asyncio.to_thread)
        with patch("src.services.vector_search_service.chromadb") as mock_chromadb:
            import time

            def hang(*args, **kwargs):
                time.sleep(100)  # Simulate hang (sync sleep for to_thread)

            mock_chromadb.PersistentClient.side_effect = hang

            # Should timeout and raise error
            with pytest.raises(ChromaInitializationError) as exc_info:
                await service._ensure_initialized(timeout=0.1)  # 100ms timeout

            # Check error message contains timeout info
            error_msg = str(exc_info.value).lower()
            assert "timed out" in error_msg or "timeout" in error_msg

    @pytest.mark.asyncio
    async def test_partial_state_cleanup_on_failure(self, temp_persist_dir):
        """Test that partial state is cleaned up on initialization failure.

        Expected: Service remains uninitialized after failed init
        """
        service = VectorSearchService(persist_directory=temp_persist_dir)

        # Mock ChromaDB module to fail (for asyncio.to_thread compatibility)
        with patch("src.services.vector_search_service.chromadb") as mock_chromadb:
            mock_chromadb.PersistentClient.side_effect = RuntimeError("ChromaDB failed")

            # Should raise error
            with pytest.raises(Exception):
                await service._ensure_initialized()

            # Service should remain uninitialized
            assert service._initialized is False
            assert service._client is None
            assert service._collection is None

    @pytest.mark.asyncio
    async def test_recovery_after_failed_initialization(self, temp_persist_dir):
        """Test that service can recover after failed initialization.

        Security (Hestia H-1): Ensures no resource leaks prevent recovery.
        """
        service = VectorSearchService(persist_directory=temp_persist_dir)

        with patch("src.services.vector_search_service.chromadb") as mock_chromadb:
            # First attempt fails
            mock_chromadb.PersistentClient.side_effect = RuntimeError("Transient failure")

            with pytest.raises(Exception):
                await service._ensure_initialized()

            assert service._initialized is False

            # Second attempt should succeed (no resource leaks blocking retry)
            mock_collection = MagicMock()
            mock_collection.count = MagicMock(return_value=0)
            mock_client = MagicMock()
            mock_client.get_or_create_collection = MagicMock(return_value=mock_collection)
            mock_chromadb.PersistentClient.side_effect = None
            mock_chromadb.PersistentClient.return_value = mock_client

            await service._ensure_initialized()

            # Service should be initialized after retry
            assert service._initialized is True
            assert service._client is not None
            assert service._collection is not None
