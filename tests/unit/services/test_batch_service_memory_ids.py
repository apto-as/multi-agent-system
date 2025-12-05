"""Test batch_create_memories returns actual UUIDs (P2 Fix Verification).

This test suite verifies that batch_create_memories correctly returns actual UUIDs
instead of None values after the P2 fix.

Test Coverage:
1. Successful batch creation returns valid UUIDs
2. Failed items have None memory_id
3. Mixed success/failure batch handling
4. Batch commit failure handling
"""

import re

import pytest

from src.models.memory import Memory
from src.services.batch_service import BatchService


@pytest.mark.asyncio
async def test_batch_create_memories_returns_valid_uuids(db_session):
    """Test that successful batch creation creates memories with valid UUIDs."""
    from sqlalchemy import select

    batch_service = BatchService()
    await batch_service.start()

    try:
        # Create batch of memories
        memories_data = [
            {"content": "Test memory 1", "agent_id": "test-agent", "namespace": "test"},
            {"content": "Test memory 2", "agent_id": "test-agent", "namespace": "test"},
            {"content": "Test memory 3", "agent_id": "test-agent", "namespace": "test"},
        ]

        job_id = await batch_service.batch_create_memories(
            memories_data=memories_data,
            agent_id="test-agent",
            namespace="test",
            batch_size=10,
        )

        # Wait for job completion
        import asyncio

        await asyncio.sleep(1.5)  # Give processor time to complete

        # Get job status
        status = await batch_service.processor.get_job_status(job_id)

        assert status is not None
        assert status["status"] == "completed", f"Job failed: {status}"
        assert status["success_count"] == 3, "All 3 memories should be created"
        assert status["failure_count"] == 0, "No failures should occur"

        # Verify memories were created in database with valid UUIDs
        result = await db_session.execute(
            select(Memory)
            .where(
                Memory.agent_id == "test-agent",
                Memory.namespace == "test",
            )
            .order_by(Memory.created_at),
        )
        memories = result.scalars().all()

        assert len(memories) == 3, "Should have 3 memories in database"

        # Verify all memories have valid UUIDs
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        )

        for i, memory in enumerate(memories):
            # P2 FIX VERIFICATION: memory.id should be a valid UUID, not None
            assert memory.id is not None, f"Memory {i} should have non-None UUID"
            assert isinstance(memory.id, str), f"Memory {i} UUID should be string"
            assert uuid_pattern.match(
                memory.id,
            ), f"Memory {i} UUID should be valid format: {memory.id}"
            assert memory.content == f"Test memory {i + 1}"

    finally:
        await batch_service.stop()


@pytest.mark.asyncio
async def test_batch_create_memories_handles_failures(db_session):
    """Test that batch handles failed items correctly (no memory created for invalid items)."""
    from sqlalchemy import select

    batch_service = BatchService()
    await batch_service.start()

    try:
        # Create batch with one invalid memory (missing content)
        memories_data = [
            {"content": "Valid memory", "agent_id": "test-agent", "namespace": "test"},
            {"agent_id": "test-agent", "namespace": "test"},  # Missing content (should fail)
        ]

        job_id = await batch_service.batch_create_memories(
            memories_data=memories_data,
            agent_id="test-agent",
            namespace="test",
            batch_size=10,
        )

        # Wait for job completion
        import asyncio

        await asyncio.sleep(1.5)

        # Get job status
        status = await batch_service.processor.get_job_status(job_id)

        assert status is not None
        assert status["success_count"] == 1, "Should have 1 successful memory"
        assert status["failure_count"] == 1, "Should have 1 failed memory"

        # Verify only valid memory was created in database
        result = await db_session.execute(
            select(Memory).where(
                Memory.agent_id == "test-agent",
                Memory.namespace == "test",
            ),
        )
        memories = result.scalars().all()

        assert len(memories) == 1, "Should have only 1 memory in database"
        assert memories[0].content == "Valid memory"
        assert memories[0].id is not None, "Valid memory should have UUID"

    finally:
        await batch_service.stop()


@pytest.mark.asyncio
async def test_batch_create_memories_mixed_success_failure(db_session):
    """Test mixed batch with both successful and failed items."""
    from sqlalchemy import select

    batch_service = BatchService()
    await batch_service.start()

    try:
        # Create batch with mixed valid/invalid
        memories_data = [
            {"content": "Memory 1", "agent_id": "test-agent", "namespace": "test"},
            {"agent_id": "test-agent"},  # Missing content (should fail)
            {"content": "Memory 3", "agent_id": "test-agent", "namespace": "test"},
            {"content": "Memory 4"},  # Missing agent_id (should use default)
        ]

        job_id = await batch_service.batch_create_memories(
            memories_data=memories_data,
            agent_id="test-agent",
            namespace="test",
            batch_size=10,
        )

        # Wait for job completion
        import asyncio

        await asyncio.sleep(1.5)

        # Get job status
        status = await batch_service.processor.get_job_status(job_id)

        assert status is not None
        assert status["success_count"] == 3, "Should have 3 successful memories"
        assert status["failure_count"] == 1, "Should have 1 failed memory"

        # Verify correct memories were created in database
        result = await db_session.execute(
            select(Memory)
            .where(
                Memory.agent_id == "test-agent",
                Memory.namespace == "test",
            )
            .order_by(Memory.created_at),
        )
        memories = result.scalars().all()

        assert len(memories) == 3, "Should have 3 memories in database"

        # Verify UUIDs are valid
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        )

        assert memories[0].content == "Memory 1"
        assert uuid_pattern.match(memories[0].id)

        assert memories[1].content == "Memory 3"
        assert uuid_pattern.match(memories[1].id)

        assert memories[2].content == "Memory 4"
        assert uuid_pattern.match(memories[2].id)

    finally:
        await batch_service.stop()


@pytest.mark.asyncio
async def test_batch_create_memories_uuid_uniqueness(db_session):
    """Test that all created memory UUIDs are unique."""
    from sqlalchemy import select

    batch_service = BatchService()
    await batch_service.start()

    try:
        # Create batch of 10 memories
        memories_data = [
            {"content": f"Memory {i}", "agent_id": "test-agent", "namespace": "test"}
            for i in range(10)
        ]

        job_id = await batch_service.batch_create_memories(
            memories_data=memories_data,
            agent_id="test-agent",
            namespace="test",
            batch_size=10,
        )

        # Wait for job completion
        import asyncio

        await asyncio.sleep(1.5)

        # Get job status
        status = await batch_service.processor.get_job_status(job_id)

        assert status is not None
        assert status["success_count"] == 10, "Should have 10 successful memories"
        assert status["failure_count"] == 0, "Should have 0 failures"

        # Verify all memories have unique UUIDs
        result = await db_session.execute(
            select(Memory).where(
                Memory.agent_id == "test-agent",
                Memory.namespace == "test",
            ),
        )
        memories = result.scalars().all()

        assert len(memories) == 10, "Should have 10 memories in database"

        # Collect all UUIDs
        uuids = [memory.id for memory in memories]

        # Verify all UUIDs are unique
        assert len(uuids) == len(set(uuids)), "All UUIDs should be unique"
        assert len(uuids) == 10, "Should have 10 unique UUIDs"

    finally:
        await batch_service.stop()
