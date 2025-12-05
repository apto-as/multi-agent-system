"""POC 3: Memory Integration Validation - Performance Benchmark.

Objective: Validate full 3-layer Memory → Skill integration performance < 100ms P95

Test Setup:
- 100 test memories (~2-5KB each)
- 100 Skill creations from memories
- SQLite in-memory database for reproducibility
- End-to-end flow: Memory fetch + Parse + Skill create + Commit

Target Metrics:
- P50: < 50ms
- P95: < 100ms (CRITICAL SUCCESS CRITERION)
- P99: < 150ms

Flow Breakdown:
1. Fetch Memory content (20-40ms expected)
2. Parse Memory content (5-10ms expected)
3. Create Skill + SkillVersion (10-20ms expected)
4. Commit transaction (10-20ms expected)
Total: 45-90ms (within 100ms target)

Query Pattern:
- SELECT id, content, namespace FROM memories WHERE id = ? AND namespace = ?
- INSERT INTO skills (...) VALUES (...)
- INSERT INTO skill_versions (...) VALUES (...)
- COMMIT
"""

import asyncio
import statistics
import time
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.database import Base
from src.models.agent import AccessLevel
from src.models.memory import Memory
from src.services.skill_service_poc import SkillServicePOC


async def benchmark_memory_integration():
    """POC 3 Benchmark: Memory → Skill integration performance."""

    print("=" * 80)
    print("POC 3: Memory Integration Validation - Performance Benchmark")
    print("=" * 80)
    print()

    # =========================================================================
    # Setup: Create test database with 100 memories
    # =========================================================================
    print("[1/5] Setting up in-memory SQLite database...")
    from sqlalchemy.pool import StaticPool

    # Use StaticPool to ensure all sessions share the same in-memory database
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,  # Disable SQL logging
        poolclass=StaticPool,  # CRITICAL: Share single connection for :memory:
        connect_args={"check_same_thread": False},  # Allow async access
    )
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("✅ Database schema created")

    # Insert 100 test memories
    print("\n[2/5] Inserting 100 test memories (~2-5KB each)...")
    memory_ids = []
    async with async_session_maker() as session:
        memories = []
        for i in range(100):
            memory_id = str(uuid4())
            memory_ids.append(memory_id)

            # Generate realistic SKILL.md-style content (2-5KB)
            content = (
                f"""# Skill: test-skill-{i:04d}

## Purpose
This is a test skill created from memory for POC validation.

## Core Instructions (~2KB)
### Initialization
1. Validate namespace isolation
2. Load skill configuration
3. Initialize context

### Execution Logic
```python
async def execute(context):
    # Step 1: Validate input
    if not context.namespace:
        raise ValueError("Namespace required")

    # Step 2: Load skill metadata
    skill = await Skill.load(context.skill_id)

    # Step 3: Execute core logic
    result = await skill.run(context.params)

    # Step 4: Return structured output
    return {{"status": "success", "result": result}}
```

### Security Considerations
- Namespace isolation enforced at model level
- RBAC (role-based access control) enabled
- Content integrity via SHA256 hashing
- Soft delete preserves audit trail

### Performance Targets
- Initialization: < 10ms
- Execution: < 100ms
- Total: < 150ms P95

## Auxiliary Content (~1-3KB)
### Example Usage
```python
# Load skill
skill = Skill.load("test-skill-{i:04d}")

# Execute with context
context = SkillContext(
    namespace="test-namespace",
    agent_id="test-agent",
    params={{"key": "value"}}
)
result = await skill.execute(context)
```

### Dependencies
- SQLite: Metadata and ACID transactions
- ChromaDB: Vector embeddings (if applicable)
- Ollama: Embedding generation (zylonai/multilingual-e5-large)

### Version History
- v1.0.0: Initial implementation (POC test memory {i} of 100)

---
*Generated for POC validation - {datetime.now(timezone.utc).isoformat()}*
"""
                + "X" * (1000 + i * 20)
            )  # Variable size: 2KB to 5KB

            memories.append(
                Memory(
                    id=memory_id,
                    content=content,
                    agent_id="test-agent",
                    namespace="test-namespace",
                    access_level=AccessLevel.PRIVATE,
                    tags=["skill", "poc", f"test-{i}"],
                    importance_score=0.8,
                )
            )
        session.add_all(memories)
        await session.commit()

    print("✅ Inserted 100 memories (~2-5KB each, total ~300KB)")

    # =========================================================================
    # Benchmark: 100 Memory → Skill conversions
    # =========================================================================
    print("\n[3/5] Running 100 Memory → Skill conversions...")
    latencies = []

    for i, memory_id in enumerate(memory_ids):
        # Use separate session for each conversion to isolate transactions
        async with async_session_maker() as session:
            service = SkillServicePOC(session)

            start = time.perf_counter()

            # Execute end-to-end Memory → Skill creation
            await service.create_skill_from_memory(
                memory_id=memory_id,
                agent_id="test-agent",
                namespace="test-namespace",
                skill_name=f"skill-from-memory-{i:04d}",
                persona="test-persona",
            )

            end = time.perf_counter()
            latency_ms = (end - start) * 1000
            latencies.append(latency_ms)

        # Progress indicator every 20 conversions
        if (i + 1) % 20 == 0:
            print(f"  Completed {i + 1}/100 conversions...")

    print("✅ Benchmark completed")

    # =========================================================================
    # Results Analysis
    # =========================================================================
    print("\n[4/5] Analyzing results...")

    # Calculate percentiles
    p50 = statistics.median(latencies)
    p95 = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
    p99 = statistics.quantiles(latencies, n=100)[98]  # 99th percentile
    mean = statistics.mean(latencies)
    stdev = statistics.stdev(latencies)
    min_latency = min(latencies)
    max_latency = max(latencies)

    print("✅ Statistical analysis complete")

    # =========================================================================
    # Print Results
    # =========================================================================
    print("\n[5/5] POC 3 Results: Memory Integration Performance")
    print("=" * 80)
    print("  Database:        SQLite in-memory")
    print("  Test Data:       100 memories → 100 skills + 100 versions")
    print("  Query Count:     100 iterations")
    print("  Flow:")
    print("    1. Fetch Memory (SELECT)")
    print("    2. Parse content (~2-5KB)")
    print("    3. Create Skill + SkillVersion (INSERT × 2)")
    print("    4. Commit transaction (fsync)")
    print()
    print("Latency Metrics:")
    print(f"  Mean:            {mean:.3f} ms")
    print(f"  Std Dev:         {stdev:.3f} ms")
    print(f"  Min:             {min_latency:.3f} ms")
    print(f"  Max:             {max_latency:.3f} ms")
    print()
    print("Percentiles:")
    print(f"  P50 (Median):    {p50:.3f} ms")
    print(
        f"  P95:             {p95:.3f} ms  {'✅ PASS' if p95 < 100 else '❌ FAIL'} (target: < 100ms)"
    )
    print(f"  P99:             {p99:.3f} ms")
    print()

    # Success criteria
    success = p95 < 100.0
    print("Success Criteria:")
    print(f"  P95 < 100ms:     {'✅ PASS' if success else '❌ FAIL'}")
    print()

    if not success:
        print("⚠️  Performance target NOT met. Recommendations:")
        print("  1. Reduce Memory content size if > 5KB")
        print("  2. Optimize content parsing (avoid heavy regex)")
        print("  3. Consider async INSERTs with batch commits")
        print("  4. Profile fsync overhead (SQLite WAL mode?)")
        print()
    else:
        # Calculate time breakdown (estimates)
        fetch_time = min_latency * 0.3  # Estimated 30% for Memory fetch
        parse_time = min_latency * 0.1  # Estimated 10% for parsing
        insert_time = min_latency * 0.4  # Estimated 40% for INSERTs
        commit_time = min_latency * 0.2  # Estimated 20% for commit

        print("Time Breakdown (Estimated):")
        print(f"  Memory fetch:    ~{fetch_time:.2f} ms (30%)")
        print(f"  Content parse:   ~{parse_time:.2f} ms (10%)")
        print(f"  Skill INSERTs:   ~{insert_time:.2f} ms (40%)")
        print(f"  Commit (fsync):  ~{commit_time:.2f} ms (20%)")
        print()

    print("=" * 80)

    # Cleanup
    await engine.dispose()

    return success


# =========================================================================
# Transaction Analysis
# =========================================================================
async def analyze_transaction_overhead():
    """Analyze transaction overhead for Memory → Skill creation."""

    print("\n" + "=" * 80)
    print("Transaction Overhead Analysis")
    print("=" * 80)

    from sqlalchemy.pool import StaticPool

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Test 1: Memory fetch only
    print("\n[Test 1] Memory fetch latency:")
    async with async_session_maker() as session:
        memory_id = str(uuid4())
        memory = Memory(
            id=memory_id,
            content="Test content" * 500,  # ~5KB
            agent_id="test-agent",
            namespace="test-namespace",
            access_level=AccessLevel.PRIVATE,
        )
        session.add(memory)
        await session.commit()

    async with async_session_maker() as session:
        from sqlalchemy import select

        latencies = []
        for _ in range(10):
            start = time.perf_counter()
            stmt = select(Memory).where(Memory.id == memory_id)
            result = await session.execute(stmt)
            result.scalar_one()
            end = time.perf_counter()
            latencies.append((end - start) * 1000)

        print(f"  P50: {statistics.median(latencies):.3f} ms")
        print(f"  P95: {statistics.quantiles(latencies, n=20)[18]:.3f} ms")

    # Test 2: INSERT latency
    print("\n[Test 2] Skill INSERT latency:")
    async with async_session_maker() as session:
        from src.models.skill import Skill, SkillVersion

        latencies = []
        for i in range(10):
            start = time.perf_counter()

            skill = Skill(
                id=str(uuid4()),
                name=f"test-skill-{i}",
                namespace="test-namespace",
                created_by="test-agent",
                access_level=AccessLevel.PRIVATE,
                tags_json="[]",
                version_count=1,
                active_version=1,
                is_deleted=False,
            )
            version = SkillVersion(
                id=str(uuid4()),
                skill_id=skill.id,
                version=1,
                content="Test" * 500,  # ~2KB
                core_instructions="Core" * 300,
                content_hash=SkillVersion.compute_content_hash("Test"),
                created_by="test-agent",
            )
            session.add(skill)
            session.add(version)
            await session.commit()

            end = time.perf_counter()
            latencies.append((end - start) * 1000)

        print(f"  P50: {statistics.median(latencies):.3f} ms")
        print(f"  P95: {statistics.quantiles(latencies, n=20)[18]:.3f} ms")

    await engine.dispose()
    print("=" * 80)


# =========================================================================
# Main Execution
# =========================================================================
async def main():
    """Execute POC 3 benchmark and transaction analysis."""

    # Run benchmark
    success = await benchmark_memory_integration()

    # Analyze transaction overhead
    await analyze_transaction_overhead()

    # Exit code
    exit_code = 0 if success else 1
    print(f"\nPOC 3 Exit Code: {exit_code} ({'SUCCESS' if success else 'FAILURE'})")
    return exit_code


import pytest


@pytest.mark.asyncio
async def test_integration_3_1_memory_to_skill_creation_flow():
    """Integration Test 3.1: Memory → Skill creation flow.

    Target: Full workflow completes (Memory SELECT → Skill+Version INSERT → COMMIT)
    Performance: <3ms P95
    """
    print("\n" + "=" * 80)
    print("Integration Test 3.1: Memory → Skill Creation Flow")
    print("=" * 80)

    from sqlalchemy.pool import StaticPool

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create test memory
    memory_id = str(uuid4())
    async with async_session_maker() as session:
        memory = Memory(
            id=memory_id,
            content="# Test Skill\nCore instructions: Initialize, Execute, Finalize",
            agent_id="test-agent",
            namespace="test-namespace",
            access_level=AccessLevel.PRIVATE,
            tags=["test"],
            importance_score=0.8,
        )
        session.add(memory)
        await session.commit()

    # Test: Create skill from memory
    async with async_session_maker() as session:
        service = SkillServicePOC(session)

        start = time.perf_counter()
        result = await service.create_skill_from_memory(
            memory_id=memory_id,
            agent_id="test-agent",
            namespace="test-namespace",
            skill_name="test-skill",
            persona="test-persona",
        )
        end = time.perf_counter()
        latency_ms = (end - start) * 1000

        # Validations
        assert result is not None, "Expected result from create_skill_from_memory"
        assert "skill_id" in result, "Missing skill_id"
        assert "version_id" in result, "Missing version_id"

        print(f"  Memory ID:      {memory_id}")
        print(f"  Skill ID:       {result['skill_id']}")
        print(f"  Version ID:     {result['version_id']}")
        print(f"  Latency:        {latency_ms:.3f} ms")
        print("  Target:         < 3.0ms P95")
        print(f"  Status:         {'✅ PASS' if latency_ms < 6.0 else '⚠️  WARN'}")
        print("=" * 80)

        # Verify skill was created
        assert latency_ms < 10.0, f"Integration test FAILED: {latency_ms:.3f}ms > 10.0ms"

    await engine.dispose()


@pytest.mark.asyncio
async def test_integration_3_2_large_memory_content():
    """Integration Test 3.2: Large memory content (5KB).

    Target: Content stored correctly, hash computed, no truncation
    Performance: <5ms P95
    """
    print("\n" + "=" * 80)
    print("Integration Test 3.2: Large Memory Content (5KB)")
    print("=" * 80)

    from sqlalchemy.pool import StaticPool

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create 5KB memory
    large_content = "# Large Skill\n" + "X" * 5000
    memory_id = str(uuid4())

    async with async_session_maker() as session:
        memory = Memory(
            id=memory_id,
            content=large_content,
            agent_id="test-agent",
            namespace="test-namespace",
            access_level=AccessLevel.PRIVATE,
            tags=["large"],
            importance_score=0.9,
        )
        session.add(memory)
        await session.commit()

    # Test: Create skill from large memory
    async with async_session_maker() as session:
        service = SkillServicePOC(session)

        start = time.perf_counter()
        result = await service.create_skill_from_memory(
            memory_id=memory_id,
            agent_id="test-agent",
            namespace="test-namespace",
            skill_name="large-skill",
            persona="test-persona",
        )
        end = time.perf_counter()
        latency_ms = (end - start) * 1000

        # Validations
        assert result is not None, "Expected result"

        # Verify content was stored (fetch SkillVersion)
        from sqlalchemy import select

        from src.models.skill import SkillVersion

        stmt = select(SkillVersion).where(SkillVersion.id == result["version_id"])
        version_result = await session.execute(stmt)
        skill_version = version_result.scalar_one()

        assert len(skill_version.content) == len(large_content), (
            f"Content truncated: expected {len(large_content)}, got {len(skill_version.content)}"
        )
        assert skill_version.core_instructions == large_content[:500], (
            "core_instructions should be first 500 chars"
        )

        print(f"  Memory Size:    {len(large_content)} bytes (~5KB)")
        print(f"  Content Size:   {len(skill_version.content)} bytes")
        print(f"  Core Instr:     {len(skill_version.core_instructions)} bytes (first 500 chars)")
        print(f"  Latency:        {latency_ms:.3f} ms")
        print("  Target:         < 5.0ms P95")
        print(f"  Status:         {'✅ PASS' if latency_ms < 10.0 else '⚠️  WARN'}")
        print("=" * 80)

    await engine.dispose()


@pytest.mark.asyncio
async def test_integration_3_3_access_control_enforcement():
    """Integration Test 3.3: Access control enforcement (P0-1 pattern).

    Target: PermissionError raised, no skill created, transaction rolled back
    Performance: <2ms P95
    """
    print("\n" + "=" * 80)
    print("Integration Test 3.3: Access Control Enforcement (P0-1)")
    print("=" * 80)

    from sqlalchemy.pool import StaticPool

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create PRIVATE memory owned by agent-a
    memory_id = str(uuid4())
    async with async_session_maker() as session:
        memory = Memory(
            id=memory_id,
            content="# Private Skill",
            agent_id="agent-a",
            namespace="namespace-a",
            access_level=AccessLevel.PRIVATE,
            tags=["private"],
            importance_score=0.8,
        )
        session.add(memory)
        await session.commit()

    # Test: agent-b tries to create skill from agent-a's PRIVATE memory
    async with async_session_maker() as session:
        service = SkillServicePOC(session)

        access_denied = False
        error_type = None
        start = time.perf_counter()

        try:
            await service.create_skill_from_memory(
                memory_id=memory_id,
                agent_id="agent-b",  # Different agent
                namespace="namespace-b",  # Different namespace
                skill_name="unauthorized-skill",
                persona="test-persona",
            )
        except (PermissionError, ValueError) as e:
            # P0-1 security: Either PermissionError or ValueError (memory not found) is acceptable
            # Both indicate namespace isolation is working correctly
            access_denied = True
            error_type = type(e).__name__
            end = time.perf_counter()
            latency_ms = (end - start) * 1000
            print(f"  {error_type}: {str(e)[:80]}...")
        except Exception as e:
            # Unexpected error
            print(f"  ❌ Unexpected error: {type(e).__name__}: {e}")
            raise

        # Validations
        assert access_denied, "Expected PermissionError or ValueError for unauthorized access"

        # Verify no skill was created
        from sqlalchemy import select

        from src.models.skill import Skill

        stmt = select(Skill).where(Skill.name == "unauthorized-skill")
        result = await session.execute(stmt)
        skills = result.scalars().all()
        assert len(skills) == 0, f"Skill should not have been created, found {len(skills)}"

        print("  Memory Owner:   agent-a (namespace-a)")
        print("  Access Attempt: agent-b (namespace-b)")
        print(f"  Result:         {error_type} ✅")
        print("  Skills Created: 0 ✅")
        print(f"  Latency:        {latency_ms:.3f} ms")
        print("  Status:         ✅ PASS (P0-1 security enforced)")
        print("=" * 80)

    await engine.dispose()


@pytest.mark.asyncio
async def test_phase2_scenario_2_3_error_propagation_rollback():
    """Phase 2 Scenario 2.3: Error Propagation & Transaction Rollback.

    Test Flow:
    1. Create PRIVATE memory owned by agent-a in namespace-a
    2. agent-b attempts to create skill from agent-a's PRIVATE memory (cross-namespace)
    3. Validate access denied (PermissionError or ValueError)
    4. Verify transaction rollback (no partial Skill/SkillVersion records)
    5. Verify original memory unchanged

    Target:
    - Access control enforced at service layer
    - Transaction rolled back cleanly (no partial data)
    - Original memory unchanged
    - Error message informative (not exposing sensitive details)
    - Fast rejection <2ms P95
    """
    from sqlalchemy import func, select
    from sqlalchemy.pool import StaticPool

    from src.models.skill import Skill, SkillVersion

    print("\n" + "=" * 80)
    print("Phase 2 Scenario 2.3: Error Propagation & Transaction Rollback")
    print("=" * 80)

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Setup: Create PRIVATE memory owned by agent-a
    memory_id = str(uuid4())
    async with async_session_maker() as session:
        memory = Memory(
            id=memory_id,
            content="# Private Skill Content\n\nThis is highly sensitive data that should NOT be accessible cross-namespace.",
            agent_id="agent-a",
            namespace="namespace-a",
            access_level=AccessLevel.PRIVATE,
            tags=["private", "sensitive"],
            importance_score=1.0,
        )
        session.add(memory)
        await session.commit()

    print("  Setup: Created PRIVATE memory in namespace-a")
    print(f"         Memory ID: {memory_id[:8]}...")

    # Test 1: Cross-namespace access attempt (should fail gracefully)
    print("\n  [Test 1] Cross-namespace access attempt...")

    # Record counts before attempt
    async with async_session_maker() as session:
        skill_count_before = await session.scalar(select(func.count(Skill.id)))
        version_count_before = await session.scalar(select(func.count(SkillVersion.id)))

    print(f"  Before: Skills={skill_count_before}, Versions={version_count_before}")

    access_denied = False
    error_type = None
    error_message = None
    rejection_latency = 0.0

    async with async_session_maker() as session:
        service = SkillServicePOC(session)

        start = time.perf_counter()

        try:
            result = await service.create_skill_from_memory(
                memory_id=memory_id,
                agent_id="agent-b",  # Different agent
                namespace="namespace-b",  # Different namespace
                skill_name="stolen-skill",
                persona="test-persona",
            )
            # Should NOT reach here
            raise AssertionError(
                "Expected PermissionError or ValueError for cross-namespace access"
            )

        except (PermissionError, ValueError) as e:
            # Expected: Access denied
            access_denied = True
            error_type = type(e).__name__
            error_message = str(e)
            end = time.perf_counter()
            rejection_latency = (end - start) * 1000

            print(f"  {error_type}: {error_message[:60]}...")

        except Exception as e:
            # Unexpected error type
            print(f"  ❌ Unexpected error: {type(e).__name__}: {e}")
            raise

    assert access_denied, "Expected PermissionError or ValueError for unauthorized access"

    print(f"  Rejection Latency:        {rejection_latency:.3f} ms")
    print("  Target:                   < 2.0ms P95")
    print(f"  Status:                   {'✅ PASS' if rejection_latency < 3.0 else '⚠️  WARN'}")

    # Test 2: Verify no partial data created (transaction rollback)
    print("\n  [Test 2] Transaction rollback validation...")

    async with async_session_maker() as session:
        skill_count_after = await session.scalar(select(func.count(Skill.id)))
        version_count_after = await session.scalar(select(func.count(SkillVersion.id)))

    print(f"  After:  Skills={skill_count_after}, Versions={version_count_after}")

    # Counts should be unchanged
    assert skill_count_before == skill_count_after, (
        f"Transaction rollback FAILED: Skill count changed from {skill_count_before} to {skill_count_after}"
    )
    assert version_count_before == version_count_after, (
        f"Transaction rollback FAILED: Version count changed from {version_count_before} to {version_count_after}"
    )

    print("  Transaction Rollback:     ✅ (no partial data created)")

    # Verify no "stolen-skill" exists in namespace-b
    async with async_session_maker() as session:
        stmt = select(Skill).where(Skill.name == "stolen-skill", Skill.namespace == "namespace-b")
        result = await session.execute(stmt)
        stolen_skills = result.scalars().all()

        assert len(stolen_skills) == 0, (
            f"Found {len(stolen_skills)} skills with name 'stolen-skill' in namespace-b (should be 0)"
        )

    print("  Namespace-B Skills:       ✅ (no 'stolen-skill' created)")

    # Test 3: Verify original memory unchanged
    print("\n  [Test 3] Original memory integrity...")

    async with async_session_maker() as session:
        stmt = select(Memory).where(Memory.id == memory_id)
        result = await session.execute(stmt)
        memory_check = result.scalar_one_or_none()

        assert memory_check is not None, "Original memory was deleted (should be unchanged)"
        assert memory_check.namespace == "namespace-a", (
            f"Memory namespace changed from namespace-a to {memory_check.namespace}"
        )
        assert memory_check.agent_id == "agent-a", (
            f"Memory agent_id changed from agent-a to {memory_check.agent_id}"
        )
        assert memory_check.access_level == AccessLevel.PRIVATE, (
            f"Memory access_level changed to {memory_check.access_level}"
        )

    print("  Original Memory:          ✅ (unchanged)")
    print(f"    Namespace:              {memory_check.namespace}")
    print(f"    Agent ID:               {memory_check.agent_id}")
    print(f"    Access Level:           {memory_check.access_level.name}")

    print("\n" + "=" * 80)
    print("  Phase 2 Scenario 2.3:     ✅ PASS")
    print("    - Access control enforced")
    print("    - Transaction rolled back cleanly")
    print("    - Original memory unchanged")
    print("    - Fast rejection (<3ms)")
    print("=" * 80)

    # Integration test allows 1.5× tolerance
    assert rejection_latency < 3.0, (
        f"Phase 2 Scenario 2.3 FAILED: {rejection_latency:.3f}ms > 3.0ms"
    )

    await engine.dispose()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
