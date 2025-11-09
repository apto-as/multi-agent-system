"""
Mem0 Feature Performance Benchmarks - Phase 1 Verification

Tests current implementation (hierarchy, tags, metadata) performance
to determine if knowledge graph implementation is necessary.

Target Metrics:
- Hierarchical Retrieval: < 50ms (3 levels)
- Tag Search: < 10ms (100 results)
- Metadata Complex Search: < 20ms
- Cross-agent Sharing: < 15ms
"""

import time

import pytest
from sqlalchemy import and_, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.memory import AccessLevel, Memory
from src.services.memory_service import HybridMemoryService


@pytest.fixture
async def memory_service(db_session: AsyncSession) -> HybridMemoryService:
    """Create memory service for testing."""
    return HybridMemoryService(db_session)


@pytest.fixture
async def hierarchical_memories(
    db_session: AsyncSession, memory_service: HybridMemoryService
) -> dict:
    """
    Create 3-level memory hierarchy for testing.

    Structure:
    - Project (1)
      - Task 1 (5)
        - Subtask 1.1 (5)
        - Subtask 1.2 (5)
        - ...
      - Task 2 (5)
      - ...
    Total: 1 + 5 + 25 = 31 memories
    """
    # Level 1: Project
    project = await memory_service.create_memory(
        content="データベース最適化プロジェクト",
        agent_id="athena",
        namespace="default",
        importance=0.9,
        tags=["project", "optimization", "database"],
        metadata={"type": "project", "status": "in_progress"},
    )

    tasks = []
    subtasks = []

    # Level 2: Tasks (5)
    for i in range(5):
        task = await memory_service.create_memory(
            content=f"タスク {i + 1}: インデックス最適化",
            agent_id="artemis",
            namespace="default",
            importance=0.8,
            tags=["task", "optimization", f"phase_{i + 1}"],
            metadata={
                "type": "task",
                "status": "pending",
                "project_id": str(project.id),
            },
            parent_memory_id=project.id,
        )
        tasks.append(task)

        # Level 3: Subtasks (5 per task)
        for j in range(5):
            subtask = await memory_service.create_memory(
                content=f"サブタスク {i + 1}.{j + 1}: {['分析', '設計', '実装', 'テスト', 'デプロイ'][j]}",
                agent_id="artemis",
                namespace="default",
                importance=0.6,
                tags=["subtask", "optimization", f"phase_{i + 1}"],
                metadata={
                    "type": "subtask",
                    "status": "pending",
                    "task_id": str(task.id),
                    "step": j + 1,
                },
                parent_memory_id=task.id,
            )
            subtasks.append(subtask)

    await db_session.commit()

    return {
        "project": project,
        "tasks": tasks,
        "subtasks": subtasks,
        "total_count": 31,
    }


@pytest.fixture
async def tagged_memories(
    db_session: AsyncSession, memory_service: HybridMemoryService
) -> list[Memory]:
    """
    Create 200 memories with various tags for search testing.

    Tag distribution:
    - optimization: 100
    - database: 80
    - critical: 40
    - performance: 60
    """
    memories = []

    tag_combinations = [
        ["optimization", "database", "critical"],  # 20
        ["optimization", "database", "performance"],  # 20
        ["optimization", "performance"],  # 20
        ["optimization", "critical"],  # 20
        ["optimization"],  # 20
        ["database", "performance"],  # 20
        ["database", "critical"],  # 20
        ["database"],  # 20
        ["performance"],  # 20
        ["critical"],  # 20
    ]

    for i, tags in enumerate(tag_combinations * 10):  # 200 memories
        memory = await memory_service.create_memory(
            content=f"最適化結果 {i + 1}: パフォーマンス改善",
            agent_id="artemis",
            namespace="default",
            importance=0.5 + (i % 5) * 0.1,
            tags=tags,
            metadata={"sequence": i + 1, "category": tags[0]},
        )
        memories.append(memory)

    await db_session.commit()
    return memories


@pytest.fixture
async def metadata_memories(
    db_session: AsyncSession, memory_service: HybridMemoryService
) -> list[Memory]:
    """
    Create 150 memories with complex metadata for filtering tests.

    Metadata structure:
    - category: performance / security / architecture
    - priority: low / medium / high / critical
    - importance: 0.3 - 1.0
    - agent_id: athena / artemis / hestia
    """
    memories = []

    categories = ["performance", "security", "architecture"]
    priorities = ["low", "medium", "high", "critical"]
    agents = ["athena", "artemis", "hestia"]
    importances = [0.3, 0.5, 0.7, 0.9, 1.0]

    for i in range(150):
        memory = await memory_service.create_memory(
            content=f"メモリ {i + 1}: {categories[i % 3]} 関連",
            agent_id=agents[i % 3],
            namespace="default",
            importance=importances[i % 5],
            tags=[categories[i % 3], priorities[i % 4]],
            metadata={
                "category": categories[i % 3],
                "priority": priorities[i % 4],
                "sequence": i + 1,
            },
        )
        memories.append(memory)

    await db_session.commit()
    return memories


@pytest.fixture
async def shared_memories(db_session: AsyncSession, memory_service: HybridMemoryService) -> dict:
    """
    Create memories with various access levels for cross-agent testing.

    Distribution:
    - PRIVATE: 40
    - TEAM: 30
    - SHARED: 20
    - PUBLIC: 10
    - SYSTEM: 5
    Total: 105
    """
    memories = {
        "private": [],
        "team": [],
        "shared": [],
        "public": [],
        "system": [],
    }

    # PRIVATE memories (Artemis only)
    for i in range(40):
        memory = await memory_service.create_memory(
            content=f"Artemis private memory {i + 1}",
            agent_id="artemis",
            namespace="default",
            importance=0.5,
            tags=["private", "artemis"],
            metadata={"access_level": "private"},
            access_level=AccessLevel.PRIVATE,
        )
        memories["private"].append(memory)

    # TEAM memories (same namespace)
    for i in range(30):
        memory = await memory_service.create_memory(
            content=f"Team memory {i + 1}",
            agent_id="artemis",
            namespace="engineering",
            importance=0.6,
            tags=["team", "shared"],
            metadata={"access_level": "team"},
            access_level=AccessLevel.TEAM,
        )
        memories["team"].append(memory)

    # SHARED memories (specific agents)
    for i in range(20):
        memory = await memory_service.create_memory(
            content=f"Shared memory {i + 1}",
            agent_id="artemis",
            namespace="default",
            importance=0.7,
            tags=["shared", "collaboration"],
            metadata={"access_level": "shared"},
            access_level=AccessLevel.SHARED,
            shared_with_agents=["athena", "hestia"],
        )
        memories["shared"].append(memory)

    # PUBLIC memories
    for i in range(10):
        memory = await memory_service.create_memory(
            content=f"Public memory {i + 1}",
            agent_id="artemis",
            namespace="default",
            importance=0.8,
            tags=["public", "documentation"],
            metadata={"access_level": "public"},
            access_level=AccessLevel.PUBLIC,
        )
        memories["public"].append(memory)

    # SYSTEM memories
    for i in range(5):
        memory = await memory_service.create_memory(
            content=f"System memory {i + 1}",
            agent_id="system",
            namespace="system",
            importance=0.9,
            tags=["system", "configuration"],
            metadata={"access_level": "system"},
            access_level=AccessLevel.SYSTEM,
        )
        memories["system"].append(memory)

    await db_session.commit()
    return memories


# ==================== Benchmark Tests ====================


@pytest.mark.asyncio
@pytest.mark.benchmark
async def test_benchmark_hierarchical_retrieval(
    db_session: AsyncSession,
    memory_service: HybridMemoryService,
    hierarchical_memories: dict,
):
    """
    Benchmark 1: Hierarchical Memory Retrieval

    Target: < 50ms for 3-level hierarchy (31 memories)
    Warning: > 100ms
    Critical: > 200ms
    """
    project = hierarchical_memories["project"]

    # Measure retrieval time
    start = time.perf_counter()

    # Level 1: Get project
    retrieved_project = await memory_service.get_memory(project.id)
    assert retrieved_project is not None

    # Level 2: Get tasks (5)
    tasks_query = await db_session.execute(
        select(Memory).where(Memory.parent_memory_id == project.id)
    )
    tasks = tasks_query.scalars().all()
    assert len(tasks) == 5

    # Level 3: Get all subtasks (25)
    all_subtasks = []
    for task in tasks:
        subtasks_query = await db_session.execute(
            select(Memory).where(Memory.parent_memory_id == task.id)
        )
        subtasks = subtasks_query.scalars().all()
        all_subtasks.extend(subtasks)
    assert len(all_subtasks) == 25

    duration_ms = (time.perf_counter() - start) * 1000

    # Performance assertions
    print(f"\n[Benchmark 1] Hierarchical Retrieval: {duration_ms:.2f}ms")
    print("  - Project: 1")
    print(f"  - Tasks: {len(tasks)}")
    print(f"  - Subtasks: {len(all_subtasks)}")
    print(f"  - Total: {1 + len(tasks) + len(all_subtasks)} memories")

    if duration_ms > 200:
        pytest.fail(f"❌ CRITICAL: Hierarchical retrieval too slow: {duration_ms:.2f}ms (> 200ms)")
    elif duration_ms > 100:
        pytest.warn(f"⚠️  WARNING: Hierarchical retrieval slow: {duration_ms:.2f}ms (> 100ms)")
    elif duration_ms < 50:
        print(f"✅ PASS: Hierarchical retrieval fast: {duration_ms:.2f}ms (< 50ms target)")
    else:
        print(f"✅ ACCEPTABLE: Hierarchical retrieval: {duration_ms:.2f}ms (50-100ms)")


@pytest.mark.asyncio
@pytest.mark.benchmark
async def test_benchmark_tag_search(db_session: AsyncSession, tagged_memories: list[Memory]):
    """
    Benchmark 2: Tag-based Search (GIN Index)

    Target: < 10ms for 100 results
    Warning: > 20ms
    Critical: > 50ms
    """
    # Warm-up query (not counted)
    await db_session.execute(
        select(Memory).where(Memory.tags.op("?|")(cast(["optimization"], ARRAY(TEXT)))).limit(10)
    )

    # Benchmark query: OR search (optimization OR database)
    start = time.perf_counter()
    results_or = await db_session.execute(
        select(Memory)
        .where(Memory.tags.op("?|")(cast(["optimization", "database"], ARRAY(TEXT))))
        .limit(100)
    )
    or_results = results_or.scalars().all()
    duration_or_ms = (time.perf_counter() - start) * 1000

    # Benchmark query: AND search (optimization AND critical)
    start = time.perf_counter()
    results_and = await db_session.execute(
        select(Memory)
        .where(Memory.tags.op("@>")(cast(["optimization"], JSONB)))
        .where(Memory.tags.op("@>")(cast(["critical"], JSONB)))
        .limit(100)
    )
    and_results = results_and.scalars().all()
    duration_and_ms = (time.perf_counter() - start) * 1000

    # Performance assertions
    max_duration = max(duration_or_ms, duration_and_ms)
    print("\n[Benchmark 2] Tag Search:")
    print(
        f"  - OR search (optimization | database): {duration_or_ms:.2f}ms ({len(or_results)} results)"
    )
    print(
        f"  - AND search (optimization & critical): {duration_and_ms:.2f}ms ({len(and_results)} results)"
    )
    print(f"  - Max duration: {max_duration:.2f}ms")

    if max_duration > 50:
        pytest.fail(f"❌ CRITICAL: Tag search too slow: {max_duration:.2f}ms (> 50ms)")
    elif max_duration > 20:
        pytest.warn(f"⚠️  WARNING: Tag search slow: {max_duration:.2f}ms (> 20ms)")
    elif max_duration < 10:
        print(f"✅ PASS: Tag search fast: {max_duration:.2f}ms (< 10ms target)")
    else:
        print(f"✅ ACCEPTABLE: Tag search: {max_duration:.2f}ms (10-20ms)")


@pytest.mark.asyncio
@pytest.mark.benchmark
async def test_benchmark_metadata_complex_search(
    db_session: AsyncSession, metadata_memories: list[Memory]
):
    """
    Benchmark 3: Complex Metadata Search (JSONB + GIN Index)

    Target: < 20ms
    Warning: > 50ms
    Critical: > 100ms
    """
    # Warm-up
    await db_session.execute(
        select(Memory).where(Memory.context["category"].astext == "performance").limit(10)
    )

    # Complex query: category + priority + importance + agent
    start = time.perf_counter()
    results = await db_session.execute(
        select(Memory)
        .where(Memory.context["category"].astext == "performance")
        .where(Memory.context["priority"].astext.in_(["high", "critical"]))
        .where(Memory.importance_score >= 0.8)
        .where(Memory.agent_id == "artemis")
        .limit(100)
    )
    complex_results = results.scalars().all()
    duration_ms = (time.perf_counter() - start) * 1000

    print(f"\n[Benchmark 3] Complex Metadata Search: {duration_ms:.2f}ms")
    print(
        "  - Filters: category=performance, priority IN (high,critical), importance>=0.8, agent=artemis"
    )
    print(f"  - Results: {len(complex_results)}")

    if duration_ms > 100:
        pytest.fail(f"❌ CRITICAL: Complex search too slow: {duration_ms:.2f}ms (> 100ms)")
    elif duration_ms > 50:
        pytest.warn(f"⚠️  WARNING: Complex search slow: {duration_ms:.2f}ms (> 50ms)")
    elif duration_ms < 20:
        print(f"✅ PASS: Complex search fast: {duration_ms:.2f}ms (< 20ms target)")
    else:
        print(f"✅ ACCEPTABLE: Complex search: {duration_ms:.2f}ms (20-50ms)")


@pytest.mark.asyncio
@pytest.mark.benchmark
async def test_benchmark_cross_agent_sharing(db_session: AsyncSession, shared_memories: dict):
    """
    Benchmark 4: Cross-agent Memory Sharing Access Control

    Target: < 15ms
    Warning: > 30ms
    Critical: > 60ms
    """
    # Athena accessing Artemis's memories
    requesting_agent = "athena"

    # Warm-up
    await db_session.execute(
        select(Memory).where(Memory.access_level == AccessLevel.PUBLIC).limit(10)
    )

    # Complex access control query
    start = time.perf_counter()
    results = await db_session.execute(
        select(Memory).where(
            and_(
                Memory.agent_id == "artemis",  # Artemis's memories
                or_(
                    Memory.access_level == AccessLevel.SYSTEM,
                    Memory.access_level == AccessLevel.PUBLIC,
                    and_(
                        Memory.access_level == AccessLevel.SHARED,
                        Memory.shared_with_agents.contains([requesting_agent]),
                    ),
                ),
            )
        )
    )
    accessible_memories = results.scalars().all()
    duration_ms = (time.perf_counter() - start) * 1000

    # Expected: PUBLIC (10) + SHARED (20 if athena in list) + SYSTEM (5)
    expected_min = 15  # At least PUBLIC + SYSTEM
    print(f"\n[Benchmark 4] Cross-agent Sharing: {duration_ms:.2f}ms")
    print(f"  - Requesting agent: {requesting_agent}")
    print("  - Target agent: artemis")
    print(f"  - Accessible memories: {len(accessible_memories)} (expected >= {expected_min})")

    assert len(accessible_memories) >= expected_min, (
        f"Access control logic error: {len(accessible_memories)} < {expected_min}"
    )

    if duration_ms > 60:
        pytest.fail(f"❌ CRITICAL: Cross-agent access too slow: {duration_ms:.2f}ms (> 60ms)")
    elif duration_ms > 30:
        pytest.warn(f"⚠️  WARNING: Cross-agent access slow: {duration_ms:.2f}ms (> 30ms)")
    elif duration_ms < 15:
        print(f"✅ PASS: Cross-agent access fast: {duration_ms:.2f}ms (< 15ms target)")
    else:
        print(f"✅ ACCEPTABLE: Cross-agent access: {duration_ms:.2f}ms (15-30ms)")


# ==================== Summary Report ====================


@pytest.mark.asyncio
@pytest.mark.benchmark
async def test_benchmark_summary():
    """
    Generate benchmark summary report.

    This test should be run last to display overall results.
    """
    print("\n" + "=" * 60)
    print("Mem0 Feature Performance Benchmark Summary")
    print("=" * 60)
    print("\nPhase 1: 階層・タグ・メタデータ性能検証")
    print("\n目標値:")
    print("  1. 階層取得 (3レベル): < 50ms")
    print("  2. タグ検索 (100件): < 10ms")
    print("  3. メタデータ複合検索: < 20ms")
    print("  4. クロスエージェント共有: < 15ms")
    print("\n判断基準:")
    print("  ✅ ALL PASS → 現状維持、知識グラフ不要")
    print("  ⚠️  WARNING → 最適化検討")
    print("  ❌ CRITICAL → 知識グラフ実装を推奨 (Option A: PostgreSQL AGE)")
    print("\n実行コマンド:")
    print("  pytest tests/performance/test_mem0_feature_benchmarks.py -v -m benchmark")
    print("=" * 60)
