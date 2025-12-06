#!/usr/bin/env python3
"""Phase 3B: Performance Benchmarking Re-validation

Objective: Confirm no performance regressions from security implementations

Success Criteria:
- POC 1: <10ms P95 (previously 1.251ms)
- POC 2: <30ms P95 (previously 0.506ms)
- POC 3: <100ms P95 (previously 1.282ms)
- No regression >10%

Alert Thresholds:
- WARNING: >10% regression
- ABORT: >50% regression
"""

import asyncio
import statistics
import sys
import time
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.database import Base
from src.models.memory import AccessLevel as MemoryAccessLevel, Memory
from src.models.skill import AccessLevel as SkillAccessLevel, Skill
from src.services.skill_service_poc import SkillServicePOC


class PerformanceValidator:
    """Performance regression validation for Phase 3B."""

    def __init__(self):
        self.results = {}
        self.baselines = {
            "poc1": {"target": 10.0, "previous": 1.251, "name": "POC 1: Metadata Layer"},
            "poc2": {"target": 30.0, "previous": 0.506, "name": "POC 2: Core Instructions"},
            "poc3": {"target": 100.0, "previous": 1.282, "name": "POC 3: Memory Integration"},
        }

    def calculate_regression(self, current: float, previous: float) -> float:
        """Calculate regression percentage."""
        if previous == 0:
            return 0.0
        return ((current - previous) / previous) * 100

    def assess_status(self, poc_id: str, p95: float) -> tuple[str, str]:
        """Assess performance status."""
        baseline = self.baselines[poc_id]
        target = baseline["target"]
        previous = baseline["previous"]

        # Check target compliance
        if p95 > target:
            return "FAIL", f"Exceeded target {target}ms"

        # Check regression
        regression_pct = self.calculate_regression(p95, previous)

        if regression_pct > 50:
            return "ABORT", f"CRITICAL: {regression_pct:.1f}% regression"
        elif regression_pct > 10:
            return "WARNING", f"{regression_pct:.1f}% regression"
        elif regression_pct < -10:
            return "IMPROVED", f"{abs(regression_pct):.1f}% improvement"
        else:
            return "PASS", f"{regression_pct:.1f}% change"

    async def benchmark_poc1(self, engine, async_session) -> dict:
        """Benchmark POC 1: Metadata Layer."""
        print("\n" + "=" * 80)
        print("POC 1: Metadata Layer Performance Re-validation")
        print("=" * 80)

        # Insert 1,000 test skills
        async with async_session() as session:
            print("\nInserting 1,000 test skills...")
            skills = [
                Skill(
                    id=str(uuid4()),
                    name=f"test-skill-{i:04d}",
                    persona="test-persona",
                    namespace="test-namespace",
                    created_by="test-agent",
                    access_level=SkillAccessLevel.PRIVATE,
                    description=f"Test skill {i} for benchmarking",
                )
                for i in range(1000)
            ]
            session.add_all(skills)
            await session.commit()
            print(f"Inserted {len(skills)} skills")

        # Benchmark list_skills()
        print("\nBenchmarking list_skills() - 100 iterations...")
        times = []

        async with async_session() as session:
            service = SkillServicePOC(session)

            for i in range(100):
                start = time.perf_counter()
                result = await service.list_skills(
                    namespace="test-namespace", agent_id="test-agent"
                )
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)

                if i % 20 == 0:
                    print(f"  Iteration {i+1}/100: {elapsed:.3f}ms")

        # Calculate statistics
        times.sort()
        p50 = times[len(times) // 2]
        p95 = times[int(0.95 * len(times))]
        p99 = times[int(0.99 * len(times))]
        avg = statistics.mean(times)

        status, message = self.assess_status("poc1", p95)

        result = {
            "poc_id": "poc1",
            "name": self.baselines["poc1"]["name"],
            "iterations": 100,
            "avg": avg,
            "p50": p50,
            "p95": p95,
            "p99": p99,
            "target": self.baselines["poc1"]["target"],
            "previous": self.baselines["poc1"]["previous"],
            "status": status,
            "message": message,
        }

        self.results["poc1"] = result
        return result

    async def benchmark_poc2(self, engine, async_session) -> dict:
        """Benchmark POC 2: Core Instructions Layer."""
        print("\n" + "=" * 80)
        print("POC 2: Core Instructions Layer Performance Re-validation")
        print("=" * 80)

        # Create test skill
        async with async_session() as session:
            print("\nCreating test skill...")
            skill = Skill(
                id=str(uuid4()),
                name="benchmark-skill",
                persona="test-persona",
                namespace="test-namespace",
                created_by="test-agent",
                access_level=SkillAccessLevel.PRIVATE,
                description="Test skill for POC2 benchmarking",
            )
            session.add(skill)
            await session.commit()
            skill_id = skill.id
            print(f"Created skill: {skill_id}")

        # Benchmark get_skill()
        print("\nBenchmarking get_skill() - 100 iterations...")
        times = []

        async with async_session() as session:
            service = SkillServicePOC(session)

            for i in range(100):
                start = time.perf_counter()
                result = await service.get_skill(
                    skill_id=skill_id,
                    namespace="test-namespace",
                    agent_id="test-agent",
                )
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)

                if i % 20 == 0:
                    print(f"  Iteration {i+1}/100: {elapsed:.3f}ms")

        # Calculate statistics
        times.sort()
        p50 = times[len(times) // 2]
        p95 = times[int(0.95 * len(times))]
        p99 = times[int(0.99 * len(times))]
        avg = statistics.mean(times)

        status, message = self.assess_status("poc2", p95)

        result = {
            "poc_id": "poc2",
            "name": self.baselines["poc2"]["name"],
            "iterations": 100,
            "avg": avg,
            "p50": p50,
            "p95": p95,
            "p99": p99,
            "target": self.baselines["poc2"]["target"],
            "previous": self.baselines["poc2"]["previous"],
            "status": status,
            "message": message,
        }

        self.results["poc2"] = result
        return result

    async def benchmark_poc3(self, engine, async_session) -> dict:
        """Benchmark POC 3: Memory Integration."""
        print("\n" + "=" * 80)
        print("POC 3: Memory Integration Performance Re-validation")
        print("=" * 80)

        # Create test memory
        async with async_session() as session:
            print("\nCreating test memory...")
            memory = Memory(
                id=str(uuid4()),
                content="Test memory content for skill creation benchmark",
                agent_id="test-agent",
                namespace="test-namespace",
                access_level=MemoryAccessLevel.PRIVATE,
            )
            session.add(memory)
            await session.commit()
            memory_id = memory.id
            print(f"Created memory: {memory_id}")

        # Benchmark create_skill_from_memory()
        print("\nBenchmarking create_skill_from_memory() - 50 iterations...")
        times = []

        for i in range(50):
            async with async_session() as session:
                service = SkillServicePOC(session)

                start = time.perf_counter()
                skill = await service.create_skill_from_memory(
                    memory_id=memory_id,
                    skill_name=f"benchmark-skill-{i}",
                    persona="test-persona",
                    namespace="test-namespace",
                    agent_id="test-agent",
                )
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)

                if i % 10 == 0:
                    print(f"  Iteration {i+1}/50: {elapsed:.3f}ms")

        # Calculate statistics
        times.sort()
        p50 = times[len(times) // 2]
        p95 = times[int(0.95 * len(times))]
        p99 = times[int(0.99 * len(times))]
        avg = statistics.mean(times)

        status, message = self.assess_status("poc3", p95)

        result = {
            "poc_id": "poc3",
            "name": self.baselines["poc3"]["name"],
            "iterations": 50,
            "avg": avg,
            "p50": p50,
            "p95": p95,
            "p99": p99,
            "target": self.baselines["poc3"]["target"],
            "previous": self.baselines["poc3"]["previous"],
            "status": status,
            "message": message,
        }

        self.results["poc3"] = result
        return result

    def print_summary(self):
        """Print performance validation summary."""
        print("\n" + "=" * 80)
        print("PHASE 3B: PERFORMANCE VALIDATION SUMMARY")
        print("=" * 80)

        for poc_id in ["poc1", "poc2", "poc3"]:
            result = self.results[poc_id]
            print(f"\n{result['name']}")
            print(f"  Iterations:     {result['iterations']}")
            print(f"  Average:        {result['avg']:.3f}ms")
            print(f"  P50:            {result['p50']:.3f}ms")
            print(f"  P95:            {result['p95']:.3f}ms")
            print(f"  P99:            {result['p99']:.3f}ms")
            print(f"  Target:         <{result['target']:.0f}ms")
            print(f"  Previous:       {result['previous']:.3f}ms")
            print(f"  Status:         {result['status']}")
            print(f"  Assessment:     {result['message']}")

        # Overall assessment
        print("\n" + "=" * 80)
        print("OVERALL ASSESSMENT")
        print("=" * 80)

        all_pass = all(r["status"] in ["PASS", "IMPROVED"] for r in self.results.values())
        has_warning = any(r["status"] == "WARNING" for r in self.results.values())
        has_abort = any(r["status"] in ["ABORT", "FAIL"] for r in self.results.values())

        if has_abort:
            print("\n❌ ABORT: Critical performance regression detected")
            print("Action: Escalate to Athena + Hera for investigation")
            return 2
        elif has_warning:
            print("\n⚠️  WARNING: Performance regression detected but acceptable")
            print("Action: Document mitigation in deployment checklist")
            return 1
        elif all_pass:
            print("\n✅ PASS: All performance targets met, no regressions detected")
            print("Action: Proceed with Phase 3C Documentation & Deployment Prep")
            return 0
        else:
            print("\n⚠️  UNKNOWN: Unexpected status combination")
            return 1

    async def run_all(self):
        """Run all performance benchmarks."""
        # Setup: Create in-memory test database
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            echo=False,
        )
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        # Create tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        try:
            # Run benchmarks
            await self.benchmark_poc1(engine, async_session)
            await self.benchmark_poc2(engine, async_session)
            await self.benchmark_poc3(engine, async_session)

            # Print summary
            exit_code = self.print_summary()

            return exit_code

        finally:
            await engine.dispose()


async def main():
    """Main entry point."""
    validator = PerformanceValidator()
    exit_code = await validator.run_all()
    sys.exit(exit_code)


if __name__ == "__main__":
    asyncio.run(main())
