#!/usr/bin/env python3
"""
Memory Baseline Establishment Tool

Runs system under typical load to establish memory usage baseline.

Usage:
    python -m shared.monitoring.memory_baseline [--duration MINUTES] [--output FILE]

Example:
    python -m shared.monitoring.memory_baseline --duration 5 --output data/memory_baseline.json
"""

import asyncio
import argparse
import json
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import List
import yaml

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.monitoring.memory_monitor import (
    MemoryMonitor,
    MonitoringTier,
    MemoryBaseline,
    MemorySnapshot,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class WorkloadSimulator:
    """Simulate typical Trinitas system workload."""

    def __init__(self):
        self.skills: List[dict] = []

    async def load_skills(self, count: int = 100) -> int:
        """
        Load skill YAML files from agents/ directory.

        Args:
            count: Target number of skills to load

        Returns:
            Actual number of skills loaded
        """
        logger.info(f"Loading up to {count} skills...")
        skills_dir = Path(__file__).parent.parent.parent / "skills"

        if not skills_dir.exists():
            logger.warning(f"Skills directory not found: {skills_dir}")
            # Simulate skill loading anyway
            logger.info("Simulating skill loading without actual files...")
            self.skills = [{"skill_name": f"skill_{i}", "version": "1.0.0"} for i in range(count)]
            return count

        # Find all YAML files
        yaml_files = list(skills_dir.rglob("*.yaml")) + list(skills_dir.rglob("*.yml"))

        loaded_count = 0
        for yaml_file in yaml_files[:count]:
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    skill_data = yaml.safe_load(f)
                    if skill_data:
                        self.skills.append(skill_data)
                        loaded_count += 1
            except Exception as e:
                logger.warning(f"Failed to load {yaml_file}: {e}")

        # If we didn't load enough, simulate the rest
        if loaded_count < count:
            simulated = count - loaded_count
            logger.info(f"Simulating {simulated} additional skills...")
            self.skills.extend([{"skill_name": f"simulated_{i}", "version": "1.0.0"} for i in range(simulated)])
            loaded_count = count

        logger.info(f"Loaded {loaded_count} skills ({len([s for s in self.skills if 'simulated_' not in str(s)])} real)")
        return loaded_count

    async def execute_tasks(self, count: int = 50):
        """
        Execute async tasks in parallel (simulated workload).

        Args:
            count: Number of tasks to execute
        """
        logger.info(f"Executing {count} async tasks...")

        async def simulate_task(task_id: int):
            """Simulate a single task."""
            await asyncio.sleep(0.01)  # Small delay
            # Simulate some data processing
            data = {"task_id": task_id, "result": [i * 2 for i in range(100)]}
            return data

        # Execute tasks in batches of 10 (to avoid overwhelming)
        batch_size = 10
        for i in range(0, count, batch_size):
            batch_end = min(i + batch_size, count)
            tasks = [simulate_task(j) for j in range(i, batch_end)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Check for errors
            errors = [r for r in results if isinstance(r, Exception)]
            if errors:
                logger.warning(f"Batch {i}-{batch_end}: {len(errors)} errors")

        logger.info(f"Completed {count} tasks")

    async def run_workload(self, duration_minutes: int = 5):
        """
        Run typical workload for specified duration.

        Args:
            duration_minutes: Duration to run workload (minutes)
        """
        logger.info(f"Running workload for {duration_minutes} minutes...")

        # Phase 1: Load skills
        await self.load_skills(count=100)

        # Phase 2: Execute tasks continuously
        start_time = asyncio.get_event_loop().time()
        duration_seconds = duration_minutes * 60
        task_count = 0

        while (asyncio.get_event_loop().time() - start_time) < duration_seconds:
            await self.execute_tasks(count=50)
            task_count += 50

            # Brief pause between batches
            await asyncio.sleep(1)

        logger.info(f"Workload completed: {task_count} total tasks executed")


async def establish_baseline(
    duration_minutes: int = 5,
    output_file: Path = Path("data/memory_baseline.json"),
    sampling_interval: int = 10,
) -> MemoryBaseline:
    """
    Run system and collect memory baseline data.

    Args:
        duration_minutes: Duration to run (minutes)
        output_file: Output file path
        sampling_interval: Sampling interval (seconds)

    Returns:
        Established baseline
    """
    logger.info(f"Establishing baseline (duration={duration_minutes}min, interval={sampling_interval}s)")

    # Initialize monitor
    # Use short baseline_window for quick baseline establishment
    baseline_window = min(duration_minutes * 60 - 20, 300)  # Leave 20s margin
    baseline_window = max(baseline_window, 30)  # Minimum 30s

    monitor = MemoryMonitor(
        tier=MonitoringTier.DEVELOPMENT,
        sampling_interval=sampling_interval,
        baseline_window=baseline_window,
    )

    # Start monitoring
    await monitor.start()

    # Wait for initial samples
    logger.info("Collecting initial samples...")
    await asyncio.sleep(sampling_interval * 3)

    # Run workload
    simulator = WorkloadSimulator()
    await simulator.run_workload(duration_minutes=duration_minutes)

    # Collect final samples
    logger.info("Collecting final samples...")
    await asyncio.sleep(sampling_interval * 3)

    # Get statistics from monitor
    stats = monitor.get_statistics()

    # Create baseline from monitor statistics
    baseline_rss_mb = monitor.get_baseline_rss_mb()
    if baseline_rss_mb is None:
        raise ValueError("Failed to establish baseline: not enough samples collected")

    # Get recent snapshots for baseline calculation
    recent_snapshots = list(monitor._snapshots)[-10:] if monitor._snapshots else []

    if not recent_snapshots:
        raise ValueError("No snapshots collected")

    # Calculate VMS and percent from recent snapshots
    avg_vms = sum(s.vms_mb for s in recent_snapshots) / len(recent_snapshots)
    avg_percent = sum(s.percent for s in recent_snapshots) / len(recent_snapshots)

    # Calculate variance
    variance = sum(abs(s.rss_mb - baseline_rss_mb) for s in recent_snapshots) / len(recent_snapshots)
    variance_percent = (variance / baseline_rss_mb) * 100 if baseline_rss_mb > 0 else 0

    # Create MemoryBaseline object
    baseline = MemoryBaseline(
        established_at=datetime.now(),
        rss_mb=baseline_rss_mb,
        vms_mb=avg_vms,
        percent=avg_percent,
        samples_count=len(recent_snapshots),
        variance_percent=variance_percent,
    )

    # Stop monitoring
    await monitor.stop()

    # Validate baseline
    is_valid, validation_msg = validate_baseline(baseline, list(monitor._snapshots))

    if not is_valid:
        logger.warning(f"Baseline validation failed: {validation_msg}")
    else:
        logger.info(f"Baseline validation passed: {validation_msg}")

    # Save to file
    output_file.parent.mkdir(parents=True, exist_ok=True)

    output_data = {
        "established_at": baseline.established_at.isoformat(),
        "duration_seconds": duration_minutes * 60,
        "baseline_rss_mb": baseline.rss_mb,
        "baseline_vms_mb": baseline.vms_mb,
        "baseline_percent": baseline.percent,
        "samples_collected": baseline.samples_count,
        "variance_percent": baseline.variance_percent,
        "validation": {
            "passed": is_valid,
            "message": validation_msg,
        },
        "reproducibility_score": calculate_reproducibility(list(monitor._snapshots)),
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    logger.info(f"Baseline saved to: {output_file}")
    logger.info(f"  RSS: {baseline.rss_mb:.2f} MB")
    logger.info(f"  Variance: {baseline.variance_percent:.2f}%")
    logger.info(f"  Samples: {baseline.samples_count}")

    return baseline


def validate_baseline(baseline: MemoryBaseline, snapshots: List[MemorySnapshot]) -> tuple[bool, str]:
    """
    Validate baseline quality.

    Args:
        baseline: Established baseline
        snapshots: Collected snapshots

    Returns:
        (is_valid, message)
    """
    # Check variance (should be <5%)
    if baseline.variance_percent > 5.0:
        return False, f"Variance too high: {baseline.variance_percent:.2f}% (threshold: 5%)"

    # Check sample count
    if baseline.samples_count < 3:
        return False, f"Not enough samples: {baseline.samples_count} (minimum: 3)"

    # Check stability (last 5 samples should be within 10% of baseline)
    recent = snapshots[-5:]
    if recent:
        deviations = [abs(s.rss_mb - baseline.rss_mb) / baseline.rss_mb * 100 for s in recent]
        max_deviation = max(deviations)

        if max_deviation > 10.0:
            return False, f"Unstable baseline: max deviation {max_deviation:.2f}% (threshold: 10%)"

    return True, "Baseline is stable and reproducible"


def calculate_reproducibility(snapshots: List[MemorySnapshot]) -> float:
    """
    Calculate reproducibility score (0.0-1.0).

    Args:
        snapshots: Collected snapshots

    Returns:
        Reproducibility score (higher is better)
    """
    if len(snapshots) < 2:
        return 0.0

    # Calculate coefficient of variation (CV)
    rss_values = [s.rss_mb for s in snapshots]
    mean_rss = sum(rss_values) / len(rss_values)
    variance = sum((x - mean_rss) ** 2 for x in rss_values) / len(rss_values)
    std_dev = variance ** 0.5

    cv = std_dev / mean_rss if mean_rss > 0 else 1.0

    # Convert CV to reproducibility score (lower CV = higher score)
    # CV of 0.05 (5%) = score of 0.95
    # CV of 0.10 (10%) = score of 0.90
    score = max(0.0, min(1.0, 1.0 - cv))

    return round(score, 2)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Establish memory baseline for Trinitas system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Establish 5-minute baseline
  python -m shared.monitoring.memory_baseline

  # Establish 10-minute baseline with custom output
  python -m shared.monitoring.memory_baseline --duration 10 --output custom_baseline.json

  # Quick baseline (1 minute, for testing)
  python -m shared.monitoring.memory_baseline --duration 1 --interval 5
        """,
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=5,
        help="Duration to run workload (minutes, default: 5)",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/memory_baseline.json"),
        help="Output file path (default: data/memory_baseline.json)",
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Sampling interval (seconds, default: 10)",
    )

    args = parser.parse_args()

    # Run baseline establishment
    try:
        baseline = asyncio.run(
            establish_baseline(
                duration_minutes=args.duration,
                output_file=args.output,
                sampling_interval=args.interval,
            )
        )

        print("\n" + "=" * 60)
        print("✅ Baseline Established Successfully!")
        print("=" * 60)
        print(f"📊 RSS: {baseline.rss_mb:.2f} MB")
        print(f"📊 VMS: {baseline.vms_mb:.2f} MB")
        print(f"📊 Memory %: {baseline.percent:.2f}%")
        print(f"📊 Variance: {baseline.variance_percent:.2f}%")
        print(f"📊 Samples: {baseline.samples_count}")
        print(f"📄 Output: {args.output}")
        print("=" * 60)

        sys.exit(0)

    except KeyboardInterrupt:
        logger.info("Baseline establishment interrupted by user")
        sys.exit(1)

    except Exception as e:
        logger.error(f"Failed to establish baseline: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
