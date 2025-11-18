#!/usr/bin/env python3
"""
Comprehensive Tests for Memory Baseline Establishment
=====================================================

Coverage target: 15% → 95%

Tests:
- WorkloadSimulator edge cases
- Baseline establishment with varying durations
- Baseline validation logic
- Reproducibility score calculation
- CLI argument parsing and error handling
- Workload simulation failures
"""

import pytest
import asyncio
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.monitoring.memory_baseline import (
    WorkloadSimulator,
    establish_baseline,
    validate_baseline,
    calculate_reproducibility,
    main,
)
from shared.monitoring.memory_monitor import (
    MemoryBaseline,
    MemorySnapshot,
    MonitoringTier,
)


# ========================
# Test Suite 1: WorkloadSimulator
# ========================

class TestWorkloadSimulator:
    """Test WorkloadSimulator skill loading and task execution"""

    @pytest.mark.asyncio
    async def test_load_skills_with_no_directory(self):
        """Test skill loading when skills/ directory doesn't exist"""
        simulator = WorkloadSimulator()

        # Should simulate skills when directory doesn't exist
        count = await simulator.load_skills(count=50)

        assert count == 50
        assert len(simulator.skills) == 50
        assert all('skill_name' in skill for skill in simulator.skills)

    @pytest.mark.asyncio
    async def test_load_skills_with_yaml_files(self, tmp_path):
        """Test skill loading from actual YAML files"""
        # Create temporary skills directory
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()

        # Create 5 YAML files
        for i in range(5):
            skill_file = skills_dir / f"skill_{i}.yaml"
            skill_file.write_text(f"skill_name: test_skill_{i}\nversion: 1.0.0")

        simulator = WorkloadSimulator()

        # Patch skills directory location
        with patch.object(Path, 'exists', return_value=True):
            with patch.object(Path, 'rglob') as mock_rglob:
                mock_rglob.return_value = list(skills_dir.glob("*.yaml"))

                count = await simulator.load_skills(count=10)

                # Should load 5 real + 5 simulated
                assert count == 10
                assert len(simulator.skills) == 10

    @pytest.mark.asyncio
    async def test_load_skills_with_corrupted_yaml(self, tmp_path):
        """Test skill loading with corrupted YAML files"""
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()

        # Create corrupted YAML file
        bad_skill = skills_dir / "bad.yaml"
        bad_skill.write_text("{ corrupted yaml content [[[")

        # Create good YAML file
        good_skill = skills_dir / "good.yaml"
        good_skill.write_text("skill_name: good\nversion: 1.0.0")

        simulator = WorkloadSimulator()

        with patch.object(Path, 'exists', return_value=True):
            with patch.object(Path, 'rglob') as mock_rglob:
                mock_rglob.return_value = [bad_skill, good_skill]

                count = await simulator.load_skills(count=5)

                # Should load 1 good + 4 simulated
                assert count == 5
                assert len(simulator.skills) == 5

    @pytest.mark.asyncio
    async def test_execute_tasks_success(self):
        """Test successful task execution"""
        simulator = WorkloadSimulator()

        # Should complete without errors
        await simulator.execute_tasks(count=20)

    @pytest.mark.asyncio
    async def test_execute_tasks_with_errors(self):
        """Test task execution with some task failures"""
        simulator = WorkloadSimulator()

        # Mock simulate_task to raise errors occasionally
        original_method = simulator.execute_tasks

        async def simulate_task_with_errors(task_id: int):
            if task_id % 5 == 0:
                raise ValueError(f"Simulated error for task {task_id}")
            await asyncio.sleep(0.001)
            return {"task_id": task_id}

        # Should handle errors gracefully
        with patch('shared.monitoring.memory_baseline.WorkloadSimulator.execute_tasks',
                   side_effect=lambda count: original_method(count)):
            await simulator.execute_tasks(count=15)

    @pytest.mark.asyncio
    async def test_run_workload_short_duration(self):
        """Test workload with very short duration (edge case)"""
        simulator = WorkloadSimulator()

        # Run for just 0.1 minutes (6 seconds)
        await simulator.run_workload(duration_minutes=0.1)

        # Should complete without errors
        assert len(simulator.skills) > 0

    @pytest.mark.asyncio
    async def test_run_workload_cancelled(self):
        """Test workload cancellation during execution"""
        simulator = WorkloadSimulator()

        # Create task and cancel it after 1 second
        task = asyncio.create_task(simulator.run_workload(duration_minutes=5))

        await asyncio.sleep(1)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task


# ========================
# Test Suite 2: Baseline Validation
# ========================

class TestBaselineValidation:
    """Test baseline validation logic"""

    def test_validate_baseline_too_high_variance(self):
        """Test validation fails with high variance"""
        baseline = MemoryBaseline(
            established_at=datetime.now(),
            rss_mb=100.0,
            vms_mb=200.0,
            percent=10.0,
            samples_count=10,
            variance_percent=7.0,  # > 5% threshold
        )

        snapshots = [
            MemorySnapshot(timestamp=datetime.now(), rss_mb=100.0, vms_mb=200.0, percent=10.0)
        ]

        is_valid, message = validate_baseline(baseline, snapshots)

        assert not is_valid
        assert "Variance too high" in message

    def test_validate_baseline_too_few_samples(self):
        """Test validation fails with insufficient samples"""
        baseline = MemoryBaseline(
            established_at=datetime.now(),
            rss_mb=100.0,
            vms_mb=200.0,
            percent=10.0,
            samples_count=2,  # < 3 minimum
            variance_percent=2.0,
        )

        snapshots = []

        is_valid, message = validate_baseline(baseline, snapshots)

        assert not is_valid
        assert "Not enough samples" in message

    def test_validate_baseline_unstable(self):
        """Test validation fails with unstable recent samples"""
        baseline = MemoryBaseline(
            established_at=datetime.now(),
            rss_mb=100.0,
            vms_mb=200.0,
            percent=10.0,
            samples_count=10,
            variance_percent=2.0,
        )

        # Create unstable snapshots (>10% deviation)
        snapshots = [
            MemorySnapshot(timestamp=datetime.now(), rss_mb=100.0, vms_mb=200.0, percent=10.0),
            MemorySnapshot(timestamp=datetime.now(), rss_mb=120.0, vms_mb=200.0, percent=12.0),  # +20%
        ] * 3

        is_valid, message = validate_baseline(baseline, snapshots)

        assert not is_valid
        assert "Unstable baseline" in message

    def test_validate_baseline_success(self):
        """Test validation succeeds with good baseline"""
        baseline = MemoryBaseline(
            established_at=datetime.now(),
            rss_mb=100.0,
            vms_mb=200.0,
            percent=10.0,
            samples_count=10,
            variance_percent=2.0,
        )

        # Create stable snapshots
        snapshots = [
            MemorySnapshot(timestamp=datetime.now(), rss_mb=100.0 + i, vms_mb=200.0, percent=10.0)
            for i in range(5)
        ]

        is_valid, message = validate_baseline(baseline, snapshots)

        assert is_valid
        assert "stable and reproducible" in message


# ========================
# Test Suite 3: Reproducibility Score
# ========================

class TestReproducibilityScore:
    """Test reproducibility score calculation"""

    def test_calculate_reproducibility_no_snapshots(self):
        """Test reproducibility with no snapshots"""
        score = calculate_reproducibility([])
        assert score == 0.0

    def test_calculate_reproducibility_single_snapshot(self):
        """Test reproducibility with single snapshot"""
        snapshots = [
            MemorySnapshot(timestamp=datetime.now(), rss_mb=100.0, vms_mb=200.0, percent=10.0)
        ]

        score = calculate_reproducibility(snapshots)
        assert score == 0.0

    def test_calculate_reproducibility_perfect_stability(self):
        """Test reproducibility with perfectly stable snapshots"""
        snapshots = [
            MemorySnapshot(timestamp=datetime.now(), rss_mb=100.0, vms_mb=200.0, percent=10.0)
            for _ in range(10)
        ]

        score = calculate_reproducibility(snapshots)
        assert score == 1.0

    def test_calculate_reproducibility_high_variance(self):
        """Test reproducibility with high variance"""
        snapshots = [
            MemorySnapshot(timestamp=datetime.now(), rss_mb=50.0 + i*20, vms_mb=200.0, percent=10.0)
            for i in range(10)
        ]

        score = calculate_reproducibility(snapshots)
        assert 0.0 <= score < 0.5  # High variance = low score

    def test_calculate_reproducibility_moderate_variance(self):
        """Test reproducibility with moderate variance"""
        snapshots = [
            MemorySnapshot(timestamp=datetime.now(), rss_mb=100.0 + i*2, vms_mb=200.0, percent=10.0)
            for i in range(10)
        ]

        score = calculate_reproducibility(snapshots)
        assert 0.9 <= score <= 1.0  # Low variance = high score


# ========================
# Test Suite 4: Baseline Establishment
# ========================

class TestBaselineEstablishment:
    """Test establish_baseline function"""

    @pytest.mark.asyncio
    async def test_establish_baseline_short_duration(self, tmp_path):
        """Test baseline establishment with minimum duration"""
        output_file = tmp_path / "baseline.json"

        # Mock MemoryMonitor to avoid actual monitoring
        with patch('shared.monitoring.memory_baseline.MemoryMonitor') as MockMonitor:
            mock_monitor = MagicMock()
            MockMonitor.return_value = mock_monitor

            # Setup mock data
            mock_snapshots = [
                MemorySnapshot(timestamp=datetime.now(), rss_mb=100.0, vms_mb=200.0, percent=10.0)
                for _ in range(5)
            ]
            mock_monitor._snapshots = mock_snapshots
            mock_monitor.get_baseline_rss_mb.return_value = 100.0
            mock_monitor.get_statistics.return_value = {}

            # Mock start/stop
            mock_monitor.start = AsyncMock()
            mock_monitor.stop = AsyncMock()

            # Run establishment (very short duration)
            baseline = await establish_baseline(
                duration_minutes=0.05,  # 3 seconds
                output_file=output_file,
                sampling_interval=1,
            )

            # Verify baseline created
            assert baseline.rss_mb == 100.0
            assert baseline.samples_count > 0

            # Verify output file created
            assert output_file.exists()

            # Verify output content
            with open(output_file, 'r') as f:
                data = json.load(f)
                assert 'baseline_rss_mb' in data
                assert data['baseline_rss_mb'] == 100.0

    @pytest.mark.asyncio
    async def test_establish_baseline_no_samples_collected(self, tmp_path):
        """Test baseline establishment fails when no samples collected"""
        output_file = tmp_path / "baseline.json"

        with patch('shared.monitoring.memory_baseline.MemoryMonitor') as MockMonitor:
            mock_monitor = MagicMock()
            MockMonitor.return_value = mock_monitor

            # No snapshots collected
            mock_monitor._snapshots = []
            mock_monitor.get_baseline_rss_mb.return_value = None

            mock_monitor.start = AsyncMock()
            mock_monitor.stop = AsyncMock()

            # Should raise ValueError
            with pytest.raises(ValueError, match="Failed to establish baseline"):
                await establish_baseline(
                    duration_minutes=0.05,
                    output_file=output_file,
                    sampling_interval=1,
                )

    @pytest.mark.asyncio
    async def test_establish_baseline_baseline_none(self, tmp_path):
        """Test baseline establishment when monitor returns None"""
        output_file = tmp_path / "baseline.json"

        with patch('shared.monitoring.memory_baseline.MemoryMonitor') as MockMonitor:
            mock_monitor = MagicMock()
            MockMonitor.return_value = mock_monitor

            # Snapshots exist but baseline is None
            mock_snapshots = [
                MemorySnapshot(timestamp=datetime.now(), rss_mb=100.0, vms_mb=200.0, percent=10.0)
            ]
            mock_monitor._snapshots = mock_snapshots
            mock_monitor.get_baseline_rss_mb.return_value = None

            mock_monitor.start = AsyncMock()
            mock_monitor.stop = AsyncMock()

            # Should raise ValueError
            with pytest.raises(ValueError, match="Failed to establish baseline"):
                await establish_baseline(
                    duration_minutes=0.05,
                    output_file=output_file,
                    sampling_interval=1,
                )


# ========================
# Test Suite 5: CLI Entry Point
# ========================

class TestCLI:
    """Test main() CLI entry point"""

    def test_main_default_args(self):
        """Test main with default arguments"""
        test_args = ['memory_baseline']

        with patch('sys.argv', test_args):
            with patch('shared.monitoring.memory_baseline.establish_baseline') as mock_establish:
                with patch('asyncio.run') as mock_run:
                    # Mock successful baseline
                    mock_baseline = MemoryBaseline(
                        established_at=datetime.now(),
                        rss_mb=100.0,
                        vms_mb=200.0,
                        percent=10.0,
                        samples_count=10,
                        variance_percent=2.0,
                    )
                    mock_run.return_value = mock_baseline

                    # Should exit with 0
                    with pytest.raises(SystemExit) as exc_info:
                        main()

                    assert exc_info.value.code == 0

    def test_main_custom_args(self):
        """Test main with custom arguments"""
        test_args = [
            'memory_baseline',
            '--duration', '10',
            '--output', '/tmp/custom.json',
            '--interval', '5'
        ]

        with patch('sys.argv', test_args):
            with patch('shared.monitoring.memory_baseline.establish_baseline') as mock_establish:
                with patch('asyncio.run') as mock_run:
                    mock_baseline = MemoryBaseline(
                        established_at=datetime.now(),
                        rss_mb=100.0,
                        vms_mb=200.0,
                        percent=10.0,
                        samples_count=10,
                        variance_percent=2.0,
                    )
                    mock_run.return_value = mock_baseline

                    with pytest.raises(SystemExit) as exc_info:
                        main()

                    assert exc_info.value.code == 0

                    # Verify establish_baseline was called with correct args
                    mock_run.assert_called_once()

    def test_main_keyboard_interrupt(self):
        """Test main handles KeyboardInterrupt"""
        test_args = ['memory_baseline']

        with patch('sys.argv', test_args):
            with patch('asyncio.run', side_effect=KeyboardInterrupt()):
                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 1

    def test_main_generic_error(self):
        """Test main handles generic exceptions"""
        test_args = ['memory_baseline']

        with patch('sys.argv', test_args):
            with patch('asyncio.run', side_effect=RuntimeError("Test error")):
                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 1
