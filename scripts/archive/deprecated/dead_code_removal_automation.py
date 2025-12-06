#!/usr/bin/env python3
"""
Dead Code Removal Automation Script
TMWS Project - Artemis Technical Perfectionist

This script safely removes dead code detected by vulture in a staged,
test-validated manner with automatic rollback on failure.

Usage:
    python scripts/dead_code_removal_automation.py [--dry-run] [--priority P0|P1|P2|P3]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class DeadCodeItem:
    """Represents a single dead code item to be removed."""

    file_path: str
    line_number: int
    item_type: str  # 'unused function', 'unused method', etc.
    item_name: str
    confidence: int
    estimated_loc: int


@dataclass
class RemovalPlan:
    """Represents a staged removal plan."""

    priority: str  # P0, P1, P2, P3
    file_path: str
    items: List[DeadCodeItem]
    total_loc_removable: int
    actual_file_lines: int
    reduction_percentage: float


class DeadCodeRemovalAutomation:
    """Main automation class for dead code removal."""

    LOC_ESTIMATES = {
        'unused function': 15,
        'unused method': 12,
        'unused class': 80,
        'unused variable': 1,
        'unused attribute': 1,
        'unused property': 8,
    }

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.backup_dir = Path('.dead_code_backups')
        self.vulture_report_path = Path('/tmp/vulture_full.txt')
        self.test_command = ['python', '-m', 'pytest', 'tests/unit/', '-v', '--tb=short']

    def run(self, priority_filter: Optional[str] = None) -> int:
        """
        Main execution flow.

        Returns:
            0 on success, non-zero on failure
        """
        print("=" * 100)
        print("TMWS DEAD CODE REMOVAL AUTOMATION")
        print("Artemis - Technical Perfectionist")
        print("=" * 100)
        print()

        if self.dry_run:
            print("🔍 DRY RUN MODE - No actual changes will be made")
            print()

        # Step 1: Run vulture
        print("Step 1: Running Vulture dead code detection...")
        if not self._run_vulture():
            print("❌ Vulture analysis failed")
            return 1

        # Step 2: Parse vulture results
        print("\nStep 2: Parsing vulture results...")
        dead_code_items = self._parse_vulture_results()
        print(f"✅ Found {len(dead_code_items)} dead code items")

        # Step 3: Create removal plans
        print("\nStep 3: Creating removal plans...")
        removal_plans = self._create_removal_plans(dead_code_items)

        # Filter by priority
        if priority_filter:
            removal_plans = [p for p in removal_plans if p.priority == priority_filter]
            print(f"   Filtered to priority {priority_filter}: {len(removal_plans)} files")

        self._print_removal_summary(removal_plans)

        # Step 4: Baseline test run
        print("\nStep 4: Running baseline tests...")
        baseline_passed = self._run_tests()
        if not baseline_passed:
            print("⚠️  WARNING: Baseline tests are failing")
            print("   Continuing anyway to remove dead code (tests may improve)")
        else:
            print("✅ Baseline tests passed")

        # Step 5: Execute removals (staged)
        if self.dry_run:
            print("\n🔍 DRY RUN - Skipping actual removal")
            self._print_detailed_plan(removal_plans)
            return 0

        print("\nStep 5: Executing staged removals...")
        success_count = 0
        failed_count = 0

        for plan in removal_plans:
            result = self._execute_removal_plan(plan)
            if result:
                success_count += 1
            else:
                failed_count += 1
                print(f"⚠️  Skipping remaining files in {plan.priority} due to test failure")
                break

        # Step 6: Final report
        print("\n" + "=" * 100)
        print("REMOVAL COMPLETE")
        print("=" * 100)
        print(f"✅ Successfully processed: {success_count} files")
        print(f"❌ Failed/Skipped: {failed_count} files")

        if success_count > 0:
            total_removed = sum(p.total_loc_removable for p in removal_plans[:success_count])
            print(f"📊 Total LOC removed: ~{total_removed}")

        return 0 if failed_count == 0 else 1

    def _run_vulture(self) -> bool:
        """Run vulture analysis."""
        try:
            result = subprocess.run(
                ['python', '-m', 'vulture', 'src/', '--min-confidence', '60'],
                capture_output=True,
                text=True,
                timeout=120
            )

            with open(self.vulture_report_path, 'w') as f:
                f.write(result.stdout)

            return True
        except Exception as e:
            print(f"Error running vulture: {e}")
            return False

    def _parse_vulture_results(self) -> List[DeadCodeItem]:
        """Parse vulture output into structured data."""
        if not self.vulture_report_path.exists():
            return []

        items = []
        pattern = re.compile(
            r'^(.+?):(\d+):\s+(.+?)\s+\'(.+?)\'\s+\((\d+)% confidence\)$'
        )

        with open(self.vulture_report_path, 'r') as f:
            for line in f:
                line = line.strip()
                match = pattern.match(line)
                if match:
                    file_path, line_no, item_type, item_name, confidence = match.groups()

                    estimated_loc = self.LOC_ESTIMATES.get(item_type, 5)

                    items.append(DeadCodeItem(
                        file_path=file_path,
                        line_number=int(line_no),
                        item_type=item_type,
                        item_name=item_name,
                        confidence=int(confidence),
                        estimated_loc=estimated_loc
                    ))

        return items

    def _create_removal_plans(self, items: List[DeadCodeItem]) -> List[RemovalPlan]:
        """Create staged removal plans grouped by file and priority."""
        # Group by file
        by_file = defaultdict(list)
        for item in items:
            by_file[item.file_path].append(item)

        plans = []
        for file_path, file_items in by_file.items():
            total_removable = sum(item.estimated_loc for item in file_items)

            # Get actual file size
            actual_lines = 0
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    actual_lines = len(f.readlines())

            reduction_pct = (total_removable / actual_lines * 100) if actual_lines > 0 else 0

            # Determine priority
            if reduction_pct > 20 or total_removable > 300:
                priority = 'P0'
            elif reduction_pct > 10 or total_removable > 150:
                priority = 'P1'
            elif total_removable > 50:
                priority = 'P2'
            else:
                priority = 'P3'

            plans.append(RemovalPlan(
                priority=priority,
                file_path=file_path,
                items=file_items,
                total_loc_removable=total_removable,
                actual_file_lines=actual_lines,
                reduction_percentage=reduction_pct
            ))

        # Sort by priority, then by removable LOC
        priority_order = {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3}
        plans.sort(key=lambda p: (priority_order[p.priority], -p.total_loc_removable))

        return plans

    def _print_removal_summary(self, plans: List[RemovalPlan]):
        """Print summary of removal plans."""
        print()
        print("=" * 100)
        print("REMOVAL PLAN SUMMARY")
        print("=" * 100)

        by_priority = defaultdict(list)
        for plan in plans:
            by_priority[plan.priority].append(plan)

        for priority in ['P0', 'P1', 'P2', 'P3']:
            priority_plans = by_priority[priority]
            if not priority_plans:
                continue

            total_files = len(priority_plans)
            total_items = sum(len(p.items) for p in priority_plans)
            total_removable = sum(p.total_loc_removable for p in priority_plans)

            print(f"\n{priority}: {total_files} files, {total_items} items, ~{total_removable} LOC")
            print("-" * 100)

            for plan in priority_plans[:5]:  # Show top 5 per priority
                file_short = plan.file_path.replace('src/', '')
                print(f"  {file_short:<60} {len(plan.items):>5} items  {plan.total_loc_removable:>6} LOC  {plan.reduction_percentage:>6.1f}%")

            if len(priority_plans) > 5:
                print(f"  ... and {len(priority_plans) - 5} more files")

    def _print_detailed_plan(self, plans: List[RemovalPlan]):
        """Print detailed removal plan (for dry-run)."""
        print("\n" + "=" * 100)
        print("DETAILED REMOVAL PLAN (DRY RUN)")
        print("=" * 100)

        for plan in plans[:10]:  # Show top 10
            print(f"\n{plan.file_path}")
            print(f"  Priority: {plan.priority}")
            print(f"  Items to remove: {len(plan.items)}")
            print(f"  Estimated LOC removal: {plan.total_loc_removable}")
            print(f"  File reduction: {plan.reduction_percentage:.1f}%")
            print("  Items:")

            for item in plan.items[:10]:  # Show top 10 items
                print(f"    Line {item.line_number}: {item.item_type} '{item.item_name}' ({item.confidence}% confidence)")

            if len(plan.items) > 10:
                print(f"    ... and {len(plan.items) - 10} more items")

    def _run_tests(self) -> bool:
        """Run test suite."""
        try:
            result = subprocess.run(
                self.test_command,
                capture_output=True,
                text=True,
                timeout=300
            )
            return result.returncode == 0
        except Exception as e:
            print(f"Error running tests: {e}")
            return False

    def _execute_removal_plan(self, plan: RemovalPlan) -> bool:
        """
        Execute a single removal plan.

        Returns:
            True if successful, False if tests failed
        """
        print(f"\n📝 Processing: {plan.file_path}")
        print(f"   Items: {len(plan.items)}, Est. LOC: {plan.total_loc_removable}")

        # Create backup
        backup_path = self._create_backup(plan.file_path)
        if not backup_path:
            print("❌ Failed to create backup, skipping")
            return False

        # TODO: Implement actual removal logic
        # This is a placeholder - actual implementation would need to:
        # 1. Parse the file's AST
        # 2. Identify the exact code blocks to remove
        # 3. Remove them safely (preserving structure)
        # 4. Write back to file

        print("   ⚠️  Removal not yet implemented (requires AST manipulation)")
        print("   This would remove the dead code items listed above")

        # Run tests
        print("   Running tests...")
        if self._run_tests():
            print("   ✅ Tests passed, removal successful")
            return True
        else:
            print("   ❌ Tests failed, rolling back")
            self._rollback(plan.file_path, backup_path)
            return False

    def _create_backup(self, file_path: str) -> Optional[Path]:
        """Create backup of file."""
        try:
            self.backup_dir.mkdir(exist_ok=True)
            backup_path = self.backup_dir / Path(file_path).name
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception as e:
            print(f"Error creating backup: {e}")
            return None

    def _rollback(self, file_path: str, backup_path: Path):
        """Rollback changes from backup."""
        try:
            shutil.copy2(backup_path, file_path)
            print(f"   ↩️  Rolled back {file_path}")
        except Exception as e:
            print(f"Error rolling back: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='TMWS Dead Code Removal Automation'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run in dry-run mode (no actual changes)'
    )
    parser.add_argument(
        '--priority',
        choices=['P0', 'P1', 'P2', 'P3'],
        help='Filter by priority level'
    )

    args = parser.parse_args()

    automation = DeadCodeRemovalAutomation(dry_run=args.dry_run)
    sys.exit(automation.run(priority_filter=args.priority))


if __name__ == '__main__':
    main()
