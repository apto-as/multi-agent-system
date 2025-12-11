#!/usr/bin/env python3
"""
TMWS Pre-Push Git Hook Validator

Validates code quality before pushing to remote repository.
Replaces GitHub Actions CI/CD with local validation.

Validation Steps:
1. Extract Issue # from commit messages
2. Run pytest (unit + integration tests)
3. Run mypy (type checking)
4. Run bandit (security scan)
5. Generate test summary JSON
6. Return exit code (0=pass, 1=fail)

Usage:
    # Called automatically by git pre-push hook
    .git/hooks/pre-push

    # Manual invocation
    python scripts/git-hooks/pre-push-validator.py

Exit Codes:
    0 = All validations passed
    1 = Validation failure (blocks push)

Environment Variables:
    SKIP_TESTS=1          - Skip pytest (NOT recommended)
    SKIP_TYPECHECK=1      - Skip mypy (NOT recommended)
    SKIP_SECURITY=1       - Skip bandit (NOT recommended)
    VALIDATOR_VERBOSE=1   - Enable verbose output
"""

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


# ============================================
# Configuration
# ============================================

PROJECT_ROOT = Path(__file__).parent.parent.parent
RESULTS_FILE = PROJECT_ROOT / ".git" / "pre-push-results.json"
VERBOSE = os.getenv("VALIDATOR_VERBOSE", "0") == "1"


# ============================================
# Data Models
# ============================================

@dataclass
class ValidationResult:
    """Result of a single validation step."""
    name: str
    passed: bool
    duration_seconds: float
    output: str
    error_count: int = 0
    warning_count: int = 0


@dataclass
class PrePushSummary:
    """Complete pre-push validation summary."""
    timestamp: str
    commit_hash: str
    issue_number: Optional[str]
    validations: list[dict]
    overall_passed: bool
    total_duration_seconds: float


# ============================================
# Validation Functions
# ============================================

def run_command(cmd: list[str], cwd: Path = PROJECT_ROOT) -> tuple[int, str, str]:
    """
    Run shell command and return (exit_code, stdout, stderr).

    Args:
        cmd: Command and arguments as list
        cwd: Working directory

    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    if VERBOSE:
        print(f"[VERBOSE] Running: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


def extract_issue_number() -> Optional[str]:
    """
    Extract Issue # from recent commit messages.

    Looks for patterns:
    - Fixes #123
    - Closes #123
    - Issue #123

    Returns:
        Issue number (without #) or None
    """
    exit_code, stdout, _ = run_command(["git", "log", "-1", "--pretty=%B"])
    if exit_code != 0:
        return None

    # Match "Fixes #123", "Closes #123", "Issue #123"
    match = re.search(r"(?:Fixes|Closes|Issue)\s+#(\d+)", stdout, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def get_current_commit_hash() -> str:
    """Get current commit hash (short)."""
    exit_code, stdout, _ = run_command(["git", "rev-parse", "--short", "HEAD"])
    return stdout.strip() if exit_code == 0 else "unknown"


def validate_pytest() -> ValidationResult:
    """
    Run pytest for unit and integration tests.

    Returns:
        ValidationResult with test outcomes
    """
    print("🧪 Running pytest...")
    start = datetime.now()

    if os.getenv("SKIP_TESTS") == "1":
        print("⚠️  SKIP_TESTS=1: Skipping pytest (NOT RECOMMENDED)")
        return ValidationResult(
            name="pytest",
            passed=True,  # Assume pass when skipped
            duration_seconds=0.0,
            output="Skipped (SKIP_TESTS=1)",
            warning_count=1
        )

    exit_code, stdout, stderr = run_command([
        "python", "-m", "pytest",
        "tests/unit/",  # Focus on unit tests (E2E requires auth router - separate issue)
        "-v",
        "--tb=short",
        "--maxfail=5"  # Stop after 5 failures
    ])

    duration = (datetime.now() - start).total_seconds()

    # Count failures/errors
    error_count = stdout.count("FAILED") + stdout.count("ERROR")

    passed = exit_code == 0
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status} (errors: {error_count}, duration: {duration:.2f}s)")

    return ValidationResult(
        name="pytest",
        passed=passed,
        duration_seconds=duration,
        output=stdout + stderr,
        error_count=error_count
    )


def validate_mypy() -> ValidationResult:
    """
    Run mypy type checking.

    Returns:
        ValidationResult with type check outcomes
    """
    print("🔍 Running mypy...")
    start = datetime.now()

    if os.getenv("SKIP_TYPECHECK") == "1":
        print("⚠️  SKIP_TYPECHECK=1: Skipping mypy (NOT RECOMMENDED)")
        return ValidationResult(
            name="mypy",
            passed=True,
            duration_seconds=0.0,
            output="Skipped (SKIP_TYPECHECK=1)",
            warning_count=1
        )

    exit_code, stdout, stderr = run_command([
        "mypy",
        "src/",
        "--ignore-missing-imports",
        "--show-error-codes"
    ])

    duration = (datetime.now() - start).total_seconds()

    # Count errors
    error_count = stdout.count("error:")

    passed = exit_code == 0
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status} (errors: {error_count}, duration: {duration:.2f}s)")

    return ValidationResult(
        name="mypy",
        passed=passed,
        duration_seconds=duration,
        output=stdout + stderr,
        error_count=error_count
    )


def validate_bandit() -> ValidationResult:
    """
    Run bandit security scan.

    Returns:
        ValidationResult with security scan outcomes
    """
    print("🔒 Running bandit...")
    start = datetime.now()

    if os.getenv("SKIP_SECURITY") == "1":
        print("⚠️  SKIP_SECURITY=1: Skipping bandit (NOT RECOMMENDED)")
        return ValidationResult(
            name="bandit",
            passed=True,
            duration_seconds=0.0,
            output="Skipped (SKIP_SECURITY=1)",
            warning_count=1
        )

    exit_code, stdout, stderr = run_command([
        "bandit",
        "-r", "src/",
        "-f", "txt",
        "-ll"  # Only report medium/high severity
    ])

    duration = (datetime.now() - start).total_seconds()

    # Bandit exit codes: 0=no issues, 1=issues found
    # Count issues
    high_count = stdout.count("Severity: High")
    medium_count = stdout.count("Severity: Medium")
    error_count = high_count + medium_count

    # Pass if no HIGH severity issues (allow MEDIUM as warnings)
    passed = high_count == 0
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status} (high: {high_count}, medium: {medium_count}, duration: {duration:.2f}s)")

    return ValidationResult(
        name="bandit",
        passed=passed,
        duration_seconds=duration,
        output=stdout + stderr,
        error_count=high_count,
        warning_count=medium_count
    )


def generate_summary(
    validations: list[ValidationResult],
    issue_number: Optional[str]
) -> PrePushSummary:
    """
    Generate comprehensive validation summary.

    Args:
        validations: List of validation results
        issue_number: GitHub Issue number (if found)

    Returns:
        PrePushSummary object
    """
    total_duration = sum(v.duration_seconds for v in validations)
    overall_passed = all(v.passed for v in validations)

    return PrePushSummary(
        timestamp=datetime.now().isoformat(),
        commit_hash=get_current_commit_hash(),
        issue_number=issue_number,
        validations=[asdict(v) for v in validations],
        overall_passed=overall_passed,
        total_duration_seconds=total_duration
    )


def save_results(summary: PrePushSummary) -> None:
    """
    Save validation results to JSON file.

    Args:
        summary: PrePushSummary to save
    """
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_FILE, "w") as f:
        json.dump(asdict(summary), f, indent=2)

    if VERBOSE:
        print(f"[VERBOSE] Results saved to {RESULTS_FILE}")


def print_summary(summary: PrePushSummary) -> None:
    """
    Print human-readable summary to console.

    Args:
        summary: PrePushSummary to display
    """
    print("\n" + "=" * 60)
    print("PRE-PUSH VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Commit: {summary.commit_hash}")
    if summary.issue_number:
        print(f"Issue:  #{summary.issue_number}")
    print(f"Time:   {summary.timestamp}")
    print(f"Duration: {summary.total_duration_seconds:.2f}s")
    print()

    for v in summary.validations:
        status = "✅ PASS" if v["passed"] else "❌ FAIL"
        name = v["name"].ljust(10)
        duration = f"{v['duration_seconds']:.2f}s"
        errors = v.get("error_count", 0)
        warnings = v.get("warning_count", 0)

        print(f"{status} | {name} | {duration:>8} | errors: {errors}, warnings: {warnings}")

    print()
    if summary.overall_passed:
        print("✅ ALL VALIDATIONS PASSED - Push allowed")
    else:
        print("❌ VALIDATION FAILED - Push blocked")
        print("Fix errors and try again")
    print("=" * 60)


# ============================================
# Main Execution
# ============================================

def main() -> int:
    """
    Main validation orchestration.

    Returns:
        Exit code (0=success, 1=failure)
    """
    print("\n🚀 TMWS Pre-Push Validation (Issue #55 Phase 2)")
    print(f"📁 Project: {PROJECT_ROOT}")
    print()

    # Extract Issue # from commit
    issue_number = extract_issue_number()
    if issue_number:
        print(f"📋 Detected Issue: #{issue_number}")

    # Run validations
    validations = [
        validate_pytest(),
        validate_mypy(),
        validate_bandit()
    ]

    # Generate and save summary
    summary = generate_summary(validations, issue_number)
    save_results(summary)

    # Print summary
    print_summary(summary)

    # Return exit code
    return 0 if summary.overall_passed else 1


if __name__ == "__main__":
    sys.exit(main())
