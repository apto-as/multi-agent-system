#!/usr/bin/env python3
"""
TMWS Issue Reporter for Git Hook Results

Posts pre-push validation results to GitHub Issues as comments.
Reads JSON results from pre-push-validator.py and formats as
GitHub-flavored markdown.

Usage:
    # Post results from latest pre-push validation
    python scripts/git-hooks/issue-reporter.py

    # Post specific results file
    python scripts/git-hooks/issue-reporter.py --results /path/to/results.json

    # Dry run (print without posting)
    python scripts/git-hooks/issue-reporter.py --dry-run

Requirements:
    - GitHub CLI (gh) must be installed
    - Results JSON from pre-push-validator.py
    - Issue # must be in commit message

Environment Variables:
    GH_TOKEN - GitHub personal access token (optional if gh is authenticated)
    REPORTER_DRY_RUN=1 - Dry run mode (print without posting)
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


# ============================================
# Configuration
# ============================================

PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_RESULTS_FILE = PROJECT_ROOT / ".git" / "pre-push-results.json"


# ============================================
# Data Models
# ============================================

@dataclass
class IssueComment:
    """GitHub Issue comment content."""
    issue_number: str
    markdown: str


# ============================================
# GitHub API Functions
# ============================================

def is_gh_installed() -> bool:
    """Check if GitHub CLI (gh) is installed."""
    try:
        result = subprocess.run(
            ["gh", "--version"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def post_comment(issue_number: str, markdown: str, dry_run: bool = False) -> bool:
    """
    Post comment to GitHub Issue.

    Args:
        issue_number: Issue number (without #)
        markdown: Comment content in markdown format
        dry_run: If True, print without posting

    Returns:
        True if successful, False otherwise
    """
    if dry_run or os.getenv("REPORTER_DRY_RUN") == "1":
        print("\n" + "=" * 60)
        print("DRY RUN MODE - Comment NOT posted")
        print("=" * 60)
        print(f"Issue: #{issue_number}")
        print("\nMarkdown Content:")
        print("-" * 60)
        print(markdown)
        print("-" * 60)
        return True

    if not is_gh_installed():
        print("❌ ERROR: GitHub CLI (gh) not installed")
        print("Install: https://cli.github.com/")
        return False

    try:
        result = subprocess.run(
            ["gh", "issue", "comment", issue_number, "--body", markdown],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT
        )

        if result.returncode == 0:
            print(f"✅ Comment posted to Issue #{issue_number}")
            return True
        else:
            print(f"❌ Failed to post comment: {result.stderr}")
            return False

    except Exception as e:
        print(f"❌ Exception posting comment: {e}")
        return False


# ============================================
# Markdown Formatting
# ============================================

def format_validation_table(validations: list[dict]) -> str:
    """
    Format validation results as markdown table.

    Args:
        validations: List of validation dictionaries

    Returns:
        Markdown table string
    """
    lines = [
        "| Validation | Status | Duration | Errors | Warnings |",
        "|------------|--------|----------|--------|----------|"
    ]

    for v in validations:
        status = "✅ PASS" if v["passed"] else "❌ FAIL"
        name = v["name"]
        duration = f"{v['duration_seconds']:.2f}s"
        errors = v.get("error_count", 0)
        warnings = v.get("warning_count", 0)

        lines.append(f"| {name} | {status} | {duration} | {errors} | {warnings} |")

    return "\n".join(lines)


def format_validation_details(validations: list[dict]) -> str:
    """
    Format detailed validation output as collapsible sections.

    Args:
        validations: List of validation dictionaries

    Returns:
        Markdown with collapsible details
    """
    sections = []

    for v in validations:
        name = v["name"]
        output = v.get("output", "").strip()

        if not output or output == f"Skipped (SKIP_{name.upper()}=1)":
            continue

        # Truncate very long output
        if len(output) > 5000:
            output = output[:5000] + "\n\n... (truncated)"

        sections.append(f"""
<details>
<summary><b>{name}</b> detailed output</summary>

```
{output}
```
</details>
""")

    return "\n".join(sections)


def generate_markdown(results: dict) -> str:
    """
    Generate GitHub-flavored markdown from results JSON.

    Args:
        results: Results dictionary from pre-push-validator.py

    Returns:
        Formatted markdown string
    """
    overall = "✅ **PASSED**" if results["overall_passed"] else "❌ **FAILED**"
    timestamp = results["timestamp"]
    commit = results["commit_hash"]
    duration = results["total_duration_seconds"]

    # Count totals
    total_errors = sum(v.get("error_count", 0) for v in results["validations"])
    total_warnings = sum(v.get("warning_count", 0) for v in results["validations"])

    markdown = f"""## 🚀 Pre-Push Validation Results

**Overall Status**: {overall}

### Summary
- **Commit**: `{commit}`
- **Timestamp**: {timestamp}
- **Total Duration**: {duration:.2f}s
- **Total Errors**: {total_errors}
- **Total Warnings**: {total_warnings}

### Validation Results

{format_validation_table(results["validations"])}

### Detailed Output

{format_validation_details(results["validations"])}

---
*Generated by TMWS Pre-Push Validator (Issue #55 Phase 2)*
*See: `scripts/git-hooks/pre-push-validator.py`*
"""

    return markdown


# ============================================
# Main Execution
# ============================================

def load_results(results_path: Path) -> Optional[dict]:
    """
    Load validation results from JSON file.

    Args:
        results_path: Path to results JSON

    Returns:
        Results dictionary or None if not found
    """
    if not results_path.exists():
        print(f"❌ Results file not found: {results_path}")
        return None

    try:
        with open(results_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error loading results: {e}")
        return None


def main() -> int:
    """
    Main execution.

    Returns:
        Exit code (0=success, 1=failure)
    """
    parser = argparse.ArgumentParser(
        description="Post pre-push validation results to GitHub Issues"
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=DEFAULT_RESULTS_FILE,
        help="Path to results JSON file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print markdown without posting"
    )

    args = parser.parse_args()

    print("📋 TMWS Issue Reporter (Issue #55 Phase 2)")

    # Load results
    results = load_results(args.results)
    if not results:
        return 1

    # Check for Issue #
    issue_number = results.get("issue_number")
    if not issue_number:
        print("⚠️  No Issue # found in commit message - skipping report")
        print("Tip: Include 'Fixes #123' in commit message")
        return 0

    print(f"📌 Target Issue: #{issue_number}")

    # Generate markdown
    markdown = generate_markdown(results)

    # Post comment
    success = post_comment(issue_number, markdown, dry_run=args.dry_run)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
