#!/usr/bin/env python3
"""
Artemis Technical Analysis Verification Script v2.0

Purpose: Prevent future analysis failures by enforcing measurement-first protocol.

Usage:
    python scripts/artemis_verify_analysis.py tests/security/test_cross_agent_access.py
"""

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple


class AnalysisVerifier:
    """技術分析の検証を自動化"""

    def __init__(self, target_path: str):
        self.target = Path(target_path)
        self.results: Dict[str, bool] = {}
        self.evidence: Dict[str, str] = {}

    def verify_file_exists(self) -> bool:
        """Phase 1: ファイルの実在確認"""
        exists = self.target.exists()
        self.results["file_exists"] = exists
        self.evidence["file_exists"] = f"File found: {self.target}" if exists else "File NOT found"
        return exists

    def verify_syntax(self) -> bool:
        """Phase 2: Python構文チェック"""
        try:
            result = subprocess.run(
                ["python", "-m", "py_compile", str(self.target)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            success = result.returncode == 0
            self.results["syntax_valid"] = success
            self.evidence["syntax_valid"] = result.stderr if result.stderr else "✅ No syntax errors"
            return success
        except Exception as e:
            self.results["syntax_valid"] = False
            self.evidence["syntax_valid"] = f"❌ Error: {e}"
            return False

    def verify_imports(self) -> bool:
        """Phase 3: Import検証"""
        try:
            # Check if imports are valid by attempting to import
            result = subprocess.run(
                ["python", "-c", f"import sys; sys.path.insert(0, '.'); exec(open('{self.target}').read())"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            success = result.returncode == 0
            self.results["imports_valid"] = success
            self.evidence["imports_valid"] = result.stderr if result.stderr else "✅ All imports successful"
            return success
        except Exception as e:
            self.results["imports_valid"] = False
            self.evidence["imports_valid"] = f"❌ Error: {e}"
            return False

    def verify_test_discovery(self) -> Tuple[bool, int]:
        """Phase 4: Pytestテスト発見"""
        try:
            result = subprocess.run(
                ["pytest", "--collect-only", "-q", str(self.target)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Count collected tests
            lines = result.stdout.split("\n")
            test_count = 0
            for line in lines:
                if "test" in line.lower() and "<Function" in line:
                    test_count += 1

            success = result.returncode == 0 and test_count > 0
            self.results["tests_discoverable"] = success
            self.evidence["tests_discoverable"] = (
                f"✅ {test_count} tests discovered" if success else f"❌ Discovery failed: {result.stderr}"
            )
            return success, test_count
        except Exception as e:
            self.results["tests_discoverable"] = False
            self.evidence["tests_discoverable"] = f"❌ Error: {e}"
            return False, 0

    def verify_test_execution(self) -> Tuple[bool, Dict[str, int]]:
        """Phase 5: テスト実行"""
        try:
            result = subprocess.run(
                ["pytest", str(self.target), "-v", "--tb=short"],
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Parse results
            stats = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
            for line in result.stdout.split("\n"):
                if " PASSED" in line:
                    stats["passed"] += 1
                elif " FAILED" in line:
                    stats["failed"] += 1
                elif " ERROR" in line:
                    stats["errors"] += 1
                elif " SKIPPED" in line:
                    stats["skipped"] += 1

            success = stats["failed"] == 0 and stats["errors"] == 0 and stats["passed"] > 0
            self.results["tests_pass"] = success
            self.evidence["tests_pass"] = (
                f"✅ {stats['passed']} PASSED, {stats['failed']} FAILED, {stats['errors']} ERRORS"
            )
            return success, stats
        except Exception as e:
            self.results["tests_pass"] = False
            self.evidence["tests_pass"] = f"❌ Error: {e}"
            return False, {}

    def verify_static_analysis(self) -> bool:
        """Phase 6: 静的解析（Ruff）"""
        try:
            result = subprocess.run(
                ["ruff", "check", str(self.target)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Ruff returns 0 if no issues, 1 if issues found
            success = result.returncode == 0
            self.results["static_analysis"] = success
            self.evidence["static_analysis"] = result.stdout if result.stdout else "✅ No issues found"
            return success
        except FileNotFoundError:
            self.results["static_analysis"] = None
            self.evidence["static_analysis"] = "⚠️  Ruff not installed"
            return True  # Don't fail if tool missing
        except Exception as e:
            self.results["static_analysis"] = False
            self.evidence["static_analysis"] = f"❌ Error: {e}"
            return False

    def generate_report(self) -> str:
        """検証レポート生成"""
        report = f"""
{'='*80}
Artemis Technical Analysis Verification Report
{'='*80}
Target: {self.target}

VERIFICATION RESULTS:
"""
        for check, result in self.results.items():
            status = "✅ PASS" if result else "❌ FAIL" if result is False else "⚠️  SKIP"
            report += f"\n{status:12} {check:25} | {self.evidence[check]}"

        # Overall assessment
        all_critical_passed = all(
            self.results.get(k, False) for k in ["file_exists", "syntax_valid", "tests_discoverable"]
        )

        report += f"""

{'='*80}
OVERALL ASSESSMENT:
{'='*80}
Critical Checks: {'✅ ALL PASSED' if all_critical_passed else '❌ SOME FAILED'}

Recommendation:
"""
        if all_critical_passed and self.results.get("tests_pass", False):
            report += "✅ Target is verified. Analysis can proceed with confidence.\n"
        else:
            report += "❌ Target has issues. Fix before analysis.\n"

        return report

    def run_full_verification(self) -> bool:
        """完全検証の実行"""
        print("Starting Artemis Technical Analysis Verification...")
        print(f"Target: {self.target}\n")

        # Phase 1: File exists
        if not self.verify_file_exists():
            print("❌ File not found. Aborting.")
            return False

        # Phase 2: Syntax
        self.verify_syntax()

        # Phase 3: Imports
        self.verify_imports()

        # Phase 4: Test discovery
        self.verify_test_discovery()

        # Phase 5: Test execution
        self.verify_test_execution()

        # Phase 6: Static analysis
        self.verify_static_analysis()

        # Generate and print report
        report = self.generate_report()
        print(report)

        # Save report
        report_path = Path("analysis_verification_report.txt")
        report_path.write_text(report)
        print(f"\n📄 Report saved: {report_path}")

        # Return success if all critical checks passed
        return all(
            self.results.get(k, False) for k in ["file_exists", "syntax_valid", "tests_discoverable"]
        )


def main():
    parser = argparse.ArgumentParser(description="Artemis Technical Analysis Verification Script v2.0")
    parser.add_argument("target", help="Path to file to verify (e.g., tests/security/test_cross_agent_access.py)")
    parser.add_argument("--strict", action="store_true", help="Fail if any check fails (including static analysis)")

    args = parser.parse_args()

    verifier = AnalysisVerifier(args.target)
    success = verifier.run_full_verification()

    if args.strict:
        success = all(verifier.results.values())

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
