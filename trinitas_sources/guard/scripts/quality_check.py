#!/usr/bin/env python3
"""
Trinitas Quality Guardian - Comprehensive Quality Check Script
Coordinates all agents for holistic code quality assessment
"""

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

# Add project root to path for imports
_script_dir = Path(__file__).resolve().parent
_project_root = _script_dir.parent.parent.parent  # trinitas-agents/
sys.path.insert(0, str(_project_root))

from shared.utils import JSONLoader, SecureFileLoader

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("TrinityGuardian")

# Quality thresholds
DOCSTRING_COVERAGE_THRESHOLD = 70  # Minimum percentage of files with docstrings


class QualityGuardian:
    """
    Main coordinator for quality checks across all Trinitas agents
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: dict[str, Any] = {}
        self.project_root = self._find_project_root()

        # Initialize secure file loader
        self.file_loader = SecureFileLoader(
            allowed_roots=[self.project_root],
            allowed_extensions=[".py", ".md", ".json", ".txt", ".rst"]
        )

        # Initialize JSON loader
        self.json_loader = JSONLoader()

    def _find_project_root(self) -> Path:
        """Find project root by looking for key files"""
        current = Path.cwd()
        markers = ["pyproject.toml", "setup.py", ".git", "requirements.txt"]

        while current != current.parent:
            if any((current / marker).exists() for marker in markers):
                return current
            current = current.parent

        return Path.cwd()

    def _discover_python_files(self) -> list[Path]:
        """
        Securely discover all Python files in the project.
        Excludes venv and __pycache__ directories.
        """
        py_files = []
        try:
            # Use pathlib's glob but validate each result
            for py_file in self.project_root.glob("**/*.py"):
                # Skip virtual environments and cache directories
                if "venv" in str(py_file) or "__pycache__" in str(py_file):
                    continue

                # Validate the path is within allowed roots
                try:
                    self.file_loader.validate_path(py_file)
                    py_files.append(py_file)
                except ValueError:
                    # Path is outside allowed roots, skip it
                    if self.verbose:
                        logger.warning(f"Skipping file outside allowed roots: {py_file}")
                    continue

        except Exception as e:
            logger.exception(f"Error discovering Python files: {e}")

        return py_files

    def run_artemis_checks(self) -> tuple[bool, dict]:
        """
        Artemis: Technical quality checks
        """
        logger.info("🏹 Artemis: Starting technical quality analysis...")
        artemis_results = {
            "ruff_lint": False,
            "ruff_format": False,
            "complexity": False,
            "type_hints": False,
            "messages": [],
        }

        # Ruff linting
        try:
            result = subprocess.run(
                ["ruff", "check", ".", "--output-format", "json"],
                check=False, capture_output=True,
                text=True,
                cwd=self.project_root,
            )

            if result.returncode == 0:
                artemis_results["ruff_lint"] = True
                artemis_results["messages"].append("✅ Code linting passed")
            else:
                issues = json.loads(result.stdout) if result.stdout else []
                artemis_results["messages"].append(
                    f"⚠️ Found {len(issues)} linting issues"
                )
                if self.verbose and issues:
                    for issue in issues[:5]:  # Show first 5 issues
                        artemis_results["messages"].append(
                            f"  - {issue.get('filename')}:{issue.get('location', {}).get('row')}: {issue.get('message')}"
                        )
        except (FileNotFoundError, PermissionError) as e:
            artemis_results["messages"].append(
                f"❌ Linting failed - file access: {e!s}"
            )
        except (json.JSONDecodeError, ValueError) as e:
            artemis_results["messages"].append(
                f"❌ Linting failed - data error: {e!s}"
            )
        except (OSError, subprocess.SubprocessError) as e:
            artemis_results["messages"].append(
                f"❌ Linting failed - process error: {e!s}"
            )

        # Ruff formatting check
        try:
            result = subprocess.run(
                ["ruff", "format", "--check", "."],
                check=False, capture_output=True,
                text=True,
                cwd=self.project_root,
            )

            if result.returncode == 0:
                artemis_results["ruff_format"] = True
                artemis_results["messages"].append("✅ Code formatting is consistent")
            else:
                artemis_results["messages"].append("⚠️ Code formatting issues detected")
        except (FileNotFoundError, PermissionError) as e:
            artemis_results["messages"].append(
                f"❌ Format check failed - file access: {e!s}"
            )
        except (OSError, subprocess.SubprocessError) as e:
            artemis_results["messages"].append(
                f"❌ Format check failed - process error: {e!s}"
            )

        # Complexity check
        try:
            result = subprocess.run(
                ["ruff", "check", ".", "--select", "C90", "--output-format", "json"],
                check=False, capture_output=True,
                text=True,
                cwd=self.project_root,
            )

            if result.returncode == 0:
                artemis_results["complexity"] = True
                artemis_results["messages"].append("✅ Code complexity is acceptable")
            else:
                artemis_results["messages"].append("⚠️ Complex code detected")
        except (FileNotFoundError, PermissionError) as e:
            artemis_results["messages"].append(
                f"❌ Complexity check failed - file access: {e!s}"
            )
        except (OSError, subprocess.SubprocessError) as e:
            artemis_results["messages"].append(
                f"❌ Complexity check failed - process error: {e!s}"
            )

        return all(
            [artemis_results["ruff_lint"], artemis_results["ruff_format"]]
        ), artemis_results

    def run_hestia_checks(self) -> tuple[bool, dict]:
        """
        Hestia: Security checks
        """
        logger.info("🔥 Hestia: Starting security analysis...")
        hestia_results = {
            "security_scan": False,
            "secrets_check": False,
            "dependencies": False,
            "messages": [],
        }

        # Check for common security issues
        security_patterns = [
            ("eval(", "Use of eval() detected - security risk"),
            ("exec(", "Use of exec() detected - security risk"),
            ("__import__", "Dynamic import detected - review needed"),
            ("pickle.loads", "Pickle deserialization - potential security risk"),
            ("subprocess.shell=True", "Shell injection risk detected"),
        ]

        py_files = self._discover_python_files()
        security_issues = []

        for py_file in py_files:
            try:
                content = self.file_loader.load_file(py_file, silent=False)
                for pattern, message in security_patterns:
                    if pattern in content:
                        security_issues.append(
                            f"{py_file.relative_to(self.project_root)}: {message}"
                        )
            except (FileNotFoundError, PermissionError, UnicodeDecodeError):
                pass  # Skip files that can't be read

        if not security_issues:
            hestia_results["security_scan"] = True
            hestia_results["messages"].append("✅ No obvious security issues detected")
        else:
            hestia_results["messages"].append(
                f"⚠️ Found {len(security_issues)} security concerns"
            )
            if self.verbose:
                for issue in security_issues[:5]:
                    hestia_results["messages"].append(f"  - {issue}")

        # Check for hardcoded secrets
        secret_patterns = [
            (r'["\'][\w]{20,}["\']', "Possible hardcoded token"),
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password detected"),
            (r'api_key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key detected"),
        ]

        import re

        secret_issues = []

        for py_file in py_files:
            # Skip test files
            if "test" in str(py_file).lower():
                continue

            try:
                content = self.file_loader.load_file(py_file, silent=False)
                for pattern, message in secret_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        secret_issues.append(
                            f"{py_file.relative_to(self.project_root)}: {message}"
                        )
            except (FileNotFoundError, PermissionError, UnicodeDecodeError):
                pass  # Skip files that can't be read

        if not secret_issues:
            hestia_results["secrets_check"] = True
            hestia_results["messages"].append("✅ No hardcoded secrets detected")
        else:
            hestia_results["messages"].append(
                f"⚠️ Possible secrets found: {len(secret_issues)}"
            )

        return hestia_results["security_scan"] and hestia_results[
            "secrets_check"
        ], hestia_results

    def run_muses_checks(self) -> tuple[bool, dict]:
        """
        Muses: Documentation checks
        """
        logger.info("📚 Muses: Checking documentation...")
        muses_results = {"readme_exists": False, "docstrings": False, "messages": []}

        # Check for README
        readme_files = ["README.md", "README.rst", "README.txt"]
        readme_exists = any((self.project_root / f).exists() for f in readme_files)

        if readme_exists:
            muses_results["readme_exists"] = True
            muses_results["messages"].append("✅ README file exists")
        else:
            muses_results["messages"].append("❌ No README file found")

        # Check for docstrings in Python files
        py_files = self._discover_python_files()
        files_with_docstrings = 0
        files_without_docstrings = 0

        for py_file in py_files:
            try:
                content = self.file_loader.load_file(py_file, silent=False)
                if '"""' in content or "'''" in content:
                    files_with_docstrings += 1
                else:
                    files_without_docstrings += 1
            except (FileNotFoundError, PermissionError, UnicodeDecodeError):
                pass  # Skip files that can't be read

        total_files = files_with_docstrings + files_without_docstrings
        if total_files > 0:
            doc_percentage = (files_with_docstrings / total_files) * 100
            if doc_percentage >= DOCSTRING_COVERAGE_THRESHOLD:
                muses_results["docstrings"] = True
                muses_results["messages"].append(
                    f"✅ Good documentation coverage: {doc_percentage:.1f}%"
                )
            else:
                muses_results["messages"].append(
                    f"⚠️ Low documentation coverage: {doc_percentage:.1f}%"
                )

        return muses_results["readme_exists"], muses_results

    def run_eris_checks(self) -> tuple[bool, dict]:
        """
        Eris: Coordination and consistency checks
        """
        logger.info("⚔️ Eris: Checking project consistency...")
        eris_results = {"structure": False, "naming": False, "messages": []}

        # Check project structure
        expected_dirs = ["tests", "docs"]
        missing_dirs = []

        for dir_name in expected_dirs:
            if not (self.project_root / dir_name).exists():
                missing_dirs.append(dir_name)

        if not missing_dirs:
            eris_results["structure"] = True
            eris_results["messages"].append("✅ Project structure is complete")
        else:
            eris_results["messages"].append(
                f"⚠️ Missing directories: {', '.join(missing_dirs)}"
            )

        # Check naming consistency
        py_files = self._discover_python_files()
        naming_issues = []

        for py_file in py_files:
            # Check for consistent naming (snake_case for files)
            if not py_file.stem.replace("_", "").replace("-", "").isalnum():
                naming_issues.append(str(py_file.relative_to(self.project_root)))

        if not naming_issues:
            eris_results["naming"] = True
            eris_results["messages"].append("✅ Naming conventions are consistent")
        else:
            eris_results["messages"].append(
                f"⚠️ Naming issues in {len(naming_issues)} files"
            )

        return eris_results["structure"], eris_results

    def generate_report(self) -> str:
        """
        Generate comprehensive quality report
        """
        report = []
        report.append("\n" + "=" * 60)
        report.append("🏛️ TRINITAS QUALITY GUARDIAN REPORT")
        report.append("=" * 60)

        # Run all checks
        artemis_pass, artemis_results = self.run_artemis_checks()
        hestia_pass, hestia_results = self.run_hestia_checks()
        muses_pass, muses_results = self.run_muses_checks()
        eris_pass, eris_results = self.run_eris_checks()

        # Artemis report
        report.append("\n🏹 ARTEMIS - Technical Excellence")
        report.append("-" * 40)
        for msg in artemis_results["messages"]:
            report.append(msg)

        # Hestia report
        report.append("\n🔥 HESTIA - Security Guardian")
        report.append("-" * 40)
        for msg in hestia_results["messages"]:
            report.append(msg)

        # Muses report
        report.append("\n📚 MUSES - Documentation Keeper")
        report.append("-" * 40)
        for msg in muses_results["messages"]:
            report.append(msg)

        # Eris report
        report.append("\n⚔️ ERIS - Coordination Master")
        report.append("-" * 40)
        for msg in eris_results["messages"]:
            report.append(msg)

        # Final verdict
        report.append("\n" + "=" * 60)
        report.append("🏛️ ATHENA'S FINAL VERDICT")
        report.append("=" * 60)

        all_pass = all([artemis_pass, hestia_pass, muses_pass, eris_pass])

        if all_pass:
            report.append("✅ **QUALITY GATE: PASSED**")
            report.append("Your code meets Trinitas quality standards!")
        else:
            report.append("❌ **QUALITY GATE: FAILED**")
            report.append("Please address the issues above before proceeding.")

        # Store results for external use
        self.results = {
            "passed": all_pass,
            "artemis": artemis_results,
            "hestia": hestia_results,
            "muses": muses_results,
            "eris": eris_results,
        }

        return "\n".join(report)

    def save_report(self, filepath: Path):
        """Save report to file"""
        report = self.generate_report()

        # Validate output path is within allowed roots
        try:
            self.file_loader.validate_path(filepath)
        except ValueError as e:
            logger.exception(f"Invalid output path: {e}")
            raise

        # Write text report securely
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_text(report, encoding="utf-8")
            logger.info(f"Report saved to {filepath}")
        except Exception as e:
            logger.exception(f"Failed to write report: {e}")
            raise

        # Also save JSON results
        json_path = filepath.with_suffix(".json")
        try:
            self.file_loader.validate_path(json_path)
            self.json_loader.dump(self.results, json_path, indent=2, sort_keys=False)
            logger.info(f"JSON results saved to {json_path}")
        except Exception as e:
            logger.exception(f"Failed to write JSON results: {e}")
            raise


def main():
    parser = argparse.ArgumentParser(
        description="Trinitas Quality Guardian - Comprehensive code quality check"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument("-o", "--output", type=Path, help="Save report to file")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument(
        "files",
        nargs="*",
        help="Files to check (if not specified, checks entire project)",
    )

    args = parser.parse_args()

    # Create and run guardian
    guardian = QualityGuardian(verbose=args.verbose)

    if args.json:
        # Generate report silently and output JSON
        guardian.generate_report()
        print(json.dumps(guardian.results, indent=2))
    else:
        # Generate and display report
        report = guardian.generate_report()
        print(report)

        # Save if requested
        if args.output:
            guardian.save_report(args.output)
            logger.info(f"Report saved to {args.output}")

    # Exit with appropriate code
    sys.exit(0 if guardian.results.get("passed", False) else 1)


if __name__ == "__main__":
    main()
