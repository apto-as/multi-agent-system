#!/usr/bin/env python3
"""
TMWS Test Suite Runner
Orchestrated by Athena with harmonious team coordination

This script provides a unified interface to run the comprehensive test suite
with proper environment setup, quality gate validation, and result reporting.
"""

import os
import sys
import subprocess
import time
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Color codes for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class TestRunner:
    """Comprehensive test runner with quality gate validation."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.start_time = datetime.now()
        self.results = {
            "unit": None,
            "integration": None, 
            "security": None,
            "performance": None,
            "e2e": None,
            "coverage": None
        }
        
    def print_header(self, title: str, color: str = Colors.CYAN):
        """Print formatted header."""
        print(f"\n{color}{Colors.BOLD}{'='*80}")
        print(f"{title.center(80)}")
        print(f"{'='*80}{Colors.END}\n")
    
    def print_status(self, message: str, status: str):
        """Print status message with color coding."""
        if status == "PASS":
            color = Colors.GREEN
            symbol = "✅"
        elif status == "FAIL":
            color = Colors.RED
            symbol = "❌"
        elif status == "WARN":
            color = Colors.YELLOW
            symbol = "⚠️"
        else:
            color = Colors.WHITE
            symbol = "ℹ️"
            
        print(f"{symbol} {color}{message}{Colors.END}")
    
    def setup_environment(self):
        """Setup test environment."""
        self.print_header("Environment Setup (Eris Coordination)", Colors.PURPLE)
        
        required_vars = {
            "TMWS_ENVIRONMENT": "test",
            "TMWS_SECRET_KEY": "test_secret_key_for_comprehensive_testing_suite_validation",
            "TMWS_AUTH_ENABLED": "true"
        }
        
        for var, default_value in required_vars.items():
            if var not in os.environ:
                os.environ[var] = default_value
                self.print_status(f"Set {var}={default_value}", "INFO")
        
        # Check database setup
        db_url = os.environ.get("TMWS_DATABASE_URL")
        if not db_url:
            if self.check_postgres():
                os.environ["TMWS_DATABASE_URL"] = "postgresql://postgres:postgres@localhost:5432/tmws_test"
                self.print_status("Using PostgreSQL test database", "PASS")
            else:
                os.environ["TMWS_DATABASE_URL"] = "sqlite:///./test.db"
                self.print_status("Using SQLite test database", "WARN")
        
        # Run migrations
        try:
            result = subprocess.run(
                ["python", "-m", "alembic", "upgrade", "head"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.print_status("Database migrations completed", "PASS")
            else:
                self.print_status("Database migration failed", "FAIL")
                print(result.stderr)
        except Exception as e:
            self.print_status(f"Migration error: {e}", "FAIL")
    
    def check_postgres(self) -> bool:
        """Check if PostgreSQL is available."""
        try:
            result = subprocess.run(
                ["pg_isready", "-h", "localhost", "-p", "5432"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def run_test_category(self, category: str, args: List[str] = None) -> Tuple[bool, Dict]:
        """Run a specific test category."""
        if args is None:
            args = []
        
        # Test category configurations
        test_configs = {
            "unit": {
                "path": "tests/unit/",
                "marker": "unit",
                "timeout": 300,
                "description": "Unit Tests (Artemis Technical Excellence)"
            },
            "integration": {
                "path": "tests/integration/",  
                "marker": "integration",
                "timeout": 600,
                "description": "Integration Tests (Eris Coordination)"
            },
            "security": {
                "path": "tests/security/",
                "marker": "security", 
                "timeout": 900,
                "description": "Security Tests (Hestia Guardian)"
            },
            "performance": {
                "path": "tests/",
                "marker": "performance",
                "timeout": 1200,
                "description": "Performance Tests (Artemis/Hera Validation)"
            },
            "e2e": {
                "path": "tests/e2e/",
                "marker": "e2e",
                "timeout": 1800,
                "description": "End-to-End Tests (Hera Strategic Validation)"
            }
        }
        
        if category not in test_configs:
            self.print_status(f"Unknown test category: {category}", "FAIL")
            return False, {}
        
        config = test_configs[category]
        self.print_header(config["description"], Colors.BLUE)
        
        # Build pytest command
        cmd = [
            "python", "-m", "pytest",
            config["path"],
            "-v",
            "-m", config["marker"],
            f"--timeout={config['timeout']}",
            f"--junitxml={category}-junit.xml",
            f"--html={category}-report.html",
            "--self-contained-html"
        ]
        
        # Add coverage for unit and integration tests
        if category in ["unit", "integration"]:
            cmd.extend([
                "--cov=src",
                f"--cov-report=xml:{category}-coverage.xml",
                "--cov-report=term-missing"
            ])
        
        cmd.extend(args)
        
        print(f"Command: {' '.join(cmd)}")
        
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                text=True
            )
            
            duration = time.time() - start_time
            success = result.returncode == 0
            
            status = "PASS" if success else "FAIL"
            self.print_status(f"{config['description']} completed in {duration:.1f}s", status)
            
            # Parse results
            results = {
                "success": success,
                "duration": duration,
                "return_code": result.returncode
            }
            
            # Try to parse JUnit XML for detailed results
            junit_file = self.project_root / f"{category}-junit.xml"
            if junit_file.exists():
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(junit_file)
                    testsuite = tree.getroot().find('testsuite')
                    if testsuite is not None:
                        results.update({
                            "tests": int(testsuite.get('tests', 0)),
                            "failures": int(testsuite.get('failures', 0)),
                            "errors": int(testsuite.get('errors', 0)),
                            "skipped": int(testsuite.get('skipped', 0))
                        })
                except Exception as e:
                    self.print_status(f"Failed to parse JUnit results: {e}", "WARN")
            
            return success, results
            
        except Exception as e:
            self.print_status(f"Test execution failed: {e}", "FAIL")
            return False, {"success": False, "error": str(e)}
    
    def analyze_coverage(self):
        """Analyze code coverage from test results."""
        self.print_header("Coverage Analysis (Muses Knowledge)", Colors.CYAN)
        
        coverage_files = []
        for category in ["unit", "integration"]:
            coverage_file = self.project_root / f"{category}-coverage.xml"
            if coverage_file.exists():
                coverage_files.append(str(coverage_file))
        
        if not coverage_files:
            self.print_status("No coverage files found", "WARN")
            return False, {"overall": 0, "critical_paths": 0}
        
        try:
            # Use coverage.py to combine and analyze
            import coverage
            
            cov = coverage.Coverage()
            cov.load()
            
            # Generate combined report
            subprocess.run([
                "python", "-m", "coverage", "combine"
            ], cwd=self.project_root, capture_output=True)
            
            subprocess.run([
                "python", "-m", "coverage", "report", "--show-missing"
            ], cwd=self.project_root)
            
            subprocess.run([
                "python", "-m", "coverage", "html", "-d", "htmlcov"
            ], cwd=self.project_root, capture_output=True)
            
            # Get coverage percentage
            result = subprocess.run([
                "python", "-m", "coverage", "report", "--format=total"
            ], cwd=self.project_root, capture_output=True, text=True)
            
            if result.returncode == 0:
                overall_coverage = float(result.stdout.strip())
                self.print_status(f"Overall coverage: {overall_coverage:.1f}%", 
                                 "PASS" if overall_coverage >= 90 else "WARN")
                
                return overall_coverage >= 90, {
                    "overall": overall_coverage,
                    "critical_paths": overall_coverage  # Simplified for now
                }
            else:
                self.print_status("Failed to get coverage report", "FAIL")
                return False, {"overall": 0, "critical_paths": 0}
                
        except ImportError:
            self.print_status("Coverage package not available", "WARN")
            return True, {"overall": 0, "critical_paths": 0}
        except Exception as e:
            self.print_status(f"Coverage analysis failed: {e}", "FAIL")
            return False, {"overall": 0, "critical_paths": 0}
    
    def validate_quality_gates(self) -> bool:
        """Validate all quality gates for deployment readiness."""
        self.print_header("Quality Gates Validation (Athena Harmony)", Colors.GREEN)
        
        gates = {
            "security_tests": self.results["security"] and self.results["security"]["success"],
            "unit_tests": self.results["unit"] and self.results["unit"]["success"], 
            "integration_tests": self.results["integration"] and self.results["integration"]["success"],
            "performance_tests": self.results["performance"] and self.results["performance"]["success"],
            "e2e_tests": self.results["e2e"] and self.results["e2e"]["success"],
            "code_coverage": self.results["coverage"] and self.results["coverage"]["success"]
        }
        
        passed_gates = sum(1 for gate in gates.values() if gate)
        total_gates = len(gates)
        success_rate = (passed_gates / total_gates) * 100
        
        print(f"\n{Colors.BOLD}Quality Gates Summary:{Colors.END}")
        for gate_name, passed in gates.items():
            status = "PASS" if passed else "FAIL"
            self.print_status(f"{gate_name.replace('_', ' ').title()}", status)
        
        print(f"\n{Colors.BOLD}Overall Score: {success_rate:.1f}% ({passed_gates}/{total_gates}){Colors.END}")
        
        # Quality gate decision
        deployment_ready = success_rate >= 80 and gates.get("security_tests", False)
        
        if deployment_ready:
            self.print_status("DEPLOYMENT APPROVED - Ready for production!", "PASS")
        else:
            self.print_status("DEPLOYMENT BLOCKED - Quality gates not met", "FAIL")
        
        return deployment_ready
    
    def generate_report(self):
        """Generate comprehensive test report."""
        self.print_header("Test Report Generation (Muses Documentation)", Colors.PURPLE)
        
        end_time = datetime.now()
        total_duration = (end_time - self.start_time).total_seconds()
        
        report = {
            "test_suite": "TMWS Phase 1 Implementation",
            "generated_at": end_time.isoformat(),
            "duration_seconds": total_duration,
            "results": self.results,
            "environment": {
                "python_version": sys.version,
                "platform": sys.platform,
                "database_url": os.environ.get("TMWS_DATABASE_URL", "not_set")
            }
        }
        
        # Write report to file
        report_file = self.project_root / "test_execution_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.print_status(f"Test report saved to {report_file}", "PASS")
        
        # Print summary
        print(f"\n{Colors.BOLD}{Colors.CYAN}Test Execution Summary{Colors.END}")
        print(f"Total Duration: {total_duration:.1f} seconds")
        print(f"Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"End Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        return report
    
    def run_full_suite(self, categories: List[str] = None, extra_args: List[str] = None):
        """Run the complete test suite."""
        if categories is None:
            categories = ["unit", "integration", "security", "performance", "e2e"]
        
        if extra_args is None:
            extra_args = []
        
        self.print_header("TMWS Phase 1 Test Suite Execution", Colors.GREEN)
        print(f"{Colors.BOLD}Trinitas Team Coordination:{Colors.END}")
        print(f"🏛️  Athena: Harmonious test orchestration")
        print(f"🏹 Artemis: Technical excellence and performance")
        print(f"🔥 Hestia: Security and vulnerability testing")
        print(f"⚔️  Eris: Integration and coordination")
        print(f"🎭 Hera: Strategic validation and E2E testing")
        print(f"📚 Muses: Documentation and reporting")
        
        # Setup environment
        self.setup_environment()
        
        # Run test categories
        success_count = 0
        for category in categories:
            success, results = self.run_test_category(category, extra_args)
            self.results[category] = results
            if success:
                success_count += 1
        
        # Analyze coverage
        coverage_success, coverage_data = self.analyze_coverage()
        self.results["coverage"] = {
            "success": coverage_success,
            **coverage_data
        }
        if coverage_success:
            success_count += 1
        
        # Validate quality gates
        deployment_ready = self.validate_quality_gates()
        
        # Generate report
        self.generate_report()
        
        # Final status
        total_categories = len(categories) + 1  # +1 for coverage
        success_rate = (success_count / total_categories) * 100
        
        self.print_header("Final Results", Colors.BOLD)
        
        if deployment_ready:
            print(f"{Colors.GREEN}{Colors.BOLD}🎉 SUCCESS: TMWS Phase 1 is ready for deployment!{Colors.END}")
            print(f"Quality Score: {success_rate:.1f}%")
            print(f"All critical requirements met.")
        else:
            print(f"{Colors.RED}{Colors.BOLD}❌ FAILURE: Quality gates not met{Colors.END}")
            print(f"Quality Score: {success_rate:.1f}%")
            print(f"Please address failing tests before deployment.")
        
        return deployment_ready


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="TMWS Comprehensive Test Suite Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Test Categories:
  unit          Unit tests for core services (Artemis)
  integration   API integration tests (Eris)
  security      Security and vulnerability tests (Hestia)
  performance   Performance and load tests (Artemis/Hera)
  e2e           End-to-end workflow tests (Hera)

Examples:
  python scripts/test-runner.py                    # Run full suite
  python scripts/test-runner.py --category unit    # Run unit tests only
  python scripts/test-runner.py --security-only    # Run security tests only
  python scripts/test-runner.py --fast             # Run fast tests only
        """
    )
    
    parser.add_argument(
        "--category", "-c",
        choices=["unit", "integration", "security", "performance", "e2e"],
        action="append",
        help="Run specific test categories (can be used multiple times)"
    )
    
    parser.add_argument(
        "--security-only", 
        action="store_true",
        help="Run only security tests (Hestia focus)"
    )
    
    parser.add_argument(
        "--fast",
        action="store_true", 
        help="Run only fast tests (exclude slow marker)"
    )
    
    parser.add_argument(
        "--coverage-only",
        action="store_true",
        help="Run tests required for coverage analysis"
    )
    
    parser.add_argument(
        "--parallel", "-j",
        type=int,
        default=1,
        help="Run tests in parallel (number of workers)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Increase output verbosity"
    )
    
    args = parser.parse_args()
    
    # Build test categories list
    categories = []
    if args.security_only:
        categories = ["security"]
    elif args.coverage_only:
        categories = ["unit", "integration"]
    elif args.category:
        categories = args.category
    else:
        categories = ["unit", "integration", "security", "performance", "e2e"]
    
    # Build extra pytest args
    extra_args = []
    if args.fast:
        extra_args.extend(["-m", "not slow"])
    
    if args.parallel > 1:
        extra_args.extend(["-n", str(args.parallel)])
    
    if args.verbose:
        extra_args.append("-vv")
    
    # Run test suite
    runner = TestRunner()
    success = runner.run_full_suite(categories, extra_args)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()