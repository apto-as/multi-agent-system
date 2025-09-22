"""
Test Configuration and Utilities for TMWS Test Suite.
Led by Muses (Knowledge Architect) with focus on comprehensive test organization.

This module provides:
- Test configuration management
- Test data factories and builders  
- Common test utilities and helpers
- Test result collection and reporting
- Coverage analysis tools
- CI/CD integration helpers

Documentation Standards:
- All test modules properly documented
- Test coverage reports generated
- Performance benchmarks tracked
- Security test results archived
"""

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class TestCategory(Enum):
    """Test categories for organization and reporting."""
    UNIT = "unit"
    INTEGRATION = "integration"
    SECURITY = "security"
    PERFORMANCE = "performance"
    E2E = "e2e"


class TestResult(Enum):
    """Test result outcomes."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class TestMetrics:
    """Test execution metrics."""
    test_name: str
    category: TestCategory
    duration_ms: float
    result: TestResult
    error_message: str | None = None
    coverage_percentage: float | None = None
    memory_usage_mb: float | None = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class SecurityTestResult:
    """Security test specific results."""
    test_name: str
    vulnerability_type: str
    risk_level: str  # low, medium, high, critical
    result: TestResult
    details: str
    remediation: str | None = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class PerformanceTestResult:
    """Performance test specific results."""
    test_name: str
    operation: str
    avg_time_ms: float
    max_time_ms: float
    min_time_ms: float
    iterations: int
    requirement_ms: float
    passed: bool
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class TestDataFactory:
    """Factory for creating test data objects."""

    @staticmethod
    def create_user_data(
        username: str = "testuser",
        email: str = "test@example.com",
        password: str = "secure_password_123",
        **kwargs
    ) -> dict[str, Any]:
        """Create user data for testing."""
        default_data = {
            "username": username,
            "email": email,
            "password": password,
            "full_name": f"Test User {username}",
            "agent_namespace": "test",
            "roles": ["user"]
        }
        default_data.update(kwargs)
        return default_data

    @staticmethod
    def create_api_key_data(
        name: str = "Test API Key",
        scopes: list[str] = None,
        **kwargs
    ) -> dict[str, Any]:
        """Create API key data for testing."""
        if scopes is None:
            scopes = ["read", "write"]

        default_data = {
            "name": name,
            "description": f"Test API key: {name}",
            "scopes": scopes,
            "expires_days": 30
        }
        default_data.update(kwargs)
        return default_data

    @staticmethod
    def create_memory_data(
        content: str = "Test memory content",
        **kwargs
    ) -> dict[str, Any]:
        """Create memory data for testing."""
        default_data = {
            "content": content,
            "importance": 0.5,
            "tags": ["test"],
            "metadata": {"category": "test"}
        }
        default_data.update(kwargs)
        return default_data


class TestResultCollector:
    """Collects and manages test results across categories."""

    def __init__(self):
        self.test_metrics: list[TestMetrics] = []
        self.security_results: list[SecurityTestResult] = []
        self.performance_results: list[PerformanceTestResult] = []
        self.coverage_data: dict[str, float] = {}
        self.start_time = datetime.now(timezone.utc)

    def add_test_metric(self, metric: TestMetrics):
        """Add test execution metric."""
        self.test_metrics.append(metric)

    def add_security_result(self, result: SecurityTestResult):
        """Add security test result."""
        self.security_results.append(result)

    def add_performance_result(self, result: PerformanceTestResult):
        """Add performance test result."""
        self.performance_results.append(result)

    def set_coverage_data(self, coverage: dict[str, float]):
        """Set code coverage data."""
        self.coverage_data = coverage

    def get_summary(self) -> dict[str, Any]:
        """Get comprehensive test summary."""
        total_tests = len(self.test_metrics)
        passed_tests = len([m for m in self.test_metrics if m.result == TestResult.PASSED])
        failed_tests = len([m for m in self.test_metrics if m.result == TestResult.FAILED])

        security_critical = len([
            r for r in self.security_results
            if r.risk_level == "critical" and r.result == TestResult.FAILED
        ])

        performance_failures = len([
            r for r in self.performance_results if not r.passed
        ])

        return {
            "execution_summary": {
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now(timezone.utc).isoformat(),
                "total_tests": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0
            },
            "security_summary": {
                "total_security_tests": len(self.security_results),
                "critical_vulnerabilities": security_critical,
                "security_passed": len([r for r in self.security_results if r.result == TestResult.PASSED])
            },
            "performance_summary": {
                "total_performance_tests": len(self.performance_results),
                "performance_failures": performance_failures,
                "avg_response_time": self._calculate_avg_performance()
            },
            "coverage_summary": {
                "overall_coverage": self.coverage_data.get("overall", 0),
                "critical_path_coverage": self.coverage_data.get("critical_paths", 0),
                "by_module": {k: v for k, v in self.coverage_data.items() if k not in ["overall", "critical_paths"]}
            }
        }

    def _calculate_avg_performance(self) -> float:
        """Calculate average performance across all tests."""
        if not self.performance_results:
            return 0.0

        total_time = sum(r.avg_time_ms for r in self.performance_results)
        return total_time / len(self.performance_results)

    def generate_report(self, output_path: str = "test_results.json"):
        """Generate comprehensive test report."""
        report = {
            "test_suite": "TMWS Phase 1 Implementation",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": self.get_summary(),
            "detailed_results": {
                "test_metrics": [asdict(m) for m in self.test_metrics],
                "security_results": [asdict(r) for r in self.security_results],
                "performance_results": [asdict(r) for r in self.performance_results]
            },
            "coverage_data": self.coverage_data,
            "recommendations": self._generate_recommendations()
        }

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return report

    def _generate_recommendations(self) -> list[str]:
        """Generate recommendations based on test results."""
        recommendations = []

        summary = self.get_summary()

        # Coverage recommendations
        overall_coverage = summary["coverage_summary"]["overall_coverage"]
        if overall_coverage < 90:
            recommendations.append(f"Increase code coverage from {overall_coverage:.1f}% to 90%+ for critical paths")

        # Security recommendations
        critical_vulns = summary["security_summary"]["critical_vulnerabilities"]
        if critical_vulns > 0:
            recommendations.append(f"Address {critical_vulns} critical security vulnerabilities immediately")

        # Performance recommendations
        perf_failures = summary["performance_summary"]["performance_failures"]
        if perf_failures > 0:
            recommendations.append(f"Fix {perf_failures} performance test failures to meet <200ms requirements")

        # Success rate recommendations
        success_rate = summary["execution_summary"]["success_rate"]
        if success_rate < 95:
            recommendations.append(f"Improve test success rate from {success_rate:.1f}% to 95%+")

        return recommendations


class TestEnvironmentManager:
    """Manages test environment setup and teardown."""

    def __init__(self, config: dict[str, Any] = None):
        self.config = config or {}
        self.temp_files: list[str] = []
        self.temp_dirs: list[str] = []

    def setup_test_database(self) -> str:
        """Setup test database and return connection string."""
        db_url = os.getenv("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

        # Ensure test database is isolated
        if "test" not in db_url.lower():
            raise ValueError("Test database URL must contain 'test' for safety")

        return db_url

    def setup_test_directories(self) -> dict[str, str]:
        """Setup temporary directories for testing."""
        import tempfile

        dirs = {}
        for dir_name in ["logs", "uploads", "temp"]:
            temp_dir = tempfile.mkdtemp(prefix=f"tmws_test_{dir_name}_")
            dirs[dir_name] = temp_dir
            self.temp_dirs.append(temp_dir)

        return dirs

    def cleanup(self):
        """Clean up test environment."""
        import shutil

        # Clean up temporary files
        for file_path in self.temp_files:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass  # Ignore cleanup errors

        # Clean up temporary directories
        for dir_path in self.temp_dirs:
            try:
                if os.path.exists(dir_path):
                    shutil.rmtree(dir_path)
            except Exception:
                pass  # Ignore cleanup errors


class CoverageAnalyzer:
    """Analyzes code coverage from test execution."""

    def __init__(self):
        self.coverage_data: dict[str, Any] = {}

    def analyze_coverage(self, coverage_file: str = ".coverage") -> dict[str, float]:
        """Analyze coverage data and return percentages by module."""
        try:
            import coverage

            cov = coverage.Coverage(data_file=coverage_file)
            cov.load()

            # Get overall coverage
            total_lines = 0
            covered_lines = 0

            module_coverage = {}

            for filename in cov.get_data().measured_files():
                if self._should_include_file(filename):
                    analysis = cov.analysis2(filename)
                    total = len(analysis[1])  # Total executable lines
                    covered = len(analysis[1]) - len(analysis[3])  # Covered lines

                    total_lines += total
                    covered_lines += covered

                    if total > 0:
                        module_coverage[self._get_module_name(filename)] = (covered / total) * 100

            overall_coverage = (covered_lines / total_lines) * 100 if total_lines > 0 else 0

            result = {
                "overall": overall_coverage,
                **module_coverage
            }

            # Calculate critical path coverage
            critical_modules = ["auth_service", "jwt_service", "security", "api"]
            critical_coverage = []
            for module, coverage_pct in module_coverage.items():
                if any(critical in module for critical in critical_modules):
                    critical_coverage.append(coverage_pct)

            if critical_coverage:
                result["critical_paths"] = sum(critical_coverage) / len(critical_coverage)
            else:
                result["critical_paths"] = 0

            return result

        except ImportError:
            # Coverage package not available
            return {"overall": 0, "critical_paths": 0}
        except Exception:
            # Coverage analysis failed
            return {"overall": 0, "critical_paths": 0}

    def _should_include_file(self, filename: str) -> bool:
        """Determine if file should be included in coverage analysis."""
        exclude_patterns = [
            "test_",
            "conftest.py",
            "__pycache__",
            ".pyc",
            "migrations/",
            "venv/",
            "env/"
        ]

        return not any(pattern in filename for pattern in exclude_patterns)

    def _get_module_name(self, filename: str) -> str:
        """Extract module name from filename."""
        path = Path(filename)
        if "src/" in str(path):
            # Extract relative path from src/
            relative_path = str(path).split("src/", 1)[1]
            module_name = relative_path.replace("/", ".").replace(".py", "")
            return module_name
        else:
            return path.stem


class CIIntegrationHelper:
    """Helper for CI/CD integration and reporting."""

    @staticmethod
    def generate_junit_xml(test_results: list[TestMetrics], output_file: str = "junit.xml"):
        """Generate JUnit XML format for CI systems."""
        from xml.etree.ElementTree import Element, SubElement, tostring

        testsuites = Element("testsuites")

        # Group by category
        by_category = {}
        for result in test_results:
            category = result.category.value
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(result)

        for category, results in by_category.items():
            testsuite = SubElement(testsuites, "testsuite")
            testsuite.set("name", f"TMWS_{category.upper()}_Tests")
            testsuite.set("tests", str(len(results)))
            testsuite.set("failures", str(len([r for r in results if r.result == TestResult.FAILED])))
            testsuite.set("errors", str(len([r for r in results if r.result == TestResult.ERROR])))
            testsuite.set("skipped", str(len([r for r in results if r.result == TestResult.SKIPPED])))

            for result in results:
                testcase = SubElement(testsuite, "testcase")
                testcase.set("name", result.test_name)
                testcase.set("classname", f"TMWS.{category}")
                testcase.set("time", str(result.duration_ms / 1000))  # Convert to seconds

                if result.result == TestResult.FAILED:
                    failure = SubElement(testcase, "failure")
                    failure.set("message", result.error_message or "Test failed")
                    failure.text = result.error_message
                elif result.result == TestResult.ERROR:
                    error = SubElement(testcase, "error")
                    error.set("message", result.error_message or "Test error")
                    error.text = result.error_message
                elif result.result == TestResult.SKIPPED:
                    SubElement(testcase, "skipped")

        # Write to file
        with open(output_file, "wb") as f:
            f.write(tostring(testsuites, encoding="utf-8"))

    @staticmethod
    def check_quality_gates(test_collector: TestResultCollector) -> dict[str, bool]:
        """Check quality gates for CI/CD pipeline."""
        summary = test_collector.get_summary()

        gates = {
            "test_success_rate": summary["execution_summary"]["success_rate"] >= 95,
            "code_coverage": summary["coverage_summary"]["overall_coverage"] >= 90,
            "critical_path_coverage": summary["coverage_summary"]["critical_path_coverage"] >= 95,
            "no_critical_security_issues": summary["security_summary"]["critical_vulnerabilities"] == 0,
            "performance_requirements": summary["performance_summary"]["performance_failures"] == 0
        }

        return gates

    @staticmethod
    def should_deploy(quality_gates: dict[str, bool]) -> bool:
        """Determine if deployment should proceed based on quality gates."""
        # All critical gates must pass
        critical_gates = [
            "no_critical_security_issues",
            "performance_requirements"
        ]

        for gate in critical_gates:
            if not quality_gates.get(gate, False):
                return False

        # At least 80% of all gates must pass
        passed_gates = sum(1 for passed in quality_gates.values() if passed)
        total_gates = len(quality_gates)

        return (passed_gates / total_gates) >= 0.8


# Global test result collector for the session
test_collector = TestResultCollector()


def pytest_runtest_makereport(item, call):
    """Hook to collect test results automatically."""
    if call.when == "call":
        # Determine test category from markers or path
        category = TestCategory.UNIT  # default

        if hasattr(item, 'pytestmark'):
            for mark in item.pytestmark:
                if mark.name == "security":
                    category = TestCategory.SECURITY
                elif mark.name == "performance":
                    category = TestCategory.PERFORMANCE
                elif mark.name == "integration":
                    category = TestCategory.INTEGRATION
                elif mark.name == "e2e":
                    category = TestCategory.E2E

        # Determine result
        if call.excinfo is None:
            result = TestResult.PASSED
            error_msg = None
        else:
            result = TestResult.FAILED
            error_msg = str(call.excinfo.value)

        # Create and add metric
        metric = TestMetrics(
            test_name=item.nodeid,
            category=category,
            duration_ms=call.duration * 1000,  # Convert to milliseconds
            result=result,
            error_message=error_msg
        )

        test_collector.add_test_metric(metric)


def pytest_sessionfinish(session, exitstatus):
    """Hook to generate final test report."""
    # Analyze coverage
    coverage_analyzer = CoverageAnalyzer()
    coverage_data = coverage_analyzer.analyze_coverage()
    test_collector.set_coverage_data(coverage_data)

    # Generate reports
    test_collector.generate_report("test_results.json")

    # Generate JUnit XML for CI
    CIIntegrationHelper.generate_junit_xml(test_collector.test_metrics, "junit.xml")

    # Check quality gates
    quality_gates = CIIntegrationHelper.check_quality_gates(test_collector)

    # Print summary
    summary = test_collector.get_summary()
    print("\n" + "="*80)
    print("TMWS TEST SUITE SUMMARY")
    print("="*80)
    print(f"Total Tests: {summary['execution_summary']['total_tests']}")
    print(f"Passed: {summary['execution_summary']['passed']}")
    print(f"Failed: {summary['execution_summary']['failed']}")
    print(f"Success Rate: {summary['execution_summary']['success_rate']:.1f}%")
    print(f"Overall Coverage: {summary['coverage_summary']['overall_coverage']:.1f}%")
    print(f"Critical Path Coverage: {summary['coverage_summary']['critical_path_coverage']:.1f}%")
    print(f"Security Issues: {summary['security_summary']['critical_vulnerabilities']} critical")
    print(f"Performance Failures: {summary['performance_summary']['performance_failures']}")

    print("\nQuality Gates:")
    for gate, passed in quality_gates.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {gate}: {status}")

    deployment_ready = CIIntegrationHelper.should_deploy(quality_gates)
    print(f"\nDeployment Ready: {'✅ YES' if deployment_ready else '❌ NO'}")

    if test_collector.get_summary()["execution_summary"]["success_rate"] < 95:
        print("\n⚠️  Warning: Test success rate below 95%")

    if summary['coverage_summary']['overall_coverage'] < 90:
        print("⚠️  Warning: Code coverage below 90%")

    print("="*80)
