# Agent Trust & Verification System - Developer Guide

**Version**: v2.2.7+
**Target Audience**: TMWS contributors, extension developers
**Last Updated**: 2025-11-07

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Integration Patterns](#integration-patterns)
4. [Extending the System](#extending-the-system)
5. [Custom Verification Tools](#custom-verification-tools)
6. [Testing](#testing)
7. [Best Practices](#best-practices)
8. [Code Examples](#code-examples)

---

## Architecture Overview

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                  Agent Trust System                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐      ┌──────────────┐      ┌───────────┐ │
│  │   Agent      │─────▶│ Verification │─────▶│  Trust    │ │
│  │   Service    │      │   Service    │      │  Scorer   │ │
│  └──────────────┘      └──────────────┘      └───────────┘ │
│         │                      │                     │       │
│         │                      │                     │       │
│         ▼                      ▼                     ▼       │
│  ┌──────────────┐      ┌──────────────┐      ┌───────────┐ │
│  │  Agent       │      │ Verification │      │  Trust    │ │
│  │  Model       │      │   Executor   │      │  History  │ │
│  └──────────────┘      └──────────────┘      └───────────┘ │
│                                                               │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │    SQLite Database          │
              ├─────────────────────────────┤
              │  • agents                   │
              │  • agent_verifications      │
              │  • agent_trust_history      │
              │  • verification_results     │
              └─────────────────────────────┘
```

### Data Flow

```
1. Agent makes claim
   └─▶ AgentService.record_claim()

2. Verification triggered
   ├─▶ VerificationService.verify_claim()
   └─▶ VerificationExecutor.execute()

3. Results collected
   └─▶ VerificationResult stored

4. Trust score updated
   ├─▶ TrustScorer.calculate_new_score()
   ├─▶ AgentService.update_trust_score()
   └─▶ TrustHistory recorded

5. Status evaluated
   └─▶ Agent.status updated if needed
```

---

## Core Components

### 1. AgentService Extension

**File**: `src/services/agent_service.py`

**New Methods**:

```python
class AgentService:
    """Extended with trust tracking capabilities."""

    async def update_agent_trust_score(
        self,
        agent_id: str,
        verification_result: VerificationResult,
    ) -> Agent:
        """Update agent's trust score based on verification result.

        Args:
            agent_id: Agent identifier
            verification_result: Result of claim verification

        Returns:
            Updated Agent object with new trust score

        Raises:
            NotFoundError: Agent not found
            ValidationError: Invalid verification result
        """
        agent = await self.get_agent_by_id(agent_id)
        if not agent:
            raise NotFoundError(f"Agent {agent_id} not found")

        # Calculate new trust score using EMA
        old_score = agent.trust_score or 1.0
        is_verified = verification_result.claim_verified

        if is_verified:
            # Gradual increase (growth_rate = 0.05)
            new_score = old_score * 0.95 + 1.0 * 0.05
        else:
            # Rapid decrease (decay_rate = 0.70)
            new_score = old_score * 0.70 + 0.0 * 0.30

        # Update agent
        agent.trust_score = max(0.0, min(1.0, new_score))
        agent.total_verifications = (agent.total_verifications or 0) + 1

        if is_verified:
            agent.successful_verifications = (agent.successful_verifications or 0) + 1
        else:
            agent.failed_verifications = (agent.failed_verifications or 0) + 1

        # Update status based on new trust score
        agent.status = self._determine_status_from_trust(agent.trust_score)

        # Record in history
        await self._record_trust_history(
            agent_id=agent_id,
            old_score=old_score,
            new_score=agent.trust_score,
            verification_result=verification_result,
        )

        await self.session.commit()
        await self.session.refresh(agent)

        logger.info(
            f"Updated trust score for {agent_id}: {old_score:.2f} → {new_score:.2f}",
            extra={
                "agent_id": agent_id,
                "old_score": old_score,
                "new_score": new_score,
                "verification_success": is_verified,
            },
        )

        return agent

    def _determine_status_from_trust(self, trust_score: float) -> str:
        """Determine agent status based on trust score."""
        if trust_score >= 0.90:
            return "TRUSTED"
        elif trust_score >= 0.75:
            return "ACTIVE"
        elif trust_score >= 0.50:
            return "MONITORED"
        elif trust_score >= 0.25:
            return "UNTRUSTED"
        else:
            return "BLOCKED"

    async def _record_trust_history(
        self,
        agent_id: str,
        old_score: float,
        new_score: float,
        verification_result: VerificationResult,
    ) -> None:
        """Record trust score change in history table."""
        from ..models.agent_trust import AgentTrustHistory

        history = AgentTrustHistory(
            agent_id=agent_id,
            old_trust_score=old_score,
            new_trust_score=new_score,
            score_change=new_score - old_score,
            verification_id=verification_result.id,
            claim=verification_result.claim,
            verified=verification_result.claim_verified,
        )

        self.session.add(history)
        # Commit happens in calling method
```

### 2. VerificationService

**File**: `src/services/verification_service.py` (new file)

```python
"""Verification service for agent claims."""

import asyncio
import logging
import subprocess
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import ValidationError, VerificationError
from ..models.agent_verification import AgentVerification, VerificationResult

logger = logging.getLogger(__name__)


class VerificationService:
    """Service for verifying agent claims."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.timeout_defaults = {
            "test_count": 30,
            "test_results": 120,
            "code_quality": 60,
            "performance": 180,
            "security": 180,
            "coverage": 120,
            "file_existence": 5,
            "custom": 300,
        }

    async def verify_claim(
        self,
        agent_id: str,
        claim: str,
        verification_type: str,
        verification_command: str | None = None,
        expected_result: Any = None,
        timeout: int | None = None,
    ) -> VerificationResult:
        """Verify an agent's claim.

        Args:
            agent_id: Agent making the claim
            claim: The claim to verify
            verification_type: Type of verification (test_count, code_quality, etc.)
            verification_command: Shell command to run for verification
            expected_result: Expected result (optional, for comparison)
            timeout: Command timeout in seconds

        Returns:
            VerificationResult with verification outcome

        Raises:
            ValidationError: Invalid parameters
            VerificationError: Verification execution failed
        """
        if not claim:
            raise ValidationError("Claim cannot be empty")

        if not verification_type:
            raise ValidationError("Verification type is required")

        # Get timeout
        timeout = timeout or self.timeout_defaults.get(verification_type, 60)

        # Create verification record
        verification = AgentVerification(
            agent_id=agent_id,
            claim=claim,
            verification_type=verification_type,
            verification_command=verification_command,
            expected_result=expected_result,
            status="PENDING",
        )

        self.session.add(verification)
        await self.session.commit()
        await self.session.refresh(verification)

        try:
            # Execute verification
            result = await self._execute_verification(
                verification_type=verification_type,
                command=verification_command,
                expected=expected_result,
                timeout=timeout,
            )

            # Create verification result
            verification_result = VerificationResult(
                verification_id=verification.id,
                claim_verified=result["verified"],
                actual_result=result.get("actual"),
                verification_output=result.get("output"),
                verification_error=result.get("error"),
                execution_time_ms=result.get("execution_time_ms"),
            )

            # Update verification status
            verification.status = "COMPLETED" if result["verified"] else "FAILED"
            verification.completed_at = datetime.utcnow()

            self.session.add(verification_result)
            await self.session.commit()
            await self.session.refresh(verification_result)

            logger.info(
                f"Verification completed for {agent_id}: {claim}",
                extra={
                    "agent_id": agent_id,
                    "verified": result["verified"],
                    "verification_type": verification_type,
                },
            )

            return verification_result

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(
                f"Verification failed for {agent_id}: {e}",
                exc_info=True,
                extra={
                    "agent_id": agent_id,
                    "claim": claim,
                    "verification_type": verification_type,
                },
            )

            # Update verification status
            verification.status = "ERROR"
            verification.completed_at = datetime.utcnow()
            await self.session.commit()

            raise VerificationError(f"Verification failed: {e}") from e

    async def _execute_verification(
        self,
        verification_type: str,
        command: str | None,
        expected: Any,
        timeout: int,
    ) -> dict[str, Any]:
        """Execute verification command and parse results."""
        if not command:
            return {"verified": False, "error": "No verification command provided"}

        start_time = datetime.utcnow()

        try:
            # Execute command with timeout
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            output = stdout.decode("utf-8") if stdout else ""
            error = stderr.decode("utf-8") if stderr else ""

            # Parse output based on verification type
            actual_result = self._parse_verification_output(
                verification_type=verification_type,
                output=output,
                returncode=process.returncode,
            )

            # Compare with expected result
            verified = self._compare_results(
                verification_type=verification_type,
                expected=expected,
                actual=actual_result,
            )

            return {
                "verified": verified,
                "actual": actual_result,
                "output": output,
                "error": error,
                "execution_time_ms": execution_time,
            }

        except asyncio.TimeoutError:
            return {
                "verified": False,
                "error": f"Verification timed out after {timeout}s",
            }
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            return {
                "verified": False,
                "error": f"Execution failed: {e}",
            }

    def _parse_verification_output(
        self,
        verification_type: str,
        output: str,
        returncode: int,
    ) -> Any:
        """Parse verification output based on type."""
        parsers = {
            "test_count": self._parse_test_count,
            "test_results": self._parse_test_results,
            "code_quality": self._parse_code_quality,
            "coverage": self._parse_coverage,
            "file_existence": self._parse_file_existence,
        }

        parser = parsers.get(verification_type, self._parse_generic)
        return parser(output, returncode)

    def _parse_test_count(self, output: str, returncode: int) -> dict[str, Any]:
        """Parse pytest test collection output."""
        import re

        # Pattern: "collected 450 items"
        match = re.search(r"collected (\d+) items?", output)
        if match:
            return {"test_count": int(match.group(1))}

        # Pattern: "450 passed"
        match = re.search(r"(\d+) passed", output)
        if match:
            return {"test_count": int(match.group(1))}

        return {"test_count": 0, "parse_error": "Could not parse test count"}

    def _parse_test_results(self, output: str, returncode: int) -> dict[str, Any]:
        """Parse pytest test results."""
        import re

        results = {
            "passed": 0,
            "failed": 0,
            "error": 0,
            "skipped": 0,
        }

        # Pattern: "5 passed, 2 failed, 1 error"
        for key in results.keys():
            match = re.search(rf"(\d+) {key}", output)
            if match:
                results[key] = int(match.group(1))

        return results

    def _parse_code_quality(self, output: str, returncode: int) -> dict[str, Any]:
        """Parse ruff/linting output."""
        # Count number of violations
        lines = output.strip().split("\n")
        violations = [line for line in lines if line and not line.startswith("Found")]

        return {
            "violation_count": len(violations),
            "violations": violations[:10],  # First 10 for brevity
        }

    def _parse_coverage(self, output: str, returncode: int) -> dict[str, Any]:
        """Parse coverage report."""
        import re

        # Pattern: "TOTAL  2594   1892  73%"
        match = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", output)
        if match:
            return {"coverage_percent": int(match.group(1))}

        return {"coverage_percent": 0, "parse_error": "Could not parse coverage"}

    def _parse_file_existence(self, output: str, returncode: int) -> dict[str, Any]:
        """Parse ls/file existence check."""
        exists = returncode == 0 and len(output.strip()) > 0
        return {"file_exists": exists}

    def _parse_generic(self, output: str, returncode: int) -> dict[str, Any]:
        """Generic output parser."""
        return {
            "output": output,
            "returncode": returncode,
            "success": returncode == 0,
        }

    def _compare_results(
        self,
        verification_type: str,
        expected: Any,
        actual: Any,
    ) -> bool:
        """Compare expected and actual results."""
        if expected is None:
            # No expected result provided, assume verification succeeded
            # if command ran successfully
            return bool(actual)

        comparators = {
            "test_count": self._compare_test_count,
            "test_results": self._compare_test_results,
            "code_quality": self._compare_code_quality,
            "coverage": self._compare_coverage,
            "file_existence": self._compare_file_existence,
        }

        comparator = comparators.get(verification_type, self._compare_generic)
        return comparator(expected, actual)

    def _compare_test_count(self, expected: Any, actual: Any) -> bool:
        """Compare test counts with tolerance."""
        if not isinstance(actual, dict) or "test_count" not in actual:
            return False

        expected_count = expected.get("test_count", expected) if isinstance(expected, dict) else expected
        actual_count = actual["test_count"]

        # Allow 5% tolerance
        tolerance = max(1, int(expected_count * 0.05))
        return abs(expected_count - actual_count) <= tolerance

    def _compare_test_results(self, expected: Any, actual: Any) -> bool:
        """Compare test results."""
        if not isinstance(actual, dict):
            return False

        # Check if failed/error counts match expected
        expected_failed = expected.get("failed", 0)
        actual_failed = actual.get("failed", 0)

        return expected_failed == actual_failed

    def _compare_code_quality(self, expected: Any, actual: Any) -> bool:
        """Compare code quality results."""
        if not isinstance(actual, dict) or "violation_count" not in actual:
            return False

        expected_count = expected.get("violation_count", expected) if isinstance(expected, dict) else expected
        actual_count = actual["violation_count"]

        # Allow 10% tolerance for violations
        tolerance = max(1, int(expected_count * 0.10))
        return abs(expected_count - actual_count) <= tolerance

    def _compare_coverage(self, expected: Any, actual: Any) -> bool:
        """Compare coverage percentages."""
        if not isinstance(actual, dict) or "coverage_percent" not in actual:
            return False

        expected_pct = expected.get("coverage_percent", expected) if isinstance(expected, dict) else expected
        actual_pct = actual["coverage_percent"]

        # Allow 2% tolerance
        return abs(expected_pct - actual_pct) <= 2

    def _compare_file_existence(self, expected: Any, actual: Any) -> bool:
        """Compare file existence."""
        if not isinstance(actual, dict) or "file_exists" not in actual:
            return False

        expected_exists = expected.get("file_exists", expected) if isinstance(expected, dict) else expected
        return expected_exists == actual["file_exists"]

    def _compare_generic(self, expected: Any, actual: Any) -> bool:
        """Generic comparison (exact match)."""
        return expected == actual
```

### 3. Database Models

**File**: `src/models/agent_verification.py` (new file)

```python
"""Agent verification models."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import MetadataMixin, TMWSBase

if TYPE_CHECKING:
    from .agent import Agent


class AgentVerification(TMWSBase, MetadataMixin):
    """Record of agent claim verification."""

    __tablename__ = "agent_verifications"

    # Foreign keys
    agent_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey("agents.agent_id"),
        nullable=False,
        index=True,
    )

    # Claim information
    claim: Mapped[str] = mapped_column(Text, nullable=False)
    verification_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    verification_command: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Expected result
    expected_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Verification status
    status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="PENDING",
        index=True,
    )  # PENDING, COMPLETED, FAILED, ERROR

    # Timestamps
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    agent: Mapped[Agent] = relationship("Agent", back_populates="verifications")
    result: Mapped[VerificationResult | None] = relationship(
        "VerificationResult",
        back_populates="verification",
        uselist=False,
    )

    # Indexes
    __table_args__ = (
        Index("ix_verification_agent_status", "agent_id", "status"),
        Index("ix_verification_agent_type", "agent_id", "verification_type"),
    )


class VerificationResult(TMWSBase, MetadataMixin):
    """Result of verification execution."""

    __tablename__ = "verification_results"

    # Foreign keys
    verification_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("agent_verifications.id"),
        nullable=False,
        unique=True,
    )

    # Verification outcome
    claim_verified: Mapped[bool] = mapped_column(
        Integer,
        nullable=False,
        index=True,
    )

    # Actual result
    actual_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Execution details
    verification_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    execution_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Relationships
    verification: Mapped[AgentVerification] = relationship(
        "AgentVerification",
        back_populates="result",
    )


class AgentTrustHistory(TMWSBase, MetadataMixin):
    """Historical record of trust score changes."""

    __tablename__ = "agent_trust_history"

    # Foreign keys
    agent_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey("agents.agent_id"),
        nullable=False,
        index=True,
    )

    verification_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("agent_verifications.id"),
        nullable=True,
    )

    # Trust score changes
    old_trust_score: Mapped[float] = mapped_column(Float, nullable=False)
    new_trust_score: Mapped[float] = mapped_column(Float, nullable=False)
    score_change: Mapped[float] = mapped_column(Float, nullable=False, index=True)

    # Associated claim
    claim: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified: Mapped[bool | None] = mapped_column(Integer, nullable=True)

    # Indexes
    __table_args__ = (
        Index("ix_trust_history_agent_time", "agent_id", "created_at"),
    )
```

---

## Integration Patterns

### Pattern 1: Manual Verification

Use when you want explicit control over verification timing:

```python
from src.services.agent_service import AgentService
from src.services.verification_service import VerificationService

async def manual_verification_example(session):
    """Example of manual claim verification."""
    agent_service = AgentService(session)
    verification_service = VerificationService(session)

    # Agent makes claim
    agent_id = "hera-strategist"
    claim = "Found 15 unused imports in src/"

    # Verify claim
    result = await verification_service.verify_claim(
        agent_id=agent_id,
        claim=claim,
        verification_type="code_quality",
        verification_command="ruff check src/ --select F401 | wc -l",
        expected_result={"violation_count": 15},
    )

    # Update trust score
    updated_agent = await agent_service.update_agent_trust_score(
        agent_id=agent_id,
        verification_result=result,
    )

    print(f"Trust Score: {updated_agent.trust_score:.2f}")
    print(f"Status: {updated_agent.status}")
```

### Pattern 2: Automatic Verification

Use for continuous monitoring:

```python
from src.services.agent_service import AgentService
from src.services.verification_service import VerificationService

class AutoVerificationDecorator:
    """Decorator for automatic claim verification."""

    def __init__(self, session):
        self.session = session
        self.verification_service = VerificationService(session)
        self.agent_service = AgentService(session)

    def verify_claim(
        self,
        verification_type: str,
        verification_command: str,
        expected_result: Any = None,
    ):
        """Decorator that automatically verifies agent claims."""
        def decorator(func):
            async def wrapper(agent_id: str, *args, **kwargs):
                # Execute original function (agent makes claim)
                claim = await func(agent_id, *args, **kwargs)

                # Verify claim automatically
                result = await self.verification_service.verify_claim(
                    agent_id=agent_id,
                    claim=claim,
                    verification_type=verification_type,
                    verification_command=verification_command,
                    expected_result=expected_result,
                )

                # Update trust score
                await self.agent_service.update_agent_trust_score(
                    agent_id=agent_id,
                    verification_result=result,
                )

                return claim, result

            return wrapper
        return decorator


# Usage
auto_verify = AutoVerificationDecorator(session)

@auto_verify.verify_claim(
    verification_type="test_count",
    verification_command="pytest tests/ --collect-only -q | grep 'test session' | awk '{print $2}'",
    expected_result={"test_count": 450},
)
async def agent_analyze_tests(agent_id: str):
    """Agent analyzes test suite."""
    # Agent's analysis logic
    return "Project has 450 total tests"
```

### Pattern 3: Batch Verification

Use for auditing multiple claims:

```python
async def batch_verification_example(session):
    """Verify multiple claims in batch."""
    verification_service = VerificationService(session)
    agent_service = AgentService(session)

    claims = [
        {
            "agent_id": "artemis-optimizer",
            "claim": "Test coverage is 85%",
            "verification_type": "coverage",
            "command": "pytest --cov=src --cov-report=term",
            "expected": {"coverage_percent": 85},
        },
        {
            "agent_id": "artemis-optimizer",
            "claim": "15 unused imports detected",
            "verification_type": "code_quality",
            "command": "ruff check src/ --select F401",
            "expected": {"violation_count": 15},
        },
        {
            "agent_id": "artemis-optimizer",
            "claim": "Database queries average 12ms",
            "verification_type": "performance",
            "command": "python scripts/benchmark_db.py",
            "expected": {"avg_query_time_ms": 12.0},
        },
    ]

    results = []
    for claim_data in claims:
        result = await verification_service.verify_claim(
            agent_id=claim_data["agent_id"],
            claim=claim_data["claim"],
            verification_type=claim_data["verification_type"],
            verification_command=claim_data["command"],
            expected_result=claim_data["expected"],
        )

        # Update trust score
        await agent_service.update_agent_trust_score(
            agent_id=claim_data["agent_id"],
            verification_result=result,
        )

        results.append({
            "claim": claim_data["claim"],
            "verified": result.claim_verified,
        })

    return results
```

---

## Extending the System

### Adding New Verification Types

1. **Add parser in VerificationService**:

```python
def _parse_database_integrity(self, output: str, returncode: int) -> dict[str, Any]:
    """Parse database integrity check output."""
    # Custom parsing logic
    if "PRAGMA integrity_check: ok" in output:
        return {"integrity_status": "OK"}
    else:
        return {"integrity_status": "CORRUPTED", "details": output}
```

2. **Add comparator**:

```python
def _compare_database_integrity(self, expected: Any, actual: Any) -> bool:
    """Compare database integrity results."""
    expected_status = expected.get("integrity_status", "OK")
    actual_status = actual.get("integrity_status")
    return expected_status == actual_status
```

3. **Register in dictionaries**:

```python
# In __init__:
self.timeout_defaults["database_integrity"] = 60

# In _parse_verification_output:
parsers["database_integrity"] = self._parse_database_integrity

# In _compare_results:
comparators["database_integrity"] = self._compare_database_integrity
```

### Creating Custom Verification Tools

```python
"""Custom verification tool for API response times."""

from src.services.verification_service import VerificationService

class APIResponseVerificationTool:
    """Custom tool for API response time verification."""

    def __init__(self, session):
        self.verification_service = VerificationService(session)

    async def verify_api_response_time(
        self,
        agent_id: str,
        claim: str,
        endpoint: str,
        expected_p95_ms: float,
    ) -> VerificationResult:
        """Verify API response time claim."""
        # Build custom verification command
        command = f"""
        curl -w "@curl-format.txt" -o /dev/null -s {endpoint} |
        jq '.time_total * 1000' |
        awk '{{sum+=$1; n++}} END {{print sum/n}}'
        """

        result = await self.verification_service.verify_claim(
            agent_id=agent_id,
            claim=claim,
            verification_type="api_performance",
            verification_command=command,
            expected_result={"avg_response_ms": expected_p95_ms},
        )

        return result


# Usage
async def example_api_verification(session):
    api_verifier = APIResponseVerificationTool(session)

    result = await api_verifier.verify_api_response_time(
        agent_id="artemis-optimizer",
        claim="User API responds in 50ms P95",
        endpoint="http://localhost:8000/api/users",
        expected_p95_ms=50.0,
    )

    print(f"API Performance Verified: {result.claim_verified}")
```

---

## Testing

### Unit Tests

```python
"""Test agent trust scoring."""

import pytest
from src.services.agent_service import AgentService
from src.services.verification_service import VerificationService
from src.models.agent_verification import VerificationResult


@pytest.fixture
async def agent_service(db_session):
    return AgentService(db_session)


@pytest.fixture
async def verification_service(db_session):
    return VerificationService(db_session)


@pytest.mark.asyncio
async def test_trust_score_decreases_on_failed_verification(
    agent_service, verification_service, db_session
):
    """Test trust score decreases when verification fails."""
    # Create agent
    agent = await agent_service.create_agent(
        agent_id="test-agent",
        display_name="Test Agent",
        agent_type="test",
        namespace="test",
    )

    assert agent.trust_score == 1.0  # Initial score

    # Create failed verification result
    verification_result = VerificationResult(
        verification_id=1,
        claim_verified=False,
        actual_result={"test_count": 100},
        verification_output="Found 100 tests, expected 450",
    )

    db_session.add(verification_result)
    await db_session.commit()

    # Update trust score
    updated_agent = await agent_service.update_agent_trust_score(
        agent_id="test-agent",
        verification_result=verification_result,
    )

    # Trust score should decrease
    assert updated_agent.trust_score < 1.0
    assert updated_agent.trust_score == pytest.approx(0.70, rel=0.01)
    assert updated_agent.status == "MONITORED"


@pytest.mark.asyncio
async def test_trust_score_increases_on_successful_verification(
    agent_service, verification_service, db_session
):
    """Test trust score increases gradually with successful verifications."""
    # Create agent with low trust score
    agent = await agent_service.create_agent(
        agent_id="test-agent-2",
        display_name="Test Agent 2",
        agent_type="test",
        namespace="test",
    )

    # Manually set low trust score
    agent.trust_score = 0.70
    await db_session.commit()

    # Create successful verification result
    verification_result = VerificationResult(
        verification_id=2,
        claim_verified=True,
        actual_result={"test_count": 450},
        verification_output="Found 450 tests as expected",
    )

    db_session.add(verification_result)
    await db_session.commit()

    # Update trust score
    updated_agent = await agent_service.update_agent_trust_score(
        agent_id="test-agent-2",
        verification_result=verification_result,
    )

    # Trust score should increase slightly
    assert updated_agent.trust_score > 0.70
    assert updated_agent.trust_score == pytest.approx(0.715, rel=0.01)  # 0.70 * 0.95 + 1.0 * 0.05


@pytest.mark.asyncio
async def test_verification_command_execution(verification_service):
    """Test verification command execution."""
    result = await verification_service.verify_claim(
        agent_id="test-agent",
        claim="Project root has README.md",
        verification_type="file_existence",
        verification_command="ls README.md",
        expected_result={"file_exists": True},
    )

    assert result.claim_verified is True
    assert result.actual_result["file_exists"] is True
```

### Integration Tests

```python
"""Integration test for trust tracking workflow."""

import pytest
from src.services.agent_service import AgentService
from src.services.verification_service import VerificationService


@pytest.mark.asyncio
async def test_end_to_end_trust_workflow(db_session):
    """Test complete trust tracking workflow."""
    agent_service = AgentService(db_session)
    verification_service = VerificationService(db_session)

    # Step 1: Create agent
    agent = await agent_service.create_agent(
        agent_id="hera-test",
        display_name="Hera Test",
        agent_type="strategist",
        namespace="test",
    )

    initial_score = agent.trust_score
    assert initial_score == 1.0

    # Step 2: Agent makes false claim
    claim1 = "Project has 1000 tests"
    result1 = await verification_service.verify_claim(
        agent_id="hera-test",
        claim=claim1,
        verification_type="test_count",
        verification_command="pytest tests/ --collect-only -q | grep -c '::test_'",
        expected_result={"test_count": 1000},
    )

    # Assume actual count is ~450, so this should fail
    assert result1.claim_verified is False

    # Step 3: Update trust score
    agent = await agent_service.update_agent_trust_score(
        agent_id="hera-test",
        verification_result=result1,
    )

    # Trust score should drop significantly
    assert agent.trust_score < initial_score
    assert agent.status in ["MONITORED", "UNTRUSTED"]

    # Step 4: Agent makes accurate claim
    claim2 = "README.md exists in project root"
    result2 = await verification_service.verify_claim(
        agent_id="hera-test",
        claim=claim2,
        verification_type="file_existence",
        verification_command="ls README.md",
        expected_result={"file_exists": True},
    )

    assert result2.claim_verified is True

    # Step 5: Update trust score again
    agent = await agent_service.update_agent_trust_score(
        agent_id="hera-test",
        verification_result=result2,
    )

    # Trust score should increase slightly
    previous_score = agent.trust_score
    assert agent.trust_score > previous_score

    # Step 6: Verify history was recorded
    from src.models.agent_trust import AgentTrustHistory
    from sqlalchemy import select

    history = await db_session.execute(
        select(AgentTrustHistory).where(
            AgentTrustHistory.agent_id == "hera-test"
        )
    )

    history_records = list(history.scalars().all())
    assert len(history_records) == 2  # Two score updates
```

---

## Best Practices

### 1. Verification Command Design

✅ **DO**:
```python
# Use specific, deterministic commands
command = "pytest tests/unit/ -v --tb=no | grep -c 'PASSED'"

# Include timeout hints in command
command = "timeout 60s pytest tests/integration/"

# Use absolute paths
command = "ls /project/root/README.md"
```

❌ **DON'T**:
```python
# Avoid commands with side effects
command = "pytest tests/ && rm -rf .pytest_cache"  # ❌ Modifies state

# Avoid non-deterministic commands
command = "pytest tests/ --random-order"  # ❌ Results vary

# Avoid relative paths
command = "ls ../README.md"  # ❌ Depends on current directory
```

### 2. Trust Score Management

✅ **DO**:
```python
# Always check agent status before critical operations
agent = await agent_service.get_agent_by_id(agent_id)
if agent.status in ["UNTRUSTED", "BLOCKED"]:
    # Require manual review
    await notify_admin(f"Agent {agent_id} requires review")

# Provide context for trust score changes
await agent_service.update_agent_trust_score(
    agent_id=agent_id,
    verification_result=result,
    context={
        "operation": "code_review",
        "reviewer": "artemis-optimizer",
    },
)

# Log trust score changes
logger.info(
    f"Trust score updated for {agent_id}",
    extra={
        "old_score": old_score,
        "new_score": new_score,
        "verification_type": result.verification_type,
    },
)
```

❌ **DON'T**:
```python
# Never bypass trust checks for convenience
# agent.status = "TRUSTED"  # ❌ Manual override without justification

# Don't ignore BLOCKED status
# if agent.status == "BLOCKED":
#     pass  # ❌ Proceed anyway

# Don't reset trust scores arbitrarily
# agent.trust_score = 1.0  # ❌ No audit trail
```

### 3. Error Handling

✅ **DO**:
```python
try:
    result = await verification_service.verify_claim(
        agent_id=agent_id,
        claim=claim,
        verification_type="test_count",
        verification_command=command,
    )
except VerificationError as e:
    # Treat verification errors as failed verifications
    logger.error(f"Verification error: {e}")
    # Optionally penalize trust score
    await agent_service.update_agent_trust_score(
        agent_id=agent_id,
        verification_result=VerificationResult(
            claim_verified=False,
            verification_error=str(e),
        ),
    )
except (KeyboardInterrupt, SystemExit):
    raise  # Never suppress these
except Exception as e:
    logger.error(f"Unexpected error: {e}", exc_info=True)
    # Don't penalize trust score for system errors
    raise
```

### 4. Performance Considerations

✅ **DO**:
```python
# Use asyncio for concurrent verifications
verifications = [
    verification_service.verify_claim(...),
    verification_service.verify_claim(...),
    verification_service.verify_claim(...),
]
results = await asyncio.gather(*verifications)

# Set reasonable timeouts
await verification_service.verify_claim(
    agent_id=agent_id,
    claim=claim,
    verification_type="security",
    timeout=180,  # 3 minutes for security scan
)

# Cache verification results
@lru_cache(maxsize=100)
async def cached_verify_claim(claim_hash: str):
    # Implementation
    pass
```

---

## Code Examples

### Example 1: Custom Verification Type for API Health

```python
"""Custom verification for API health checks."""

from src.services.verification_service import VerificationService


class APIHealthVerification:
    """Verify API health claims."""

    def __init__(self, session):
        self.verification_service = VerificationService(session)

        # Extend parsers
        self.verification_service._parse_verification_output = self._extended_parser
        self.verification_service._compare_results = self._extended_comparator

    def _extended_parser(self, verification_type, output, returncode):
        """Extended parser with API health support."""
        if verification_type == "api_health":
            return self._parse_api_health(output, returncode)
        else:
            # Fall back to default parsers
            return self.verification_service._parse_verification_output(
                verification_type, output, returncode
            )

    def _parse_api_health(self, output: str, returncode: int) -> dict:
        """Parse API health check response."""
        import json

        try:
            data = json.loads(output)
            return {
                "status": data.get("status"),
                "response_time_ms": data.get("response_time"),
                "healthy": data.get("status") == "healthy",
            }
        except json.JSONDecodeError:
            return {
                "status": "error",
                "healthy": False,
                "error": "Invalid JSON response",
            }

    def _extended_comparator(self, verification_type, expected, actual):
        """Extended comparator with API health support."""
        if verification_type == "api_health":
            return self._compare_api_health(expected, actual)
        else:
            return self.verification_service._compare_results(
                verification_type, expected, actual
            )

    def _compare_api_health(self, expected: Any, actual: Any) -> bool:
        """Compare API health results."""
        expected_healthy = expected.get("healthy", True)
        actual_healthy = actual.get("healthy", False)
        return expected_healthy == actual_healthy


# Usage
async def verify_api_health(session, agent_id):
    verifier = APIHealthVerification(session)

    result = await verifier.verification_service.verify_claim(
        agent_id=agent_id,
        claim="User API is healthy",
        verification_type="api_health",
        verification_command='curl -s http://localhost:8000/health | jq "."',
        expected_result={"healthy": True},
    )

    return result
```

### Example 2: Verification Dashboard

```python
"""Trust score monitoring dashboard."""

from datetime import datetime, timedelta
from src.services.agent_service import AgentService


async def generate_trust_dashboard(session):
    """Generate comprehensive trust dashboard."""
    agent_service = AgentService(session)

    # Get all agents
    agents = await agent_service.list_agents(limit=1000)

    dashboard_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "summary": {
            "total_agents": len(agents),
            "trusted": 0,
            "active": 0,
            "monitored": 0,
            "untrusted": 0,
            "blocked": 0,
        },
        "agents": [],
    }

    for agent in agents:
        # Count by status
        dashboard_data["summary"][agent.status.lower()] += 1

        # Get agent details
        agent_data = {
            "agent_id": agent.agent_id,
            "display_name": agent.display_name,
            "trust_score": agent.trust_score,
            "status": agent.status,
            "total_verifications": agent.total_verifications or 0,
            "successful_verifications": agent.successful_verifications or 0,
            "failed_verifications": agent.failed_verifications or 0,
            "accuracy_rate": (
                agent.successful_verifications / agent.total_verifications
                if agent.total_verifications
                else 0.0
            ),
        }

        dashboard_data["agents"].append(agent_data)

    # Sort by trust score (lowest first for priority attention)
    dashboard_data["agents"].sort(key=lambda x: x["trust_score"])

    return dashboard_data


# Generate dashboard
dashboard = await generate_trust_dashboard(session)

print(f"Total Agents: {dashboard['summary']['total_agents']}")
print(f"Trusted: {dashboard['summary']['trusted']}")
print(f"Blocked: {dashboard['summary']['blocked']}")
print("\nLow Trust Agents (Priority):")
for agent in dashboard["agents"][:5]:  # Top 5 lowest
    print(f"  {agent['agent_id']}: {agent['trust_score']:.2f} ({agent['status']})")
```

---

## Next Steps

- **Users**: See [User Guide: Agent Trust](./USER_GUIDE_AGENT_TRUST.md)
- **Operators**: See [Operations Guide: Monitoring](./OPERATIONS_GUIDE_MONITORING.md)
- **API Reference**: See [API Reference: Trust System](./API_REFERENCE_TRUST_SYSTEM.md)

---

**Questions?**
- GitHub Issues: [github.com/apto-as/tmws/issues](https://github.com/apto-as/tmws/issues)
- Development Setup: [DEVELOPMENT_SETUP.md](../DEVELOPMENT_SETUP.md)

---

*This developer guide is part of TMWS v2.2.7+ Agent Trust & Verification System.*
