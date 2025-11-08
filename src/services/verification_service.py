"""Verification service for claim validation and evidence recording

Handles verification workflow:
1. Execute verification command
2. Compare result with claim
3. Record evidence to memory
4. Update trust score

Performance target: <500ms P95 per verification
"""
import asyncio
import json
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    AgentNotFoundError,
    DatabaseError,
    VerificationError,
    log_and_raise
)
from src.models.agent import Agent
from src.models.memory import Memory
from src.models.verification import VerificationRecord
from src.services.memory_service import HybridMemoryService
from src.services.trust_service import TrustService


class ClaimType(str, Enum):
    """Types of claims that can be verified"""
    TEST_RESULT = "test_result"
    PERFORMANCE_METRIC = "performance_metric"
    CODE_QUALITY = "code_quality"
    SECURITY_FINDING = "security_finding"
    DEPLOYMENT_STATUS = "deployment_status"
    CUSTOM = "custom"


class VerificationResult:
    """Result of a verification operation"""

    def __init__(
        self,
        claim: dict[str, Any],
        actual: dict[str, Any],
        accurate: bool,
        evidence_id: UUID,
        verification_id: UUID,
        new_trust_score: float
    ):
        self.claim = claim
        self.actual = actual
        self.accurate = accurate
        self.evidence_id = evidence_id
        self.verification_id = verification_id
        self.new_trust_score = new_trust_score

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "claim": self.claim,
            "actual": self.actual,
            "accurate": self.accurate,
            "evidence_id": str(self.evidence_id),
            "verification_id": str(self.verification_id),
            "new_trust_score": self.new_trust_score
        }


class VerificationService:
    """Service for claim verification and evidence recording"""

    def __init__(
        self,
        session: AsyncSession,
        memory_service: HybridMemoryService | None = None,
        trust_service: TrustService | None = None
    ):
        """Initialize verification service

        Args:
            session: Database session
            memory_service: Memory service for evidence recording
            trust_service: Trust service for score updates
        """
        self.session = session
        self.memory_service = memory_service or HybridMemoryService(session)
        self.trust_service = trust_service or TrustService(session)

    async def verify_claim(
        self,
        agent_id: str,
        claim_type: ClaimType | str,
        claim_content: dict[str, Any],
        verification_command: str,
        verified_by_agent_id: str | None = None
    ) -> VerificationResult:
        """Verify a claim by executing verification command

        Args:
            agent_id: Agent making the claim
            claim_type: Type of claim
            claim_content: The claim to verify
            verification_command: Command to execute for verification
            verified_by_agent_id: Optional agent performing verification

        Returns:
            VerificationResult with evidence and trust score

        Raises:
            AgentNotFoundError: If agent doesn't exist
            VerificationError: If verification execution fails
            ValidationError: If self-verification attempted (V-TRUST-5 fix)
            DatabaseError: If database operations fail

        Performance target: <500ms P95

        Security:
            - V-TRUST-5: Prevent self-verification (verifier cannot be same as agent)
        """
        from src.core.exceptions import ValidationError

        try:
            # V-TRUST-5: Prevent self-verification
            if verified_by_agent_id is not None and verified_by_agent_id == agent_id:
                log_and_raise(
                    ValidationError,
                    f"Self-verification not allowed: agent {agent_id} cannot verify own claims",
                    details={
                        "agent_id": agent_id,
                        "verified_by_agent_id": verified_by_agent_id,
                        "claim_type": claim_type
                    }
                )

            # Verify agent exists
            result = await self.session.execute(
                select(Agent).where(Agent.agent_id == agent_id)
            )
            agent = result.scalar_one_or_none()

            if not agent:
                log_and_raise(
                    AgentNotFoundError,
                    f"Agent not found: {agent_id}",
                    details={"agent_id": agent_id}
                )

            # Execute verification command
            verification_start = datetime.utcnow()
            actual_result = await self._execute_verification(verification_command)
            verification_duration_ms = (
                datetime.utcnow() - verification_start
            ).total_seconds() * 1000

            # Compare claim with actual result
            accurate = self._compare_results(claim_content, actual_result)

            # Create verification record
            verification_record = VerificationRecord(
                id=uuid4(),
                agent_id=agent_id,
                claim_type=claim_type if isinstance(claim_type, str) else claim_type.value,
                claim_content=claim_content,
                verification_command=verification_command,
                verification_result=actual_result,
                accurate=accurate,
                verified_at=datetime.utcnow(),
                verified_by_agent_id=verified_by_agent_id
            )
            self.session.add(verification_record)

            # Record evidence to memory (use agent namespace)
            evidence_memory = await self._create_evidence_memory(
                agent_id=agent_id,
                namespace=agent.namespace,
                verification_record=verification_record,
                verification_duration_ms=verification_duration_ms
            )

            # Link evidence to verification
            verification_record.evidence_memory_id = evidence_memory.id

            # Update trust score
            new_trust_score = await self.trust_service.update_trust_score(
                agent_id=agent_id,
                accurate=accurate,
                verification_id=verification_record.id,
                reason=f"verification_{claim_type}"
            )

            await self.session.commit()

            return VerificationResult(
                claim=claim_content,
                actual=actual_result,
                accurate=accurate,
                evidence_id=evidence_memory.id,
                verification_id=verification_record.id,
                new_trust_score=new_trust_score
            )

        except (AgentNotFoundError, VerificationError):
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            log_and_raise(
                DatabaseError,
                f"Failed to verify claim for agent {agent_id}",
                original_exception=e,
                details={
                    "agent_id": agent_id,
                    "claim_type": claim_type
                }
            )

    async def _execute_verification(
        self,
        command: str,
        timeout_seconds: float = 30.0
    ) -> dict[str, Any]:
        """Execute verification command and capture result

        Args:
            command: Shell command to execute
            timeout_seconds: Maximum execution time

        Returns:
            Dictionary with command output and metadata

        Raises:
            VerificationError: If command fails or times out
        """
        try:
            # Execute command in subprocess
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout_seconds
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                log_and_raise(
                    VerificationError,
                    f"Verification command timed out after {timeout_seconds}s",
                    details={"command": command, "timeout": timeout_seconds}
                )

            return {
                "stdout": stdout.decode() if stdout else "",
                "stderr": stderr.decode() if stderr else "",
                "return_code": process.returncode,
                "command": command,
                "timestamp": datetime.utcnow().isoformat()
            }

        except VerificationError:
            raise
        except Exception as e:
            log_and_raise(
                VerificationError,
                f"Failed to execute verification command: {command}",
                original_exception=e,
                details={"command": command}
            )

    def _compare_results(
        self,
        claim: dict[str, Any],
        actual: dict[str, Any]
    ) -> bool:
        """Compare claimed result with actual result

        Args:
            claim: Claimed result
            actual: Actual result from verification

        Returns:
            True if claim is accurate

        Strategy:
        1. Check return_code matches (if claimed)
        2. Check output contains claimed values
        3. Check numeric values within tolerance
        """
        # If claim specifies return_code, it must match
        if "return_code" in claim:
            if claim["return_code"] != actual.get("return_code"):
                return False

        # If claim specifies output patterns, verify them
        if "output_contains" in claim:
            actual_output = actual.get("stdout", "") + actual.get("stderr", "")
            patterns = claim["output_contains"]
            if isinstance(patterns, str):
                patterns = [patterns]

            for pattern in patterns:
                if pattern not in actual_output:
                    return False

        # If claim specifies numeric values, check with tolerance
        if "metrics" in claim and "metrics" in actual:
            for key, claimed_value in claim["metrics"].items():
                actual_value = actual["metrics"].get(key)

                if actual_value is None:
                    return False

                # Check numeric tolerance (default 5%)
                tolerance = claim.get("tolerance", 0.05)
                if isinstance(claimed_value, (int, float)):
                    if abs(actual_value - claimed_value) > abs(claimed_value * tolerance):
                        return False

        # If claim specifies exact match
        if "exact_match" in claim:
            return claim["exact_match"] == actual

        # Default: return_code 0 means success
        return actual.get("return_code") == 0

    async def _create_evidence_memory(
        self,
        agent_id: str,
        namespace: str,
        verification_record: VerificationRecord,
        verification_duration_ms: float
    ) -> Memory:
        """Create memory record with verification evidence

        Args:
            agent_id: Agent identifier
            namespace: Namespace for memory
            verification_record: Verification record
            verification_duration_ms: Execution time

        Returns:
            Created memory record
        """
        # Format evidence content
        evidence_content = self._format_evidence(
            verification_record,
            verification_duration_ms
        )

        # Create memory with proper context metadata
        memory = await self.memory_service.create_memory(
            content=evidence_content,
            agent_id=agent_id,
            namespace=namespace,
            importance_score=0.9 if verification_record.accurate else 1.0,  # Higher for failures
            tags=["verification", "evidence", verification_record.claim_type],
            context={
                "verification_id": str(verification_record.id),
                "claim_type": verification_record.claim_type,
                "accurate": verification_record.accurate,
                "duration_ms": verification_duration_ms,
                "verified_at": verification_record.verified_at.isoformat()
            }
        )

        return memory

    def _format_evidence(
        self,
        verification_record: VerificationRecord,
        duration_ms: float
    ) -> str:
        """Format verification evidence as human-readable text

        Args:
            verification_record: Verification record
            duration_ms: Execution duration

        Returns:
            Formatted evidence text
        """
        accurate_emoji = "✅" if verification_record.accurate else "❌"
        result = verification_record.verification_result

        evidence = f"""
{accurate_emoji} Verification Result: {verification_record.claim_type}

## Claim
{json.dumps(verification_record.claim_content, indent=2)}

## Verification Command
```bash
{verification_record.verification_command}
```

## Actual Result
- Return Code: {result.get('return_code')}
- Duration: {duration_ms:.2f}ms

### Output
```
{result.get('stdout', '')}
```

### Errors
```
{result.get('stderr', '')}
```

## Verdict
{'ACCURATE - Claim verified' if verification_record.accurate else 'INACCURATE - Claim rejected'}
"""
        return evidence.strip()

    async def get_verification_history(
        self,
        agent_id: str,
        claim_type: ClaimType | str | None = None,
        limit: int = 100
    ) -> list[dict[str, Any]]:
        """Get verification history for an agent

        Args:
            agent_id: Agent identifier
            claim_type: Optional filter by claim type
            limit: Maximum records to return

        Returns:
            List of verification records

        Raises:
            AgentNotFoundError: If agent doesn't exist
        """
        try:
            # Verify agent exists
            result = await self.session.execute(
                select(Agent).where(Agent.agent_id == agent_id)
            )
            if not result.scalar_one_or_none():
                log_and_raise(
                    AgentNotFoundError,
                    f"Agent not found: {agent_id}",
                    details={"agent_id": agent_id}
                )

            # Build query
            query = select(VerificationRecord).where(
                VerificationRecord.agent_id == agent_id
            )

            if claim_type:
                type_value = claim_type if isinstance(claim_type, str) else claim_type.value
                query = query.where(VerificationRecord.claim_type == type_value)

            query = query.order_by(
                VerificationRecord.verified_at.desc()
            ).limit(limit)

            result = await self.session.execute(query)
            records = result.scalars().all()

            return [
                {
                    "id": str(record.id),
                    "claim_type": record.claim_type,
                    "claim_content": record.claim_content,
                    "verification_result": record.verification_result,
                    "accurate": record.accurate,
                    "evidence_memory_id": str(record.evidence_memory_id) if record.evidence_memory_id else None,
                    "verified_at": record.verified_at.isoformat(),
                    "verified_by": record.verified_by_agent_id
                }
                for record in records
            ]

        except AgentNotFoundError:
            raise
        except Exception as e:
            log_and_raise(
                DatabaseError,
                f"Failed to get verification history for agent {agent_id}",
                original_exception=e,
                details={"agent_id": agent_id, "claim_type": claim_type}
            )

    async def get_verification_statistics(
        self,
        agent_id: str
    ) -> dict[str, Any]:
        """Get verification statistics for an agent

        Args:
            agent_id: Agent identifier

        Returns:
            Dictionary with verification statistics

        Raises:
            AgentNotFoundError: If agent doesn't exist
        """
        try:
            # Get agent with verification metrics
            result = await self.session.execute(
                select(Agent).where(Agent.agent_id == agent_id)
            )
            agent = result.scalar_one_or_none()

            if not agent:
                log_and_raise(
                    AgentNotFoundError,
                    f"Agent not found: {agent_id}",
                    details={"agent_id": agent_id}
                )

            # Get recent verifications
            recent_query = select(VerificationRecord).where(
                VerificationRecord.agent_id == agent_id
            ).order_by(
                VerificationRecord.verified_at.desc()
            ).limit(10)

            result = await self.session.execute(recent_query)
            recent_verifications = result.scalars().all()

            # Calculate statistics by claim type
            type_stats: dict[str, dict[str, int]] = {}
            for record in await self.get_verification_history(agent_id, limit=1000):
                claim_type = record["claim_type"]
                if claim_type not in type_stats:
                    type_stats[claim_type] = {"total": 0, "accurate": 0}

                type_stats[claim_type]["total"] += 1
                if record["accurate"]:
                    type_stats[claim_type]["accurate"] += 1

            return {
                "agent_id": agent_id,
                "trust_score": agent.trust_score,
                "total_verifications": agent.total_verifications,
                "accurate_verifications": agent.accurate_verifications,
                "accuracy_rate": agent.verification_accuracy,
                "requires_verification": agent.requires_verification,
                "by_claim_type": {
                    claim_type: {
                        "total": stats["total"],
                        "accurate": stats["accurate"],
                        "accuracy": stats["accurate"] / stats["total"] if stats["total"] > 0 else 0.0
                    }
                    for claim_type, stats in type_stats.items()
                },
                "recent_verifications": [
                    {
                        "claim_type": v.claim_type,
                        "accurate": v.accurate,
                        "verified_at": v.verified_at.isoformat()
                    }
                    for v in recent_verifications
                ]
            }

        except AgentNotFoundError:
            raise
        except Exception as e:
            log_and_raise(
                DatabaseError,
                f"Failed to get verification statistics for agent {agent_id}",
                original_exception=e,
                details={"agent_id": agent_id}
            )
