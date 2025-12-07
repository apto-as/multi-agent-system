"""MCP tools for agent trust and verification system

Provides user-facing interface for:
1. Verifying claims and recording evidence
2. Retrieving agent trust scores
3. Viewing verification history
"""

import logging
from typing import Any

from mcp.server import Server

from src.core.database import get_session
from src.services.trust_service import TrustService
from src.services.verification_service import ClaimType, VerificationService

logger = logging.getLogger(__name__)


async def register_verification_tools(mcp: Server) -> None:
    """Register verification tools with MCP server

    Args:
        mcp: MCP server instance
    """

    @mcp.tool()
    async def verify_and_record(
        agent_id: str,
        claim_type: str,
        claim_content: dict[str, Any],
        verification_command: str,
        verified_by_agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Verify a claim and record evidence

        This tool executes a verification command to validate an agent's claim,
        records the evidence in memory, and updates the agent's trust score.

        Args:
            agent_id: Agent making the claim (e.g., "artemis-optimizer")
            claim_type: Type of claim - one of:
                - test_result: Test execution results
                - performance_metric: Performance measurements
                - code_quality: Code quality metrics
                - security_finding: Security audit findings
                - deployment_status: Deployment status
                - custom: Other claim types
            claim_content: The claim to verify as JSON, e.g.:
                {"return_code": 0, "output_contains": "100% PASSED"}
                {"metrics": {"coverage": 90.0}, "tolerance": 0.05}
            verification_command: Shell command to execute for verification
            verified_by_agent_id: Optional agent performing verification

        Returns:
            Dictionary with verification result:
            {
                "claim": {...},  # Original claim
                "actual": {...},  # Actual result
                "accurate": true/false,
                "evidence_id": "uuid",  # Memory ID of evidence
                "verification_id": "uuid",
                "new_trust_score": 0.55
            }

        Example:
            await verify_and_record(
                agent_id="artemis-optimizer",
                claim_type="test_result",
                claim_content={
                    "return_code": 0,
                    "output_contains": ["PASSED", "100%"]
                },
                verification_command="pytest tests/unit/ -v"
            )

        Raises:
            AgentNotFoundError: If agent doesn't exist
            VerificationError: If verification command fails
        """
        async with get_session() as session:
            service = VerificationService(session)

            result = await service.verify_claim(
                agent_id=agent_id,
                claim_type=ClaimType(claim_type),
                claim_content=claim_content,
                verification_command=verification_command,
                verified_by_agent_id=verified_by_agent_id,
            )

            return result.to_dict()

    @mcp.tool()
    async def get_agent_trust_score(agent_id: str) -> dict[str, Any]:
        """Get agent trust score and statistics

        Args:
            agent_id: Agent identifier (e.g., "artemis-optimizer")

        Returns:
            Dictionary with trust information:
            {
                "agent_id": "artemis-optimizer",
                "trust_score": 0.75,
                "total_verifications": 20,
                "accurate_verifications": 15,
                "verification_accuracy": 0.75,
                "requires_verification": false,
                "is_reliable": true
            }

        Example:
            score_info = await get_agent_trust_score("artemis-optimizer")
            if score_info["requires_verification"]:
                print("This agent requires verification for reports")

        Raises:
            AgentNotFoundError: If agent doesn't exist
        """
        async with get_session() as session:
            service = TrustService(session)
            return await service.get_trust_score(agent_id)

    @mcp.tool()
    async def get_verification_history(
        agent_id: str, claim_type: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Get agent verification history

        Args:
            agent_id: Agent identifier
            claim_type: Optional filter by claim type
            limit: Maximum records to return (default: 100)

        Returns:
            List of verification records:
            [
                {
                    "id": "uuid",
                    "claim_type": "test_result",
                    "claim_content": {...},
                    "verification_result": {...},
                    "accurate": true,
                    "evidence_memory_id": "uuid",
                    "verified_at": "2025-01-01T12:00:00",
                    "verified_by": "hestia-auditor"
                },
                ...
            ]

        Example:
            # Get all verifications
            history = await get_verification_history("artemis-optimizer")

            # Get only test results
            test_history = await get_verification_history(
                "artemis-optimizer",
                claim_type="test_result"
            )

        Raises:
            AgentNotFoundError: If agent doesn't exist
        """
        async with get_session() as session:
            service = VerificationService(session)

            return await service.get_verification_history(
                agent_id=agent_id,
                claim_type=ClaimType(claim_type) if claim_type else None,
                limit=limit,
            )

    @mcp.tool()
    async def get_verification_statistics(agent_id: str) -> dict[str, Any]:
        """Get comprehensive verification statistics for an agent

        Args:
            agent_id: Agent identifier

        Returns:
            Dictionary with statistics:
            {
                "agent_id": "artemis-optimizer",
                "trust_score": 0.75,
                "total_verifications": 100,
                "accurate_verifications": 75,
                "accuracy_rate": 0.75,
                "requires_verification": false,
                "by_claim_type": {
                    "test_result": {
                        "total": 50,
                        "accurate": 45,
                        "accuracy": 0.9
                    },
                    "security_finding": {
                        "total": 30,
                        "accurate": 20,
                        "accuracy": 0.67
                    }
                },
                "recent_verifications": [...]
            }

        Example:
            stats = await get_verification_statistics("artemis-optimizer")
            print(f"Trust score: {stats['trust_score']:.2%}")
            print(f"Accuracy by type: {stats['by_claim_type']}")

        Raises:
            AgentNotFoundError: If agent doesn't exist
        """
        async with get_session() as session:
            service = VerificationService(session)
            return await service.get_verification_statistics(agent_id)

    @mcp.tool()
    async def get_trust_history(agent_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Get agent trust score history

        Args:
            agent_id: Agent identifier
            limit: Maximum records to return (default: 100)

        Returns:
            List of trust score changes:
            [
                {
                    "id": "uuid",
                    "old_score": 0.5,
                    "new_score": 0.55,
                    "delta": +0.05,
                    "verification_id": "uuid",
                    "reason": "verification_test_result",
                    "changed_at": "2025-01-01T12:00:00"
                },
                ...
            ]

        Example:
            history = await get_trust_history("artemis-optimizer", limit=10)
            for change in history:
                delta = change['delta']
                sign = '+' if delta > 0 else ''
                print(f"{change['changed_at']}: {sign}{delta:.3f} ({change['reason']})")

        Raises:
            AgentNotFoundError: If agent doesn't exist
        """
        async with get_session() as session:
            service = TrustService(session)
            return await service.get_trust_history(agent_id, limit=limit)
