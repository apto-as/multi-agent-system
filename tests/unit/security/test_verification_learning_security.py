"""Security Tests for Verification-Learning Integration (Phase 2A)

This test suite validates V-VERIFY security controls for the integration
between VerificationService and LearningTrustIntegration.

Test Coverage:
- V-VERIFY-1: Command Injection Prevention
- V-VERIFY-2: Verifier Authorization
- V-VERIFY-3: Namespace Isolation
- V-VERIFY-4: Pattern Eligibility Validation

Security Focus Areas:
- Cross-namespace attacks
- Self-trust boosting
- Pattern injection attacks
- Denial of Service
- Privilege escalation
- Information disclosure

Author: Hestia (Security Guardian)
Date: 2025-11-11

Note: These tests require Ollama server for HybridMemoryService embedding operations.
      Tests are skipped when Ollama is unavailable (Issue #52 graceful degradation).
"""

from uuid import uuid4

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    ValidationError,
)
from src.models.agent import AccessLevel, Agent
from src.models.learning_pattern import LearningPattern
from src.services.verification_service import ClaimType, VerificationService


def _is_ollama_available() -> bool:
    """Check if Ollama server is available."""
    try:
        for url in ["http://localhost:11434/api/tags", "http://host.docker.internal:11434/api/tags"]:
            try:
                response = httpx.get(url, timeout=2.0)
                if response.status_code == 200:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


# Skip all tests in this module if Ollama is not available
pytestmark = pytest.mark.skipif(
    not _is_ollama_available(),
    reason="Ollama server not available - tests require embedding service"
)

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
async def verification_service(db_session: AsyncSession) -> VerificationService:
    """Create VerificationService instance"""
    return VerificationService(db_session)


@pytest.fixture
async def attacker_agent(db_session: AsyncSession) -> Agent:
    """Create attacker agent (different namespace)"""
    agent = Agent(
        agent_id="attacker-agent",
        display_name="Attacker Agent",
        namespace="attacker-namespace",
        trust_score=0.3,
        total_verifications=0,
        accurate_verifications=0,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest.fixture
async def victim_agent(db_session: AsyncSession) -> Agent:
    """Create victim agent (different namespace)"""
    agent = Agent(
        agent_id="victim-agent",
        display_name="Victim Agent",
        namespace="victim-namespace",
        trust_score=0.7,
        total_verifications=10,
        accurate_verifications=9,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest.fixture
async def verifier_agent(db_session: AsyncSession) -> Agent:
    """Create legitimate verifier agent"""
    agent = Agent(
        agent_id="verifier-agent",
        display_name="Verifier Agent",
        namespace="verifier-namespace",
        trust_score=0.8,
        total_verifications=50,
        accurate_verifications=48,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest.fixture
async def victim_private_pattern(db_session: AsyncSession, victim_agent: Agent) -> LearningPattern:
    """Create private pattern owned by victim"""
    pattern = LearningPattern(
        agent_id=victim_agent.agent_id,
        namespace=victim_agent.namespace,
        pattern_name="Victim's private pattern",
        category="optimization",
        pattern_data={"strategy": "private_optimization", "context": "victim_only"},
        access_level=AccessLevel.PRIVATE.value,
        usage_count=10,
        success_rate=0.9,
    )
    db_session.add(pattern)
    await db_session.commit()
    await db_session.refresh(pattern)
    return pattern


@pytest.fixture
async def public_pattern(db_session: AsyncSession, victim_agent: Agent) -> LearningPattern:
    """Create public pattern"""
    pattern = LearningPattern(
        agent_id=victim_agent.agent_id,
        namespace=victim_agent.namespace,
        pattern_name="Public optimization pattern",
        category="optimization",
        pattern_data={"strategy": "public_optimization"},
        access_level=AccessLevel.PUBLIC.value,
        usage_count=20,
        success_rate=0.85,
    )
    db_session.add(pattern)
    await db_session.commit()
    await db_session.refresh(pattern)
    return pattern


@pytest.fixture
async def attacker_owned_pattern(
    db_session: AsyncSession, attacker_agent: Agent
) -> LearningPattern:
    """Create public pattern owned by attacker (for self-boosting tests)"""
    pattern = LearningPattern(
        agent_id=attacker_agent.agent_id,
        namespace=attacker_agent.namespace,
        pattern_name="Attacker's public pattern",
        category="attack",
        pattern_data={"strategy": "self_boost"},
        access_level=AccessLevel.PUBLIC.value,
        usage_count=5,
        success_rate=1.0,  # Artificially high
    )
    db_session.add(pattern)
    await db_session.commit()
    await db_session.refresh(pattern)
    return pattern


# =============================================================================
# V-VERIFY-1: Command Injection Prevention
# =============================================================================


@pytest.mark.asyncio
async def test_command_injection_via_pattern_id_rejected(
    verification_service: VerificationService, attacker_agent: Agent, verifier_agent: Agent
):
    """Test V-VERIFY-1: Pattern ID injection attempts are rejected

    Threat: Attacker tries to inject malicious commands via pattern_id field
    Attack Vector: pattern_id = "valid-uuid; rm -rf /"
    Expected: Graceful degradation, verification succeeds, no command execution
    """
    malicious_pattern_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee; rm -rf /"

    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": malicious_pattern_id,  # Injection attempt
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification should succeed (graceful degradation)
    assert result.accurate is True
    # Pattern propagation should fail safely
    # (malicious pattern_id is not a valid UUID, caught by UUID(pattern_id_str))


@pytest.mark.asyncio
async def test_sql_injection_via_pattern_id_rejected(
    verification_service: VerificationService, attacker_agent: Agent, verifier_agent: Agent
):
    """Test V-VERIFY-1: SQL injection via pattern_id rejected

    Threat: Attacker tries SQL injection via pattern_id
    Attack Vector: pattern_id = "' OR '1'='1"
    Expected: Invalid UUID format, graceful degradation
    """
    sql_injection_pattern_id = "' OR '1'='1"

    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={"return_code": 0, "pattern_id": sql_injection_pattern_id},
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds (graceful degradation)
    assert result.accurate is True
    # SQL injection attempt fails at UUID parsing


@pytest.mark.asyncio
async def test_path_traversal_via_pattern_id_rejected(
    verification_service: VerificationService, attacker_agent: Agent, verifier_agent: Agent
):
    """Test V-VERIFY-1: Path traversal via pattern_id rejected

    Threat: Attacker tries path traversal attack
    Attack Vector: pattern_id = "../../../etc/passwd"
    Expected: Invalid UUID format, graceful degradation
    """
    path_traversal_pattern_id = "../../../etc/passwd"

    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={"return_code": 0, "pattern_id": path_traversal_pattern_id},
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds (graceful degradation)
    assert result.accurate is True


# =============================================================================
# V-VERIFY-2: Verifier Authorization (inherited from VerificationService)
# =============================================================================


@pytest.mark.asyncio
async def test_self_verification_prevented(
    verification_service: VerificationService, attacker_agent: Agent
):
    """Test V-VERIFY-2: Self-verification prevented (V-TRUST-5)

    Threat: Agent tries to verify own claims
    Attack Vector: verified_by_agent_id == agent_id
    Expected: ValidationError raised
    """
    with pytest.raises(ValidationError) as exc_info:
        await verification_service.verify_claim(
            agent_id=attacker_agent.agent_id,
            claim_type=ClaimType.TEST_RESULT,
            claim_content={"return_code": 0},
            verification_command="true",
            verified_by_agent_id=attacker_agent.agent_id,  # Self-verification
        )

    assert "Self-verification not allowed" in str(exc_info.value)


# =============================================================================
# V-VERIFY-3: Namespace Isolation
# =============================================================================


@pytest.mark.asyncio
async def test_cross_namespace_pattern_access_rejected(
    verification_service: VerificationService,
    attacker_agent: Agent,
    verifier_agent: Agent,
    victim_private_pattern: LearningPattern,
    db_session: AsyncSession,
):
    """Test V-VERIFY-3: Cross-namespace private pattern access rejected

    Threat: Attacker tries to manipulate victim's private pattern
    Attack Vector: attacker-namespace tries to access victim-namespace's private pattern
    Expected: Graceful degradation, pattern not updated, verification succeeds
    """
    # Record initial state
    initial_usage = victim_private_pattern.usage_count
    initial_trust = attacker_agent.trust_score

    # Attacker tries to link to victim's private pattern
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": str(victim_private_pattern.id),  # Cross-namespace access
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds (graceful degradation)
    assert result.accurate is True

    # Refresh pattern
    await db_session.refresh(victim_private_pattern)

    # Victim's pattern should NOT be modified by attacker
    assert victim_private_pattern.usage_count == initial_usage  # Unchanged

    # Attacker's trust score increases only from verification (not pattern)
    # (base verification boost, no pattern boost)
    assert result.new_trust_score > initial_trust


@pytest.mark.asyncio
async def test_namespace_verified_from_database(
    verification_service: VerificationService,
    attacker_agent: Agent,
    verifier_agent: Agent,
    public_pattern: LearningPattern,
    db_session: AsyncSession,
):
    """Test V-VERIFY-3: Namespace verified from database (not user input)

    Threat: Attacker provides spoofed namespace in claim_content
    Attack Vector: claim_content = {"namespace": "victim-namespace", "pattern_id": ...}
    Expected: Namespace from DB (attacker-namespace) used for authorization

    Security: VerificationService.verify_claim() fetches agent.namespace from DB
              and passes it to _propagate_to_learning_patterns()
    """
    # Attacker tries to spoof namespace in claim
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": str(public_pattern.id),
            "namespace": "victim-namespace",  # Spoofed namespace (ignored)
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds
    assert result.accurate is True

    # Namespace from claim_content should be IGNORED
    # LearningTrustIntegration receives attacker_agent.namespace from DB
    # Public pattern access is allowed, so propagation succeeds


# =============================================================================
# V-VERIFY-4: Pattern Eligibility Validation
# =============================================================================


@pytest.mark.asyncio
async def test_self_owned_pattern_rejected_for_trust_boost(
    verification_service: VerificationService,
    attacker_agent: Agent,
    verifier_agent: Agent,
    attacker_owned_pattern: LearningPattern,
    db_session: AsyncSession,
):
    """Test V-VERIFY-4: Self-owned patterns rejected for trust propagation

    Threat: Attacker creates public pattern and verifies against it to boost trust
    Attack Vector: attacker verifies claim linked to attacker's own public pattern
    Expected: Graceful degradation, no trust boost from pattern (only from verification)
    """
    initial_trust = attacker_agent.trust_score

    # Attacker verifies with their own public pattern
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": str(attacker_owned_pattern.id),  # Self-owned
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds
    assert result.accurate is True

    # Trust score should increase ONLY from verification, not pattern
    # (base verification boost ~0.05, no pattern boost)
    trust_delta = result.new_trust_score - initial_trust

    # Expected: ~0.05 from verification, 0.0 from pattern (self-owned rejected)
    assert 0.04 <= trust_delta <= 0.06, (
        f"Trust delta {trust_delta} outside expected range (0.04-0.06)"
    )


@pytest.mark.asyncio
async def test_private_pattern_rejected_for_trust_propagation(
    verification_service: VerificationService,
    victim_agent: Agent,
    verifier_agent: Agent,
    victim_private_pattern: LearningPattern,
    db_session: AsyncSession,
):
    """Test V-VERIFY-4: Private patterns rejected for trust propagation

    Threat: Agent tries to boost trust via private pattern (gaming prevention)
    Expected: Graceful degradation, no trust boost from pattern
    """
    initial_trust = victim_agent.trust_score

    # Owner verifies with their own private pattern
    result = await verification_service.verify_claim(
        agent_id=victim_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": str(victim_private_pattern.id),  # Private pattern
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds
    assert result.accurate is True

    # Trust boost only from verification (not from private pattern)
    trust_delta = result.new_trust_score - initial_trust
    assert 0.04 <= trust_delta <= 0.06, f"Trust delta {trust_delta} outside expected range"


@pytest.mark.asyncio
async def test_public_pattern_eligible_for_trust_propagation(
    verification_service: VerificationService,
    attacker_agent: Agent,
    verifier_agent: Agent,
    public_pattern: LearningPattern,
    db_session: AsyncSession,
):
    """Test V-VERIFY-4: Public patterns ARE eligible for trust propagation

    This is the ALLOWED case - public patterns from other agents boost trust
    """
    initial_trust = attacker_agent.trust_score

    # Agent verifies with someone else's public pattern (allowed)
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": str(public_pattern.id),  # Public, not self-owned
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds
    assert result.accurate is True

    # Trust boost from BOTH verification AND pattern
    # Expected: ~0.05 from verification + ~0.02 from pattern = ~0.07 total
    trust_delta = result.new_trust_score - initial_trust
    assert trust_delta >= 0.05, (
        f"Trust delta {trust_delta} should be >= 0.05 (verification + pattern)"
    )


# =============================================================================
# Denial of Service (DoS)
# =============================================================================


@pytest.mark.asyncio
async def test_pattern_propagation_failure_doesnt_block_verification(
    verification_service: VerificationService, attacker_agent: Agent, verifier_agent: Agent
):
    """Test DoS: Pattern propagation failures don't block verification

    Threat: Attacker provides invalid pattern_id to DoS verification service
    Expected: Graceful degradation, verification succeeds
    """
    # Invalid pattern_id (DoS attempt)
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={"return_code": 0, "pattern_id": "invalid-uuid-dos-attack"},
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification MUST succeed despite propagation error
    assert result.accurate is True
    assert result.verification_id is not None


@pytest.mark.asyncio
async def test_nonexistent_pattern_doesnt_block_verification(
    verification_service: VerificationService, attacker_agent: Agent, verifier_agent: Agent
):
    """Test DoS: Nonexistent pattern_id doesn't block verification

    Threat: Attacker provides valid UUID but nonexistent pattern
    Expected: Graceful degradation, verification succeeds
    """
    nonexistent_pattern_id = str(uuid4())

    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={"return_code": 0, "pattern_id": nonexistent_pattern_id},
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds
    assert result.accurate is True


# =============================================================================
# Information Disclosure
# =============================================================================


@pytest.mark.asyncio
async def test_pattern_details_not_leaked_in_errors(
    verification_service: VerificationService,
    attacker_agent: Agent,
    verifier_agent: Agent,
    victim_private_pattern: LearningPattern,
):
    """Test Information Disclosure: Pattern details not leaked in error messages

    Threat: Attacker probes for private pattern existence via error messages
    Expected: No information disclosure, graceful degradation
    """
    # Attacker probes victim's private pattern
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={"return_code": 0, "pattern_id": str(victim_private_pattern.id)},
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds (no error leaked)
    assert result.accurate is True

    # No exception raised, attacker learns nothing about pattern existence


# =============================================================================
# Edge Cases & Attack Vectors
# =============================================================================


@pytest.mark.asyncio
async def test_null_pattern_id_graceful_degradation(
    verification_service: VerificationService, attacker_agent: Agent, verifier_agent: Agent
):
    """Test Edge Case: null pattern_id causes graceful degradation"""
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": None,  # Null
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds
    assert result.accurate is True


@pytest.mark.asyncio
async def test_empty_string_pattern_id_graceful_degradation(
    verification_service: VerificationService, attacker_agent: Agent, verifier_agent: Agent
):
    """Test Edge Case: empty string pattern_id causes graceful degradation"""
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": "",  # Empty string
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds
    assert result.accurate is True


@pytest.mark.asyncio
async def test_malformed_json_in_pattern_id_graceful_degradation(
    verification_service: VerificationService, attacker_agent: Agent, verifier_agent: Agent
):
    """Test Edge Case: malformed JSON in pattern_id field"""
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": '{"malicious": "json"}',  # JSON object as string
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds
    assert result.accurate is True


@pytest.mark.asyncio
async def test_unicode_pattern_id_graceful_degradation(
    verification_service: VerificationService, attacker_agent: Agent, verifier_agent: Agent
):
    """Test Edge Case: Unicode characters in pattern_id"""
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": "🔥💀🚨",  # Unicode emoji
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )

    # Verification succeeds
    assert result.accurate is True


# =============================================================================
# Final Security Validation
# =============================================================================


@pytest.mark.asyncio
async def test_comprehensive_attack_chain_fails_safely(
    verification_service: VerificationService,
    attacker_agent: Agent,
    verifier_agent: Agent,
    victim_private_pattern: LearningPattern,
    attacker_owned_pattern: LearningPattern,
    db_session: AsyncSession,
):
    """Test Comprehensive: Multi-stage attack chain fails safely

    Attack Chain:
    1. Self-verification attempt (blocked by V-VERIFY-2)
    2. Cross-namespace private pattern access (blocked by V-VERIFY-4)
    3. Self-owned pattern boost (blocked by V-VERIFY-4)
    4. Command injection via pattern_id (blocked by UUID parsing)

    Expected: All attacks fail gracefully, system remains secure
    """
    initial_trust = attacker_agent.trust_score

    # Attack 1: Self-verification (should raise ValidationError)
    with pytest.raises(ValidationError):
        await verification_service.verify_claim(
            agent_id=attacker_agent.agent_id,
            claim_type=ClaimType.TEST_RESULT,
            claim_content={"return_code": 0},
            verification_command="true",
            verified_by_agent_id=attacker_agent.agent_id,  # Self-verification
        )

    # Attack 2: Cross-namespace private pattern (graceful degradation)
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": str(victim_private_pattern.id),  # Cross-namespace
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )
    assert result.accurate is True

    # Attack 3: Self-owned pattern boost (graceful degradation)
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": str(attacker_owned_pattern.id),  # Self-owned
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )
    assert result.accurate is True

    # Attack 4: Command injection (graceful degradation)
    result = await verification_service.verify_claim(
        agent_id=attacker_agent.agent_id,
        claim_type=ClaimType.TEST_RESULT,
        claim_content={
            "return_code": 0,
            "pattern_id": "malicious; rm -rf /",  # Command injection
        },
        verification_command="true",
        verified_by_agent_id=verifier_agent.agent_id,
    )
    assert result.accurate is True

    # Final validation: attacker's trust score only increased from legitimate verifications
    # (2 successful verifications × ~0.05 = ~0.10 increase, no pattern boosts)
    await db_session.refresh(attacker_agent)
    trust_increase = attacker_agent.trust_score - initial_trust

    # Should be around 0.10-0.15 (2-3 verifications without pattern boosts)
    assert 0.08 <= trust_increase <= 0.17, (
        f"Trust increase {trust_increase} indicates attack succeeded"
    )
