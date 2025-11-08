#!/usr/bin/env python3
"""Verification script for Agent Trust & Verification System

This script demonstrates that all components are properly implemented:
1. Models compile and import correctly
2. Services are functional
3. Algorithms produce expected results
4. All classes are properly structured

Usage:
    python scripts/verify_trust_system.py
"""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def verify_imports():
    """Verify all components can be imported"""
    print("=" * 60)
    print("PHASE 1: Verifying Imports")
    print("=" * 60)

    try:
        from src.models.verification import VerificationRecord, TrustScoreHistory
        print("✅ Models: VerificationRecord, TrustScoreHistory")

        from src.services.trust_service import TrustService, TrustScoreCalculator
        print("✅ Services: TrustService, TrustScoreCalculator")

        from src.services.verification_service import (
            VerificationService,
            ClaimType,
            VerificationResult
        )
        print("✅ Services: VerificationService, ClaimType, VerificationResult")

        from src.core.exceptions import AgentNotFoundError, VerificationError
        print("✅ Exceptions: AgentNotFoundError, VerificationError")

        print("\n✅ All imports successful!\n")
        return True

    except Exception as e:
        print(f"\n❌ Import failed: {e}\n")
        return False


def verify_trust_calculator():
    """Verify trust score calculator algorithm"""
    print("=" * 60)
    print("PHASE 2: Verifying Trust Score Calculator")
    print("=" * 60)

    try:
        from src.services.trust_service import TrustScoreCalculator

        calc = TrustScoreCalculator(alpha=0.1, min_observations=5)

        # Test 1: Accurate verification increases score
        old_score = 0.5
        new_score = calc.calculate_new_score(old_score, accurate=True)
        expected = 0.1 * 1.0 + 0.9 * 0.5  # 0.55
        assert abs(new_score - expected) < 0.001, f"Expected {expected}, got {new_score}"
        print(f"✅ Accurate verification: {old_score:.3f} → {new_score:.3f} (+{new_score-old_score:.3f})")

        # Test 2: Inaccurate verification decreases score
        old_score = 0.5
        new_score = calc.calculate_new_score(old_score, accurate=False)
        expected = 0.1 * 0.0 + 0.9 * 0.5  # 0.45
        assert abs(new_score - expected) < 0.001, f"Expected {expected}, got {new_score}"
        print(f"✅ Inaccurate verification: {old_score:.3f} → {new_score:.3f} ({new_score-old_score:.3f})")

        # Test 3: Convergence with repeated accurate verifications
        score = 0.5
        for _ in range(100):
            score = calc.calculate_new_score(score, accurate=True)
        assert score > 0.95, f"Expected >0.95 after 100 accurate, got {score}"
        print(f"✅ Convergence (100 accurate): 0.500 → {score:.3f}")

        # Test 4: Convergence with repeated inaccurate verifications
        score = 0.5
        for _ in range(100):
            score = calc.calculate_new_score(score, accurate=False)
        assert score < 0.05, f"Expected <0.05 after 100 inaccurate, got {score}"
        print(f"✅ Convergence (100 inaccurate): 0.500 → {score:.3f}")

        # Test 5: Reliability check
        assert not calc.is_reliable(4), "Should not be reliable with 4 observations"
        assert calc.is_reliable(5), "Should be reliable with 5 observations"
        print(f"✅ Reliability threshold: {calc.min_observations} observations")

        print("\n✅ Trust calculator algorithm verified!\n")
        return True

    except Exception as e:
        print(f"\n❌ Trust calculator test failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False


def verify_claim_types():
    """Verify claim types are properly defined"""
    print("=" * 60)
    print("PHASE 3: Verifying Claim Types")
    print("=" * 60)

    try:
        from src.services.verification_service import ClaimType

        expected_types = [
            "test_result",
            "performance_metric",
            "code_quality",
            "security_finding",
            "deployment_status",
            "custom"
        ]

        actual_types = [ct.value for ct in ClaimType]

        for expected in expected_types:
            assert expected in actual_types, f"Missing claim type: {expected}"
            print(f"✅ ClaimType.{expected.upper()}")

        print("\n✅ All claim types defined!\n")
        return True

    except Exception as e:
        print(f"\n❌ Claim types test failed: {e}\n")
        return False


def verify_model_properties():
    """Verify Agent model trust-related properties"""
    print("=" * 60)
    print("PHASE 4: Verifying Agent Model Properties")
    print("=" * 60)

    try:
        from src.models.agent import Agent

        # Test 1: verification_accuracy property
        agent = Agent(
            agent_id="test",
            display_name="Test",
            namespace="test",
            total_verifications=10,
            accurate_verifications=7
        )
        assert agent.verification_accuracy == 0.7
        print(f"✅ verification_accuracy: 7/10 = {agent.verification_accuracy:.1f}")

        # Test 2: verification_accuracy with no verifications
        agent_new = Agent(
            agent_id="new",
            display_name="New",
            namespace="test",
            total_verifications=0,
            accurate_verifications=0
        )
        assert agent_new.verification_accuracy == 0.5  # Neutral starting point
        print(f"✅ verification_accuracy (no data): {agent_new.verification_accuracy:.1f} (neutral)")

        # Test 3: requires_verification property
        agent_trusted = Agent(
            agent_id="trusted",
            display_name="Trusted",
            namespace="test",
            trust_score=0.8
        )
        assert agent_trusted.requires_verification is False
        print(f"✅ requires_verification (trust={agent_trusted.trust_score:.1f}): {agent_trusted.requires_verification}")

        agent_untrusted = Agent(
            agent_id="untrusted",
            display_name="Untrusted",
            namespace="test",
            trust_score=0.5
        )
        assert agent_untrusted.requires_verification is True
        print(f"✅ requires_verification (trust={agent_untrusted.trust_score:.1f}): {agent_untrusted.requires_verification}")

        print("\n✅ Agent model properties verified!\n")
        return True

    except Exception as e:
        print(f"\n❌ Agent model test failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all verification tests"""
    print("\n" + "=" * 60)
    print(" Agent Trust & Verification System - Verification Script")
    print("=" * 60 + "\n")

    results = []

    # Run all verification phases
    results.append(("Imports", verify_imports()))
    results.append(("Trust Calculator", verify_trust_calculator()))
    results.append(("Claim Types", verify_claim_types()))
    results.append(("Agent Model Properties", verify_model_properties()))

    # Summary
    print("=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)

    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{name:.<40} {status}")
        if not passed:
            all_passed = False

    print("=" * 60)

    if all_passed:
        print("\n✅ ALL VERIFICATIONS PASSED\n")
        print("The Agent Trust & Verification System is properly implemented.")
        print("All components are functional and ready for testing.\n")
        return 0
    else:
        print("\n❌ SOME VERIFICATIONS FAILED\n")
        print("Please review the errors above and fix the issues.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
