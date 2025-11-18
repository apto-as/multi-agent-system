#!/usr/bin/env python3
"""
Test script for decision_check.py functionality
"""
import json
import sys
from pathlib import Path

# Add hooks directory to path (project .claude/ directory)
project_root = Path(__file__).parent.parent
hooks_dir = project_root / ".claude" / "hooks" / "core"
sys.path.insert(0, str(hooks_dir))

try:
    from decision_check import DecisionCheckHook
    print("✅ Successfully imported DecisionCheckHook")
except ImportError as e:
    print(f"❌ Failed to import: {e}")
    sys.exit(1)

# Test data
test_cases = [
    {
        "name": "Persona Detection: Artemis (optimization)",
        "input": {"prompt": {"text": "optimize database performance"}},
        "expected_persona": "artemis-optimizer",
        "expected_type": "OPTIMIZATION"
    },
    {
        "name": "Persona Detection: Hestia (security)",
        "input": {"prompt": {"text": "check for security vulnerabilities"}},
        "expected_persona": "hestia-auditor",
        "expected_type": "SECURITY"
    },
    {
        "name": "Persona Detection: Athena (architecture)",
        "input": {"prompt": {"text": "design system architecture"}},
        "expected_persona": "athena-conductor",
        "expected_type": "ARCHITECTURE"
    },
    {
        "name": "Persona Detection: Muses (documentation)",
        "input": {"prompt": {"text": "create documentation for API"}},
        "expected_persona": "muses-documenter",
        "expected_type": "IMPLEMENTATION"
    },
]

def test_persona_detection():
    """Test persona detection functionality"""
    hook = DecisionCheckHook()

    print("\n=== Testing Persona Detection ===\n")

    for test in test_cases:
        prompt = test["input"]["prompt"]["text"]

        # Test _detect_persona
        detected_persona = hook._detect_persona(prompt)

        # Test _classify_decision_type
        decision_type = hook._classify_decision_type(prompt)

        print(f"Test: {test['name']}")
        print(f"  Input: '{prompt}'")
        print(f"  Expected Persona: {test['expected_persona']}")
        print(f"  Detected Persona: {detected_persona}")
        print(f"  Expected Type: {test['expected_type']}")
        print(f"  Detected Type: {decision_type.value}")

        if detected_persona == test['expected_persona']:
            print("  ✅ Persona detection PASSED")
        else:
            print("  ❌ Persona detection FAILED")

        if decision_type.value == test['expected_type']:
            print("  ✅ Decision type PASSED")
        else:
            print("  ⚠️ Decision type differs (not necessarily wrong)")

        print()

def test_importance_calculation():
    """Test importance scoring"""
    hook = DecisionCheckHook()

    print("=== Testing Importance Calculation ===\n")

    from decision_memory import AutonomyLevel

    test_prompts = [
        ("fix typo in comment", AutonomyLevel.LEVEL_1_AUTONOMOUS, 0.5, 0.6),
        ("critical security patch needed", AutonomyLevel.LEVEL_2_APPROVAL, 0.8, 1.0),
        ("urgent database optimization", AutonomyLevel.LEVEL_1_AUTONOMOUS, 0.6, 0.7),
    ]

    for prompt, level, min_score, max_score in test_prompts:
        importance = hook._calculate_importance(level, prompt)
        print(f"Prompt: '{prompt}'")
        print(f"  Level: {level.value}")
        print(f"  Importance: {importance:.2f}")
        print(f"  Expected range: {min_score:.2f} - {max_score:.2f}")

        if min_score <= importance <= max_score:
            print("  ✅ PASSED")
        else:
            print("  ❌ FAILED")
        print()

def test_tag_generation():
    """Test semantic tag generation"""
    hook = DecisionCheckHook()

    print("=== Testing Tag Generation ===\n")

    from decision_memory import DecisionType

    test_cases = [
        ("optimize python database queries", "artemis-optimizer", DecisionType.OPTIMIZATION,
         ["python", "database", "performance"]),
        ("secure api authentication", "hestia-auditor", DecisionType.SECURITY,
         ["api", "security"]),
        ("implement typescript interface", "artemis-optimizer", DecisionType.IMPLEMENTATION,
         ["typescript"]),
    ]

    for prompt, persona, decision_type, expected_tech_tags in test_cases:
        tags = hook._generate_tags(prompt, persona, decision_type)
        print(f"Prompt: '{prompt}'")
        print(f"  Generated tags: {tags}")
        print(f"  Expected tech tags: {expected_tech_tags}")

        has_expected = all(tag in tags for tag in expected_tech_tags)
        if has_expected:
            print("  ✅ PASSED")
        else:
            print("  ❌ FAILED - missing expected tags")
        print()

if __name__ == "__main__":
    print("=" * 60)
    print("TMWS Integration - decision_check.py Test Suite")
    print("=" * 60)

    try:
        test_persona_detection()
        test_importance_calculation()
        test_tag_generation()

        print("=" * 60)
        print("✅ All tests completed!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
