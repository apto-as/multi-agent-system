#!/usr/bin/env python3
"""
Test script for precompact_memory_injection.py functionality
"""
import json
import sys
from pathlib import Path

# Add hooks directory to path (project .claude/ directory)
project_root = Path(__file__).parent.parent
hooks_dir = project_root / ".claude" / "hooks" / "core"
sys.path.insert(0, str(hooks_dir))

try:
    from precompact_memory_injection import PreCompactMemoryInjectionHook
    print("✅ Successfully imported PreCompactMemoryInjectionHook")
except ImportError as e:
    print(f"❌ Failed to import: {e}")
    sys.exit(1)

def test_query_extraction():
    """Test extraction of recent user queries"""
    hook = PreCompactMemoryInjectionHook()

    print("\n=== Testing Query Extraction ===\n")

    # Test data: conversation with mixed user/assistant messages
    test_conversation = {
        "conversation": {
            "messages": [
                {"role": "user", "content": "How do we optimize the database?"},
                {"role": "assistant", "content": "We can add indexes..."},
                {"role": "user", "content": "What about security concerns?"},
                {"role": "assistant", "content": "Good point..."},
                {"role": "user", "content": "Can you check for vulnerabilities?"},
                {"role": "assistant", "content": "I'll scan..."},
                {"role": "user", "content": "Also optimize the API calls"},
            ]
        }
    }

    queries = hook._extract_recent_queries(
        test_conversation["conversation"]["messages"],
        limit=3
    )

    print("Extracted queries (last 3 user messages):")
    for i, query in enumerate(queries, 1):
        print(f"  {i}. {query}")

    expected_count = 3
    expected_last = "Also optimize the API calls"

    if len(queries) == expected_count:
        print(f"\n✅ Extracted correct number of queries ({expected_count})")
    else:
        print(f"\n❌ Expected {expected_count} queries, got {len(queries)}")

    if queries and queries[0] == expected_last:
        print(f"✅ Most recent query is correct")
    else:
        print(f"❌ Most recent query mismatch")

    print()

def test_memory_deduplication():
    """Test memory deduplication logic"""
    hook = PreCompactMemoryInjectionHook()

    print("=== Testing Memory Deduplication ===\n")

    # Mock Decision objects
    from decision_memory import Decision, DecisionType, AutonomyLevel, DecisionOutcome
    from datetime import datetime

    # Create duplicate memories (same decision_id)
    memories = [
        Decision(
            decision_id="decision-001",
            timestamp=datetime.now(),
            decision_type=DecisionType.OPTIMIZATION,
            autonomy_level=AutonomyLevel.LEVEL_1_AUTONOMOUS,
            context="Context 1",
            question="Question 1",
            options=["A", "B"],
            outcome=DecisionOutcome.APPROVED,
            chosen_option="A",
            reasoning="Reasoning 1",
            persona="artemis-optimizer",
            importance=0.8,
            tags=["tag1"],
            metadata={}
        ),
        Decision(
            decision_id="decision-002",
            timestamp=datetime.now(),
            decision_type=DecisionType.SECURITY,
            autonomy_level=AutonomyLevel.LEVEL_2_APPROVAL,
            context="Context 2",
            question="Question 2",
            options=["A", "B"],
            outcome=DecisionOutcome.APPROVED,
            chosen_option="A",
            reasoning="Reasoning 2",
            persona="hestia-auditor",
            importance=0.9,
            tags=["tag2"],
            metadata={}
        ),
        Decision(
            decision_id="decision-001",  # Duplicate!
            timestamp=datetime.now(),
            decision_type=DecisionType.OPTIMIZATION,
            autonomy_level=AutonomyLevel.LEVEL_1_AUTONOMOUS,
            context="Context 1 (duplicate)",
            question="Question 1",
            options=["A", "B"],
            outcome=DecisionOutcome.APPROVED,
            chosen_option="A",
            reasoning="Reasoning 1",
            persona="artemis-optimizer",
            importance=0.8,
            tags=["tag1"],
            metadata={}
        ),
    ]

    print(f"Input: {len(memories)} memories (with 1 duplicate)")

    unique_memories = hook._deduplicate_memories(memories)

    print(f"Output: {len(unique_memories)} unique memories")
    print("\nUnique decision IDs:")
    for mem in unique_memories:
        print(f"  - {mem.decision_id} ({mem.persona})")

    if len(unique_memories) == 2:
        print("\n✅ Deduplication PASSED")
    else:
        print(f"\n❌ Deduplication FAILED - expected 2 unique, got {len(unique_memories)}")

    print()

def test_memory_formatting():
    """Test memory context formatting"""
    hook = PreCompactMemoryInjectionHook()

    print("=== Testing Memory Formatting ===\n")

    from decision_memory import Decision, DecisionType, AutonomyLevel, DecisionOutcome
    from datetime import datetime

    # Create sample memories
    memories = [
        Decision(
            decision_id="decision-test-001",
            timestamp=datetime.now(),
            decision_type=DecisionType.OPTIMIZATION,
            autonomy_level=AutonomyLevel.LEVEL_1_AUTONOMOUS,
            context="Optimized database queries by adding indexes",
            question="Should we optimize?",
            options=["Yes", "No"],
            outcome=DecisionOutcome.APPROVED,
            chosen_option="Yes",
            reasoning="Performance improvement of 90% expected",
            persona="artemis-optimizer",
            importance=0.85,
            tags=["database", "performance", "optimization"],
            metadata={}
        ),
    ]

    formatted = hook._format_memory_context(memories)

    print("Formatted output:")
    print(formatted)

    # Check key elements
    checks = [
        ("<system-reminder>" in formatted, "Contains <system-reminder> tag"),
        ("📚 **Relevant Past Memories**" in formatted, "Contains header"),
        ("Memory 1: OPTIMIZATION" in formatted, "Contains memory title"),
        ("**Persona**: artemis-optimizer" in formatted, "Contains persona"),
        ("**Importance**: 0.85" in formatted, "Contains importance"),
        ("*Total memories injected: 1*" in formatted, "Contains count"),
        ("</system-reminder>" in formatted, "Closing tag present"),
    ]

    print("\nValidation:")
    all_passed = True
    for passed, description in checks:
        if passed:
            print(f"  ✅ {description}")
        else:
            print(f"  ❌ {description}")
            all_passed = False

    if all_passed:
        print("\n✅ Formatting PASSED")
    else:
        print("\n❌ Formatting FAILED")

    print()

def test_empty_handling():
    """Test handling of empty inputs"""
    hook = PreCompactMemoryInjectionHook()

    print("=== Testing Empty Input Handling ===\n")

    # Empty conversation
    result = hook._extract_recent_queries([], limit=3)
    print(f"Empty messages: {result}")
    if result == []:
        print("  ✅ Handles empty messages")
    else:
        print("  ❌ Should return empty list")

    # Empty memories
    formatted = hook._format_memory_context([])
    print(f"\nEmpty memories formatting: '{formatted}'")
    if formatted == "":
        print("  ✅ Returns empty string for no memories")
    else:
        print("  ❌ Should return empty string")

    print()

if __name__ == "__main__":
    print("=" * 60)
    print("TMWS Integration - precompact_memory_injection.py Test Suite")
    print("=" * 60)

    try:
        test_query_extraction()
        test_memory_deduplication()
        test_memory_formatting()
        test_empty_handling()

        print("=" * 60)
        print("✅ All tests completed!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
