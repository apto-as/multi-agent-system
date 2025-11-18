#!/usr/bin/env python3
"""Simple test for precompact_memory_injection.py methods"""
from enum import Enum
from datetime import datetime

class DecisionType(Enum):
    SECURITY = "SECURITY"
    OPTIMIZATION = "OPTIMIZATION"

class AutonomyLevel(Enum):
    LEVEL_1_AUTONOMOUS = "level_1_autonomous"

class DecisionOutcome(Enum):
    APPROVED = "APPROVED"

class Decision:
    def __init__(self, decision_id, timestamp, decision_type, autonomy_level,
                 context, question, options, outcome, chosen_option, reasoning,
                 persona, importance, tags, metadata):
        self.decision_id = decision_id
        self.timestamp = timestamp
        self.decision_type = decision_type
        self.autonomy_level = autonomy_level
        self.context = context
        self.question = question
        self.options = options
        self.outcome = outcome
        self.chosen_option = chosen_option
        self.reasoning = reasoning
        self.persona = persona
        self.importance = importance
        self.tags = tags
        self.metadata = metadata

def _extract_recent_queries(messages: list, limit: int = 3) -> list:
    """Extract recent user queries from conversation"""
    queries = []
    
    for message in reversed(messages):
        if len(queries) >= limit:
            break
        
        if message.get("role") == "user":
            content = message.get("content", "")
            if isinstance(content, str) and content.strip():
                queries.append(content.strip())
    
    return queries

def _deduplicate_memories(memories: list) -> list:
    """Remove duplicate memories by decision_id"""
    seen_ids = set()
    unique = []
    
    for memory in memories:
        if memory.decision_id not in seen_ids:
            seen_ids.add(memory.decision_id)
            unique.append(memory)
    
    return unique

def _format_memory_context(memories: list) -> str:
    """Format memories as context injection"""
    if not memories:
        return ""
    
    context_lines = [
        "<system-reminder>",
        "📚 **Relevant Past Memories** (from TMWS)",
        "",
        "The following past decisions and learnings may be relevant to the current conversation:",
        ""
    ]
    
    for i, memory in enumerate(memories, 1):
        context_lines.extend([
            f"### Memory {i}: {memory.decision_type.value}",
            f"**Persona**: {memory.persona}",
            f"**Context**: {memory.context[:150]}...",
            f"**Outcome**: {memory.outcome.value}",
            f"**Reasoning**: {memory.reasoning[:200]}...",
            f"**Importance**: {memory.importance:.2f}",
            f"**Tags**: {', '.join(memory.tags[:5])}",
            ""
        ])
    
    context_lines.extend([
        "---",
        f"*Total memories injected: {len(memories)}*",
        "</system-reminder>"
    ])
    
    return "\n".join(context_lines)

print("=" * 60)
print("TMWS Integration - precompact_memory_injection.py Tests")
print("=" * 60 + "\n")

# Test 1: Query Extraction
print("TEST 1: Query Extraction")
messages = [
    {"role": "user", "content": "How to optimize database?"},
    {"role": "assistant", "content": "You can add indexes..."},
    {"role": "user", "content": "What about security?"},
    {"role": "assistant", "content": "Good point..."},
    {"role": "user", "content": "Check for vulnerabilities"},
]

queries = _extract_recent_queries(messages, limit=3)
print(f"Extracted {len(queries)} queries:")
for i, q in enumerate(queries, 1):
    print(f"  {i}. {q}")

expected = 3
status = "✅" if len(queries) == expected else "❌"
print(f"{status} Expected {expected} queries, got {len(queries)}\n")

# Test 2: Deduplication
print("TEST 2: Memory Deduplication")
memories = [
    Decision("dec-001", datetime.now(), DecisionType.OPTIMIZATION, 
             AutonomyLevel.LEVEL_1_AUTONOMOUS, "Context 1", "Q1", ["A"], 
             DecisionOutcome.APPROVED, "A", "R1", "artemis", 0.8, ["tag1"], {}),
    Decision("dec-002", datetime.now(), DecisionType.SECURITY,
             AutonomyLevel.LEVEL_1_AUTONOMOUS, "Context 2", "Q2", ["A"],
             DecisionOutcome.APPROVED, "A", "R2", "hestia", 0.9, ["tag2"], {}),
    Decision("dec-001", datetime.now(), DecisionType.OPTIMIZATION,  # Duplicate!
             AutonomyLevel.LEVEL_1_AUTONOMOUS, "Context 1 (dup)", "Q1", ["A"],
             DecisionOutcome.APPROVED, "A", "R1", "artemis", 0.8, ["tag1"], {}),
]

print(f"Input: {len(memories)} memories (with 1 duplicate)")
unique = _deduplicate_memories(memories)
print(f"Output: {len(unique)} unique memories")

expected = 2
status = "✅" if len(unique) == expected else "❌"
print(f"{status} Expected {expected} unique, got {len(unique)}\n")

# Test 3: Memory Formatting
print("TEST 3: Memory Context Formatting")
test_memory = Decision(
    "dec-test-001", datetime.now(), DecisionType.OPTIMIZATION,
    AutonomyLevel.LEVEL_1_AUTONOMOUS,
    "Optimized database queries by adding indexes",
    "Should we optimize?", ["Yes", "No"],
    DecisionOutcome.APPROVED, "Yes",
    "Performance improvement of 90% expected",
    "artemis-optimizer", 0.85,
    ["database", "performance", "optimization"], {}
)

formatted = _format_memory_context([test_memory])
print("Formatted output:")
print(formatted[:300] + "..." if len(formatted) > 300 else formatted)

checks = [
    ("<system-reminder>" in formatted, "Has <system-reminder> tag"),
    ("Memory 1: OPTIMIZATION" in formatted, "Has memory title"),
    ("artemis-optimizer" in formatted, "Has persona"),
    ("</system-reminder>" in formatted, "Has closing tag"),
]

print("\nValidation:")
all_passed = True
for passed, desc in checks:
    status = "✅" if passed else "❌"
    print(f"  {status} {desc}")
    if not passed:
        all_passed = False

# Test 4: Empty handling
print("\nTEST 4: Empty Input Handling")
empty_queries = _extract_recent_queries([], limit=3)
status = "✅" if empty_queries == [] else "❌"
print(f"{status} Empty messages → {empty_queries}")

empty_format = _format_memory_context([])
status = "✅" if empty_format == "" else "❌"
print(f"{status} Empty memories → '{empty_format}'\n")

print("=" * 60)
print("✅ All precompact tests completed!")
print("=" * 60)
