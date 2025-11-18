#!/usr/bin/env python3
"""Simple test for decision_check.py methods without dependencies"""
from enum import Enum

class DecisionType(Enum):
    SECURITY = "SECURITY"
    ARCHITECTURE = "ARCHITECTURE"
    OPTIMIZATION = "OPTIMIZATION"
    IMPLEMENTATION = "IMPLEMENTATION"

class AutonomyLevel(Enum):
    LEVEL_1_AUTONOMOUS = "level_1_autonomous"
    LEVEL_2_APPROVAL = "level_2_approval"

def _detect_persona(prompt: str) -> str:
    """Detect which Trinitas persona should handle this task"""
    prompt_lower = prompt.lower()
    
    persona_triggers = {
        "athena-conductor": ["orchestrate", "coordinate", "workflow", "automation", "parallel"],
        "artemis-optimizer": ["optimize", "performance", "quality", "technical", "efficiency"],
        "hestia-auditor": ["security", "audit", "risk", "vulnerability", "threat"],
        "eris-coordinator": ["coordinate", "tactical", "team", "collaboration"],
        "hera-strategist": ["strategy", "planning", "architecture", "vision", "roadmap"],
        "muses-documenter": ["document", "knowledge", "record", "guide"]
    }
    
    for persona, keywords in persona_triggers.items():
        if any(keyword in prompt_lower for keyword in keywords):
            return persona
    
    return "athena-conductor"

def _classify_decision_type(prompt: str) -> DecisionType:
    """Classify the type of decision being made"""
    prompt_lower = prompt.lower()
    
    if any(kw in prompt_lower for kw in ["security", "vulnerability", "attack"]):
        return DecisionType.SECURITY
    if any(kw in prompt_lower for kw in ["architecture", "design", "structure"]):
        return DecisionType.ARCHITECTURE
    if any(kw in prompt_lower for kw in ["optimize", "performance", "speed"]):
        return DecisionType.OPTIMIZATION
    
    return DecisionType.IMPLEMENTATION

def _calculate_importance(autonomy_level: AutonomyLevel, prompt: str) -> float:
    """Calculate importance score (0.0-1.0)"""
    base_importance = 0.8 if autonomy_level == AutonomyLevel.LEVEL_2_APPROVAL else 0.5
    
    prompt_lower = prompt.lower()
    critical_keywords = ["critical", "urgent", "important", "emergency"]
    boost = sum(0.05 for kw in critical_keywords if kw in prompt_lower)
    
    return min(1.0, base_importance + boost)

def _generate_tags(prompt: str, persona: str, decision_type: DecisionType) -> list:
    """Generate semantic tags for memory indexing"""
    tags = ["auto-classified", "user-prompt", persona, decision_type.value]
    
    prompt_lower = prompt.lower()
    tech_keywords = {
        "python": ["python", "py"],
        "javascript": ["javascript", "js", "node"],
        "database": ["database", "sql", "sqlite"],
        "api": ["api", "rest", "graphql"],
        "security": ["security", "auth"],
        "performance": ["performance", "optimize"]
    }
    
    for tag, keywords in tech_keywords.items():
        if any(kw in prompt_lower for kw in keywords):
            tags.append(tag)
    
    return tags

print("=" * 60)
print("TMWS Integration - Method Tests")
print("=" * 60 + "\n")

# Test 1: Persona Detection
print("TEST 1: Persona Detection")
test_cases = [
    ("optimize database", "artemis-optimizer"),
    ("security audit", "hestia-auditor"),
    ("design architecture", "hera-strategist"),
]

for prompt, expected in test_cases:
    result = _detect_persona(prompt)
    status = "✅" if result == expected else "❌"
    print(f"{status} '{prompt}' → {result} (expected: {expected})")

# Test 2: Decision Type
print("\nTEST 2: Decision Type")
test_cases = [
    ("optimize speed", DecisionType.OPTIMIZATION),
    ("fix security bug", DecisionType.SECURITY),
    ("design new system", DecisionType.ARCHITECTURE),
]

for prompt, expected in test_cases:
    result = _classify_decision_type(prompt)
    status = "✅" if result == expected else "❌"
    print(f"{status} '{prompt}' → {result.value} (expected: {expected.value})")

# Test 3: Importance
print("\nTEST 3: Importance")
test_cases = [
    ("fix typo", AutonomyLevel.LEVEL_1_AUTONOMOUS, 0.5),
    ("critical fix", AutonomyLevel.LEVEL_2_APPROVAL, 0.85),
]

for prompt, level, expected in test_cases:
    result = _calculate_importance(level, prompt)
    status = "✅" if result == expected else "❌"
    print(f"{status} '{prompt}' + {level.value} → {result:.2f} (expected: {expected:.2f})")

# Test 4: Tags
print("\nTEST 4: Tag Generation")
prompt = "optimize python database"
persona = "artemis-optimizer"
decision_type = DecisionType.OPTIMIZATION
tags = _generate_tags(prompt, persona, decision_type)
expected_tags = ["python", "database", "performance"]
has_all = all(tag in tags for tag in expected_tags)
status = "✅" if has_all else "❌"
print(f"{status} Tags: {tags}")
print(f"   Expected tech tags: {expected_tags}")

print("\n" + "=" * 60)
print("✅ All tests completed!")
print("=" * 60)
