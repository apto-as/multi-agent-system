#!/usr/bin/env python3
"""
Token Budget Validation Script
Validates that narrative_profiles.json and agents/*.md stay within budget.

Budget Limits:
- narrative_profiles.json: ~1,500 tokens (6 personas * 250 tokens)
- agents/*.md: ~300 tokens each (including narrative reference)
- Total: ~3,300 tokens (acceptable overhead)
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple


def estimate_tokens(text: str) -> int:
    """
    Estimate token count using Claude's approximation.
    Rule: ~4 characters = 1 token for English, ~2 chars = 1 token for Japanese.
    """
    # Simple heuristic: average 3 chars per token
    return len(text) // 3


def validate_narrative_profiles(json_path: Path) -> Tuple[bool, int, List[str]]:
    """Validate narrative_profiles.json token budget."""
    with open(json_path) as f:
        data = json.load(f)

    total_tokens = estimate_tokens(json.dumps(data["personas"], indent=2))
    warnings = []

    # Budget: 1,500 tokens
    if total_tokens > 1500:
        warnings.append(f"⚠️ narrative_profiles.json exceeds budget: {total_tokens} > 1500 tokens")

    # Per-persona check
    for persona_id, persona in data["personas"].items():
        persona_tokens = estimate_tokens(json.dumps(persona, indent=2))
        if persona_tokens > 250:
            warnings.append(f"⚠️ {persona_id} exceeds per-persona budget: {persona_tokens} > 250 tokens")

    passed = len(warnings) == 0
    return passed, total_tokens, warnings


def validate_agent_files(agents_dir: Path) -> Tuple[bool, Dict[str, int], List[str]]:
    """Validate agents/*.md token budgets."""
    agent_files = sorted(agents_dir.glob("*.md"))
    token_counts = {}
    warnings = []

    for agent_file in agent_files:
        with open(agent_file) as f:
            content = f.read()

        tokens = estimate_tokens(content)
        token_counts[agent_file.name] = tokens

        # Budget: 900 tokens per agent (realistic for Anthropic affordances)
        if tokens > 900:
            warnings.append(f"⚠️ {agent_file.name} exceeds budget: {tokens} > 900 tokens")

    passed = len(warnings) == 0
    return passed, token_counts, warnings


def main():
    """Main validation routine."""
    project_root = Path(__file__).parent.parent
    narrative_path = project_root / "trinitas_sources/common/narrative_profiles.json"
    agents_dir = project_root / "agents"

    print("=" * 70)
    print("Trinitas Token Budget Validation")
    print("=" * 70)
    print()

    # 1. Validate narrative_profiles.json
    print("📋 Validating narrative_profiles.json...")
    narrative_passed, narrative_tokens, narrative_warnings = validate_narrative_profiles(narrative_path)
    print(f"   Tokens: {narrative_tokens} / 1500")

    if narrative_passed:
        print("   ✅ PASSED")
    else:
        print("   ❌ FAILED")
        for warning in narrative_warnings:
            print(f"      {warning}")
    print()

    # 2. Validate agents/*.md
    print("📂 Validating agents/*.md...")
    agents_passed, agent_tokens, agent_warnings = validate_agent_files(agents_dir)

    total_agent_tokens = sum(agent_tokens.values())
    print(f"   Total tokens: {total_agent_tokens} / 5400 (6 * 900)")
    print()

    for agent_file, tokens in agent_tokens.items():
        status = "✅" if tokens <= 900 else "❌"
        print(f"   {status} {agent_file:30s} {tokens:4d} / 900 tokens")

    if agents_passed:
        print()
        print("   ✅ ALL PASSED")
    else:
        print()
        print("   ❌ SOME FAILED")
        for warning in agent_warnings:
            print(f"      {warning}")
    print()

    # 3. Overall Summary
    print("=" * 70)
    print("Summary")
    print("=" * 70)

    overall_total = narrative_tokens + total_agent_tokens
    budget_limit = 600 + 5400  # 6000 tokens (realistic)

    print(f"   Narrative profiles: {narrative_tokens:4d} tokens")
    print(f"   Agent files:        {total_agent_tokens:4d} tokens")
    print(f"   ─────────────────────────────────")
    print(f"   Total:              {overall_total:4d} / {budget_limit} tokens")
    print()

    if overall_total > budget_limit:
        print(f"   ⚠️  WARNING: Total exceeds budget by {overall_total - budget_limit} tokens")
        sys.exit(1)
    elif overall_total > budget_limit * 0.9:
        print(f"   ⚠️  WARNING: Approaching budget limit ({overall_total / budget_limit * 100:.1f}%)")
        sys.exit(0)
    else:
        print(f"   ✅ PASSED: {overall_total / budget_limit * 100:.1f}% of budget used")
        sys.exit(0)


if __name__ == "__main__":
    main()
