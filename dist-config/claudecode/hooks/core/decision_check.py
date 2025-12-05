#!/usr/bin/env python3
"""
decision_check.py - UserPromptSubmit Hook for Trinitas Decision System
========================================================================

Trinitasの2レベル自律実行システム（Level 1/2）のためのフック。

Level 1 (自律実行可能):
- バグ修正、コードクリーンアップ、ドキュメント更新、テスト追加
- パフォーマンス最適化、リファクタリング

Level 2 (ユーザー承認必須):
- 新機能、新依存関係、スキーマ変更、API変更
- 外部統合、アーキテクチャ変更

パフォーマンス目標: <50ms分類
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import asyncio

# decision_memory.pyをインポート
sys.path.insert(0, str(Path(__file__).parent))
from decision_memory import (
    TrinitasDecisionMemory,
    Decision,
    DecisionType,
    AutonomyLevel,
    DecisionOutcome
)
from rate_limiter import ThreadSafeRateLimiter, RateLimitExceeded
from security_utils import (
    sanitize_prompt,
    redact_secrets,
    sanitize_log_message,
    safe_json_parse,
    validate_and_resolve_path,
)


class DecisionCheckHook:
    """UserPromptSubmit Hook for Decision Classification and Approval"""

    def __init__(self):
        """Initialize hook with decision memory system and rate limiter"""
        # Validate and create fallback directory with security checks
        fallback_dir = Path.home() / ".claude" / "memory" / "decisions"
        safe_fallback_dir = validate_and_resolve_path(
            fallback_dir,
            base_dir=Path.home(),
            allow_create=True
        )

        self.decision_memory = TrinitasDecisionMemory(
            tmws_url="http://localhost:8000",
            fallback_dir=safe_fallback_dir,
            cache_size=100,
            timeout=0.3
        )

        # Rate limiter: 100 calls/60 seconds (DoS protection)
        self.rate_limiter = ThreadSafeRateLimiter(
            max_calls=100,
            window_seconds=60,
            burst_size=10
        )

    async def process_hook(self, stdin_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main hook processing logic with security checks

        Args:
            stdin_data: JSON from stdin containing prompt data

        Returns:
            dict: {"addedContext": [...]} for stdout
        """
        try:
            # **CRITICAL: Check rate limit FIRST (DoS protection)**
            try:
                self.rate_limiter.check(operation_id="user_prompt_submit")
            except RateLimitExceeded as e:
                # Log rate limit event
                print(f"[decision_check] {sanitize_log_message(str(e))}", file=sys.stderr)
                # Fail-safe: don't block user, return empty context
                return {"addedContext": []}

            # Extract prompt text
            prompt_text = self._extract_prompt(stdin_data)

            if not prompt_text:
                return {"addedContext": []}

            # Sanitize prompt (comprehensive: control chars, Unicode, length)
            sanitized_prompt = sanitize_prompt(prompt_text, max_length=1000)

            # Step 1: Classify autonomy level (<50ms target)
            autonomy_level = await self.decision_memory.classify_autonomy_level(
                action_description=sanitized_prompt
            )

            # Step 2: Level 2 detection → inject approval request
            if autonomy_level == AutonomyLevel.LEVEL_2_APPROVAL:
                # Redact secrets from prompt before showing to user
                safe_prompt = redact_secrets(sanitized_prompt)
                approval_reminder = self._generate_approval_request(safe_prompt)

                # Record Level 2 detection (async, non-blocking)
                asyncio.create_task(
                    self._record_decision_async(
                        prompt=sanitized_prompt,
                        autonomy_level=autonomy_level,
                        outcome=DecisionOutcome.DEFERRED,  # Awaiting user approval
                        reasoning="Level 2 action detected, awaiting user approval"
                    )
                )

                return {
                    "addedContext": [
                        {
                            "type": "text",
                            "text": approval_reminder
                        }
                    ]
                }

            # Level 1: No intervention, record autonomous execution
            asyncio.create_task(
                self._record_decision_async(
                    prompt=sanitized_prompt,
                    autonomy_level=autonomy_level,
                    outcome=DecisionOutcome.APPROVED,  # Auto-approved (Level 1)
                    reasoning="Level 1 action, autonomous execution approved"
                )
            )

            return {"addedContext": []}

        except (ValueError, TypeError, KeyError) as e:
            # Expected validation errors
            print(f"[decision_check] Validation error: {sanitize_log_message(str(e))}", file=sys.stderr)
            return {"addedContext": []}
        except Exception as e:
            # Unexpected errors (potential security issue)
            print(f"[decision_check] Unexpected error: {type(e).__name__}: {sanitize_log_message(str(e))}", file=sys.stderr)
            return {"addedContext": []}

    def _extract_prompt(self, stdin_data: Dict[str, Any]) -> str:
        """
        Extract prompt text from stdin data

        Args:
            stdin_data: JSON object from stdin

        Returns:
            str: Prompt text or empty string
        """
        prompt = stdin_data.get("prompt", {})
        if isinstance(prompt, dict):
            return prompt.get("text", "")
        return ""


    def _generate_approval_request(self, prompt: str) -> str:
        """
        Generate <system-reminder> for Level 2 approval request

        Args:
            prompt: User's prompt text

        Returns:
            str: System reminder with approval question
        """
        return f"""<system-reminder>
⚠️ **Trinitas Decision Approval Required (Level 2)**

以下のアクションはユーザー承認が必要です：

**検出されたアクション**: {prompt}

**理由**: このアクションには以下が含まれます：
- 新機能、新依存関係、または外部統合
- データベーススキーマまたはAPI変更
- アーキテクチャの変更
- その他の重要なシステム変更

**ご確認ください**:
1. ✅ 承認: このアクションを実行する
2. ❌ 拒否: 実行しない
3. 📝 修正: 別のアプローチを提案

あなたの承認をお待ちしております...
</system-reminder>"""

    def _detect_persona(self, prompt: str) -> str:
        """
        Detect which Trinitas persona should handle this task

        Uses keyword matching to identify the most appropriate persona.
        Performance: <5ms (simple string matching)

        Args:
            prompt: User's prompt text

        Returns:
            str: Persona identifier (e.g., "athena-conductor")
        """
        prompt_lower = prompt.lower()

        # Persona trigger keywords (from AGENTS.md)
        persona_triggers = {
            "athena-conductor": ["orchestrate", "coordinate", "workflow", "automation", "parallel", "オーケストレーション", "調整", "ワークフロー"],
            "artemis-optimizer": ["optimize", "performance", "quality", "technical", "efficiency", "最適化", "品質", "パフォーマンス"],
            "hestia-auditor": ["security", "audit", "risk", "vulnerability", "threat", "セキュリティ", "監査", "脆弱性"],
            "eris-coordinator": ["coordinate", "tactical", "team", "collaboration", "チーム調整", "戦術", "協力"],
            "hera-strategist": ["strategy", "planning", "architecture", "vision", "roadmap", "戦略", "計画", "アーキテクチャ"],
            "muses-documenter": ["document", "knowledge", "record", "guide", "ドキュメント", "文書化", "記録"]
        }

        # Check each persona's triggers
        for persona, keywords in persona_triggers.items():
            if any(keyword in prompt_lower for keyword in keywords):
                return persona

        # Default: Athena (harmonious conductor)
        return "athena-conductor"

    def _classify_decision_type(self, prompt: str) -> DecisionType:
        """
        Classify the type of decision being made

        Performance: <3ms

        Args:
            prompt: User's prompt text

        Returns:
            DecisionType: Type of decision
        """
        prompt_lower = prompt.lower()

        # Security-related keywords
        if any(kw in prompt_lower for kw in ["security", "vulnerability", "attack", "セキュリティ", "脆弱性"]):
            return DecisionType.SECURITY

        # Architecture-related keywords
        if any(kw in prompt_lower for kw in ["architecture", "design", "structure", "アーキテクチャ", "設計"]):
            return DecisionType.ARCHITECTURE

        # Optimization-related keywords
        if any(kw in prompt_lower for kw in ["optimize", "performance", "speed", "最適化", "パフォーマンス"]):
            return DecisionType.OPTIMIZATION

        # Implementation (default)
        return DecisionType.IMPLEMENTATION

    def _calculate_importance(self, autonomy_level: AutonomyLevel, prompt: str) -> float:
        """
        Calculate importance score for this decision (0.0-1.0)

        Higher importance = higher priority in memory retrieval

        Args:
            autonomy_level: Classified autonomy level
            prompt: User's prompt text

        Returns:
            float: Importance score (0.0-1.0)
        """
        # Base importance
        base_importance = 0.8 if autonomy_level == AutonomyLevel.LEVEL_2_APPROVAL else 0.5

        # Boost for critical keywords
        prompt_lower = prompt.lower()
        critical_keywords = ["critical", "urgent", "important", "emergency", "重要", "緊急", "クリティカル"]

        boost = sum(0.05 for kw in critical_keywords if kw in prompt_lower)

        # Cap at 1.0
        return min(1.0, base_importance + boost)

    def _generate_tags(self, prompt: str, persona: str, decision_type: DecisionType) -> list[str]:
        """
        Generate semantic tags for memory indexing

        Tags improve memory search and categorization in TMWS

        Args:
            prompt: User's prompt text
            persona: Detected persona
            decision_type: Classified decision type

        Returns:
            list[str]: List of tags for indexing
        """
        tags = [
            "auto-classified",
            "user-prompt",
            persona,
            decision_type.value
        ]

        # Add domain-specific tags
        prompt_lower = prompt.lower()

        # Technology tags
        tech_keywords = {
            "python": ["python", "py"],
            "javascript": ["javascript", "js", "node"],
            "typescript": ["typescript", "ts"],
            "database": ["database", "sql", "sqlite", "postgres"],
            "api": ["api", "rest", "graphql"],
            "security": ["security", "auth", "セキュリティ"],
            "performance": ["performance", "optimize", "パフォーマンス"]
        }

        for tag, keywords in tech_keywords.items():
            if any(kw in prompt_lower for kw in keywords):
                tags.append(tag)

        return tags

    async def _record_decision_async(
        self,
        prompt: str,
        autonomy_level: AutonomyLevel,
        outcome: DecisionOutcome,
        reasoning: str
    ) -> None:
        """
        Record decision asynchronously (non-blocking) with TMWS integration

        Enhanced with persona detection, decision type classification,
        importance scoring, and semantic tagging.

        Args:
            prompt: User's prompt text
            autonomy_level: Classified autonomy level
            outcome: Decision outcome
            reasoning: Reasoning for the decision
        """
        try:
            # Enhanced metadata collection
            persona = self._detect_persona(prompt)
            decision_type = self._classify_decision_type(prompt)
            importance = self._calculate_importance(autonomy_level, prompt)
            tags = self._generate_tags(prompt, persona, decision_type)

            # Create decision record with enhanced metadata
            decision = Decision(
                decision_id=f"decision-{datetime.now().timestamp()}",
                timestamp=datetime.now(),
                decision_type=decision_type,  # Enhanced classification
                autonomy_level=autonomy_level,
                context=f"User prompt: {prompt[:200]}",  # Truncate for storage
                question="このアクションを実行すべきか？",
                options=["承認", "拒否", "修正"],
                outcome=outcome,
                chosen_option=outcome.value,
                reasoning=reasoning,
                persona=persona,  # Auto-detected persona
                importance=importance,  # Dynamic importance scoring
                tags=tags,  # Semantic tags for better search
                metadata={
                    "prompt_length": len(prompt),
                    "hook": "decision_check",
                    "timestamp": datetime.now().isoformat(),
                    "autonomy_level": autonomy_level.value,
                    "decision_type": decision_type.value
                }
            )

            # Record decision (with fallback)
            await self.decision_memory.record_user_decision(decision)

        except Exception as e:
            # Logging only, don't block hook (sanitize log message)
            print(f"[decision_check] Failed to record decision: {sanitize_log_message(str(e))}", file=sys.stderr)


def main():
    """
    Main entry point for UserPromptSubmit hook

    Reads JSON from stdin, processes, writes JSON to stdout
    """
    try:
        # Read and parse stdin with security checks
        stdin_raw = sys.stdin.read()
        stdin_data = safe_json_parse(stdin_raw, max_size=10_000, max_depth=10)

        # Create hook instance
        hook = DecisionCheckHook()

        # Process hook (async)
        output = asyncio.run(hook.process_hook(stdin_data))

        # Write stdout
        print(json.dumps(output, ensure_ascii=False))

        # Exit success
        sys.exit(0)

    except ValueError as e:
        # JSON parsing or validation error
        print(f"[decision_check] Input validation error: {sanitize_log_message(str(e))}", file=sys.stderr)
        print(json.dumps({"addedContext": []}, ensure_ascii=False))
        sys.exit(0)
    except Exception as e:
        # Fail-safe: return empty context, exit success
        print(f"[decision_check] Fatal error: {type(e).__name__}: {sanitize_log_message(str(e))}", file=sys.stderr)
        print(json.dumps({"addedContext": []}, ensure_ascii=False))
        sys.exit(0)


if __name__ == "__main__":
    main()
