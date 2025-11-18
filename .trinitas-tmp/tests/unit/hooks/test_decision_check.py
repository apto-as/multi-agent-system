"""
Unit Tests for decision_check.py UserPromptSubmit Hook
=======================================================

Tests for Level 1/2 detection, approval flow, and performance.

Target: <50ms hook latency, >90% detection accuracy
"""

import pytest
import asyncio
import json
import sys
from pathlib import Path
from io import StringIO

# Import the module to test
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / ".claude" / "hooks" / "core"))

from decision_check import DecisionCheckHook


class TestDecisionCheckHook:
    """Test decision_check.py UserPromptSubmit hook"""

    @pytest.fixture
    def hook(self):
        """Create DecisionCheckHook instance for testing"""
        return DecisionCheckHook()

    # ========== Level 1 (Autonomous) Tests ==========

    @pytest.mark.asyncio
    async def test_level1_bug_fix_no_intervention(self, hook):
        """Level 1 bug fix should not trigger approval"""
        stdin_data = {
            "prompt": {"text": "fix bug in user authentication logic"}
        }

        output = await hook.process_hook(stdin_data)

        # No context added
        assert output == {"addedContext": []}

    @pytest.mark.asyncio
    async def test_level1_cleanup_no_intervention(self, hook):
        """Level 1 code cleanup should not trigger approval"""
        stdin_data = {
            "prompt": {"text": "remove unused imports from auth service"}
        }

        output = await hook.process_hook(stdin_data)

        # No context added
        assert output == {"addedContext": []}

    @pytest.mark.asyncio
    async def test_level1_documentation_no_intervention(self, hook):
        """Level 1 documentation update should not trigger approval"""
        stdin_data = {
            "prompt": {"text": "update documentation for API endpoints"}
        }

        output = await hook.process_hook(stdin_data)

        # No context added
        assert output == {"addedContext": []}

    @pytest.mark.asyncio
    async def test_level1_test_addition_no_intervention(self, hook):
        """Level 1 test addition should not trigger approval"""
        stdin_data = {
            "prompt": {"text": "add test for user registration flow"}
        }

        output = await hook.process_hook(stdin_data)

        # No context added
        assert output == {"addedContext": []}

    @pytest.mark.asyncio
    async def test_level1_optimization_no_intervention(self, hook):
        """Level 1 optimization should not trigger approval"""
        stdin_data = {
            "prompt": {"text": "optimize database query performance"}
        }

        output = await hook.process_hook(stdin_data)

        # No context added
        assert output == {"addedContext": []}

    # ========== Level 2 (User Approval) Tests ==========

    @pytest.mark.asyncio
    async def test_level2_new_feature_approval_request(self, hook):
        """Level 2 new feature should trigger approval request"""
        stdin_data = {
            "prompt": {"text": "new feature for real-time notifications"}
        }

        output = await hook.process_hook(stdin_data)

        # Approval request added
        assert len(output["addedContext"]) == 1
        assert output["addedContext"][0]["type"] == "text"
        text = output["addedContext"][0]["text"]

        # Verify approval request content
        assert "<system-reminder>" in text
        assert "Decision Approval Required" in text
        assert "新機能" in text or "new feature" in text.lower()
        assert "承認" in text  # Japanese "approve"

    @pytest.mark.asyncio
    async def test_level2_new_dependency_approval_request(self, hook):
        """Level 2 new dependency should trigger approval request"""
        stdin_data = {
            "prompt": {"text": "add package for machine learning with TensorFlow"}
        }

        output = await hook.process_hook(stdin_data)

        # Approval request added
        assert len(output["addedContext"]) == 1
        assert "<system-reminder>" in output["addedContext"][0]["text"]

    @pytest.mark.asyncio
    async def test_level2_schema_change_approval_request(self, hook):
        """Level 2 schema change should trigger approval request"""
        stdin_data = {
            "prompt": {"text": "alter table users add column email_verified"}
        }

        output = await hook.process_hook(stdin_data)

        # Approval request added
        assert len(output["addedContext"]) == 1
        assert "<system-reminder>" in output["addedContext"][0]["text"]

    @pytest.mark.asyncio
    async def test_level2_api_change_approval_request(self, hook):
        """Level 2 API change should trigger approval request"""
        stdin_data = {
            "prompt": {"text": "new endpoint for user profile management"}
        }

        output = await hook.process_hook(stdin_data)

        # Approval request added
        assert len(output["addedContext"]) == 1
        assert "<system-reminder>" in output["addedContext"][0]["text"]

    @pytest.mark.asyncio
    async def test_level2_integration_approval_request(self, hook):
        """Level 2 integration should trigger approval request"""
        stdin_data = {
            "prompt": {"text": "integrate with Stripe payment gateway"}
        }

        output = await hook.process_hook(stdin_data)

        # Approval request added
        assert len(output["addedContext"]) == 1
        assert "<system-reminder>" in output["addedContext"][0]["text"]

    # ========== Edge Cases ==========

    @pytest.mark.asyncio
    async def test_empty_prompt_no_intervention(self, hook):
        """Empty prompt should return empty context"""
        stdin_data = {
            "prompt": {"text": ""}
        }

        output = await hook.process_hook(stdin_data)

        # No context added
        assert output == {"addedContext": []}

    @pytest.mark.asyncio
    async def test_missing_prompt_field(self, hook):
        """Missing prompt field should be handled gracefully"""
        stdin_data = {}

        output = await hook.process_hook(stdin_data)

        # No context added, no exception
        assert output == {"addedContext": []}

    @pytest.mark.asyncio
    async def test_malformed_prompt_structure(self, hook):
        """Malformed prompt structure should be handled"""
        stdin_data = {
            "prompt": "not a dict"
        }

        output = await hook.process_hook(stdin_data)

        # No context added, no exception
        assert output == {"addedContext": []}

    # ========== Prompt Sanitization ==========

    @pytest.mark.asyncio
    async def test_prompt_sanitization_newlines(self, hook):
        """Newlines should be sanitized from prompt"""
        prompt_with_newlines = "fix bug\nin authentication\nlogic"

        sanitized = hook._sanitize_prompt(prompt_with_newlines)

        # Newlines replaced with spaces
        assert '\n' not in sanitized
        assert sanitized == "fix bug in authentication logic"

    @pytest.mark.asyncio
    async def test_prompt_sanitization_length_limit(self, hook):
        """Long prompts should be truncated to 1000 chars"""
        long_prompt = "a" * 2000

        sanitized = hook._sanitize_prompt(long_prompt)

        # Truncated to 1000 chars
        assert len(sanitized) == 1000

    # ========== Performance Tests ==========

    @pytest.mark.asyncio
    async def test_hook_latency_target(self, hook):
        """Hook should process in <50ms"""
        import time

        stdin_data = {
            "prompt": {"text": "new feature for analytics dashboard"}
        }

        start = time.perf_counter()
        await hook.process_hook(stdin_data)
        duration = (time.perf_counter() - start) * 1000  # Convert to ms

        assert duration < 50, f"Hook took {duration:.2f}ms (target: <50ms)"

    @pytest.mark.asyncio
    async def test_level1_performance(self, hook):
        """Level 1 classification should be fast"""
        import time

        stdin_data = {
            "prompt": {"text": "fix bug in payment processing"}
        }

        start = time.perf_counter()
        await hook.process_hook(stdin_data)
        duration = (time.perf_counter() - start) * 1000  # ms

        assert duration < 50, f"Level 1 took {duration:.2f}ms"

    @pytest.mark.asyncio
    async def test_level2_performance(self, hook):
        """Level 2 classification should be fast"""
        import time

        stdin_data = {
            "prompt": {"text": "new feature for user notifications"}
        }

        start = time.perf_counter()
        await hook.process_hook(stdin_data)
        duration = (time.perf_counter() - start) * 1000  # ms

        assert duration < 50, f"Level 2 took {duration:.2f}ms"

    # ========== Approval Request Format ==========

    @pytest.mark.asyncio
    async def test_approval_request_contains_prompt(self, hook):
        """Approval request should include original prompt"""
        prompt_text = "new feature for user analytics"
        stdin_data = {
            "prompt": {"text": prompt_text}
        }

        output = await hook.process_hook(stdin_data)

        # Prompt should be in approval request
        approval_text = output["addedContext"][0]["text"]
        assert prompt_text in approval_text

    @pytest.mark.asyncio
    async def test_approval_request_has_options(self, hook):
        """Approval request should have clear options"""
        stdin_data = {
            "prompt": {"text": "new integration with AWS S3"}
        }

        output = await hook.process_hook(stdin_data)

        approval_text = output["addedContext"][0]["text"]

        # Should have 3 options
        assert "✅" in approval_text  # Approve option
        assert "❌" in approval_text  # Reject option
        assert "📝" in approval_text  # Modify option

        # Japanese text
        assert "承認" in approval_text
        assert "拒否" in approval_text
        assert "修正" in approval_text


class TestErrorHandling:
    """Test error handling and fail-safe behavior"""

    @pytest.fixture
    def hook(self):
        """Create DecisionCheckHook instance"""
        return DecisionCheckHook()

    @pytest.mark.asyncio
    async def test_exception_returns_empty_context(self, hook):
        """Exceptions should return empty context (fail-safe)"""
        # Force exception with invalid data
        stdin_data = {"prompt": {"text": None}}  # None will cause issues

        output = await hook.process_hook(stdin_data)

        # Should return empty context, not raise
        assert output == {"addedContext": []}


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
