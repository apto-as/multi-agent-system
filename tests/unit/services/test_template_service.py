"""Unit tests for TemplateService (Issue #60)."""

import pytest
from datetime import UTC, datetime

from src.services.template_service import (
    PhaseTemplate,
    TemplateService,
    DEFAULT_TEMPLATES,
    _TEMPLATE_CACHE,
    _CACHE_TIMESTAMP,
    _CACHE_TTL_SECONDS,
)
from src.core.exceptions import NotFoundError, ValidationError


@pytest.fixture
def template_service(db_session):
    """Create TemplateService instance with test session."""
    return TemplateService(db_session)


@pytest.fixture
def clear_cache():
    """Clear template cache before each test."""
    global _TEMPLATE_CACHE, _CACHE_TIMESTAMP
    _TEMPLATE_CACHE.clear()
    _CACHE_TIMESTAMP.clear()
    yield
    # Reset to default templates after test
    for template_id, template in DEFAULT_TEMPLATES.items():
        _TEMPLATE_CACHE[template_id] = template
        _CACHE_TIMESTAMP[template_id] = datetime.now(UTC)


class TestPhaseTemplate:
    """Tests for PhaseTemplate data class."""

    def test_template_initialization(self):
        """Test PhaseTemplate can be initialized with required fields."""
        template = PhaseTemplate(
            template_id="test_template",
            name="Test Template",
            description="Test description",
            task_type="test_type",
            phases=[
                {
                    "phase": "test_phase",
                    "name": "Test Phase",
                    "agents": ["test-agent"],
                    "approval_gate": "Test gate",
                }
            ],
        )

        assert template.template_id == "test_template"
        assert template.name == "Test Template"
        assert template.task_type == "test_type"
        assert len(template.phases) == 1
        assert template.complexity == "medium"
        assert template.success_rate == 0.8

    def test_template_to_dict(self):
        """Test template serialization to dictionary."""
        template = PhaseTemplate(
            template_id="test",
            name="Test",
            description="Desc",
            task_type="test_type",
            phases=[{"phase": "test"}],
        )

        result = template.to_dict()

        assert result["template_id"] == "test"
        assert result["name"] == "Test"
        assert "created_at" in result
        assert isinstance(result["phases"], list)


class TestTemplateServiceCRUD:
    """Tests for CRUD operations."""

    @pytest.mark.asyncio
    async def test_get_template_from_cache(self, template_service):
        """Test getting template from cache."""
        template = await template_service.get_template("quick_fix")

        assert template is not None
        assert template.template_id == "quick_fix"
        assert template.name == "Quick Fix"
        assert len(template.phases) == 2

    @pytest.mark.asyncio
    async def test_get_template_not_found(self, template_service):
        """Test getting non-existent template returns None."""
        template = await template_service.get_template("nonexistent")

        assert template is None

    @pytest.mark.asyncio
    async def test_get_template_by_task_type(self, template_service):
        """Test getting template by task type."""
        template = await template_service.get_template_by_task_type("security_audit")

        assert template is not None
        assert template.task_type == "security_audit"
        assert "hestia-auditor" in template.phases[1]["agents"]

    @pytest.mark.asyncio
    async def test_create_template_success(self, template_service, clear_cache):
        """Test creating a new template."""
        template = await template_service.create_template(
            template_id="custom_template",
            name="Custom Template",
            description="Custom workflow",
            task_type="custom",
            phases=[
                {
                    "phase": "custom_phase",
                    "name": "Custom Phase",
                    "agents": ["test-agent"],
                    "approval_gate": "Custom gate",
                    "timeout_minutes": 30,
                }
            ],
            complexity="low",
            estimated_duration_minutes=30,
            keywords=["custom", "test"],
            success_rate=0.9,
        )

        assert template.template_id == "custom_template"
        assert template.complexity == "low"
        assert template.estimated_duration_minutes == 30
        assert "custom" in template.keywords

        # Verify cached
        assert "custom_template" in _TEMPLATE_CACHE

    @pytest.mark.asyncio
    async def test_create_template_duplicate_id(self, template_service):
        """Test creating template with duplicate ID fails."""
        with pytest.raises(ValidationError, match="already exists"):
            await template_service.create_template(
                template_id="quick_fix",  # Already exists
                name="Duplicate",
                description="Test",
                task_type="test",
                phases=[
                    {
                        "phase": "test",
                        "name": "Test",
                        "agents": ["test"],
                        "approval_gate": "gate",
                    }
                ],
            )

    @pytest.mark.asyncio
    async def test_create_template_invalid_complexity(self, template_service, clear_cache):
        """Test creating template with invalid complexity fails."""
        with pytest.raises(ValidationError, match="Invalid complexity"):
            await template_service.create_template(
                template_id="test",
                name="Test",
                description="Test",
                task_type="test",
                phases=[
                    {
                        "phase": "test",
                        "name": "Test",
                        "agents": ["test"],
                        "approval_gate": "gate",
                    }
                ],
                complexity="invalid",
            )

    @pytest.mark.asyncio
    async def test_create_template_invalid_success_rate(
        self, template_service, clear_cache
    ):
        """Test creating template with invalid success_rate fails."""
        with pytest.raises(ValidationError, match="Invalid success_rate"):
            await template_service.create_template(
                template_id="test",
                name="Test",
                description="Test",
                task_type="test",
                phases=[
                    {
                        "phase": "test",
                        "name": "Test",
                        "agents": ["test"],
                        "approval_gate": "gate",
                    }
                ],
                success_rate=1.5,  # Invalid
            )

    @pytest.mark.asyncio
    async def test_create_template_missing_phase_fields(
        self, template_service, clear_cache
    ):
        """Test creating template with incomplete phase config fails."""
        with pytest.raises(ValidationError, match="missing required keys"):
            await template_service.create_template(
                template_id="test",
                name="Test",
                description="Test",
                task_type="test",
                phases=[
                    {
                        "phase": "test",
                        "name": "Test",
                        # Missing: agents, approval_gate
                    }
                ],
            )

    @pytest.mark.asyncio
    async def test_list_templates_no_filter(self, template_service):
        """Test listing all templates."""
        templates = await template_service.list_templates()

        assert len(templates) == 5  # 5 default templates
        template_ids = [t.template_id for t in templates]
        assert "quick_fix" in template_ids
        assert "security_audit" in template_ids
        assert "full_development" in template_ids

    @pytest.mark.asyncio
    async def test_list_templates_filter_by_complexity(self, template_service):
        """Test listing templates filtered by complexity."""
        templates = await template_service.list_templates(filter_by="low")

        assert len(templates) == 1
        assert templates[0].complexity == "low"

    @pytest.mark.asyncio
    async def test_list_templates_filter_by_task_type(self, template_service):
        """Test listing templates filtered by task type."""
        templates = await template_service.list_templates(filter_by="quick_fix")

        assert len(templates) == 1
        assert templates[0].task_type == "quick_fix"

    @pytest.mark.asyncio
    async def test_update_template_success(self, template_service, clear_cache):
        """Test updating template fields (custom template only - system protected)."""
        # Create a custom template to update (system templates are protected)
        await template_service.create_template(
            template_id="updatable_template",
            name="Updatable Template",
            description="Template for update testing",
            task_type="test",
            phases=[
                {
                    "phase": "test_phase",
                    "name": "Test Phase",
                    "agents": ["test-agent"],
                    "approval_gate": "Test gate",
                }
            ],
        )

        updated = await template_service.update_template(
            "updatable_template", name="Updated Template", estimated_duration_minutes=50
        )

        assert updated.name == "Updated Template"
        assert updated.estimated_duration_minutes == 50

        # Verify cache updated
        cached = await template_service.get_template("updatable_template")
        assert cached.name == "Updated Template"

    @pytest.mark.asyncio
    async def test_update_template_not_found(self, template_service):
        """Test updating non-existent template fails."""
        with pytest.raises(NotFoundError, match="PhaseTemplate"):
            await template_service.update_template("nonexistent", name="Test")

    @pytest.mark.asyncio
    async def test_update_template_invalid_complexity(self, template_service, clear_cache):
        """Test updating template with invalid complexity fails."""
        # Create a custom template (system templates are protected)
        await template_service.create_template(
            template_id="complexity_test_template",
            name="Complexity Test",
            description="Template for complexity validation testing",
            task_type="test",
            phases=[
                {
                    "phase": "test_phase",
                    "name": "Test Phase",
                    "agents": ["test-agent"],
                    "approval_gate": "Test gate",
                }
            ],
        )

        with pytest.raises(ValidationError, match="Invalid complexity"):
            await template_service.update_template("complexity_test_template", complexity="invalid")

    @pytest.mark.asyncio
    async def test_delete_template_success(self, template_service, clear_cache):
        """Test deleting a template."""
        # Create a template to delete
        await template_service.create_template(
            template_id="to_delete",
            name="Delete Me",
            description="Test",
            task_type="test",
            phases=[
                {
                    "phase": "test",
                    "name": "Test",
                    "agents": ["test"],
                    "approval_gate": "gate",
                }
            ],
        )

        # Delete it
        result = await template_service.delete_template("to_delete")

        assert result is True
        assert "to_delete" not in _TEMPLATE_CACHE

        # Verify not found
        template = await template_service.get_template("to_delete")
        assert template is None

    @pytest.mark.asyncio
    async def test_delete_template_not_found(self, template_service):
        """Test deleting non-existent template fails."""
        with pytest.raises(NotFoundError, match="PhaseTemplate"):
            await template_service.delete_template("nonexistent")


class TestTemplateSelection:
    """Tests for intelligent template selection."""

    @pytest.mark.asyncio
    async def test_select_template_by_user_hint(self, template_service):
        """Test template selection with explicit user hint."""
        template = await template_service.select_template(
            task_content="Fix the login bug", user_hint="/trinitas quick_fix"
        )

        assert template.template_id == "quick_fix"

    @pytest.mark.asyncio
    async def test_select_template_by_hint_with_spaces(self, template_service):
        """Test template selection with hint containing spaces."""
        template = await template_service.select_template(
            task_content="Audit the system", user_hint="security audit"
        )

        assert template.template_id == "security_audit"

    @pytest.mark.asyncio
    async def test_select_template_by_keywords_bug_fix(self, template_service):
        """Test template selection for bug fix by keywords."""
        template = await template_service.select_template(
            task_content="There's a small bug in the login form that needs a quick fix. "
            "It's a typo in the error message."
        )

        assert template.template_id == "quick_fix"

    @pytest.mark.asyncio
    async def test_select_template_by_keywords_security(self, template_service):
        """Test template selection for security audit by keywords."""
        template = await template_service.select_template(
            task_content="Perform a comprehensive security audit of the authentication "
            "system. Check for vulnerabilities and compliance issues."
        )

        assert template.template_id == "security_audit"

    @pytest.mark.asyncio
    async def test_select_template_by_keywords_ui(self, template_service):
        """Test template selection for UI design by keywords."""
        template = await template_service.select_template(
            task_content="Design a new user interface for the dashboard. Focus on visual "
            "layout and component styling with proper accessibility."
        )

        assert template.template_id == "ui_design"

    @pytest.mark.asyncio
    async def test_select_template_by_keywords_refactoring(self, template_service):
        """Test template selection for refactoring by keywords."""
        template = await template_service.select_template(
            task_content="Refactor the codebase to improve code quality and reduce "
            "technical debt. Clean up code smells."
        )

        assert template.template_id == "refactoring"

    @pytest.mark.asyncio
    async def test_select_template_by_complexity_small_task(self, template_service):
        """Test template selection favors quick_fix for small tasks."""
        template = await template_service.select_template(
            task_content="Fix typo"  # Very short, low complexity
        )

        assert template.template_id == "quick_fix"

    @pytest.mark.asyncio
    async def test_select_template_by_complexity_large_task(self, template_service):
        """Test template selection for large complex tasks."""
        template = await template_service.select_template(
            task_content="Build a comprehensive new feature with complete architecture, "
            "implementation, testing, documentation, and security review. "
            "This is a large, complex project requiring full development workflow. " * 5
        )

        # Should select full_development due to size and complexity
        assert template.template_id == "full_development"

    @pytest.mark.asyncio
    async def test_select_template_fallback(self, template_service, clear_cache):
        """Test template selection with generic, feature-development content."""
        # Content with "comprehensive" and "feature" keywords should match full_development
        template = await template_service.select_template(
            task_content="Build a comprehensive new feature with complete architecture, "
            "implementation, testing, and documentation. This is a large development "
            "project requiring full workflow."
        )

        # Should select full_development due to keywords
        assert template.template_id == "full_development"


class TestTemplateCaching:
    """Tests for in-memory caching."""

    @pytest.mark.asyncio
    async def test_cache_initialization(self, template_service):
        """Test cache is initialized with default templates."""
        assert len(_TEMPLATE_CACHE) >= 5
        assert "quick_fix" in _TEMPLATE_CACHE
        assert "security_audit" in _TEMPLATE_CACHE

    @pytest.mark.asyncio
    async def test_cache_hit(self, template_service):
        """Test cache is used on repeated access."""
        # First access
        template1 = await template_service.get_template("quick_fix")
        timestamp1 = _CACHE_TIMESTAMP.get("quick_fix")

        # Second access (should use cache)
        template2 = await template_service.get_template("quick_fix")
        timestamp2 = _CACHE_TIMESTAMP.get("quick_fix")

        assert template1 is template2  # Same object
        assert timestamp1 == timestamp2  # Timestamp unchanged

    @pytest.mark.asyncio
    async def test_cache_is_valid(self, template_service):
        """Test cache validity check."""
        # Template in cache
        assert template_service._is_cache_valid("quick_fix")

        # Template not in cache
        assert not template_service._is_cache_valid("nonexistent")

    @pytest.mark.asyncio
    async def test_cache_update_on_create(self, template_service, clear_cache):
        """Test cache is updated when template is created."""
        await template_service.create_template(
            template_id="new_template",
            name="New",
            description="New",
            task_type="new",
            phases=[
                {
                    "phase": "test",
                    "name": "Test",
                    "agents": ["test"],
                    "approval_gate": "gate",
                }
            ],
        )

        assert "new_template" in _TEMPLATE_CACHE
        assert template_service._is_cache_valid("new_template")

    @pytest.mark.asyncio
    async def test_cache_update_on_modify(self, template_service, clear_cache):
        """Test cache is updated when template is modified (custom template only)."""
        # Create a custom template (system templates are protected)
        await template_service.create_template(
            template_id="modifiable_template",
            name="Original Name",
            description="Template for cache modification testing",
            task_type="test",
            phases=[
                {
                    "phase": "test_phase",
                    "name": "Test Phase",
                    "agents": ["test-agent"],
                    "approval_gate": "Test gate",
                }
            ],
        )

        original = await template_service.get_template("modifiable_template")
        original_name = original.name

        await template_service.update_template("modifiable_template", name="Modified Name")

        updated = await template_service.get_template("modifiable_template")
        assert updated.name == "Modified Name"
        assert updated.name != original_name

    @pytest.mark.asyncio
    async def test_cache_removal_on_delete(self, template_service, clear_cache):
        """Test cache is cleared when template is deleted."""
        # Create and cache a template
        await template_service.create_template(
            template_id="to_delete",
            name="Delete",
            description="Delete",
            task_type="delete",
            phases=[
                {
                    "phase": "test",
                    "name": "Test",
                    "agents": ["test"],
                    "approval_gate": "gate",
                }
            ],
        )
        assert "to_delete" in _TEMPLATE_CACHE

        # Delete it
        await template_service.delete_template("to_delete")

        assert "to_delete" not in _TEMPLATE_CACHE
        assert not template_service._is_cache_valid("to_delete")


class TestTemplateStats:
    """Tests for template statistics."""

    @pytest.mark.asyncio
    async def test_get_template_stats(self, template_service):
        """Test getting template statistics."""
        stats = await template_service.get_template_stats()

        assert stats["total_templates"] == 5
        assert "by_complexity" in stats
        assert stats["by_complexity"]["low"] == 1  # quick_fix
        assert stats["by_complexity"]["high"] >= 1
        assert "average_duration" in stats
        assert stats["average_duration"] > 0
        assert "average_success_rate" in stats
        assert 0.0 <= stats["average_success_rate"] <= 1.0
        assert "cache_size" in stats
        assert stats["cache_size"] >= 5


class TestDefaultTemplates:
    """Tests for default template configurations."""

    def test_quick_fix_template_structure(self):
        """Test quick_fix template has correct structure."""
        template = DEFAULT_TEMPLATES["quick_fix"]

        assert template.complexity == "low"
        assert len(template.phases) == 2
        assert template.phases[0]["agents"] == ["metis-developer"]
        assert template.phases[1]["agents"] == ["artemis-optimizer"]
        assert "fix" in template.keywords

    def test_security_audit_template_structure(self):
        """Test security_audit template has correct structure."""
        template = DEFAULT_TEMPLATES["security_audit"]

        assert template.complexity == "high"
        assert len(template.phases) == 3
        assert "hestia-auditor" in template.phases[1]["agents"]
        assert "security" in template.keywords

    def test_full_development_template_structure(self):
        """Test full_development template has correct structure."""
        template = DEFAULT_TEMPLATES["full_development"]

        assert template.complexity == "high"
        assert len(template.phases) == 4
        assert "hera-strategist" in template.phases[0]["agents"]
        assert "athena-conductor" in template.phases[0]["agents"]

    def test_ui_design_template_structure(self):
        """Test ui_design template has correct structure."""
        template = DEFAULT_TEMPLATES["ui_design"]

        assert template.complexity == "medium"
        assert len(template.phases) == 3
        assert "aphrodite-designer" in template.phases[0]["agents"]

    def test_refactoring_template_structure(self):
        """Test refactoring template has correct structure."""
        template = DEFAULT_TEMPLATES["refactoring"]

        assert template.complexity == "medium"
        assert len(template.phases) == 3
        assert "artemis-optimizer" in template.phases[0]["agents"]
        assert "refactor" in template.keywords

    def test_all_templates_have_required_fields(self):
        """Test all default templates have required fields."""
        for template_id, template in DEFAULT_TEMPLATES.items():
            assert template.template_id == template_id
            assert template.name
            assert template.description
            assert template.task_type
            assert len(template.phases) > 0
            assert template.complexity in ["low", "medium", "high"]
            assert 0.0 <= template.success_rate <= 1.0
            assert template.estimated_duration_minutes > 0

            # All phases have required fields
            for phase in template.phases:
                assert "phase" in phase
                assert "name" in phase
                assert "agents" in phase
                assert "approval_gate" in phase
                assert isinstance(phase["agents"], list)
                assert len(phase["agents"]) > 0
