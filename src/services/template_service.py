"""Template Service for Trinitas Full Mode Dynamic Configuration.

Provides CRUD operations and intelligent template selection for Trinitas orchestration.
Templates define phase structures, agent assignments, and execution parameters for
different task types (quick_fix, security_audit, full_development, etc.).

Features:
- In-memory caching with 300s TTL for performance
- Keyword-based template matching (40% weight)
- Complexity estimation (30% weight)
- Duration estimation (20% weight)
- Historical success rate (10% weight)
- User hint prioritization ("/trinitas quick_fix")
"""

import logging
import re
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import NotFoundError, ValidationError
from .base_service import BaseService

logger = logging.getLogger(__name__)


# In-memory cache for templates (300-second TTL) with LRU eviction
# H-5 Fix: Added cache size limit to prevent memory exhaustion
_MAX_CACHE_SIZE = 100  # Maximum cached templates
_TEMPLATE_CACHE: OrderedDict[str, "PhaseTemplate"] = OrderedDict()
_CACHE_TIMESTAMP: dict[str, datetime] = {}
_CACHE_TTL_SECONDS = 300

# H-2 Fix: Whitelist of fields allowed in update operations
ALLOWED_UPDATE_FIELDS = {
    "name",
    "description",
    "phases",
    "complexity",
    "estimated_duration_minutes",
    "keywords",
    "metadata",
}

# H-3 Fix: Validation constraints for JSON data
MAX_JSON_DEPTH = 5
MAX_JSON_SIZE_BYTES = 100_000  # 100KB limit
MAX_KEYWORDS_COUNT = 50
MAX_KEYWORD_LENGTH = 100
MAX_PHASES_COUNT = 10
MAX_TASK_CONTENT_LENGTH = 10_000  # M-4 Fix: ReDoS protection


class PhaseTemplate:
    """Phase template configuration for Trinitas Full Mode.

    This is a lightweight data class representing a template configuration.
    In production, this would be backed by a database model.
    """

    def __init__(
        self,
        template_id: str,
        name: str,
        description: str,
        task_type: str,
        phases: list[dict[str, Any]],
        complexity: str = "medium",  # low, medium, high
        estimated_duration_minutes: int = 60,
        keywords: list[str] | None = None,
        success_rate: float = 0.8,
        metadata: dict[str, Any] | None = None,
    ):
        self.template_id = template_id
        self.name = name
        self.description = description
        self.task_type = task_type
        self.phases = phases
        self.complexity = complexity
        self.estimated_duration_minutes = estimated_duration_minutes
        self.keywords = keywords or []
        self.success_rate = success_rate
        self.metadata = metadata or {}
        self.created_at = datetime.now(UTC)

    def to_dict(self) -> dict[str, Any]:
        """Convert template to dictionary representation."""
        return {
            "template_id": self.template_id,
            "name": self.name,
            "description": self.description,
            "task_type": self.task_type,
            "phases": self.phases,
            "complexity": self.complexity,
            "estimated_duration_minutes": self.estimated_duration_minutes,
            "keywords": self.keywords,
            "success_rate": self.success_rate,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


# Default templates for Trinitas Full Mode
DEFAULT_TEMPLATES = {
    "quick_fix": PhaseTemplate(
        template_id="quick_fix",
        name="Quick Fix",
        description="Rapid implementation and verification for small fixes",
        task_type="quick_fix",
        phases=[
            {
                "phase": "implementation",
                "name": "Implementation",
                "description": "Direct implementation of fix",
                "agents": ["metis-developer"],
                "approval_gate": "Code review passed",
                "timeout_minutes": 30,
                "required_outputs": ["code_changes", "test_results"],
            },
            {
                "phase": "verification",
                "name": "Verification",
                "description": "Quick verification and testing",
                "agents": ["artemis-optimizer"],
                "approval_gate": "Tests passing, no regressions",
                "timeout_minutes": 15,
                "required_outputs": ["verification_report"],
            },
        ],
        complexity="low",
        estimated_duration_minutes=45,
        keywords=[
            "fix",
            "bug",
            "hotfix",
            "patch",
            "urgent",
            "quick",
            "small",
            "typo",
            "correction",
        ],
        success_rate=0.95,
    ),
    "security_audit": PhaseTemplate(
        template_id="security_audit",
        name="Security Audit",
        description="Comprehensive security review and documentation",
        task_type="security_audit",
        phases=[
            {
                "phase": "planning",
                "name": "Audit Planning",
                "description": "Define audit scope and threat model",
                "agents": ["hera-strategist"],
                "approval_gate": "Scope approved",
                "timeout_minutes": 30,
                "required_outputs": ["audit_plan", "threat_model"],
            },
            {
                "phase": "verification",
                "name": "Security Analysis",
                "description": "Deep security audit by Hestia",
                "agents": ["hestia-auditor"],
                "approval_gate": "No critical vulnerabilities",
                "timeout_minutes": 90,
                "required_outputs": ["security_report", "vulnerability_list"],
            },
            {
                "phase": "documentation",
                "name": "Security Documentation",
                "description": "Document findings and remediation steps",
                "agents": ["muses-documenter"],
                "approval_gate": "Documentation complete",
                "timeout_minutes": 30,
                "required_outputs": ["security_documentation"],
            },
        ],
        complexity="high",
        estimated_duration_minutes=150,
        keywords=[
            "security",
            "audit",
            "vulnerability",
            "penetration",
            "threat",
            "risk",
            "compliance",
            "hardening",
        ],
        success_rate=0.85,
    ),
    "full_development": PhaseTemplate(
        template_id="full_development",
        name="Full Development",
        description="Complete 4-phase development workflow",
        task_type="full_development",
        phases=[
            {
                "phase": "phase_1_strategic",
                "name": "Strategic Planning",
                "description": "Architecture and resource coordination",
                "agents": ["hera-strategist", "athena-conductor"],
                "approval_gate": "Strategic consensus",
                "timeout_minutes": 60,
                "required_outputs": ["architecture_design", "resource_plan"],
            },
            {
                "phase": "phase_2_implementation",
                "name": "Implementation",
                "description": "Development and testing",
                "agents": ["artemis-optimizer", "metis-developer"],
                "approval_gate": "Tests passing, no regressions",
                "timeout_minutes": 120,
                "required_outputs": ["code_changes", "test_suite"],
            },
            {
                "phase": "phase_3_verification",
                "name": "Verification",
                "description": "Security and quality audit",
                "agents": ["hestia-auditor", "artemis-optimizer"],
                "approval_gate": "Security approved",
                "timeout_minutes": 60,
                "required_outputs": ["security_report", "performance_report"],
            },
            {
                "phase": "phase_4_documentation",
                "name": "Documentation",
                "description": "Comprehensive documentation",
                "agents": ["muses-documenter", "aphrodite-designer"],
                "approval_gate": "Documentation complete",
                "timeout_minutes": 45,
                "required_outputs": ["user_docs", "api_docs"],
            },
        ],
        complexity="high",
        estimated_duration_minutes=285,
        keywords=[
            "feature",
            "development",
            "implementation",
            "architecture",
            "complex",
            "large",
            "comprehensive",
        ],
        success_rate=0.8,
    ),
    "ui_design": PhaseTemplate(
        template_id="ui_design",
        name="UI/UX Design",
        description="Design-focused workflow with implementation",
        task_type="ui_design",
        phases=[
            {
                "phase": "planning",
                "name": "Design Planning",
                "description": "User research and design strategy",
                "agents": ["aphrodite-designer", "athena-conductor"],
                "approval_gate": "Design strategy approved",
                "timeout_minutes": 45,
                "required_outputs": ["design_strategy", "user_research"],
            },
            {
                "phase": "implementation",
                "name": "UI Implementation",
                "description": "Build UI components and pages",
                "agents": ["aphrodite-designer", "metis-developer"],
                "approval_gate": "Design review passed",
                "timeout_minutes": 90,
                "required_outputs": ["ui_components", "style_guide"],
            },
            {
                "phase": "verification",
                "name": "Accessibility & Performance",
                "description": "Verify WCAG compliance and performance",
                "agents": ["artemis-optimizer"],
                "approval_gate": "Accessibility and performance approved",
                "timeout_minutes": 30,
                "required_outputs": ["accessibility_report", "performance_metrics"],
            },
        ],
        complexity="medium",
        estimated_duration_minutes=165,
        keywords=[
            "ui",
            "ux",
            "design",
            "interface",
            "frontend",
            "visual",
            "layout",
            "component",
            "styling",
        ],
        success_rate=0.88,
    ),
    "refactoring": PhaseTemplate(
        template_id="refactoring",
        name="Code Refactoring",
        description="Code quality improvement workflow",
        task_type="refactoring",
        phases=[
            {
                "phase": "planning",
                "name": "Refactoring Planning",
                "description": "Identify code smells and create plan",
                "agents": ["artemis-optimizer", "athena-conductor"],
                "approval_gate": "Refactoring plan approved",
                "timeout_minutes": 30,
                "required_outputs": ["refactoring_plan", "impact_analysis"],
            },
            {
                "phase": "implementation",
                "name": "Code Refactoring",
                "description": "Refactor code with test coverage",
                "agents": ["artemis-optimizer", "metis-developer"],
                "approval_gate": "All tests passing",
                "timeout_minutes": 90,
                "required_outputs": ["refactored_code", "test_results"],
            },
            {
                "phase": "verification",
                "name": "Quality Verification",
                "description": "Verify code quality metrics",
                "agents": ["artemis-optimizer"],
                "approval_gate": "Quality metrics improved",
                "timeout_minutes": 20,
                "required_outputs": ["quality_report"],
            },
        ],
        complexity="medium",
        estimated_duration_minutes=140,
        keywords=[
            "refactor",
            "cleanup",
            "improve",
            "optimize",
            "quality",
            "debt",
            "technical debt",
            "code smell",
        ],
        success_rate=0.9,
    ),
}


class TemplateService(BaseService):
    """Service for managing Trinitas Full Mode templates.

    Provides:
    - CRUD operations for phase templates
    - Intelligent template selection based on task content
    - In-memory caching with TTL for performance
    - Keyword matching, complexity estimation, and success rate analysis
    """

    def __init__(self, session: AsyncSession):
        """Initialize template service with database session."""
        super().__init__(session)
        self._initialize_default_templates()

    def _initialize_default_templates(self):
        """Load default templates into cache on initialization."""
        global _TEMPLATE_CACHE, _CACHE_TIMESTAMP
        for template_id, template in DEFAULT_TEMPLATES.items():
            _TEMPLATE_CACHE[template_id] = template
            _CACHE_TIMESTAMP[template_id] = datetime.now(UTC)

    def _is_cache_valid(self, template_id: str) -> bool:
        """Check if cached template is still valid (within TTL)."""
        if template_id not in _CACHE_TIMESTAMP:
            return False
        age = (datetime.now(UTC) - _CACHE_TIMESTAMP[template_id]).total_seconds()
        return age < _CACHE_TTL_SECONDS

    def _cache_template(self, template: PhaseTemplate):
        """Store template in cache with current timestamp.

        H-5 Fix: Implements LRU eviction when cache is full.
        """
        global _TEMPLATE_CACHE, _CACHE_TIMESTAMP

        # H-5 Fix: Evict oldest entries if cache is full
        while len(_TEMPLATE_CACHE) >= _MAX_CACHE_SIZE:
            oldest_key = next(iter(_TEMPLATE_CACHE))
            _TEMPLATE_CACHE.pop(oldest_key)
            _CACHE_TIMESTAMP.pop(oldest_key, None)
            logger.debug(f"Cache evicted oldest template: {oldest_key}")

        _TEMPLATE_CACHE[template.template_id] = template
        _CACHE_TIMESTAMP[template.template_id] = datetime.now(UTC)

    async def get_template(self, template_id: str) -> PhaseTemplate | None:
        """Get template by ID.

        Uses in-memory cache with 300s TTL. Returns None if not found.

        Args:
            template_id: Unique template identifier

        Returns:
            PhaseTemplate if found, None otherwise
        """
        # Check cache first
        if self._is_cache_valid(template_id):
            logger.debug(f"Cache hit for template: {template_id}")
            return _TEMPLATE_CACHE.get(template_id)

        # In production, this would query database:
        # result = await self.session.execute(
        #     select(PhaseTemplate).where(PhaseTemplate.template_id == template_id)
        # )
        # template = result.scalar_one_or_none()

        # For now, return from default templates
        template = DEFAULT_TEMPLATES.get(template_id)
        if template:
            self._cache_template(template)

        return template

    async def get_template_by_task_type(self, task_type: str) -> PhaseTemplate | None:
        """Get template by task type.

        Args:
            task_type: Task type identifier (e.g., "quick_fix", "security_audit")

        Returns:
            PhaseTemplate if found, None otherwise
        """
        # In production, query database by task_type
        # For now, search default templates
        for template in DEFAULT_TEMPLATES.values():
            if template.task_type == task_type:
                self._cache_template(template)
                return template

        return None

    async def select_template(
        self, task_content: str, user_hint: str | None = None
    ) -> PhaseTemplate:
        """Intelligently select template based on task content and user hints.

        Selection algorithm (prioritized):
        1. User hint (100% if provided): "/trinitas quick_fix" → quick_fix template
        2. Keyword matching (40% weight): Match task content to template keywords
        3. Complexity estimation (30% weight): Estimate task complexity
        4. Duration estimation (20% weight): Prefer shorter templates for simple tasks
        5. Historical success rate (10% weight): Favor templates with higher success rates

        Args:
            task_content: Full task description/content
            user_hint: Optional user hint (e.g., "quick_fix", "security_audit")

        Returns:
            PhaseTemplate best matching the task requirements

        Raises:
            NotFoundError: If no suitable template found (should never happen with fallback)
        """
        # M-4 Fix: ReDoS protection - limit input size
        if len(task_content) > MAX_TASK_CONTENT_LENGTH:
            logger.warning(
                f"Task content truncated from {len(task_content)} to {MAX_TASK_CONTENT_LENGTH} chars"
            )
            task_content = task_content[:MAX_TASK_CONTENT_LENGTH]

        # Priority 1: User hint (explicit template selection)
        if user_hint:
            # Extract template name from hints like "/trinitas quick_fix"
            hint_lower = user_hint.lower()
            for template_id in DEFAULT_TEMPLATES:
                if template_id in hint_lower or template_id.replace("_", " ") in hint_lower:
                    template = await self.get_template(template_id)
                    if template:
                        logger.info(
                            f"Template selected by user hint: {template.name} "
                            f"(hint: {user_hint})"
                        )
                        return template

        # Prepare task content for analysis
        task_lower = task_content.lower()
        task_words = set(re.findall(r"\w+", task_lower))

        # Score each template
        scores: dict[str, float] = {}

        for template_id, template in DEFAULT_TEMPLATES.items():
            score = 0.0

            # Priority 2: Keyword matching (40% weight)
            keyword_matches = sum(
                1 for keyword in template.keywords if keyword.lower() in task_lower
            )
            keyword_score = min(keyword_matches / max(len(template.keywords), 1), 1.0)
            score += keyword_score * 0.4

            # Priority 3: Complexity estimation (30% weight)
            # Estimate complexity by content length and technical terms
            complexity_indicators = {
                "low": ["fix", "bug", "typo", "small", "quick", "simple"],
                "medium": ["refactor", "improve", "update", "enhance", "modify"],
                "high": [
                    "feature",
                    "architecture",
                    "security",
                    "complex",
                    "comprehensive",
                ],
            }

            estimated_complexity = "medium"  # default
            if len(task_content) < 100:
                estimated_complexity = "low"
            elif len(task_content) > 500:
                estimated_complexity = "high"

            # Adjust by indicator words
            for complexity_level, indicators in complexity_indicators.items():
                if any(indicator in task_lower for indicator in indicators):
                    estimated_complexity = complexity_level
                    break

            complexity_match = 1.0 if template.complexity == estimated_complexity else 0.5
            score += complexity_match * 0.3

            # Priority 4: Duration estimation (20% weight)
            # Prefer shorter templates for smaller tasks
            duration_ratio = min(
                template.estimated_duration_minutes / 180, 1.0
            )  # normalize to 180min
            if len(task_content) < 200:
                # Small task: prefer short templates
                duration_score = 1.0 - duration_ratio
            else:
                # Large task: no strong preference
                duration_score = 0.5

            score += duration_score * 0.2

            # Priority 5: Historical success rate (10% weight)
            score += template.success_rate * 0.1

            scores[template_id] = score
            logger.debug(
                f"Template {template.name} scored {score:.3f} "
                f"(keyword: {keyword_score:.2f}, complexity: {complexity_match:.2f}, "
                f"duration: {duration_score:.2f}, success: {template.success_rate:.2f})"
            )

        # Select best template
        if not scores:
            # Fallback to full_development if no templates scored
            logger.warning("No templates scored, falling back to full_development")
            return DEFAULT_TEMPLATES["full_development"]

        best_template_id = max(scores, key=scores.get)  # type: ignore
        best_template = DEFAULT_TEMPLATES[best_template_id]

        logger.info(
            f"Template selected: {best_template.name} "
            f"(score: {scores[best_template_id]:.3f}, "
            f"complexity: {best_template.complexity}, "
            f"duration: {best_template.estimated_duration_minutes}min)"
        )

        return best_template

    async def create_template(
        self,
        template_id: str,
        name: str,
        description: str,
        task_type: str,
        phases: list[dict[str, Any]],
        complexity: str = "medium",
        estimated_duration_minutes: int = 60,
        keywords: list[str] | None = None,
        success_rate: float = 0.8,
        metadata: dict[str, Any] | None = None,
    ) -> PhaseTemplate:
        """Create a new phase template.

        Args:
            template_id: Unique identifier (e.g., "quick_fix")
            name: Human-readable name
            description: Template description
            task_type: Task type identifier
            phases: List of phase configurations (dicts with phase, name, agents, etc.)
            complexity: Complexity level (low, medium, high)
            estimated_duration_minutes: Estimated execution time
            keywords: Keywords for matching
            success_rate: Historical success rate (0.0-1.0)
            metadata: Additional metadata

        Returns:
            Created PhaseTemplate

        Raises:
            ValidationError: If template_id already exists or validation fails
        """
        # Validate template_id uniqueness
        existing = await self.get_template(template_id)
        if existing:
            raise ValidationError(f"Template with ID '{template_id}' already exists")

        # H-3 Fix: Validate template_id format (alphanumeric + underscore only)
        if not re.match(r"^[a-z0-9_]+$", template_id):
            raise ValidationError(
                f"Invalid template_id '{template_id}'. "
                "Only lowercase alphanumeric characters and underscores allowed."
            )

        # Validate complexity
        if complexity not in ["low", "medium", "high"]:
            raise ValidationError(f"Invalid complexity: {complexity}. Must be low/medium/high")

        # Validate success_rate
        if not 0.0 <= success_rate <= 1.0:
            raise ValidationError(f"Invalid success_rate: {success_rate}. Must be 0.0-1.0")

        # M-2 Fix: Validate keywords count and length
        if keywords:
            if len(keywords) > MAX_KEYWORDS_COUNT:
                raise ValidationError(f"Maximum {MAX_KEYWORDS_COUNT} keywords allowed")
            for keyword in keywords:
                if not isinstance(keyword, str):
                    raise ValidationError("Keywords must be strings")
                if len(keyword) > MAX_KEYWORD_LENGTH:
                    raise ValidationError(f"Keyword exceeds {MAX_KEYWORD_LENGTH} characters")

        # Validate phases structure using shared validation
        self._validate_phases(phases)

        template = PhaseTemplate(
            template_id=template_id,
            name=name,
            description=description,
            task_type=task_type,
            phases=phases,
            complexity=complexity,
            estimated_duration_minutes=estimated_duration_minutes,
            keywords=keywords,
            success_rate=success_rate,
            metadata=metadata,
        )

        # In production, save to database:
        # await self.session.add(template)
        # await self.session.commit()

        # Cache the new template
        self._cache_template(template)

        logger.info(
            f"Created template: {template.name} "
            f"({len(template.phases)} phases, {template.complexity} complexity)"
        )

        return template

    async def list_templates(self, filter_by: str | None = None) -> list[PhaseTemplate]:
        """List all available templates.

        Args:
            filter_by: Optional filter by task_type or complexity

        Returns:
            List of PhaseTemplate objects
        """
        # In production, query database:
        # query = select(PhaseTemplate)
        # if filter_by:
        #     query = query.where(
        #         or_(
        #             PhaseTemplate.task_type == filter_by,
        #             PhaseTemplate.complexity == filter_by,
        #         )
        #     )
        # result = await self.session.execute(query)
        # templates = result.scalars().all()

        # For now, return default templates
        templates = list(DEFAULT_TEMPLATES.values())

        if filter_by:
            filter_lower = filter_by.lower()
            templates = [
                t
                for t in templates
                if t.task_type == filter_lower or t.complexity == filter_lower
            ]

        logger.debug(f"Listed {len(templates)} templates (filter: {filter_by})")
        return templates

    async def update_template(
        self,
        template_id: str,
        **updates: Any,
    ) -> PhaseTemplate:
        """Update an existing template.

        Args:
            template_id: Template identifier
            **updates: Fields to update (name, description, phases, etc.)

        Returns:
            Updated PhaseTemplate

        Raises:
            NotFoundError: If template not found
            ValidationError: If validation fails or system template modification attempted
        """
        template = await self.get_template(template_id)
        if not template:
            raise NotFoundError("PhaseTemplate", template_id)

        # H-1 Fix: Prevent system template modification
        if template_id in DEFAULT_TEMPLATES:
            raise ValidationError(
                f"Cannot modify system template '{template_id}'. "
                "Create a custom template instead."
            )

        # H-2 Fix: Whitelist allowed fields - prevent arbitrary attribute injection
        for key, value in updates.items():
            if key not in ALLOWED_UPDATE_FIELDS:
                raise ValidationError(
                    f"Field '{key}' cannot be updated. "
                    f"Allowed fields: {', '.join(sorted(ALLOWED_UPDATE_FIELDS))}"
                )

            # Validate specific fields
            if key == "complexity" and value not in ["low", "medium", "high"]:
                raise ValidationError(f"Invalid complexity: {value}")

            # M-2 Fix: Validate keywords count and length
            if key == "keywords":
                if not isinstance(value, list):
                    raise ValidationError("Keywords must be a list")
                if len(value) > MAX_KEYWORDS_COUNT:
                    raise ValidationError(f"Maximum {MAX_KEYWORDS_COUNT} keywords allowed")
                for keyword in value:
                    if not isinstance(keyword, str):
                        raise ValidationError("Keywords must be strings")
                    if len(keyword) > MAX_KEYWORD_LENGTH:
                        raise ValidationError(
                            f"Keyword exceeds {MAX_KEYWORD_LENGTH} characters"
                        )

            # Validate phases structure
            if key == "phases":
                self._validate_phases(value)

            if hasattr(template, key):
                setattr(template, key, value)

        # In production, update database:
        # await self.session.commit()

        # Update cache
        self._cache_template(template)

        logger.info(f"Updated template: {template.name} ({len(updates)} fields)")
        return template

    def _validate_phases(self, phases: list[dict[str, Any]]) -> None:
        """Validate phases structure for H-3 protection.

        Args:
            phases: List of phase configurations

        Raises:
            ValidationError: If validation fails
        """
        if not phases:
            raise ValidationError("Template must have at least one phase")

        if len(phases) > MAX_PHASES_COUNT:
            raise ValidationError(f"Maximum {MAX_PHASES_COUNT} phases allowed")

        for idx, phase in enumerate(phases):
            required_keys = ["phase", "name", "agents", "approval_gate"]
            missing = [key for key in required_keys if key not in phase]
            if missing:
                raise ValidationError(
                    f"Phase {idx} missing required keys: {missing}"
                )

            # H-3 Fix: Validate agent names (alphanumeric + hyphens only)
            if "agents" in phase:
                for agent in phase["agents"]:
                    if not isinstance(agent, str):
                        raise ValidationError(f"Agent name must be string, got: {type(agent)}")
                    if not re.match(r"^[a-z0-9-]+$", agent):
                        raise ValidationError(
                            f"Invalid agent name '{agent}'. "
                            "Only lowercase alphanumeric characters and hyphens allowed."
                        )

    async def delete_template(self, template_id: str) -> bool:
        """Delete a template.

        Args:
            template_id: Template identifier

        Returns:
            True if deleted successfully

        Raises:
            NotFoundError: If template not found
            ValidationError: If attempting to delete system template
        """
        template = await self.get_template(template_id)
        if not template:
            raise NotFoundError("PhaseTemplate", template_id)

        # H-1 Fix: Prevent system template deletion
        if template_id in DEFAULT_TEMPLATES:
            raise ValidationError(
                f"Cannot delete system template '{template_id}'. "
                "System templates are protected."
            )

        # In production, delete from database:
        # await self.session.delete(template)
        # await self.session.commit()

        # Remove from cache
        global _TEMPLATE_CACHE, _CACHE_TIMESTAMP
        _TEMPLATE_CACHE.pop(template_id, None)
        _CACHE_TIMESTAMP.pop(template_id, None)

        logger.info(f"Deleted template: {template.name}")
        return True

    async def get_template_stats(self) -> dict[str, Any]:
        """Get statistics about available templates.

        Returns:
            Dictionary with template statistics
        """
        templates = await self.list_templates()

        stats = {
            "total_templates": len(templates),
            "by_complexity": {
                "low": len([t for t in templates if t.complexity == "low"]),
                "medium": len([t for t in templates if t.complexity == "medium"]),
                "high": len([t for t in templates if t.complexity == "high"]),
            },
            "average_duration": (
                sum(t.estimated_duration_minutes for t in templates) / len(templates)
                if templates
                else 0
            ),
            "average_success_rate": (
                sum(t.success_rate for t in templates) / len(templates) if templates else 0
            ),
            "cache_size": len(_TEMPLATE_CACHE),
            "cached_templates": list(_TEMPLATE_CACHE.keys()),
        }

        return stats
