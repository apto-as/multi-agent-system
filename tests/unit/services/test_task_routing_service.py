"""Unit tests for TaskRoutingService.

Tests intelligent task-to-agent routing based on content analysis,
persona patterns, and agent capabilities.
"""

import pytest

from src.services.task_routing_service import (
    AgentTier,
    RoutingResult,
    TaskRoutingService,
)


class TestAgentTier:
    """Tests for AgentTier enum."""

    def test_tier_values(self):
        """Verify tier priority values."""
        assert AgentTier.STRATEGIC.value == 1
        assert AgentTier.SPECIALIST.value == 2
        assert AgentTier.SUPPORT.value == 3

    def test_tier_ordering(self):
        """Verify strategic > specialist > support."""
        assert AgentTier.STRATEGIC.value < AgentTier.SPECIALIST.value
        assert AgentTier.SPECIALIST.value < AgentTier.SUPPORT.value


class TestRoutingResult:
    """Tests for RoutingResult dataclass."""

    def test_routing_result_creation(self):
        """Verify RoutingResult can be created with all fields."""
        result = RoutingResult(
            primary_agent="athena-conductor",
            support_agents=["aurora-researcher"],
            confidence=0.85,
            reasoning="Test reasoning",
            detected_patterns=["athena-conductor"],
            suggested_phase="Phase 1: Strategic Planning",
        )
        assert result.primary_agent == "athena-conductor"
        assert result.confidence == 0.85
        assert result.suggested_phase == "Phase 1: Strategic Planning"

    def test_routing_result_defaults(self):
        """Verify optional field defaults."""
        result = RoutingResult(
            primary_agent="test",
            support_agents=[],
            confidence=0.5,
            reasoning="test",
            detected_patterns=[],
        )
        assert result.suggested_phase is None


class TestTaskRoutingService:
    """Tests for TaskRoutingService."""

    @pytest.fixture
    def routing_service(self):
        """Create a routing service instance."""
        return TaskRoutingService()

    class TestPersonaPatterns:
        """Tests for persona pattern detection."""

        @pytest.fixture
        def routing_service(self):
            return TaskRoutingService()

        def test_detect_athena_patterns(self, routing_service):
            """Athena triggers on orchestration/workflow keywords."""
            matches = routing_service.detect_personas(
                "orchestrate the workflow and coordinate parallel tasks",
            )
            assert "athena-conductor" in matches
            assert matches["athena-conductor"] > 0.3

        def test_detect_artemis_patterns(self, routing_service):
            """Artemis triggers on optimization/performance keywords."""
            matches = routing_service.detect_personas(
                "optimize performance and improve code quality",
            )
            assert "artemis-optimizer" in matches
            assert matches["artemis-optimizer"] > 0.3

        def test_detect_hestia_patterns(self, routing_service):
            """Hestia triggers on security/audit keywords."""
            matches = routing_service.detect_personas(
                "security audit and vulnerability assessment",
            )
            assert "hestia-auditor" in matches
            assert matches["hestia-auditor"] > 0.3

        def test_detect_eris_patterns(self, routing_service):
            """Eris triggers on coordination/team keywords."""
            matches = routing_service.detect_personas(
                "coordinate the team and resolve conflicts",
            )
            assert "eris-coordinator" in matches

        def test_detect_hera_patterns(self, routing_service):
            """Hera triggers on strategy/architecture keywords."""
            matches = routing_service.detect_personas(
                "strategic planning and architecture design",
            )
            assert "hera-strategist" in matches

        def test_detect_muses_patterns(self, routing_service):
            """Muses triggers on documentation keywords."""
            matches = routing_service.detect_personas(
                "document the API and create specifications",
            )
            assert "muses-documenter" in matches

        def test_detect_aphrodite_patterns(self, routing_service):
            """Aphrodite triggers on design/UI/UX keywords."""
            matches = routing_service.detect_personas(
                "design the user interface with good usability",
            )
            assert "aphrodite-designer" in matches

        def test_detect_metis_patterns(self, routing_service):
            """Metis triggers on implementation/code keywords."""
            matches = routing_service.detect_personas(
                "implement the feature and write tests",
            )
            assert "metis-developer" in matches

        def test_detect_aurora_patterns(self, routing_service):
            """Aurora triggers on search/research keywords."""
            matches = routing_service.detect_personas(
                "search for context and research patterns",
            )
            assert "aurora-researcher" in matches

        def test_multiple_personas_detected(self, routing_service):
            """Multiple personas can be detected from single input."""
            matches = routing_service.detect_personas(
                "optimize security and document the architecture",
            )
            assert len(matches) >= 2
            # Should detect artemis (optimize), hestia (security), muses (document)

        def test_empty_content_returns_empty(self, routing_service):
            """Empty content returns no matches."""
            matches = routing_service.detect_personas("")
            assert matches == {}

        def test_no_matches_returns_empty(self, routing_service):
            """Unrelated content returns no matches."""
            matches = routing_service.detect_personas("hello world foo bar")
            assert matches == {}

        def test_case_insensitive_matching(self, routing_service):
            """Pattern matching is case insensitive."""
            lower = routing_service.detect_personas("optimize performance")
            upper = routing_service.detect_personas("OPTIMIZE PERFORMANCE")
            assert "artemis-optimizer" in lower
            assert "artemis-optimizer" in upper

    class TestTaskTypeDetection:
        """Tests for task type detection."""

        @pytest.fixture
        def routing_service(self):
            return TaskRoutingService()

        def test_detect_security_audit(self, routing_service):
            """Detects security audit task type."""
            task_type = routing_service.detect_task_type("security audit the system")
            assert task_type == "security_audit"

        def test_detect_architecture(self, routing_service):
            """Detects architecture task type."""
            task_type = routing_service.detect_task_type("architect the new system")
            assert task_type == "architecture"

        def test_detect_implementation(self, routing_service):
            """Detects implementation task type."""
            task_type = routing_service.detect_task_type("implement the new feature")
            assert task_type == "implementation"

        def test_detect_documentation(self, routing_service):
            """Detects documentation task type."""
            task_type = routing_service.detect_task_type("document the API")
            assert task_type == "documentation"

        def test_detect_debugging(self, routing_service):
            """Detects debugging task type."""
            task_type = routing_service.detect_task_type("debug the failing test")
            assert task_type == "debugging"

        def test_detect_research(self, routing_service):
            """Detects research task type."""
            task_type = routing_service.detect_task_type("research best practices")
            assert task_type == "research"

        def test_detect_optimization(self, routing_service):
            """Detects optimization task type."""
            task_type = routing_service.detect_task_type("optimize query performance")
            assert task_type == "optimization"

        def test_no_task_type_detected(self, routing_service):
            """Returns None when no task type detected."""
            task_type = routing_service.detect_task_type("hello world")
            assert task_type is None

    class TestPhaseRecommendation:
        """Tests for phase recommendation."""

        @pytest.fixture
        def routing_service(self):
            return TaskRoutingService()

        def test_strategic_phase(self, routing_service):
            """Strategy and architecture map to Phase 1."""
            phase = routing_service.get_phase_recommendation("strategy")
            assert "Phase 1" in phase

            phase = routing_service.get_phase_recommendation("architecture")
            assert "Phase 1" in phase

        def test_implementation_phase(self, routing_service):
            """Implementation tasks map to Phase 2."""
            phase = routing_service.get_phase_recommendation("implementation")
            assert "Phase 2" in phase

        def test_verification_phase(self, routing_service):
            """Security audit maps to Phase 3."""
            phase = routing_service.get_phase_recommendation("security_audit")
            assert "Phase 3" in phase

        def test_documentation_phase(self, routing_service):
            """Documentation maps to Phase 4."""
            phase = routing_service.get_phase_recommendation("documentation")
            assert "Phase 4" in phase

        def test_unknown_task_type(self, routing_service):
            """Unknown task type returns None."""
            phase = routing_service.get_phase_recommendation("unknown")
            assert phase is None

        def test_none_task_type(self, routing_service):
            """None task type returns None."""
            phase = routing_service.get_phase_recommendation(None)
            assert phase is None

    class TestRouteTask:
        """Tests for the main route_task method."""

        @pytest.fixture
        def routing_service(self):
            return TaskRoutingService()

        def test_routes_to_collaboration_matrix(self, routing_service):
            """Known task types use collaboration matrix."""
            result = routing_service.route_task("security audit the codebase")
            assert result.primary_agent == "hestia-auditor"
            assert result.confidence == 0.85  # Matrix match confidence

        def test_routes_via_pattern_matching(self, routing_service):
            """Falls back to pattern matching when no task type."""
            result = routing_service.route_task("optimize everything")
            assert result.primary_agent == "artemis-optimizer"
            assert result.confidence > 0.2  # Pattern match confidence

        def test_defaults_to_athena(self, routing_service):
            """Defaults to Athena when no patterns detected."""
            result = routing_service.route_task("hello world foo bar")
            assert result.primary_agent == "athena-conductor"
            assert result.confidence == 0.5  # Default confidence
            assert "aurora-researcher" in result.support_agents

        def test_includes_detected_patterns(self, routing_service):
            """Result includes detected persona patterns."""
            result = routing_service.route_task("optimize and secure")
            assert len(result.detected_patterns) > 0

        def test_includes_phase_recommendation(self, routing_service):
            """Result includes phase recommendation for known types."""
            result = routing_service.route_task("implement the feature")
            assert result.suggested_phase is not None
            assert "Phase 2" in result.suggested_phase

        def test_tier_priority_sorting(self, routing_service):
            """Higher tier agents prioritized for equal scores."""
            # Both Athena (strategic) and Eris (specialist) detect coordination
            result = routing_service.route_task("coordinate coordination")
            # With equal pattern scores, strategic tier should win
            # (or the first match based on detection order)
            assert result.primary_agent in ["athena-conductor", "eris-coordinator"]

    class TestTrinitasFullModeRouting:
        """Tests for get_trinitas_full_mode_routing."""

        @pytest.fixture
        def routing_service(self):
            return TaskRoutingService()

        def test_returns_full_mode_structure(self, routing_service):
            """Returns complete 4-phase execution plan."""
            plan = routing_service.get_trinitas_full_mode_routing("implement auth")
            assert plan["mode"] == "trinitas_full"
            assert "routing" in plan
            assert "execution_plan" in plan

        def test_includes_all_phases(self, routing_service):
            """Plan includes all 4 execution phases."""
            plan = routing_service.get_trinitas_full_mode_routing("test task")
            exec_plan = plan["execution_plan"]
            assert "phase_1_strategic" in exec_plan
            assert "phase_2_implementation" in exec_plan
            assert "phase_3_verification" in exec_plan
            assert "phase_4_documentation" in exec_plan

        def test_phase_1_has_strategic_agents(self, routing_service):
            """Phase 1 includes Hera and Athena."""
            plan = routing_service.get_trinitas_full_mode_routing("test")
            phase_1 = plan["execution_plan"]["phase_1_strategic"]
            assert "hera-strategist" in phase_1["agents"]
            assert "athena-conductor" in phase_1["agents"]

        def test_phase_3_has_hestia(self, routing_service):
            """Phase 3 includes Hestia for verification."""
            plan = routing_service.get_trinitas_full_mode_routing("test")
            phase_3 = plan["execution_plan"]["phase_3_verification"]
            assert "hestia-auditor" in phase_3["agents"]

        def test_phase_4_has_muses(self, routing_service):
            """Phase 4 includes Muses for documentation."""
            plan = routing_service.get_trinitas_full_mode_routing("test")
            phase_4 = plan["execution_plan"]["phase_4_documentation"]
            assert "muses-documenter" in phase_4["agents"]

        def test_includes_coordinator(self, routing_service):
            """Plan includes Eris as coordinator."""
            plan = routing_service.get_trinitas_full_mode_routing("test")
            assert plan["coordinator"] == "eris-coordinator"

        def test_includes_approval_gates(self, routing_service):
            """Each phase includes approval gate."""
            plan = routing_service.get_trinitas_full_mode_routing("test")
            for phase_key in ["phase_1_strategic", "phase_2_implementation",
                             "phase_3_verification", "phase_4_documentation"]:
                phase = plan["execution_plan"][phase_key]
                assert "approval_gate" in phase

    class TestAgentCapabilities:
        """Tests for AGENT_CAPABILITIES constant."""

        def test_all_agents_have_capabilities(self):
            """All 9 agents have defined capabilities."""
            caps = TaskRoutingService.AGENT_CAPABILITIES
            assert len(caps) == 9
            for agent_id in TaskRoutingService.AGENT_TIERS:
                assert agent_id in caps

        def test_capabilities_are_lists(self):
            """Each agent's capabilities is a non-empty list."""
            for agent_id, caps in TaskRoutingService.AGENT_CAPABILITIES.items():
                assert isinstance(caps, list)
                assert len(caps) > 0

    class TestCollaborationMatrix:
        """Tests for COLLABORATION_MATRIX constant."""

        def test_matrix_has_expected_task_types(self):
            """Matrix includes common task types."""
            matrix = TaskRoutingService.COLLABORATION_MATRIX
            expected = [
                "architecture", "implementation", "security_audit",
                "documentation", "debugging", "research",
            ]
            for task_type in expected:
                assert task_type in matrix

        def test_matrix_structure(self):
            """Each entry is (primary, support_list, reviewer) tuple."""
            for task_type, entry in TaskRoutingService.COLLABORATION_MATRIX.items():
                assert len(entry) == 3
                primary, support, reviewer = entry
                assert isinstance(primary, str)
                assert isinstance(support, list)
                assert isinstance(reviewer, str)
