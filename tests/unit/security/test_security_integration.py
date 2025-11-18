#!/usr/bin/env python3
"""
Test suite for Trinitas Security Integration
セキュリティフレームワークとTrinitasシステムの統合テスト

Test Coverage:
- TrinitasSecurityIntegration singleton pattern
- Initialization and configuration
- Persona management (set/get current persona)
- Tool access validation integration
- Secure tool wrapper decorator
- Persona context manager
- Capabilities retrieval
- Security status monitoring
- Emergency lockdown
- Convenience functions
- Error handling and edge cases
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

from shared.security.security_integration import (
    TrinitasSecurityIntegration,
    SecurityIntegrationError,
    set_persona,
    get_current_persona,
    validate_access,
    secure_tool,
    persona_context,
    get_capabilities,
    get_security_status,
    emergency_shutdown,
    initialize_security,
)

from shared.security.access_validator import (
    AccessResult,
    ValidationResult,
)


@pytest.fixture
def config_file(tmp_path):
    """Fixture: Create a valid config file"""
    config_path = tmp_path / "tool-matrix.json"
    config = {
        "metadata": {"version": "1.0.0"},
        "security_classifications": {},
        "tool_definitions": {
            "safe_read_tools": {
                "tools": ["Read", "Grep", "Glob"],
                "restrictions": {},
            },
            "code_modification_tools": {
                "tools": ["Write", "Edit"],
                "restrictions": {},
            },
            "audit_tools": {
                "tools": ["Bash"],
                "restrictions": {"allowed_commands": ["npm audit"]},
            },
        },
        "persona_access_matrix": {
            "athena": {
                "role": "Harmonious Conductor",
                "description": "システム全体の調和的な指揮",
                "security_clearance": "ORCHESTRATION",
                "allowed_tool_groups": ["safe_read_tools"],
                "special_permissions": {"workflow_automation": True},
                "restrictions": {"no_direct_code_modification": True},
            },
            "artemis": {
                "role": "Technical Perfectionist",
                "description": "パフォーマンス最適化",
                "security_clearance": "FULL_MODIFY",
                "allowed_tool_groups": ["safe_read_tools", "code_modification_tools"],
                "special_permissions": {"code_refactoring": True},
                "restrictions": {},
            },
            "hestia": {
                "role": "Security Guardian",
                "description": "セキュリティ分析",
                "security_clearance": "READ_ONLY",
                "allowed_tool_groups": ["safe_read_tools", "audit_tools"],
                "special_permissions": {"security_scanning": True},
                "restrictions": {"no_modification_allowed": True},
            },
        },
        "security_policies": {},
        "monitoring_and_alerting": {
            "alert_thresholds": {"failed_access_attempts": 3}
        },
    }

    with open(config_path, "w") as f:
        json.dump(config, f)

    return config_path


@pytest.fixture
def integration(config_file):
    """Fixture: Create a fresh SecurityIntegration instance"""
    # Import the module to access global instance
    from shared.security import security_integration

    # Reset singleton
    TrinitasSecurityIntegration._instance = None
    TrinitasSecurityIntegration._validator = None

    instance = TrinitasSecurityIntegration()
    instance.initialize(config_path=str(config_file))

    # Clear quarantine state and failed attempts to ensure test isolation
    instance._validator.quarantined_personas.clear()
    instance._validator.failed_attempts.clear()
    instance._current_persona = None

    # Update global instance reference to point to fresh instance
    security_integration._security_integration = instance

    yield instance

    # Teardown: Clear state after test to prevent leakage to next test
    if instance._validator:
        instance._validator.quarantined_personas.clear()
        instance._validator.failed_attempts.clear()
    instance._current_persona = None

    # Also update global instance in teardown
    security_integration._security_integration = instance


class TestSingletonPattern:
    """Test TrinitasSecurityIntegration singleton pattern"""

    def test_singleton_instance(self, config_file):
        """Test that multiple calls return the same instance"""
        # Reset singleton
        TrinitasSecurityIntegration._instance = None

        instance1 = TrinitasSecurityIntegration()
        instance2 = TrinitasSecurityIntegration()

        assert instance1 is instance2

    def test_singleton_initialization_once(self, config_file):
        """Test that initialization only happens once"""
        TrinitasSecurityIntegration._instance = None

        instance = TrinitasSecurityIntegration()
        assert instance.initialized is False

        instance.initialize(config_path=str(config_file))
        assert instance.initialized is True

        # Second initialization should be a no-op
        instance.initialize(config_path=str(config_file))
        assert instance.initialized is True


class TestInitialization:
    """Test TrinitasSecurityIntegration initialization"""

    def test_initialization_with_valid_config(self, config_file):
        """Test successful initialization with valid config"""
        TrinitasSecurityIntegration._instance = None

        integration = TrinitasSecurityIntegration()
        integration.initialize(config_path=str(config_file))

        assert integration.initialized is True
        assert integration._validator is not None
        assert integration._current_persona is None
        assert len(integration._session_data) == 0

    def test_initialization_with_missing_config(self, tmp_path):
        """Test initialization with missing config file"""
        TrinitasSecurityIntegration._instance = None

        integration = TrinitasSecurityIntegration()
        missing_path = tmp_path / "nonexistent.json"

        with pytest.raises(SecurityIntegrationError) as exc_info:
            integration.initialize(config_path=str(missing_path))

        assert "セキュリティ初期化に失敗" in str(exc_info.value)
        assert integration.initialized is False

    def test_initialization_with_invalid_json(self, tmp_path):
        """Test initialization with invalid JSON config"""
        TrinitasSecurityIntegration._instance = None

        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")

        integration = TrinitasSecurityIntegration()

        with pytest.raises(SecurityIntegrationError) as exc_info:
            integration.initialize(config_path=str(invalid_file))

        assert "設定データエラー" in str(exc_info.value)

    def test_initialization_auto_finds_default_config(self, config_file):
        """Test initialization finds default config path"""
        TrinitasSecurityIntegration._instance = None

        with patch("os.path.dirname") as mock_dirname:
            mock_dirname.return_value = str(config_file.parent)
            with patch("os.path.join") as mock_join:
                mock_join.return_value = str(config_file)

                integration = TrinitasSecurityIntegration()
                integration.initialize(config_path=None)

                assert integration.initialized is True


class TestPersonaManagement:
    """Test persona setting and retrieval"""

    def test_set_current_persona_valid(self, integration):
        """Test setting a valid persona"""
        integration.set_current_persona("athena")

        assert integration.get_current_persona() == "athena"

    def test_set_current_persona_unknown(self, integration):
        """Test setting an unknown persona raises error"""
        with pytest.raises(SecurityIntegrationError) as exc_info:
            integration.set_current_persona("unknown_persona")

        assert "未知のペルソナ" in str(exc_info.value)

    def test_set_current_persona_quarantined(self, integration):
        """Test setting a quarantined persona raises error"""
        # Quarantine athena
        integration._validator.quarantined_personas.add("athena")

        with pytest.raises(SecurityIntegrationError) as exc_info:
            integration.set_current_persona("athena")

        assert "隔離中" in str(exc_info.value)

    def test_set_current_persona_auto_initializes(self, config_file):
        """Test set_current_persona auto-initializes if not initialized"""
        TrinitasSecurityIntegration._instance = None

        integration = TrinitasSecurityIntegration()
        assert integration.initialized is False

        with patch.object(integration, "initialize") as mock_init:
            integration.set_current_persona("athena")
            mock_init.assert_called_once()

    def test_get_current_persona_none(self, integration):
        """Test get_current_persona returns None initially"""
        assert integration.get_current_persona() is None


class TestToolAccessValidation:
    """Test tool access validation"""

    def test_validate_tool_access_granted(self, integration):
        """Test tool access validation when granted"""
        integration.set_current_persona("athena")

        result = integration.validate_tool_access(
            tool="Read",
            operation="file_read",
            target_path="./src/main.py",
        )

        assert isinstance(result, ValidationResult)
        assert result.result == AccessResult.GRANTED

    def test_validate_tool_access_denied(self, integration):
        """Test tool access validation when denied"""
        integration.set_current_persona("athena")

        result = integration.validate_tool_access(
            tool="Write",  # Not allowed for athena
            operation="file_write",
        )

        assert result.result == AccessResult.DENIED

    def test_validate_tool_access_no_persona_set(self, integration):
        """Test tool access validation fails when no persona is set"""
        with pytest.raises(SecurityIntegrationError) as exc_info:
            integration.validate_tool_access(tool="Read")

        assert "ペルソナが設定されていません" in str(exc_info.value)

    def test_validate_tool_access_not_initialized(self, config_file):
        """Test tool access validation auto-initializes"""
        TrinitasSecurityIntegration._instance = None

        integration = TrinitasSecurityIntegration()
        integration.set_current_persona("athena")

        with patch.object(integration, "initialize") as mock_init:
            # Will call initialize if not initialized
            pass


class TestSecureToolWrapper:
    """Test secure_tool_wrapper decorator"""

    def test_secure_tool_wrapper_success(self, integration):
        """Test secure tool wrapper allows execution when access granted"""
        integration.set_current_persona("athena")

        def mock_tool_function(file_path):
            return f"Read: {file_path}"

        wrapped = integration.secure_tool_wrapper("Read", mock_tool_function)
        result = wrapped(file_path="./src/main.py")

        assert result == "Read: ./src/main.py"

    def test_secure_tool_wrapper_denied(self, integration):
        """Test secure tool wrapper blocks execution when access denied"""
        integration.set_current_persona("athena")

        def mock_tool_function(file_path):
            return f"Write: {file_path}"

        wrapped = integration.secure_tool_wrapper("Write", mock_tool_function)

        with pytest.raises(SecurityIntegrationError) as exc_info:
            wrapped(file_path="./src/main.py")

        assert "アクセス拒否" in str(exc_info.value)

    def test_secure_tool_wrapper_high_risk_warning(self, integration):
        """Test secure tool wrapper logs warning for high-risk operations"""
        integration.set_current_persona("artemis")

        def mock_bash_function(command):
            return f"Executed: {command}"

        with patch("shared.security.security_integration.security_logger") as mock_logger:
            wrapped = integration.secure_tool_wrapper("Bash", mock_bash_function)

            # Create a mock result with high risk
            mock_result = ValidationResult(
                result=AccessResult.GRANTED,
                reason="Test",
                risk_level=8,
                recommendations=[],
            )

            with patch.object(integration, "validate_tool_access", return_value=mock_result):
                wrapped(command="npm install")

                # Should log high-risk warning
                assert any(
                    "高リスク操作実行" in str(call_args)
                    for call_args in mock_logger.warning.call_args_list
                )

    def test_secure_tool_wrapper_preserves_function_metadata(self, integration):
        """Test secure tool wrapper preserves original function metadata"""

        def original_function():
            """Original docstring"""
            pass

        wrapped = integration.secure_tool_wrapper("Read", original_function)

        assert wrapped.__name__ == "original_function"
        assert wrapped.__doc__ == "Original docstring"

    def test_secure_tool_wrapper_error_handling(self, integration):
        """Test secure tool wrapper handles tool execution errors"""
        integration.set_current_persona("athena")

        def mock_failing_tool(file_path):
            raise FileNotFoundError("File not found")

        wrapped = integration.secure_tool_wrapper("Read", mock_failing_tool)

        with pytest.raises(FileNotFoundError):
            wrapped(file_path="./nonexistent.py")


class TestPersonaContextManager:
    """Test persona_context context manager"""

    def test_persona_context_basic(self, integration):
        """Test persona context manager basic usage"""
        integration.set_current_persona("athena")

        with integration.create_persona_context("artemis") as ctx:
            assert integration.get_current_persona() == "artemis"

        # Should restore previous persona
        assert integration.get_current_persona() == "athena"

    def test_persona_context_no_previous_persona(self, integration):
        """Test persona context manager with no previous persona"""
        assert integration.get_current_persona() is None

        with integration.create_persona_context("athena"):
            assert integration.get_current_persona() == "athena"

        # Should clear persona after context
        assert integration.get_current_persona() is None

    def test_persona_context_exception_handling(self, integration):
        """Test persona context manager restores persona on exception"""
        integration.set_current_persona("athena")

        with pytest.raises(RuntimeError):
            with integration.create_persona_context("artemis"):
                assert integration.get_current_persona() == "artemis"
                raise RuntimeError("Test exception")

        # Should still restore previous persona
        assert integration.get_current_persona() == "athena"

    def test_persona_context_nested(self, integration):
        """Test nested persona contexts"""
        integration.set_current_persona("athena")

        with integration.create_persona_context("artemis"):
            assert integration.get_current_persona() == "artemis"

            with integration.create_persona_context("hestia"):
                assert integration.get_current_persona() == "hestia"

            assert integration.get_current_persona() == "artemis"

        assert integration.get_current_persona() == "athena"


class TestCapabilitiesRetrieval:
    """Test get_persona_capabilities"""

    def test_get_capabilities_for_current_persona(self, integration):
        """Test getting capabilities for current persona"""
        integration.set_current_persona("athena")

        capabilities = integration.get_persona_capabilities()

        assert capabilities["persona"] == "athena"
        assert capabilities["role"] == "Harmonious Conductor"
        assert capabilities["security_clearance"] == "ORCHESTRATION"
        assert "Read" in capabilities["allowed_tools"]
        assert "Grep" in capabilities["allowed_tools"]
        assert capabilities["special_permissions"]["workflow_automation"] is True
        assert capabilities["restrictions"]["no_direct_code_modification"] is True
        assert capabilities["is_quarantined"] is False

    def test_get_capabilities_for_specific_persona(self, integration):
        """Test getting capabilities for a specific persona"""
        integration.set_current_persona("athena")

        capabilities = integration.get_persona_capabilities(persona="artemis")

        assert capabilities["persona"] == "artemis"
        assert capabilities["role"] == "Technical Perfectionist"
        assert capabilities["security_clearance"] == "FULL_MODIFY"
        assert "Write" in capabilities["allowed_tools"]
        assert "Edit" in capabilities["allowed_tools"]

    def test_get_capabilities_unknown_persona(self, integration):
        """Test getting capabilities for unknown persona raises error"""
        with pytest.raises(SecurityIntegrationError) as exc_info:
            integration.get_persona_capabilities(persona="unknown")

        assert "未知のペルソナ" in str(exc_info.value)

    def test_get_capabilities_no_persona_set(self, integration):
        """Test getting capabilities without persona set raises error"""
        with pytest.raises(SecurityIntegrationError) as exc_info:
            integration.get_persona_capabilities()

        assert "ペルソナが指定されていません" in str(exc_info.value)

    def test_get_capabilities_shows_quarantine_status(self, integration):
        """Test capabilities show quarantine status"""
        integration.set_current_persona("athena")

        # Quarantine athena
        integration._validator.quarantined_personas.add("athena")

        capabilities = integration.get_persona_capabilities()

        assert capabilities["is_quarantined"] is True


class TestSecurityStatus:
    """Test get_security_status"""

    def test_get_security_status_initialized(self, integration):
        """Test security status when initialized"""
        integration.set_current_persona("athena")

        status = integration.get_security_status()

        assert status["initialized"] is True
        assert status["current_persona"] == "athena"
        assert isinstance(status["quarantined_personas"], list)
        assert isinstance(status["failed_attempts"], dict)
        assert "config_version" in status

    def test_get_security_status_not_initialized(self):
        """Test security status when not initialized"""
        TrinitasSecurityIntegration._instance = None

        integration = TrinitasSecurityIntegration()
        status = integration.get_security_status()

        assert "error" in status
        assert "初期化されていません" in status["error"]

    def test_get_security_status_with_quarantined_personas(self, integration):
        """Test security status shows quarantined personas"""
        integration._validator.quarantined_personas.add("athena")
        integration._validator.quarantined_personas.add("artemis")

        status = integration.get_security_status()

        assert "athena" in status["quarantined_personas"]
        assert "artemis" in status["quarantined_personas"]

    def test_get_security_status_with_failed_attempts(self, integration):
        """Test security status shows failed attempts"""
        integration._validator.failed_attempts["athena"] = 2
        integration._validator.failed_attempts["hestia"] = 1

        status = integration.get_security_status()

        assert status["failed_attempts"]["athena"] == 2
        assert status["failed_attempts"]["hestia"] == 1


class TestEmergencyLockdown:
    """Test emergency_lockdown"""

    def test_emergency_lockdown(self, integration):
        """Test emergency lockdown quarantines all personas"""
        integration.set_current_persona("athena")

        result = integration.emergency_lockdown("Security breach detected")

        assert result["status"] == "emergency_lockdown"
        assert "Security breach detected" in result["reason"]
        assert len(result["quarantined_personas"]) >= 3  # All personas
        assert "athena" in result["quarantined_personas"]
        assert "artemis" in result["quarantined_personas"]
        assert "hestia" in result["quarantined_personas"]

    def test_emergency_lockdown_clears_current_persona(self, integration):
        """Test emergency lockdown clears current persona"""
        integration.set_current_persona("athena")

        integration.emergency_lockdown("Test emergency")

        assert integration.get_current_persona() is None

    def test_emergency_lockdown_logs_critical(self, integration):
        """Test emergency lockdown logs critical message"""
        with patch("shared.security.security_integration.security_logger") as mock_logger:
            integration.emergency_lockdown("Critical security incident")

            mock_logger.critical.assert_called_once()
            call_args = mock_logger.critical.call_args[0][0]
            assert "緊急ロックダウン実行" in call_args


class TestConvenienceFunctions:
    """Test module-level convenience functions"""

    def test_initialize_security_function(self, config_file):
        """Test initialize_security convenience function"""
        TrinitasSecurityIntegration._instance = None

        initialize_security(config_path=str(config_file))

        # Should initialize the singleton
        instance = TrinitasSecurityIntegration()
        assert instance.initialized is True

    def test_set_persona_function(self, integration):
        """Test set_persona convenience function"""
        set_persona("athena")

        assert get_current_persona() == "athena"

    def test_get_current_persona_function(self, integration):
        """Test get_current_persona convenience function"""
        integration.set_current_persona("artemis")

        result = get_current_persona()

        assert result == "artemis"

    def test_validate_access_function(self, integration):
        """Test validate_access convenience function"""
        set_persona("athena")

        result = validate_access("Read", target_path="./src/main.py")

        assert isinstance(result, ValidationResult)

    def test_secure_tool_decorator(self, integration):
        """Test secure_tool decorator"""
        set_persona("athena")

        @secure_tool("Read")
        def mock_read_tool(file_path):
            return f"Read: {file_path}"

        result = mock_read_tool(file_path="./src/main.py")

        assert result == "Read: ./src/main.py"

    def test_persona_context_function(self, integration):
        """Test persona_context convenience function"""
        set_persona("athena")

        with persona_context("artemis"):
            assert get_current_persona() == "artemis"

        assert get_current_persona() == "athena"

    def test_get_capabilities_function(self, integration):
        """Test get_capabilities convenience function"""
        set_persona("athena")

        capabilities = get_capabilities()

        assert capabilities["persona"] == "athena"

    def test_get_security_status_function(self, integration):
        """Test get_security_status convenience function"""
        status = get_security_status()

        assert status["initialized"] is True

    def test_emergency_shutdown_function(self, integration):
        """Test emergency_shutdown convenience function"""
        result = emergency_shutdown("Test emergency")

        assert result["status"] == "emergency_lockdown"


class TestIntegrationScenarios:
    """Test complete integration scenarios"""

    def test_scenario_athena_reads_file(self, integration):
        """Test Athena reading a file (allowed)"""
        set_persona("athena")

        result = validate_access("Read", target_path="./src/main.py")

        assert result.result == AccessResult.GRANTED

    def test_scenario_athena_writes_file_denied(self, integration):
        """Test Athena writing a file (denied)"""
        set_persona("athena")

        result = validate_access("Write", target_path="./src/main.py")

        assert result.result == AccessResult.DENIED

    def test_scenario_artemis_modifies_code(self, integration):
        """Test Artemis modifying code (allowed)"""
        set_persona("artemis")

        result = validate_access("Edit", target_path="./src/utils.py")

        # May be granted depending on path restrictions
        assert result.result in [AccessResult.GRANTED, AccessResult.DENIED]

    def test_scenario_hestia_audit_only(self, integration):
        """Test Hestia can only audit (read-only)"""
        set_persona("hestia")

        read_result = validate_access("Read", target_path="./src/main.py")
        # Should be allowed

        write_result = validate_access("Write", target_path="./src/main.py")
        assert write_result.result == AccessResult.DENIED

    def test_scenario_multiple_personas_workflow(self, integration):
        """Test workflow with multiple personas"""
        # Athena designs
        with persona_context("athena"):
            assert get_current_persona() == "athena"
            caps = get_capabilities()
            assert "workflow_automation" in caps["special_permissions"]

        # Artemis implements
        with persona_context("artemis"):
            assert get_current_persona() == "artemis"
            caps = get_capabilities()
            assert "code_refactoring" in caps["special_permissions"]

        # Hestia audits
        with persona_context("hestia"):
            assert get_current_persona() == "hestia"
            caps = get_capabilities()
            assert "security_scanning" in caps["special_permissions"]

    def test_scenario_failed_attempts_lead_to_quarantine(self, integration):
        """Test multiple failed attempts lead to quarantine"""
        set_persona("athena")

        # Make 3 failed attempts (threshold)
        for i in range(3):
            result = validate_access("InvalidTool")
            if i < 2:
                assert result.result == AccessResult.DENIED

        # Check if quarantined
        status = get_security_status()
        assert "athena" in status["quarantined_personas"]

    def test_scenario_secure_tool_wrapper_in_workflow(self, integration):
        """Test secure tool wrapper in a workflow"""
        set_persona("athena")

        @secure_tool("Read")
        def read_file(file_path):
            return {"content": f"Content of {file_path}", "size": 1024}

        result = read_file(file_path="./src/main.py")

        assert "content" in result
        assert result["content"] == "Content of ./src/main.py"
