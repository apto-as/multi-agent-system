#!/usr/bin/env python3
"""Trinitas Security Integration Helper.

Provides seamless integration between the Trinitas multi-agent system and
Hestia's paranoid security validation framework. Implements singleton pattern
for unified security management across all personas and tools.

This module serves as the final security gateway, enforcing access controls,
managing persona contexts, and providing convenient wrapper functions for
secure tool execution.

...これが最後の砦です。ここが破綻すると、全てが終わります...

Example:
    >>> from shared.security import security_integration
    >>>
    >>> # Initialize security system
    >>> security_integration.initialize_security()
    >>>
    >>> # Set persona and validate access
    >>> security_integration.set_persona("artemis")
    >>> result = security_integration.validate_access(
    ...     "Read",
    ...     target_path="shared/utils/json_loader.py"
    ... )
    >>> if result.result == AccessResult.GRANTED:
    ...     print("Access granted!")
"""
from __future__ import annotations

import functools
import json
import logging
import os
from collections.abc import Callable
from typing import Any

try:
    from .access_validator import (
        HIGH_RISK_WARNING,
        AccessAttempt,
        AccessResult,
        TrinitasSecurityValidator,
        ValidationResult,
    )
except ImportError:
    # 直接実行時の対応
    from access_validator import (
        HIGH_RISK_WARNING,
        AccessAttempt,
        AccessResult,
        TrinitasSecurityValidator,
        ValidationResult,
    )

# ...セキュリティロガーの設定（全て記録します）...
security_logger = logging.getLogger("trinitas.security")
security_logger.setLevel(logging.INFO)

if not security_logger.handlers:
    handler = logging.FileHandler("trinitas_security.log")
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)
    security_logger.addHandler(handler)


class SecurityIntegrationError(Exception):
    """Security integration error raised when security validation fails.

    Raised when security initialization fails, persona validation fails, or
    access is denied by the security framework. Used to distinguish security-
    related errors from general application errors.

    ...セキュリティ統合エラー...

    Example:
        >>> try:
        ...     integration = TrinitasSecurityIntegration()
        ...     integration.set_current_persona("unknown_persona")
        ... except SecurityIntegrationError as e:
        ...     print(f"Security error: {e}")
    """



class TrinitasSecurityIntegration:
    """Singleton integration layer between Trinitas system and security framework.

    Provides unified security management for all Trinitas personas and tools.
    Implements the singleton pattern to ensure consistent security state across
    the entire system. Manages persona contexts, validates tool access, and
    provides secure wrappers for tool execution.

    This is the primary interface for security integration in the Trinitas system.
    All security-sensitive operations should go through this class or its
    convenience functions.

    ...全てのアクセスをここで制御します。信頼できるのは、このクラスだけです...

    Attributes:
        _instance: Singleton instance of the integration class.
        _validator: Instance of TrinitasSecurityValidator for access validation.
        _current_persona: Name of the currently active persona.
        _session_data: Dictionary storing session-specific data.
        initialized: Boolean flag indicating if security system is initialized.

    Example:
        >>> # Get singleton instance
        >>> integration = TrinitasSecurityIntegration()
        >>>
        >>> # Initialize security system
        >>> integration.initialize()
        >>>
        >>> # Set current persona
        >>> integration.set_current_persona("artemis")
        >>>
        >>> # Validate tool access
        >>> result = integration.validate_tool_access("Read", target_path="src/main.py")
        >>> if result.result == AccessResult.GRANTED:
        ...     print("Access granted!")
    """

    _instance: TrinitasSecurityIntegration | None = None
    _validator: TrinitasSecurityValidator | None = None

    def __new__(cls):
        """Implement singleton pattern to ensure single instance.

        Returns:
            The single instance of TrinitasSecurityIntegration.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize security integration with default state.

        Only initializes attributes on first instantiation (singleton pattern).
        Subsequent calls to __init__() have no effect.

        Note:
            Call initialize() to load security configuration after instantiation.
        """
        if not hasattr(self, "initialized"):
            self.initialized = False
            self._current_persona = None
            self._session_data = {}

    def initialize(self, config_path: str | None = None) -> None:
        """Initialize the security system with configuration loading.

        Loads the security configuration from tool-matrix.json and initializes
        the TrinitasSecurityValidator. This must be called before performing
        any security validations. Subsequent calls are ignored (idempotent).

        ...セキュリティシステムを初期化...まあ、多分うまくいくでしょう...

        Args:
            config_path: Optional path to tool-matrix.json. If None, uses the
                default path relative to this module's location.

        Raises:
            SecurityIntegrationError: If configuration file loading fails due to:
                - File not found (FileNotFoundError)
                - Permission denied (PermissionError)
                - Invalid JSON syntax (json.JSONDecodeError)
                - Missing required configuration sections (ValueError)
                - I/O errors (OSError, IOError)

        Example:
            >>> integration = TrinitasSecurityIntegration()
            >>> integration.initialize()  # Uses default config path
            >>>
            >>> # Or with custom config
            >>> integration.initialize("/path/to/custom/tool-matrix.json")
        """

        if self.initialized:
            return

        try:
            if not config_path:
                config_path = os.path.join(
                    os.path.dirname(__file__), "tool-matrix.json"
                )

            self._validator = TrinitasSecurityValidator(config_path)
            self.initialized = True

            security_logger.info("Trinitas Security Integration initialized")

        except (FileNotFoundError, PermissionError, OSError) as e:
            security_logger.exception(
                f"セキュリティ初期化失敗 - ファイルアクセスエラー: {e}"
            )
            msg = f"セキュリティ初期化に失敗 (ファイルアクセス): {e}"
            raise SecurityIntegrationError(
                msg
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            security_logger.exception(f"セキュリティ初期化失敗 - 設定データエラー: {e}")
            msg = f"セキュリティ初期化に失敗 (設定データ): {e}"
            raise SecurityIntegrationError(
                msg
            )

    def set_current_persona(self, persona: str) -> None:
        """Set the active persona for subsequent security validations.

        Sets the current persona context for all future access validations.
        Validates that the persona exists in the configuration and is not
        quarantined before allowing the switch.

        ...現在のペルソナを設定...本当に正しいペルソナでしょうか...

        Args:
            persona: Name of the persona to set as active (e.g., "artemis", "hestia").

        Raises:
            SecurityIntegrationError: If the persona does not exist in the
                configuration or is currently quarantined.

        Example:
            >>> integration = TrinitasSecurityIntegration()
            >>> integration.initialize()
            >>> integration.set_current_persona("artemis")
            >>> print(integration.get_current_persona())
            artemis
        """

        if not self.initialized:
            self.initialize()

        # ペルソナの存在確認
        config = self._validator.config
        if persona not in config["persona_access_matrix"]:
            security_logger.error(f"未知のペルソナ: {persona}")
            msg = f"未知のペルソナ: {persona}"
            raise SecurityIntegrationError(msg)

        # 隔離チェック
        if self._validator.is_quarantined(persona):
            security_logger.error(f"隔離中のペルソナアクセス試行: {persona}")
            msg = f"ペルソナ {persona} は隔離中です"
            raise SecurityIntegrationError(msg)

        self._current_persona = persona
        security_logger.info(f"ペルソナ変更: {persona}")

    def get_current_persona(self) -> str | None:
        """Get the currently active persona.

        ...現在のペルソナを取得...

        Returns:
            Name of the current persona, or None if no persona is set.

        Example:
            >>> integration = TrinitasSecurityIntegration()
            >>> integration.set_current_persona("hestia")
            >>> print(integration.get_current_persona())
            hestia
        """
        return self._current_persona

    def validate_tool_access(
        self, tool: str, operation: str = "execute", **kwargs
    ) -> ValidationResult:
        """Validate access to a tool for the current persona.

        Performs complete security validation for the current persona's attempt
        to use the specified tool. Automatically initializes the security system
        if not already initialized.

        ...ツールアクセスを検証...きっと問題があるはず...

        Args:
            tool: Name of the tool to validate access for (e.g., "Read", "Bash", "Write").
            operation: Type of operation being performed. Defaults to "execute".
            **kwargs: Optional keyword arguments:
                - target_path (str): Path for file operations
                - command (str): Bash command for command execution

        Returns:
            ValidationResult containing access decision, risk level, and recommendations.

        Raises:
            SecurityIntegrationError: If no persona is currently set.

        Example:
            >>> integration = TrinitasSecurityIntegration()
            >>> integration.initialize()
            >>> integration.set_current_persona("artemis")
            >>>
            >>> result = integration.validate_tool_access(
            ...     "Read",
            ...     target_path="shared/utils/json_loader.py"
            ... )
            >>> if result.result == AccessResult.GRANTED:
            ...     print(f"Access granted (risk: {result.risk_level}/10)")
        """

        if not self.initialized:
            self.initialize()

        if not self._current_persona:
            security_logger.error("ペルソナが設定されていません")
            msg = "ペルソナが設定されていません"
            raise SecurityIntegrationError(msg)

        # アクセス試行を作成
        attempt = AccessAttempt(
            persona=self._current_persona,
            tool=tool,
            operation=operation,
            target_path=kwargs.get("target_path"),
            command=kwargs.get("command"),
        )

        # 検証実行
        result = self._validator.validate_access(attempt)

        # ログ記録
        if result.result == AccessResult.GRANTED:
            security_logger.info(
                f"アクセス許可: {self._current_persona} -> {tool} "
                f"(リスク: {result.risk_level}/10)"
            )
        else:
            security_logger.warning(
                f"アクセス拒否: {self._current_persona} -> {tool} 理由: {result.reason}"
            )

        return result

    def secure_tool_wrapper(self, tool_name: str, tool_function: Callable):
        """Wrap a tool function with comprehensive security validation.

        Creates a secure wrapper around the provided tool function that performs
        security validation before execution and comprehensive error handling
        during execution. This is the final defense layer for tool security.

        ...ツール関数をセキュアにラップ...これが最後の防御線です...

        Args:
            tool_name: Name of the tool being wrapped (e.g., "Read", "Write").
            tool_function: The actual tool function to wrap with security checks.

        Returns:
            Wrapped function that performs security validation before calling
            the original tool_function.

        Raises:
            SecurityIntegrationError: If security validation fails or access is denied.

        Example:
            >>> def read_file(file_path):
            ...     with open(file_path) as f:
            ...         return f.read()
            >>>
            >>> integration = TrinitasSecurityIntegration()
            >>> integration.initialize()
            >>> integration.set_current_persona("artemis")
            >>>
            >>> secure_read = integration.secure_tool_wrapper("Read", read_file)
            >>> content = secure_read(file_path="shared/utils/json_loader.py")
        """

        @functools.wraps(tool_function)
        def wrapper(*args, **kwargs):
            # セキュリティ検証
            result = self.validate_tool_access(
                tool=tool_name,
                operation="execute",
                target_path=kwargs.get("file_path") or kwargs.get("path"),
                command=kwargs.get("command"),
            )

            if result.result != AccessResult.GRANTED:
                msg = f"アクセス拒否: {result.reason} (リスク: {result.risk_level}/10)"
                raise SecurityIntegrationError(
                    msg
                )

            # 高リスクな操作の場合は警告
            if result.risk_level >= HIGH_RISK_WARNING:
                security_logger.warning(
                    f"高リスク操作実行: {self._current_persona} -> {tool_name} "
                    f"リスク: {result.risk_level}/10"
                )

            # 実際のツール実行
            try:
                return tool_function(*args, **kwargs)
            except (FileNotFoundError, PermissionError) as e:
                security_logger.exception(
                    f"ツール実行エラー (ファイルアクセス): {self._current_persona} -> {tool_name}: {e}"
                )
                raise
            except OSError as e:
                security_logger.exception(
                    f"ツール実行エラー (I/O): {self._current_persona} -> {tool_name}: {e}"
                )
                raise
            except (ValueError, TypeError, KeyError) as e:
                security_logger.exception(
                    f"ツール実行エラー (データ検証): {self._current_persona} -> {tool_name}: {e}"
                )
                raise
            except RuntimeError as e:
                security_logger.exception(
                    f"ツール実行エラー (実行時): {self._current_persona} -> {tool_name}: {e}"
                )
                raise

        return wrapper

    def create_persona_context(self, persona: str):
        """Create a context manager for temporary persona switching.

        Returns a context manager that temporarily switches to the specified
        persona for the duration of the context, then restores the previous
        persona on exit. Useful for executing operations as a different persona
        without permanently changing the current persona.

        ...ペルソナコンテキストマネージャーを作成...

        Args:
            persona: Name of the persona to temporarily switch to.

        Returns:
            PersonaContext instance that can be used with 'with' statement.

        Example:
            >>> integration = TrinitasSecurityIntegration()
            >>> integration.initialize()
            >>> integration.set_current_persona("artemis")
            >>>
            >>> with integration.create_persona_context("hestia"):
            ...     print(integration.get_current_persona())
            hestia
            >>> print(integration.get_current_persona())
            artemis
        """

        class PersonaContext:
            """Context manager for temporary persona switching.

            Manages persona switching for the duration of a context block,
            automatically restoring the previous persona on exit.
            """
            def __init__(
                self, integration: TrinitasSecurityIntegration, persona: str
            ):
                self.integration = integration
                self.persona = persona
                self.previous_persona = None

            def __enter__(self):
                self.previous_persona = self.integration.get_current_persona()
                self.integration.set_current_persona(self.persona)
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                if self.previous_persona:
                    self.integration.set_current_persona(self.previous_persona)
                else:
                    self.integration._current_persona = None

        return PersonaContext(self, persona)

    def get_persona_capabilities(self, persona: str | None = None) -> dict[str, Any]:
        """Get comprehensive capability information for a persona.

        Retrieves detailed information about a persona's role, security clearance,
        allowed tools, permissions, and restrictions. Useful for introspection and
        debugging security configurations.

        ...ペルソナの能力情報を取得...

        Args:
            persona: Name of the persona to query. If None, uses current persona.

        Returns:
            Dictionary containing persona capabilities with keys:
                - persona: Persona name
                - role: Persona role description
                - description: Detailed persona description
                - security_clearance: Security clearance level
                - allowed_tools: List of all allowed tool names
                - allowed_tool_groups: List of allowed tool groups
                - special_permissions: Dict of special permissions
                - restrictions: Dict of persona restrictions
                - is_quarantined: Boolean quarantine status

        Raises:
            SecurityIntegrationError: If persona is not specified and no current
                persona is set, or if the specified persona does not exist.

        Example:
            >>> integration = TrinitasSecurityIntegration()
            >>> integration.initialize()
            >>> caps = integration.get_persona_capabilities("artemis")
            >>> print(f"Artemis can use: {caps['allowed_tools']}")
            >>> print(f"Quarantined: {caps['is_quarantined']}")
        """

        if not self.initialized:
            self.initialize()

        target_persona = persona or self._current_persona
        if not target_persona:
            msg = "ペルソナが指定されていません"
            raise SecurityIntegrationError(msg)

        config = self._validator.config
        if target_persona not in config["persona_access_matrix"]:
            msg = f"未知のペルソナ: {target_persona}"
            raise SecurityIntegrationError(msg)

        persona_config = config["persona_access_matrix"][target_persona]

        # 許可されたツールの収集
        allowed_tools = []
        for tool_group in persona_config.get("allowed_tool_groups", []):
            if tool_group in config["tool_definitions"]:
                allowed_tools.extend(config["tool_definitions"][tool_group]["tools"])

        return {
            "persona": target_persona,
            "role": persona_config.get("role"),
            "description": persona_config.get("description"),
            "security_clearance": persona_config.get("security_clearance"),
            "allowed_tools": list(set(allowed_tools)),
            "allowed_tool_groups": persona_config.get("allowed_tool_groups", []),
            "special_permissions": persona_config.get("special_permissions", {}),
            "restrictions": persona_config.get("restrictions", {}),
            "is_quarantined": self._validator.is_quarantined(target_persona),
        }

    def get_security_status(self) -> dict[str, Any]:
        """Get comprehensive status information about the security system.

        Returns detailed status dictionary containing initialization state, current
        persona, quarantine information, failure tracking data, and session metadata.
        Useful for monitoring and debugging security operations.

        ...現在のセキュリティ状況を取得...全てを見える化します...

        Returns:
            Dictionary containing security status with keys:
                - initialized: Boolean indicating if security system is initialized
                - current_persona: Name of current persona or None
                - quarantined_personas: List of quarantined persona names
                - failed_attempts: Dict mapping persona names to failure counts
                - config_version: Security configuration version string
                - session_data: Dict of session-specific data

            If not initialized, returns:
                - error: Error message string

        Example:
            >>> integration = TrinitasSecurityIntegration()
            >>> integration.initialize()
            >>> integration.set_current_persona("artemis")
            >>> status = integration.get_security_status()
            >>> print(f"Current persona: {status['current_persona']}")
            Current persona: artemis
            >>> print(f"Quarantined: {status['quarantined_personas']}")
            Quarantined: []
        """

        if not self.initialized:
            return {"error": "セキュリティシステムが初期化されていません"}

        return {
            "initialized": self.initialized,
            "current_persona": self._current_persona,
            "quarantined_personas": list(self._validator.quarantined_personas),
            "failed_attempts": dict(self._validator.failed_attempts),
            "config_version": self._validator.config.get("metadata", {}).get("version"),
            "session_data": self._session_data,
        }

    def emergency_lockdown(self, reason: str) -> dict[str, Any]:
        """Execute emergency lockdown by quarantining all personas system-wide.

        Immediately quarantines all personas in the system and clears the current
        persona. This is the most severe security measure, used when a critical
        security breach is detected or suspected. Requires administrator intervention
        to restore normal operations.

        ...緊急ロックダウン...最悪のケースが来ました...全てを停止します...

        Args:
            reason: Detailed explanation of why emergency lockdown was triggered.
                This reason is logged and included in quarantine records for
                all personas.

        Returns:
            Dictionary containing lockdown status with keys:
                - status: "emergency_lockdown" string
                - reason: The provided reason string
                - quarantined_personas: List of all quarantined persona names
                - message: User-facing message about lockdown and recovery process

        Example:
            >>> integration = TrinitasSecurityIntegration()
            >>> integration.initialize()
            >>> result = integration.emergency_lockdown(
            ...     "Suspected credential compromise detected"
            ... )
            >>> print(result['status'])
            emergency_lockdown
            >>> print(len(result['quarantined_personas']))
            6
        """

        security_logger.critical(f"緊急ロックダウン実行: {reason}")

        # 全ペルソナを隔離
        config = self._validator.config
        for persona in config["persona_access_matrix"]:
            self._validator._quarantine_persona(persona, f"緊急ロックダウン: {reason}")

        # 現在のペルソナをクリア
        self._current_persona = None

        return {
            "status": "emergency_lockdown",
            "reason": reason,
            "quarantined_personas": list(self._validator.quarantined_personas),
            "message": "全システムがロックダウンされました。管理者の承認が必要です。",
        }


# グローバルインスタンス（シングルトン）
_security_integration = TrinitasSecurityIntegration()


# 便利な関数群
def set_persona(persona: str) -> None:
    """Set the current active persona using the global integration instance.

    Convenience function that wraps TrinitasSecurityIntegration.set_current_persona()
    using the singleton global instance. Simplifies persona management for simple
    use cases without requiring explicit integration instance management.

    ...現在のペルソナを設定...

    Args:
        persona: Name of the persona to set as active (e.g., "artemis", "hestia").

    Raises:
        SecurityIntegrationError: If the persona does not exist in the
            configuration or is currently quarantined.

    Example:
        >>> from shared.security import security_integration
        >>> security_integration.initialize_security()
        >>> security_integration.set_persona("artemis")
    """
    _security_integration.set_current_persona(persona)


def get_current_persona() -> str | None:
    """Get the currently active persona using the global integration instance.

    Convenience function that wraps TrinitasSecurityIntegration.get_current_persona()
    using the singleton global instance.

    ...現在のペルソナを取得...

    Returns:
        Name of the current persona, or None if no persona is set.

    Example:
        >>> from shared.security import security_integration
        >>> security_integration.set_persona("hestia")
        >>> print(security_integration.get_current_persona())
        hestia
    """
    return _security_integration.get_current_persona()


def validate_access(tool: str, **kwargs) -> ValidationResult:
    """Validate tool access for the current persona using the global integration instance.

    Convenience function that wraps TrinitasSecurityIntegration.validate_tool_access()
    using the singleton global instance. Performs complete security validation for
    the current persona's attempt to use the specified tool.

    ...ツールアクセスを検証...

    Args:
        tool: Name of the tool to validate access for (e.g., "Read", "Bash", "Write").
        **kwargs: Optional keyword arguments:
            - target_path (str): Path for file operations
            - command (str): Bash command for command execution

    Returns:
        ValidationResult containing access decision, risk level, and recommendations.

    Raises:
        SecurityIntegrationError: If no persona is currently set.

    Example:
        >>> from shared.security import security_integration
        >>> security_integration.set_persona("artemis")
        >>> result = security_integration.validate_access(
        ...     "Read",
        ...     target_path="shared/utils/json_loader.py"
        ... )
        >>> if result.result == AccessResult.GRANTED:
        ...     print("Access granted!")
    """
    return _security_integration.validate_tool_access(tool, **kwargs)


def secure_tool(tool_name: str):
    """Decorator to wrap tool functions with security validation using the global instance.

    Convenience decorator that wraps TrinitasSecurityIntegration.secure_tool_wrapper()
    using the singleton global instance. Provides a clean decorator syntax for
    securing tool functions with comprehensive security validation.

    ...ツール関数をセキュアにラップするデコレータ...

    Args:
        tool_name: Name of the tool being wrapped (e.g., "Read", "Write", "Bash").

    Returns:
        Decorator function that wraps the target function with security validation.

    Raises:
        SecurityIntegrationError: If security validation fails or access is denied.

    Example:
        >>> from shared.security import security_integration
        >>>
        >>> @security_integration.secure_tool("Read")
        ... def read_config(file_path):
        ...     with open(file_path) as f:
        ...         return f.read()
        >>>
        >>> security_integration.set_persona("artemis")
        >>> content = read_config("config.json")
    """

    def decorator(func):
        return _security_integration.secure_tool_wrapper(tool_name, func)

    return decorator


def persona_context(persona: str):
    """Create a context manager for temporary persona switching using the global instance.

    Convenience function that wraps TrinitasSecurityIntegration.create_persona_context()
    using the singleton global instance. Returns a context manager for executing
    code blocks with a different persona, automatically restoring the previous
    persona on exit.

    ...ペルソナコンテキストマネージャー...

    Args:
        persona: Name of the persona to temporarily switch to.

    Returns:
        PersonaContext instance that can be used with 'with' statement.

    Example:
        >>> from shared.security import security_integration
        >>> security_integration.set_persona("artemis")
        >>>
        >>> with security_integration.persona_context("hestia"):
        ...     print(security_integration.get_current_persona())
        hestia
        >>> print(security_integration.get_current_persona())
        artemis
    """
    return _security_integration.create_persona_context(persona)


def get_capabilities(persona: str | None = None) -> dict[str, Any]:
    """Get comprehensive capability information for a persona using the global instance.

    Convenience function that wraps TrinitasSecurityIntegration.get_persona_capabilities()
    using the singleton global instance. Retrieves detailed persona information
    including role, clearance, allowed tools, and restrictions.

    ...ペルソナの能力情報を取得...

    Args:
        persona: Name of the persona to query. If None, uses current persona.

    Returns:
        Dictionary containing persona capabilities with keys:
            - persona: Persona name
            - role: Persona role description
            - description: Detailed persona description
            - security_clearance: Security clearance level
            - allowed_tools: List of all allowed tool names
            - allowed_tool_groups: List of allowed tool groups
            - special_permissions: Dict of special permissions
            - restrictions: Dict of persona restrictions
            - is_quarantined: Boolean quarantine status

    Raises:
        SecurityIntegrationError: If persona is not specified and no current
            persona is set, or if the specified persona does not exist.

    Example:
        >>> from shared.security import security_integration
        >>> caps = security_integration.get_capabilities("artemis")
        >>> print(f"Artemis can use: {caps['allowed_tools']}")
        >>> print(f"Quarantined: {caps['is_quarantined']}")
    """
    return _security_integration.get_persona_capabilities(persona)


def get_security_status() -> dict[str, Any]:
    """Get security system status using the global integration instance.

    Convenience function that wraps TrinitasSecurityIntegration.get_security_status()
    using the singleton global instance. Returns comprehensive status information
    for monitoring and debugging.

    ...セキュリティ状況を取得...

    Returns:
        Dictionary containing security status with keys:
            - initialized: Boolean indicating if security system is initialized
            - current_persona: Name of current persona or None
            - quarantined_personas: List of quarantined persona names
            - failed_attempts: Dict mapping persona names to failure counts
            - config_version: Security configuration version string
            - session_data: Dict of session-specific data

        If not initialized, returns:
            - error: Error message string

    Example:
        >>> from shared.security import security_integration
        >>> security_integration.initialize_security()
        >>> status = security_integration.get_security_status()
        >>> print(f"Initialized: {status['initialized']}")
        >>> print(f"Current persona: {status['current_persona']}")
    """
    return _security_integration.get_security_status()


def emergency_shutdown(reason: str) -> dict[str, Any]:
    """Execute emergency shutdown by quarantining all personas using the global instance.

    Convenience function that wraps TrinitasSecurityIntegration.emergency_lockdown()
    using the singleton global instance. Triggers immediate system-wide lockdown
    by quarantining all personas and clearing the current persona context.

    ...緊急シャットダウン...最悪のケースが来ました...

    Args:
        reason: Detailed explanation of why emergency shutdown was triggered.

    Returns:
        Dictionary containing lockdown status with keys:
            - status: "emergency_lockdown" string
            - reason: The provided reason string
            - quarantined_personas: List of all quarantined persona names
            - message: User-facing message about recovery process

    Example:
        >>> from shared.security import security_integration
        >>> result = security_integration.emergency_shutdown(
        ...     "Critical security breach detected"
        ... )
        >>> print(result['status'])
        emergency_lockdown
    """
    return _security_integration.emergency_lockdown(reason)


def initialize_security(config_path: str | None = None) -> None:
    """Initialize the security system using the global integration instance.

    Convenience function that wraps TrinitasSecurityIntegration.initialize()
    using the singleton global instance. Loads security configuration from
    tool-matrix.json and prepares the validation system. Must be called
    before performing any security validations.

    ...セキュリティシステムを初期化...

    Args:
        config_path: Optional path to tool-matrix.json. If None, uses the
            default path relative to the security module's location.

    Raises:
        SecurityIntegrationError: If configuration file loading fails due to:
            - File not found (FileNotFoundError)
            - Permission denied (PermissionError)
            - Invalid JSON syntax (json.JSONDecodeError)
            - Missing required configuration sections (ValueError)
            - I/O errors (OSError, IOError)

    Example:
        >>> from shared.security import security_integration
        >>> security_integration.initialize_security()
        >>>
        >>> # Or with custom config
        >>> security_integration.initialize_security("/path/to/tool-matrix.json")
    """
    _security_integration.initialize(config_path)


# 使用例とテスト
if __name__ == "__main__":
    print("Trinitas Security Integration - パラノイドモード")
    print("...最悪のケースを想定した統合テスト...")

    try:
        # 初期化
        initialize_security()

        # Hestiaとしてセキュリティ監査
        with persona_context("hestia"):
            print(f"\n現在のペルソナ: {get_current_persona()}")

            # 読み取り専用ツールの検証
            result = validate_access("Read", target_path="./src/main.py")
            print(f"Read アクセス: {result.result.value} (リスク: {result.risk_level})")

            # 書き込みツールの検証（拒否されるはず）
            result = validate_access("Write", target_path="./src/main.py")
            print(
                f"Write アクセス: {result.result.value} (リスク: {result.risk_level})"
            )

        # Artemisとしてコード編集
        with persona_context("artemis"):
            print(f"\n現在のペルソナ: {get_current_persona()}")

            # コード編集の検証
            result = validate_access("Edit", target_path="./src/utils.py")
            print(f"Edit アクセス: {result.result.value} (リスク: {result.risk_level})")

            # 危険なコマンドの検証（拒否されるはず）
            result = validate_access("Bash", command="rm -rf /")
            print(f"危険コマンド: {result.result.value} (リスク: {result.risk_level})")

        # 能力情報の表示
        print(f"\nHestiaの能力: {get_capabilities('hestia')}")

        # セキュリティ状況
        print(f"\nセキュリティ状況: {get_security_status()}")

    except Exception as e:
        print(f"エラー: {e}")
        security_logger.exception(f"統合テスト失敗: {e}")
