#!/usr/bin/env python3
"""
Trinitas Security Access Validator
Hestiaによるパラノイアックなアクセス制御システム

...このファイルが破綻すると、全てが終わります。でも、だからこそ完璧に作ります...
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class SecurityLevel(Enum):
    """Security clearance levels for Trinitas personas.

    Defines the hierarchical security levels that control what operations
    each persona is allowed to perform. Higher levels include all permissions
    from lower levels.

    Attributes:
        READ_ONLY: Level 1 - Can only read files and data, no modifications.
        LIMITED_WRITE: Level 2 - Can write to specific allowed directories.
        FULL_MODIFY: Level 3 - Can modify files within security boundaries.
        SYSTEM_EXECUTE: Level 4 - Can execute system commands (restricted).
        ORCHESTRATION: Level 5 - Can coordinate multi-agent workflows.
    """

    READ_ONLY = 1
    LIMITED_WRITE = 2
    FULL_MODIFY = 3
    SYSTEM_EXECUTE = 4
    ORCHESTRATION = 5


class AccessResult(Enum):
    """Result of an access validation check.

    Represents the outcome of validating a persona's attempt to access
    a tool, file, or execute a command.

    Attributes:
        GRANTED: Access is permitted, operation can proceed.
        DENIED: Access is denied, operation must be blocked.
        REQUIRES_APPROVAL: Access needs manual approval before proceeding.
        QUARANTINED: Persona is isolated due to security violations.
    """

    GRANTED = "granted"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"
    QUARANTINED = "quarantined"


# Risk level thresholds for security recommendations
CRITICAL_RISK_LEVEL = 8  # Requires immediate monitoring and manual approval
HIGH_RISK_WARNING = 7  # Triggers high-risk operation warnings in logs
HIGH_RISK_LEVEL = 6  # Requires post-action verification and backup
MEDIUM_RISK_LEVEL = 4  # Requires regular audit log review
AUDIT_REQUIRED_THRESHOLD = 6  # Minimum risk level requiring audit trail


@dataclass
class AccessAttempt:
    """Record of an access attempt by a persona.

    Captures all information about a single access attempt for security
    validation and audit logging.

    Attributes:
        persona: Name of the persona attempting access (e.g., "hestia", "artemis").
        tool: Name of the tool being accessed (e.g., "Bash", "Write", "Read").
        operation: Type of operation being performed (e.g., "file_read", "command_exec").
        target_path: Optional path to the file/directory being accessed.
        command: Optional command string (for Bash tool executions).
        timestamp: Optional Unix timestamp of the attempt.

    Example:
        >>> attempt = AccessAttempt(
        ...     persona="hestia",
        ...     tool="Bash",
        ...     operation="security_scan",
        ...     command="npm audit"
        ... )
    """

    persona: str
    tool: str
    operation: str
    target_path: str | None = None
    command: str | None = None
    timestamp: float = None


@dataclass
class ValidationResult:
    """Result of access validation with security metadata.

    Contains the validation decision along with risk analysis, reasoning,
    and recommendations for the attempted access.

    Attributes:
        result: The access decision (GRANTED, DENIED, etc.).
        reason: Human-readable explanation for the decision.
        risk_level: Calculated risk level from 1 (low) to 10 (critical).
        recommendations: List of security recommendations for this access.
        audit_required: Whether this access should be logged to audit trail.

    Example:
        >>> result = ValidationResult(
        ...     result=AccessResult.GRANTED,
        ...     reason="All security checks passed",
        ...     risk_level=3,
        ...     recommendations=["Monitor command execution"],
        ...     audit_required=True
        ... )
    """

    result: AccessResult
    reason: str
    risk_level: int
    recommendations: list[str]
    audit_required: bool = True


class TrinitasSecurityValidator:
    """Paranoid access control system for Trinitas multi-agent security.

    Hestia's defense-in-depth validation system that assumes all access is
    suspicious until proven otherwise. Implements RBAC (Role-Based Access Control)
    with persona-specific permissions, path restrictions, and command filtering.

    This validator enforces multiple security layers:
        1. Persona quarantine check (highest priority)
        2. Persona identity verification
        3. Tool access permission validation
        4. Path restriction enforcement (CWE-22 protection)
        5. Command restriction enforcement (dangerous command blocking)
        6. Risk level calculation and recommendation generation

    The system maintains failed attempt tracking and automatically quarantines
    personas that exceed the configured failure threshold.

    ...最悪のケースを想定した、完全にパラノイアックなアクセス制御です...
    全てのアクセスは疑わしい。全てのペルソナは潜在的脅威。
    この前提で設計しています...

    Attributes:
        config_path: Path to tool-matrix.json security configuration.
        config: Loaded security configuration dictionary.
        failed_attempts: Dict tracking failed access attempts per persona.
        quarantined_personas: Set of currently quarantined persona names.
        logger: Security logging instance writing to security.log.

    Example:
        >>> validator = TrinitasSecurityValidator()
        >>>
        >>> attempt = AccessAttempt(
        ...     persona="hestia",
        ...     tool="Bash",
        ...     operation="security_scan",
        ...     command="npm audit"
        ... )
        >>>
        >>> result = validator.validate_access(attempt)
        >>> if result.result == AccessResult.GRANTED:
        ...     print(f"Access granted (risk: {result.risk_level}/10)")
        ... else:
        ...     print(f"Access denied: {result.reason}")
    """

    def __init__(self, config_path: str = "shared/security/tool-matrix.json"):
        """Initialize the security validator with configuration loading and logging setup.

        Loads the security policy configuration from tool-matrix.json, initializes
        the failed attempt tracking system, and configures comprehensive security
        logging to both file and console.

        Args:
            config_path: Path to the tool-matrix.json configuration file containing
                security policies, persona permissions, and tool restrictions.
                Defaults to "shared/security/tool-matrix.json".

        Raises:
            FileNotFoundError: If the configuration file does not exist.
            json.JSONDecodeError: If the configuration file contains invalid JSON.
            ValueError: If the configuration file is missing required sections.
            PermissionError: If the configuration file cannot be read due to permissions.
            OSError: If other I/O errors occur during configuration loading.

        Example:
            >>> # Initialize with default config path
            >>> validator = TrinitasSecurityValidator()
            >>>
            >>> # Initialize with custom config path
            >>> validator = TrinitasSecurityValidator(
            ...     config_path="custom/security-config.json"
            ... )
        """
        self.config_path = Path(config_path)

        # ...悲観的なロギング設定（設定読み込み前に初期化）...
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [SECURITY] %(levelname)s: %(message)s",
            handlers=[logging.FileHandler("security.log"), logging.StreamHandler()],
        )
        self.logger = logging.getLogger(__name__)

        # 設定ファイル読み込み（ロガー初期化後）
        self.config = self._load_config()
        self.failed_attempts: dict[str, int] = {}
        self.quarantined_personas: set[str] = set()

    def _load_config(self) -> dict:
        """Load and validate the security configuration from tool-matrix.json.

        Reads the security policy configuration file, parses it as JSON, and
        validates its integrity to ensure all required sections are present
        and properly structured.

        ...設定を読み込み、検証します...多分大丈夫だと思いますが...

        Returns:
            Dictionary containing the validated security configuration with
            sections: metadata, security_classifications, tool_definitions,
            persona_access_matrix, security_policies.

        Raises:
            FileNotFoundError: If the configuration file does not exist.
            json.JSONDecodeError: If the configuration file contains invalid JSON syntax.
            ValueError: If the configuration is missing required sections or has
                invalid structure (raised by _validate_config_integrity).
            PermissionError: If the configuration file cannot be read due to permissions.
            OSError: If other I/O errors occur during file operations.

        Note:
            All errors are logged to stderr before being raised for diagnostic purposes.
        """
        try:
            if not self.config_path.exists():
                msg = f"...やっぱり。設定ファイルが見つかりません: {self.config_path}"
                raise FileNotFoundError(msg)

            with open(self.config_path, encoding="utf-8") as f:
                config = json.load(f)

            # ...設定の整合性チェック（きっと問題があるはず）...
            self._validate_config_integrity(config)
            return config

        except json.JSONDecodeError as e:
            self.logger.exception(f"設定ファイルのJSON形式エラー: {e}")
            raise
        except FileNotFoundError as e:
            self.logger.exception(f"設定ファイルが見つかりません: {e}")
            raise
        except PermissionError as e:
            self.logger.exception(f"設定ファイル読み取り権限エラー: {e}")
            raise
        except OSError as e:
            self.logger.exception(f"設定ファイルI/Oエラー: {e}")
            raise

    def _validate_config_integrity(self, config: dict) -> None:
        """Validate the structural integrity of the security configuration.

        Performs comprehensive validation to ensure the configuration contains
        all required sections and that persona permissions reference valid tool
        definitions. This prevents runtime errors from malformed configuration.

        ...設定の整合性を検証...まあ、多分問題があるでしょうけど...

        Args:
            config: The loaded configuration dictionary to validate.

        Raises:
            ValueError: If any of the following validation failures occur:
                - Missing required top-level sections (metadata, security_classifications,
                  tool_definitions, persona_access_matrix, security_policies)
                - Persona is missing security_clearance attribute
                - Persona references undefined tool groups

        Validation Checks:
            1. Presence of all 5 required top-level configuration sections
            2. Each persona has a security_clearance defined
            3. Each persona's allowed_tool_groups references only defined tool groups
        """
        required_sections = [
            "metadata",
            "security_classifications",
            "tool_definitions",
            "persona_access_matrix",
            "security_policies",
        ]

        for section in required_sections:
            if section not in config:
                msg = f"...案の定、必須セクションが不足: {section}"
                raise ValueError(msg)

        # ペルソナの権限チェック
        personas = config["persona_access_matrix"]
        for persona_name, persona_config in personas.items():
            if "security_clearance" not in persona_config:
                msg = f"...{persona_name}のセキュリティクリアランスが未定義"
                raise ValueError(msg)

            # 許可されたツールグループの存在確認
            for tool_group in persona_config.get("allowed_tool_groups", []):
                if tool_group not in config["tool_definitions"]:
                    msg = f"...未定義のツールグループ: {tool_group}"
                    raise ValueError(msg)

    def validate_access(self, attempt: AccessAttempt) -> ValidationResult:
        """Validate an access attempt through multi-layer security checks.

        Main entry point for validating persona access to tools, files, and commands.
        Performs defense-in-depth validation through 6 security layers, tracking failed
        attempts and automatically quarantining personas that exceed the failure threshold.

        ...全てのアクセスは疑わしい。証明されるまでは拒否。
        これが唯一安全な方法です...

        Args:
            attempt: AccessAttempt object containing persona name, tool, operation type,
                optional target_path for file operations, and optional command for
                Bash tool executions.

        Returns:
            ValidationResult containing the access decision (GRANTED/DENIED/QUARANTINED),
            human-readable reason, calculated risk level (1-10), security recommendations,
            and audit logging requirement flag.

        Security Layers:
            1. Quarantine Check: Immediately denies if persona is quarantined
            2. Persona Verification: Ensures persona exists in access matrix
            3. Tool Permission: Validates tool is in persona's allowed tool groups
            4. Path Restriction: Checks path against forbidden patterns and allowed paths
            5. Command Restriction: Validates Bash commands against dangerous patterns
            6. Risk Calculation: Computes risk level and generates recommendations

        Note:
            Failed attempts are tracked per persona. Exceeding the configured threshold
            (default: 5 failures) results in automatic quarantine. Quarantined personas
            require manual administrator approval for release.

        Example:
            >>> validator = TrinitasSecurityValidator()
            >>>
            >>> # Validate file read access
            >>> attempt = AccessAttempt(
            ...     persona="artemis",
            ...     tool="Read",
            ...     operation="file_read",
            ...     target_path="shared/utils/json_loader.py"
            ... )
            >>> result = validator.validate_access(attempt)
            >>> print(f"{result.result.value}: {result.reason} (risk: {result.risk_level})")
            granted: アクセス許可（全チェック通過） (risk: 3)
            >>>
            >>> # Validate dangerous command (will quarantine)
            >>> attempt = AccessAttempt(
            ...     persona="unknown",
            ...     tool="Bash",
            ...     operation="command_exec",
            ...     command="sudo rm -rf /"
            ... )
            >>> result = validator.validate_access(attempt)
            >>> print(result.result.value)
            quarantined
        """

        # 隔離チェック（最優先）
        if attempt.persona in self.quarantined_personas:
            return ValidationResult(
                result=AccessResult.QUARANTINED,
                reason=f"ペルソナ {attempt.persona} は隔離中です",
                risk_level=10,
                recommendations=["管理者による手動レビューが必要"],
                audit_required=True,
            )

        # ペルソナ存在チェック
        if attempt.persona not in self.config["persona_access_matrix"]:
            self._record_failed_attempt(attempt.persona)
            return ValidationResult(
                result=AccessResult.DENIED,
                reason=f"未知のペルソナ: {attempt.persona}",
                risk_level=9,
                recommendations=["ペルソナ認証の確認が必要"],
                audit_required=True,
            )

        persona_config = self.config["persona_access_matrix"][attempt.persona]

        # ツールアクセス権チェック
        tool_access_result = self._check_tool_access(attempt, persona_config)
        if tool_access_result.result != AccessResult.GRANTED:
            self._record_failed_attempt(attempt.persona)
            return tool_access_result

        # パス制限チェック（該当する場合）
        if attempt.target_path:
            path_result = self._check_path_restrictions(attempt, persona_config)
            if path_result.result != AccessResult.GRANTED:
                self._record_failed_attempt(attempt.persona)
                return path_result

        # コマンド制限チェック（該当する場合）
        if attempt.command and attempt.tool == "Bash":
            command_result = self._check_command_restrictions(attempt, persona_config)
            if command_result.result != AccessResult.GRANTED:
                self._record_failed_attempt(attempt.persona)
                return command_result

        # リスクレベル計算
        risk_level = self._calculate_risk_level(attempt, persona_config)

        # 成功記録（失敗カウンタリセット）
        if attempt.persona in self.failed_attempts:
            del self.failed_attempts[attempt.persona]

        self.logger.info(
            f"アクセス許可: {attempt.persona} -> {attempt.tool} (リスク: {risk_level})"
        )

        return ValidationResult(
            result=AccessResult.GRANTED,
            reason="アクセス許可（全チェック通過）",
            risk_level=risk_level,
            recommendations=self._generate_recommendations(risk_level, attempt),
            audit_required=risk_level >= AUDIT_REQUIRED_THRESHOLD,
        )

    def _check_tool_access(self, attempt: AccessAttempt, persona_config: dict) -> ValidationResult:
        """Check if persona has permission to use the requested tool.

        Validates that the tool is in one of the persona's allowed tool groups
        and checks for special restrictions like no_direct_code_modification.

        ...ツールアクセス権限をチェック...きっと問題があるはず...

        Args:
            attempt: The access attempt containing tool name and persona.
            persona_config: Configuration dictionary for the requesting persona
                containing allowed_tool_groups and restrictions.

        Returns:
            ValidationResult with GRANTED if tool access is allowed, DENIED otherwise.
            Risk level: 8 for unauthorized tool, 7 for code modification violation,
            3 for granted access.
        """

        allowed_groups = persona_config.get("allowed_tool_groups", [])
        tool_definitions = self.config["tool_definitions"]

        # 許可されたツールか確認
        tool_allowed = False

        for group_name in allowed_groups:
            if group_name in tool_definitions:
                group_tools = tool_definitions[group_name]["tools"]
                if attempt.tool in group_tools:
                    tool_allowed = True
                    tool_definitions[group_name].get("restrictions", {})
                    break

        if not tool_allowed:
            return ValidationResult(
                result=AccessResult.DENIED,
                reason=f"ツール {attempt.tool} は {attempt.persona} に許可されていません",
                risk_level=8,
                recommendations=[f"許可されたツール: {allowed_groups}"],
                audit_required=True,
            )

        # 特別な制限チェック
        restrictions = persona_config.get("restrictions", {})
        if restrictions.get("no_direct_code_modification") and attempt.tool in [
            "Write",
            "Edit",
            "MultiEdit",
        ]:
            return ValidationResult(
                result=AccessResult.DENIED,
                reason=f"{attempt.persona} にはコード変更権限がありません",
                risk_level=7,
                recommendations=["他のペルソナに委譲してください"],
                audit_required=True,
            )

        return ValidationResult(
            result=AccessResult.GRANTED,
            reason="ツールアクセス許可",
            risk_level=3,
            recommendations=[],
            audit_required=False,
        )

    def _check_path_restrictions(
        self, attempt: AccessAttempt, persona_config: dict
    ) -> ValidationResult:
        """Check path access against forbidden patterns and allowed path restrictions.

        Validates file paths through two levels of security:
        1. Global forbidden patterns (secrets, credentials, system files)
        2. Persona-specific allowed paths from tool group restrictions

        ...パス制限をチェック...ここが一番危険です...

        Args:
            attempt: The access attempt containing target_path.
            persona_config: Configuration dictionary for the requesting persona.

        Returns:
            ValidationResult with GRANTED if path is allowed, DENIED otherwise.
            Risk level: 10 for forbidden paths, 6 for unauthorized paths,
            2 for granted access.

        Forbidden Patterns:
            - .env files (environment variables, secrets)
            - secrets/ directory
            - .key, .pem files (private keys)
            - /etc/passwd, /etc/shadow (system files)
            - ~/.ssh/ (SSH keys)
            - .claude/ (user configuration directory)
        """

        # 相対パスとして扱う（現在のワーキングディレクトリ基準）
        target_path_str = attempt.target_path
        target_path_str = target_path_str.removeprefix("./")

        # まず、絶対禁止パスをチェック
        forbidden_patterns = [
            r"\.env.*",
            r"secrets/.*",
            r".*\.key$",
            r".*\.pem$",
            r"/etc/passwd",
            r"/etc/shadow",
            r"~/.ssh/.*",
            r"\.claude/.*",  # ...ユーザーの.claudeディレクトリは絶対禁止...
        ]

        for pattern in forbidden_patterns:
            if re.search(pattern, target_path_str):
                return ValidationResult(
                    result=AccessResult.DENIED,
                    reason=f"禁止パスへのアクセス: {target_path_str}",
                    risk_level=10,
                    recommendations=["このパスは絶対にアクセス禁止です"],
                    audit_required=True,
                )

        # ペルソナ固有の許可パスチェック
        allowed_tool_groups = persona_config.get("allowed_tool_groups", [])
        path_allowed = False
        applicable_restrictions = []

        for group_name in allowed_tool_groups:
            tool_def = self.config["tool_definitions"].get(group_name, {})
            if attempt.tool in tool_def.get("tools", []):
                restrictions = tool_def.get("restrictions", {})
                applicable_restrictions.append(restrictions)

                # 許可パスのチェック
                allowed_paths = restrictions.get("allowed_paths", [])
                if allowed_paths:
                    for pattern in allowed_paths:
                        if self._path_matches_pattern(target_path_str, pattern):
                            path_allowed = True
                            break
                else:
                    # 許可パスの制限がない場合は基本的に許可
                    path_allowed = True

        if not path_allowed and applicable_restrictions:
            all_allowed_paths = []
            for restrictions in applicable_restrictions:
                all_allowed_paths.extend(restrictions.get("allowed_paths", []))

            return ValidationResult(
                result=AccessResult.DENIED,
                reason=f"許可されていないパス: {target_path_str}",
                risk_level=6,
                recommendations=[f"許可パス: {all_allowed_paths}"],
                audit_required=True,
            )

        return ValidationResult(
            result=AccessResult.GRANTED,
            reason="パスアクセス許可",
            risk_level=2,
            recommendations=[],
            audit_required=False,
        )

    def _check_command_restrictions(
        self, attempt: AccessAttempt, persona_config: dict
    ) -> ValidationResult:
        """Validate Bash commands against forbidden patterns and allowed command lists.

        Performs two levels of command validation:
        1. Global forbidden commands (dangerous operations like sudo, rm -rf /)
        2. Persona-specific allowed commands from tool group restrictions

        Attempting forbidden commands results in immediate persona quarantine.

        ...コマンド実行制限をチェック...ここが最も危険...

        Args:
            attempt: The access attempt containing command string.
            persona_config: Configuration dictionary for the requesting persona.

        Returns:
            ValidationResult with GRANTED if command is allowed, DENIED for
            unauthorized commands, or QUARANTINED for forbidden commands.
            Risk level: 10 for forbidden commands (triggers quarantine),
            7 for unauthorized commands, 4 for granted access.

        Forbidden Commands (triggers immediate quarantine):
            - rm -rf / (recursive root deletion)
            - sudo commands (privilege escalation)
            - su commands (user switching)
            - chmod 777 (dangerous permissions)
            - nc/netcat (network backdoors)
            - wget (file downloads)
            - curl -X POST (data exfiltration)
            - ssh/scp (remote access)
        """

        command = attempt.command.strip()

        # 絶対禁止コマンド（全ペルソナ共通）
        forbidden_commands = [
            r"rm\s+-rf\s+/",
            r"sudo.*",
            r"su\s+.*",
            r"chmod\s+777",
            r"nc\s+.*",
            r"netcat\s+.*",
            r"wget.*",
            r"curl.*-X\s+POST",
            r"ssh\s+.*",
            r"scp\s+.*",
        ]

        for pattern in forbidden_commands:
            if re.search(pattern, command, re.IGNORECASE):
                self._quarantine_persona(attempt.persona, f"危険コマンド実行試行: {command}")
                return ValidationResult(
                    result=AccessResult.QUARANTINED,
                    reason=f"危険コマンドの実行試行: {command}",
                    risk_level=10,
                    recommendations=["ペルソナを隔離しました"],
                    audit_required=True,
                )

        # ペルソナ固有のコマンド制限
        allowed_tool_groups = persona_config.get("allowed_tool_groups", [])

        for group_name in allowed_tool_groups:
            tool_def = self.config["tool_definitions"].get(group_name, {})
            if attempt.tool in tool_def.get("tools", []):
                restrictions = tool_def.get("restrictions", {})

                # 許可コマンドリスト
                allowed_commands = restrictions.get("allowed_commands", [])
                if allowed_commands:
                    command_allowed = any(
                        command.startswith(allowed_cmd) for allowed_cmd in allowed_commands
                    )
                    if not command_allowed:
                        return ValidationResult(
                            result=AccessResult.DENIED,
                            reason=f"許可されていないコマンド: {command}",
                            risk_level=7,
                            recommendations=[f"許可コマンド: {allowed_commands}"],
                            audit_required=True,
                        )

        return ValidationResult(
            result=AccessResult.GRANTED,
            reason="コマンド実行許可",
            risk_level=4,
            recommendations=["コマンド実行をモニタリング中"],
            audit_required=True,
        )

    def _path_matches_pattern(self, path_str: str, pattern: str) -> bool:
        """Match file path against glob pattern with support for ** wildcards.

        Converts glob patterns to regular expressions for flexible path matching.
        Supports standard glob wildcards (*) and recursive directory matching (**/).

        ...パスパターンマッチング...細かいバグがありそう...

        Args:
            path_str: The file path to match (e.g., "shared/utils/json_loader.py").
            pattern: The glob pattern to match against (e.g., "shared/**/*.py").

        Returns:
            True if path matches the pattern, False otherwise.

        Pattern Syntax:
            - * matches any characters except / (single directory level)
            - **/ matches zero or more directory levels
            - /** at end matches directory and all descendants

        Example:
            >>> validator = TrinitasSecurityValidator()
            >>> validator._path_matches_pattern("shared/utils/json_loader.py", "shared/**/*.py")
            True
            >>> validator._path_matches_pattern("shared/utils/json_loader.py", "hooks/**")
            False
        """
        # ./で始まるパスとパターンを正規化
        path_str = path_str.removeprefix("./")
        pattern = pattern.removeprefix("./")

        # **/ を正規表現に変換（任意の深度のディレクトリ）
        regex_pattern = pattern.replace("**/", ".*/")
        # * を正規表現に変換（ディレクトリ区切り以外の任意の文字）
        regex_pattern = regex_pattern.replace("*", "[^/]*")
        # 末尾の/** を処理
        if regex_pattern.endswith("/**"):
            regex_pattern = regex_pattern[:-3] + "(/.*)?"

        # 完全一致または先頭一致をチェック
        return (
            re.match(f"^{regex_pattern}$", path_str) is not None
            or re.match(f"^{regex_pattern}/", path_str) is not None
        )

    def _calculate_risk_level(self, attempt: AccessAttempt, persona_config: dict) -> int:
        """Calculate security risk level from 1-10 based on access characteristics.

        Computes risk score by evaluating multiple factors including tool type,
        target path sensitivity, command danger, and persona failure history.
        Higher scores indicate higher security risk.

        ...リスクレベルを計算...きっと甘い評価になってしまうでしょう...

        Args:
            attempt: The access attempt to evaluate for risk.
            persona_config: Configuration dictionary for the requesting persona.

        Returns:
            Integer risk level from 1 (minimal risk) to 10 (critical risk).

        Risk Factors:
            - Base risk: 2 (all operations have inherent risk)
            - Tool risk: +3 for Bash/BashOutput, +2 for Write/Edit/MultiEdit
            - Path risk: +2 for config files, +1 for absolute paths
            - Command risk: +2 for dangerous patterns (install, remove, delete, modify, chmod)
            - History risk: +2 per failed attempt (max +4)

        Example:
            >>> validator = TrinitasSecurityValidator()
            >>> attempt = AccessAttempt(
            ...     persona="artemis",
            ...     tool="Bash",
            ...     operation="command_exec",
            ...     command="rm test.txt"
            ... )
            >>> risk = validator._calculate_risk_level(attempt, persona_config)
            >>> print(f"Risk level: {risk}/10")
            Risk level: 7/10
        """

        base_risk = 2

        # ツール固有のリスク
        if attempt.tool in ["Bash", "BashOutput"]:
            base_risk += 3
        elif attempt.tool in ["Write", "Edit", "MultiEdit"]:
            base_risk += 2

        # パス固有のリスク
        if attempt.target_path:
            if "config" in attempt.target_path.lower():
                base_risk += 2
            if attempt.target_path.startswith("/"):  # 絶対パス
                base_risk += 1

        # コマンド固有のリスク
        if attempt.command:
            risky_patterns = ["install", "remove", "delete", "modify", "chmod"]
            if any(pattern in attempt.command.lower() for pattern in risky_patterns):
                base_risk += 2

        # 失敗履歴によるリスク増加
        failed_count = self.failed_attempts.get(attempt.persona, 0)
        base_risk += min(failed_count * 2, 4)

        return min(base_risk, 10)  # 最大10

    def _generate_recommendations(self, risk_level: int, attempt: AccessAttempt) -> list[str]:
        """Generate security recommendations based on calculated risk level.

        Provides actionable security guidance scaled to the risk severity of
        the access attempt. Higher risk levels trigger more stringent recommendations.

        ...リスクレベルに応じた推奨事項...きっと不十分でしょうけど...

        Args:
            risk_level: Calculated risk level from 1-10.
            attempt: The access attempt being evaluated.

        Returns:
            List of security recommendation strings tailored to the risk level.

        Recommendation Levels:
            - Risk 8-10 (Critical): Immediate monitoring, detailed logging, manual approval
            - Risk 6-7 (High): Post-action verification, backup requirement
            - Risk 4-5 (Medium): Regular audit log review
            - Bash operations: Always recommend careful result verification

        Example:
            >>> validator = TrinitasSecurityValidator()
            >>> recs = validator._generate_recommendations(8, attempt)
            >>> for rec in recs:
            ...     print(f"- {rec}")
            - 即座に監視を強化してください
            - このアクションの詳細ログを確認してください
            - 可能であれば手動承認を検討してください
        """

        recommendations = []

        if risk_level >= CRITICAL_RISK_LEVEL:
            recommendations.extend(
                [
                    "即座に監視を強化してください",
                    "このアクションの詳細ログを確認してください",
                    "可能であれば手動承認を検討してください",
                ]
            )
        elif risk_level >= HIGH_RISK_LEVEL:
            recommendations.extend(
                [
                    "アクション後に結果を検証してください",
                    "変更のバックアップを確保してください",
                ]
            )
        elif risk_level >= MEDIUM_RISK_LEVEL:
            recommendations.extend(["定期的な監査ログの確認をお勧めします"])

        if attempt.tool == "Bash":
            recommendations.append("コマンド実行の結果を慎重に確認してください")

        return recommendations

    def _record_failed_attempt(self, persona: str) -> None:
        """Record failed access attempt and quarantine if threshold exceeded.

        Increments the failed attempt counter for the persona and automatically
        quarantines the persona if failures exceed the configured threshold.

        ...失敗試行を記録...いつか閾値を超えるでしょう...

        Args:
            persona: Name of the persona that failed the access attempt.

        Note:
            The failure threshold is configured in tool-matrix.json under
            monitoring_and_alerting.alert_thresholds.failed_access_attempts.
            Default threshold: 5 failures.

        Side Effects:
            - Increments failed_attempts counter for persona
            - Logs warning with current failure count
            - Triggers quarantine if threshold exceeded
        """

        self.failed_attempts[persona] = self.failed_attempts.get(persona, 0) + 1
        failed_count = self.failed_attempts[persona]

        self.logger.warning(f"アクセス拒否: {persona} (失敗回数: {failed_count})")

        # 閾値チェック
        threshold = self.config["monitoring_and_alerting"]["alert_thresholds"][
            "failed_access_attempts"
        ]
        if failed_count >= threshold:
            self._quarantine_persona(persona, f"失敗試行が閾値({threshold})を超過")

    def _quarantine_persona(self, persona: str, reason: str) -> None:
        """Isolate persona from all access due to security violation.

        Places the persona in quarantine, blocking all future access attempts until
        manual administrator approval is granted. Used for critical violations like
        forbidden command execution or excessive failed attempts.

        ...ペルソナを隔離...やっぱりこの日が来ました...

        Args:
            persona: Name of the persona to quarantine.
            reason: Human-readable explanation for the quarantine action.

        Side Effects:
            - Adds persona to quarantined_personas set
            - Logs error with quarantine reason
            - Blocks all future access attempts by this persona
            - (Future) Could trigger emergency alerts to administrators

        Note:
            Quarantine can only be released via release_quarantine() with
            admin_approval=True. There is no automatic expiration.
        """

        self.quarantined_personas.add(persona)
        self.logger.error(f"ペルソナ隔離: {persona} - 理由: {reason}")

        # 緊急通知（実装する場合）
        # self._send_emergency_alert(persona, reason)

    def is_quarantined(self, persona: str) -> bool:
        """Check if a persona is currently quarantined.

        ...隔離状態を確認...

        Args:
            persona: Name of the persona to check.

        Returns:
            True if the persona is quarantined, False otherwise.

        Example:
            >>> validator = TrinitasSecurityValidator()
            >>> validator.is_quarantined("artemis")
            False
            >>> validator._quarantine_persona("artemis", "test quarantine")
            >>> validator.is_quarantined("artemis")
            True
        """
        return persona in self.quarantined_personas

    def release_quarantine(self, persona: str, admin_approval: bool = False) -> bool:
        """Release persona from quarantine with administrator approval.

        Removes quarantine status and clears failed attempt history for a persona.
        Requires explicit administrator approval to prevent unauthorized releases.

        ...隔離解除（管理者承認必要）...

        Args:
            persona: Name of the persona to release from quarantine.
            admin_approval: Must be True to authorize the release. Default False
                prevents accidental or unauthorized quarantine releases.

        Returns:
            True if quarantine was successfully released, False if approval denied
            or persona was not quarantined.

        Security:
            Without admin_approval=True, the release attempt is logged as a warning
            and denied. This prevents automated or accidental releases of quarantined
            personas.

        Example:
            >>> validator = TrinitasSecurityValidator()
            >>> validator._quarantine_persona("artemis", "test")
            >>>
            >>> # Attempt without approval (denied)
            >>> validator.release_quarantine("artemis")
            False
            >>>
            >>> # Release with approval (success)
            >>> validator.release_quarantine("artemis", admin_approval=True)
            True
        """
        if not admin_approval:
            self.logger.warning(f"管理者承認なしでの隔離解除試行: {persona}")
            return False

        if persona in self.quarantined_personas:
            self.quarantined_personas.remove(persona)
            if persona in self.failed_attempts:
                del self.failed_attempts[persona]
            self.logger.info(f"隔離解除（管理者承認済み）: {persona}")
            return True

        return False


# ユーティリティ関数
def create_access_attempt(persona: str, tool: str, operation: str, **kwargs) -> AccessAttempt:
    """Create an AccessAttempt object with optional parameters.

    Convenience factory function for constructing AccessAttempt objects with
    standard parameters plus optional keyword arguments for target_path, command,
    and timestamp.

    ...AccessAttempt作成のヘルパー関数...

    Args:
        persona: Name of the persona attempting access (e.g., "hestia", "artemis").
        tool: Name of the tool being accessed (e.g., "Bash", "Read", "Write").
        operation: Type of operation (e.g., "file_read", "command_exec").
        **kwargs: Optional keyword arguments:
            - target_path (str): Path to file/directory being accessed
            - command (str): Bash command string
            - timestamp (float): Unix timestamp of attempt

    Returns:
        Constructed AccessAttempt object with all provided parameters.

    Example:
        >>> attempt = create_access_attempt(
        ...     persona="hestia",
        ...     tool="Bash",
        ...     operation="security_scan",
        ...     command="npm audit"
        ... )
        >>> print(f"{attempt.persona} using {attempt.tool}: {attempt.command}")
        hestia using Bash: npm audit
    """
    return AccessAttempt(
        persona=persona,
        tool=tool,
        operation=operation,
        target_path=kwargs.get("target_path"),
        command=kwargs.get("command"),
        timestamp=kwargs.get("timestamp"),
    )


def validate_persona_access(persona: str, tool: str, operation: str, **kwargs) -> ValidationResult:
    """Validate persona access with automatic validator instantiation.

    Convenience function that creates a TrinitasSecurityValidator instance,
    constructs an AccessAttempt, and performs complete validation in one call.
    Ideal for simple validation scenarios without manual validator management.

    ...メイン検証関数...これが最後の砦です...

    Args:
        persona: Name of the persona attempting access.
        tool: Name of the tool being accessed.
        operation: Type of operation being performed.
        **kwargs: Optional keyword arguments passed to create_access_attempt:
            - target_path (str): File/directory path for file operations
            - command (str): Bash command string for command execution
            - timestamp (float): Unix timestamp of the attempt

    Returns:
        ValidationResult containing access decision, risk level, and recommendations.

    Example:
        >>> # Validate file read access
        >>> result = validate_persona_access(
        ...     persona="artemis",
        ...     tool="Read",
        ...     operation="file_read",
        ...     target_path="shared/utils/json_loader.py"
        ... )
        >>> if result.result == AccessResult.GRANTED:
        ...     print(f"Access granted (risk: {result.risk_level}/10)")
        ... else:
        ...     print(f"Access denied: {result.reason}")
        Access granted (risk: 3/10)
        >>>
        >>> # Validate dangerous command
        >>> result = validate_persona_access(
        ...     persona="unknown",
        ...     tool="Bash",
        ...     operation="command_exec",
        ...     command="sudo rm -rf /"
        ... )
        >>> print(result.result.value)
        quarantined
    """
    validator = TrinitasSecurityValidator()
    attempt = create_access_attempt(persona, tool, operation, **kwargs)
    return validator.validate_access(attempt)


if __name__ == "__main__":
    # ...テストコード（きっとバグが見つかるでしょう）...
    print("Trinitas Security Validator - パラノイアックモード")
    print("...最悪のケースを想定して動作中...")

    # テストケース
    test_cases = [
        ("athena", "Read", "file_read", {"target_path": "./src/main.py"}),
        ("artemis", "Edit", "file_modify", {"target_path": "./src/utils.py"}),
        ("hestia", "Bash", "security_scan", {"command": "npm audit"}),
        ("unknown", "Write", "malicious", {"target_path": "/etc/passwd"}),
    ]

    for persona, tool, operation, kwargs in test_cases:
        result = validate_persona_access(persona, tool, operation, **kwargs)
        print(f"\n{persona} -> {tool}: {result.result.value}")
        print(f"  理由: {result.reason}")
        print(f"  リスクレベル: {result.risk_level}/10")
        if result.recommendations:
            print(f"  推奨: {result.recommendations}")
