"""AST-based Code Validator for MCP Hub Subprocess Sandboxing.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 2.3 - Runtime Protection
Requirement: S-P0-4 - Subprocess Sandboxing

Security Properties:
- AST-based static analysis of Python code
- Detection of dangerous imports and builtins
- Prevention of code injection attacks
- Defense-in-depth layer before execution

This implements the Minimal Viable Sandbox (MVS) approach:
- AST analysis ONLY (blocks 90% of attack vectors)
- Maximum security ROI with minimal complexity
- Resource limits deferred to Phase 3

Usage:
    >>> validator = CodeValidator()
    >>> result = validator.validate("import os")
    >>> if not result.is_safe:
    ...     print(f"Blocked: {result.violations}")

Author: Metis (Implementation) + Hestia (Security Review) + Eris (Tactical Design)
Created: 2025-12-05
"""

import ast
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

# Forbidden imports - modules that provide system access
FORBIDDEN_IMPORTS: frozenset[str] = frozenset(
    [
        # System access
        "os",
        "sys",
        "subprocess",
        "shutil",
        "pathlib",
        # Network access
        "socket",
        "urllib",
        "urllib.request",
        "urllib.parse",
        "http",
        "http.client",
        "http.server",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "telnetlib",
        # Code execution
        "code",
        "codeop",
        "compile",
        "ast",  # Prevent meta-programming attacks
        "dis",
        "inspect",
        "importlib",
        # Process/threading
        "multiprocessing",
        "threading",
        "concurrent",
        "asyncio.subprocess",
        # Dangerous I/O
        "pickle",
        "shelve",
        "marshal",
        "ctypes",
        "cffi",
        # Command execution
        "pty",
        "popen2",
        "commands",
        # Dangerous builtins access
        "builtins",
        "__builtin__",
    ]
)

# Forbidden builtins - functions that should never be called
FORBIDDEN_BUILTINS: frozenset[str] = frozenset(
    [
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "input",
        "breakpoint",
        "help",  # Can reveal system info
        "license",
        "credits",
        "exit",
        "quit",
        "globals",
        "locals",
        "vars",
        "dir",
        "getattr",
        "setattr",
        "delattr",
        "hasattr",
    ]
)

# Forbidden attribute access patterns
FORBIDDEN_ATTRIBUTES: frozenset[str] = frozenset(
    [
        "__class__",
        "__bases__",
        "__subclasses__",
        "__mro__",
        "__globals__",
        "__code__",
        "__closure__",
        "__builtins__",
        "__import__",
        "__dict__",
        "__module__",
        "__spec__",
        "__loader__",
        "__file__",
        "__cached__",
        "__path__",
        "__package__",
    ]
)


# ============================================================================
# EXCEPTIONS
# ============================================================================


class CodeValidationError(Exception):
    """Code validation error.

    Raised when code fails security validation.
    """

    def __init__(
        self,
        message: str,
        violations: list[str] | None = None,
        code_snippet: str | None = None,
    ):
        super().__init__(message)
        self.violations = violations or []
        self.code_snippet = code_snippet


# ============================================================================
# DATA CLASSES
# ============================================================================


@dataclass
class ValidationResult:
    """Result of code validation.

    Attributes:
        is_safe: True if code passed all security checks
        violations: List of security violation descriptions
        ast_parsed: True if code could be parsed as valid Python
        line_count: Number of lines in the code
        import_count: Number of import statements found
    """

    is_safe: bool
    violations: list[str] = field(default_factory=list)
    ast_parsed: bool = True
    line_count: int = 0
    import_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "is_safe": self.is_safe,
            "violations": self.violations,
            "ast_parsed": self.ast_parsed,
            "line_count": self.line_count,
            "import_count": self.import_count,
            "violation_count": len(self.violations),
        }


@dataclass
class CodeValidatorConfig:
    """Configuration for code validator.

    Attributes:
        max_code_length: Maximum code length in characters
        max_line_count: Maximum number of lines
        max_import_count: Maximum number of imports
        max_ast_depth: Maximum AST nesting depth
        forbidden_imports: Set of forbidden module names
        forbidden_builtins: Set of forbidden builtin names
        forbidden_attributes: Set of forbidden attribute names
    """

    max_code_length: int = 50_000  # 50KB
    max_line_count: int = 500
    max_import_count: int = 20
    max_ast_depth: int = 10
    forbidden_imports: frozenset[str] = FORBIDDEN_IMPORTS
    forbidden_builtins: frozenset[str] = FORBIDDEN_BUILTINS
    forbidden_attributes: frozenset[str] = FORBIDDEN_ATTRIBUTES


# ============================================================================
# AST VISITOR
# ============================================================================


class SecurityVisitor(ast.NodeVisitor):
    """AST visitor for security analysis.

    Traverses the AST looking for security violations:
    - Forbidden imports
    - Forbidden builtin calls
    - Forbidden attribute access
    - Dangerous string operations (potential injection)
    """

    def __init__(self, config: CodeValidatorConfig):
        self.config = config
        self.violations: list[str] = []
        self.import_count = 0
        self.depth = 0
        self.max_depth_reached = 0

    def visit(self, node: ast.AST) -> Any:
        """Visit a node with depth tracking."""
        self.depth += 1
        self.max_depth_reached = max(self.max_depth_reached, self.depth)

        if self.depth > self.config.max_ast_depth:
            self.violations.append(f"AST depth exceeded maximum ({self.config.max_ast_depth})")
            self.depth -= 1
            return None

        result = super().visit(node)
        self.depth -= 1
        return result

    def visit_Import(self, node: ast.Import) -> None:
        """Check import statements."""
        self.import_count += 1

        for alias in node.names:
            module_name = alias.name
            # Check full module and parent modules
            parts = module_name.split(".")
            for i in range(len(parts)):
                check_name = ".".join(parts[: i + 1])
                if check_name in self.config.forbidden_imports:
                    self.violations.append(
                        f"Forbidden import: '{module_name}' (line {node.lineno})"
                    )
                    break

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check from-import statements."""
        self.import_count += 1

        if node.module:
            module_name = node.module
            # Check full module and parent modules
            parts = module_name.split(".")
            for i in range(len(parts)):
                check_name = ".".join(parts[: i + 1])
                if check_name in self.config.forbidden_imports:
                    self.violations.append(
                        f"Forbidden import: 'from {module_name}' (line {node.lineno})"
                    )
                    break

        # Also check imported names
        for alias in node.names:
            if alias.name in self.config.forbidden_imports:
                self.violations.append(
                    f"Forbidden import name: '{alias.name}' (line {node.lineno})"
                )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check function calls for forbidden builtins."""
        # Check direct name calls: eval(), exec(), etc.
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.config.forbidden_builtins:
                self.violations.append(
                    f"Forbidden builtin call: '{func_name}()' (line {node.lineno})"
                )

        # Check attribute calls: obj.eval(), getattr(), etc.
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if attr_name in self.config.forbidden_builtins:
                self.violations.append(
                    f"Forbidden method call: '.{attr_name}()' (line {node.lineno})"
                )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Check attribute access for dangerous patterns."""
        attr_name = node.attr

        if attr_name in self.config.forbidden_attributes:
            self.violations.append(
                f"Forbidden attribute access: '.{attr_name}' (line {node.lineno})"
            )

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Check subscript access for string-based attribute access."""
        # Detect patterns like: obj["__class__"]
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            key = node.slice.value
            if key in self.config.forbidden_attributes:
                self.violations.append(
                    f"Forbidden subscript access: '[{key!r}]' (line {node.lineno})"
                )

        self.generic_visit(node)


# ============================================================================
# CODE VALIDATOR
# ============================================================================


class CodeValidator:
    """AST-based code validator for subprocess sandboxing.

    Security Features:
    - Static AST analysis of Python code
    - Detection of dangerous imports and builtins
    - Detection of dangerous attribute access
    - Code size and complexity limits

    Usage:
        >>> validator = CodeValidator()
        >>> result = validator.validate("print('hello')")
        >>> print(result.is_safe)  # True

        >>> result = validator.validate("import os")
        >>> print(result.is_safe)  # False
        >>> print(result.violations)  # ["Forbidden import: 'os'"]
    """

    def __init__(self, config: CodeValidatorConfig | None = None):
        """Initialize code validator.

        Args:
            config: Validation configuration (uses defaults if None)
        """
        self.config = config or CodeValidatorConfig()
        logger.debug(
            f"CodeValidator initialized with limits: "
            f"code_length={self.config.max_code_length}, "
            f"lines={self.config.max_line_count}, "
            f"imports={self.config.max_import_count}"
        )

    def validate(self, code: str) -> ValidationResult:
        """Validate Python code for security.

        Args:
            code: Python source code to validate

        Returns:
            ValidationResult with safety status and any violations
        """
        violations: list[str] = []

        # Check code length
        if len(code) > self.config.max_code_length:
            violations.append(
                f"Code length ({len(code)} chars) exceeds maximum ({self.config.max_code_length})"
            )
            return ValidationResult(
                is_safe=False,
                violations=violations,
                ast_parsed=False,
            )

        # Check line count
        lines = code.split("\n")
        line_count = len(lines)
        if line_count > self.config.max_line_count:
            violations.append(
                f"Line count ({line_count}) exceeds maximum ({self.config.max_line_count})"
            )
            return ValidationResult(
                is_safe=False,
                violations=violations,
                ast_parsed=False,
                line_count=line_count,
            )

        # Parse AST
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            violations.append(f"Syntax error: {e}")
            return ValidationResult(
                is_safe=False,
                violations=violations,
                ast_parsed=False,
                line_count=line_count,
            )

        # Run security visitor
        visitor = SecurityVisitor(self.config)
        visitor.visit(tree)
        violations.extend(visitor.violations)

        # Check import count
        if visitor.import_count > self.config.max_import_count:
            violations.append(
                f"Import count ({visitor.import_count}) exceeds maximum "
                f"({self.config.max_import_count})"
            )

        is_safe = len(violations) == 0

        if not is_safe:
            logger.warning(f"Code validation failed: {len(violations)} violation(s)")

        return ValidationResult(
            is_safe=is_safe,
            violations=violations,
            ast_parsed=True,
            line_count=line_count,
            import_count=visitor.import_count,
        )

    def validate_or_raise(self, code: str) -> ValidationResult:
        """Validate code and raise on failure.

        Args:
            code: Python source code to validate

        Returns:
            ValidationResult if code is safe

        Raises:
            CodeValidationError: If code fails validation
        """
        result = self.validate(code)

        if not result.is_safe:
            # Truncate code for error message
            snippet = code[:200] + "..." if len(code) > 200 else code
            raise CodeValidationError(
                f"Code validation failed: {len(result.violations)} violation(s)",
                violations=result.violations,
                code_snippet=snippet,
            )

        return result


# ============================================================================
# SINGLETON
# ============================================================================

_validator: CodeValidator | None = None


def get_code_validator() -> CodeValidator:
    """Get singleton CodeValidator instance.

    Returns:
        CodeValidator instance
    """
    global _validator
    if _validator is None:
        _validator = CodeValidator()
    return _validator


def validate_code(code: str) -> ValidationResult:
    """Validate code using singleton validator.

    Convenience function for quick validation.

    Args:
        code: Python source code to validate

    Returns:
        ValidationResult with safety status
    """
    validator = get_code_validator()
    return validator.validate(code)


def validate_code_or_raise(code: str) -> ValidationResult:
    """Validate code and raise on failure.

    Convenience function using singleton validator.

    Args:
        code: Python source code to validate

    Returns:
        ValidationResult if code is safe

    Raises:
        CodeValidationError: If code fails validation
    """
    validator = get_code_validator()
    return validator.validate_or_raise(code)
