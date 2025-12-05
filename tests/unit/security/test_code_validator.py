"""Unit tests for S-P0-4: Subprocess Sandboxing (AST-based Code Validation).

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 2.3 - Runtime Protection

Tests for:
- Forbidden import detection
- Forbidden builtin detection
- Forbidden attribute access detection
- Code size and complexity limits
- AST parsing error handling

Author: Metis (Testing) + Hestia (Security Review)
Created: 2025-12-05
"""

import pytest

from src.infrastructure.security.code_validator import (
    CodeValidationError,
    CodeValidator,
    CodeValidatorConfig,
    ValidationResult,
    validate_code,
    validate_code_or_raise,
)


class TestForbiddenImports:
    """Tests for forbidden import detection."""

    def test_import_os_blocked(self):
        """Test that 'import os' is blocked."""
        result = validate_code("import os")

        assert not result.is_safe
        assert len(result.violations) == 1
        assert "Forbidden import: 'os'" in result.violations[0]

    def test_import_subprocess_blocked(self):
        """Test that 'import subprocess' is blocked."""
        result = validate_code("import subprocess")

        assert not result.is_safe
        assert "subprocess" in result.violations[0]

    def test_import_socket_blocked(self):
        """Test that 'import socket' is blocked (network access)."""
        result = validate_code("import socket")

        assert not result.is_safe
        assert "socket" in result.violations[0]

    def test_from_os_import_blocked(self):
        """Test that 'from os import ...' is blocked."""
        result = validate_code("from os import path, system")

        assert not result.is_safe
        assert "from os" in result.violations[0]

    def test_from_subprocess_import_blocked(self):
        """Test that 'from subprocess import ...' is blocked."""
        result = validate_code("from subprocess import Popen, PIPE")

        assert not result.is_safe
        assert "subprocess" in result.violations[0]

    def test_nested_import_blocked(self):
        """Test that nested module imports are blocked (e.g., urllib.request)."""
        result = validate_code("import urllib.request")

        assert not result.is_safe
        assert "urllib" in result.violations[0]

    def test_requests_blocked(self):
        """Test that 'import requests' is blocked (external HTTP)."""
        result = validate_code("import requests")

        assert not result.is_safe
        assert "requests" in result.violations[0]

    def test_ctypes_blocked(self):
        """Test that 'import ctypes' is blocked (FFI access)."""
        result = validate_code("import ctypes")

        assert not result.is_safe
        assert "ctypes" in result.violations[0]

    def test_pickle_blocked(self):
        """Test that 'import pickle' is blocked (deserialization attacks)."""
        result = validate_code("import pickle")

        assert not result.is_safe
        assert "pickle" in result.violations[0]

    def test_safe_import_allowed(self):
        """Test that safe imports are allowed."""
        safe_code = """
import json
import math
import re
from datetime import datetime
from typing import Any
"""
        result = validate_code(safe_code)

        assert result.is_safe
        assert len(result.violations) == 0
        assert result.import_count == 5

    def test_multiple_forbidden_imports(self):
        """Test detection of multiple forbidden imports."""
        code = """
import os
import subprocess
import socket
"""
        result = validate_code(code)

        assert not result.is_safe
        assert len(result.violations) == 3


class TestForbiddenBuiltins:
    """Tests for forbidden builtin detection."""

    def test_eval_blocked(self):
        """Test that eval() is blocked."""
        result = validate_code("result = eval('1 + 1')")

        assert not result.is_safe
        assert "Forbidden builtin call: 'eval()'" in result.violations[0]

    def test_exec_blocked(self):
        """Test that exec() is blocked."""
        result = validate_code("exec('print(1)')")

        assert not result.is_safe
        assert "Forbidden builtin call: 'exec()'" in result.violations[0]

    def test_compile_blocked(self):
        """Test that compile() is blocked."""
        result = validate_code("code = compile('x=1', '<string>', 'exec')")

        assert not result.is_safe
        assert "Forbidden builtin call: 'compile()'" in result.violations[0]

    def test_open_blocked(self):
        """Test that open() is blocked."""
        result = validate_code("f = open('/etc/passwd', 'r')")

        assert not result.is_safe
        assert "Forbidden builtin call: 'open()'" in result.violations[0]

    def test_input_blocked(self):
        """Test that input() is blocked."""
        result = validate_code("user_input = input('Enter: ')")

        assert not result.is_safe
        assert "Forbidden builtin call: 'input()'" in result.violations[0]

    def test___import___blocked(self):
        """Test that __import__() is blocked."""
        result = validate_code("os = __import__('os')")

        assert not result.is_safe
        assert "__import__" in result.violations[0]

    def test_getattr_blocked(self):
        """Test that getattr() is blocked (attribute access bypass)."""
        result = validate_code("val = getattr(obj, 'secret')")

        assert not result.is_safe
        assert "getattr" in result.violations[0]

    def test_safe_builtins_allowed(self):
        """Test that safe builtins are allowed."""
        safe_code = """
result = len([1, 2, 3])
text = str(123)
items = list(range(10))
total = sum([1, 2, 3])
is_true = bool(1)
"""
        result = validate_code(safe_code)

        assert result.is_safe
        assert len(result.violations) == 0


class TestForbiddenAttributes:
    """Tests for forbidden attribute access detection."""

    def test___class___blocked(self):
        """Test that __class__ access is blocked."""
        result = validate_code("cls = obj.__class__")

        assert not result.is_safe
        assert "__class__" in result.violations[0]

    def test___subclasses___blocked(self):
        """Test that __subclasses__ access is blocked."""
        result = validate_code("subs = cls.__subclasses__()")

        assert not result.is_safe
        assert "__subclasses__" in result.violations[0]

    def test___globals___blocked(self):
        """Test that __globals__ access is blocked."""
        result = validate_code("g = func.__globals__")

        assert not result.is_safe
        assert "__globals__" in result.violations[0]

    def test___builtins___blocked(self):
        """Test that __builtins__ attribute access is blocked."""
        # Direct name `__builtins__` is a Name node, not Attribute
        # Test the actual pattern that would be used for bypass
        result = validate_code("b = obj.__builtins__")

        assert not result.is_safe
        assert any("__builtins__" in v for v in result.violations)

    def test_subscript_attribute_access_blocked(self):
        """Test that subscript-based attribute access is blocked."""
        result = validate_code('val = obj["__class__"]')

        assert not result.is_safe
        assert "__class__" in result.violations[0]

    def test_safe_attributes_allowed(self):
        """Test that normal attributes are allowed."""
        safe_code = """
name = obj.name
value = data.value
items = container.items()
"""
        result = validate_code(safe_code)

        assert result.is_safe


class TestCodeSizeLimits:
    """Tests for code size and complexity limits."""

    def test_code_length_limit(self):
        """Test that code length is limited."""
        config = CodeValidatorConfig(max_code_length=100)
        validator = CodeValidator(config)

        long_code = "x = 1\n" * 50  # ~300 chars

        result = validator.validate(long_code)

        assert not result.is_safe
        assert "Code length" in result.violations[0]

    def test_line_count_limit(self):
        """Test that line count is limited."""
        config = CodeValidatorConfig(max_line_count=10)
        validator = CodeValidator(config)

        many_lines = "\n".join([f"x{i} = {i}" for i in range(20)])

        result = validator.validate(many_lines)

        assert not result.is_safe
        assert "Line count" in result.violations[0]

    def test_import_count_limit(self):
        """Test that import count is limited."""
        config = CodeValidatorConfig(max_import_count=3)
        validator = CodeValidator(config)

        many_imports = """
import json
import math
import re
import collections
import itertools
"""

        result = validator.validate(many_imports)

        assert not result.is_safe
        assert "Import count" in result.violations[0]

    def test_ast_depth_limit(self):
        """Test that AST nesting depth is limited."""
        config = CodeValidatorConfig(max_ast_depth=5)
        validator = CodeValidator(config)

        # Create deeply nested code using function calls (each call adds depth)
        # Use nested function calls which create deeper AST
        deep_code = "result = f1(f2(f3(f4(f5(f6(f7(f8(f9(f10(1))))))))))"

        result = validator.validate(deep_code)

        assert not result.is_safe
        assert "AST depth exceeded" in result.violations[0]


class TestSyntaxErrors:
    """Tests for syntax error handling."""

    def test_syntax_error_detected(self):
        """Test that syntax errors are caught."""
        result = validate_code("def incomplete(")

        assert not result.is_safe
        assert result.ast_parsed is False
        assert "Syntax error" in result.violations[0]

    def test_indentation_error_detected(self):
        """Test that indentation errors are caught."""
        code = """
def foo():
x = 1
"""
        result = validate_code(code)

        assert not result.is_safe
        assert result.ast_parsed is False


class TestValidationResult:
    """Tests for ValidationResult functionality."""

    def test_result_to_dict(self):
        """Test ValidationResult.to_dict()."""
        result = ValidationResult(
            is_safe=False,
            violations=["error1", "error2"],
            ast_parsed=True,
            line_count=10,
            import_count=3,
        )

        result_dict = result.to_dict()

        assert result_dict["is_safe"] is False
        assert result_dict["violation_count"] == 2
        assert result_dict["line_count"] == 10
        assert result_dict["import_count"] == 3

    def test_safe_result_properties(self):
        """Test safe validation result."""
        result = validate_code("x = 1 + 2")

        assert result.is_safe is True
        assert result.violations == []
        assert result.ast_parsed is True
        assert result.line_count == 1


class TestValidateOrRaise:
    """Tests for validate_or_raise functionality."""

    def test_safe_code_returns_result(self):
        """Test that safe code returns result."""
        result = validate_code_or_raise("x = 1")

        assert result.is_safe is True

    def test_unsafe_code_raises(self):
        """Test that unsafe code raises CodeValidationError."""
        with pytest.raises(CodeValidationError) as excinfo:
            validate_code_or_raise("import os")

        assert "1 violation(s)" in str(excinfo.value)
        assert len(excinfo.value.violations) == 1
        assert excinfo.value.code_snippet is not None

    def test_error_includes_snippet(self):
        """Test that error includes code snippet."""
        long_code = "import os\n" * 50

        with pytest.raises(CodeValidationError) as excinfo:
            validate_code_or_raise(long_code)

        # Snippet should be truncated
        assert "..." in excinfo.value.code_snippet


class TestSecurityBypassAttempts:
    """Tests for common security bypass attempts."""

    def test_string_concatenation_import_bypass(self):
        """Test that string concatenation bypass is blocked.

        This would require __import__ which is blocked.
        """
        code = "__import__('o' + 's')"

        result = validate_code(code)

        assert not result.is_safe
        assert "__import__" in result.violations[0]

    def test_getattr_bypass_blocked(self):
        """Test that getattr-based bypass is blocked."""
        # Use attribute access to __builtins__ instead of direct name
        code = "getattr(obj.__builtins__, 'eval')('1+1')"

        result = validate_code(code)

        assert not result.is_safe
        # Multiple violations: getattr, __builtins__, eval
        assert len(result.violations) >= 2

    def test_class_mro_bypass_blocked(self):
        """Test that class.__mro__ bypass is blocked."""
        code = "''.__class__.__mro__[1].__subclasses__()"

        result = validate_code(code)

        assert not result.is_safe
        # Multiple violations: __class__, __mro__, __subclasses__
        assert len(result.violations) >= 2

    def test_lambda_exec_blocked(self):
        """Test that lambda with exec is blocked."""
        code = "(lambda: exec('import os'))()"

        result = validate_code(code)

        assert not result.is_safe
        assert any("exec" in v for v in result.violations)

    def test_nested_getattr_blocked(self):
        """Test that nested getattr is blocked."""
        code = "getattr(getattr(obj, 'x'), 'y')"

        result = validate_code(code)

        assert not result.is_safe
        assert len(result.violations) >= 1


class TestCodeValidatorConfig:
    """Tests for CodeValidatorConfig."""

    def test_custom_config(self):
        """Test custom configuration."""
        config = CodeValidatorConfig(
            max_code_length=1000,
            max_line_count=100,
            max_import_count=5,
            max_ast_depth=15,
        )

        assert config.max_code_length == 1000
        assert config.max_line_count == 100
        assert config.max_import_count == 5
        assert config.max_ast_depth == 15

    def test_default_config(self):
        """Test default configuration values."""
        config = CodeValidatorConfig()

        assert config.max_code_length == 50_000
        assert config.max_line_count == 500
        assert config.max_import_count == 20
        assert config.max_ast_depth == 10


class TestModuleImports:
    """Tests for module import functionality."""

    def test_security_module_exports(self):
        """Test that code validator is exported from security module."""
        from src.infrastructure.security import (
            CodeValidationError,
            CodeValidator,
            CodeValidatorConfig,
            ValidationResult,
            validate_code,
            validate_code_or_raise,
        )

        assert CodeValidator is not None
        assert CodeValidatorConfig is not None
        assert CodeValidationError is not None
        assert ValidationResult is not None
        assert validate_code is not None
        assert validate_code_or_raise is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
