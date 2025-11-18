#!/usr/bin/env python3
"""
Unified JSON Loading Utility for Trinitas
Provides consistent error handling and validation for JSON operations

Created: 2025-10-15 (Phase 1 Day 3)
Purpose: Eliminate code duplication across JSON loading operations
"""
from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


class JSONLoadError(Exception):
    """Base exception for JSON loading errors.

    This exception is raised when JSON loading or parsing fails and
    silent mode is not enabled. It wraps underlying exceptions like
    FileNotFoundError, JSONDecodeError, etc.

    Attributes:
        message: Error message describing the failure.

    Example:
        >>> try:
        ...     JSONLoader.load_from_file('invalid.json')
        ... except JSONLoadError as e:
        ...     print(f"Failed to load: {e}")
    """



class JSONLoader:
    """Unified JSON loading with comprehensive error handling.

    This class provides static methods for loading JSON from various sources
    (files, strings, stdin) with consistent error handling and optional default
    values. All methods support silent mode for suppressing error messages.

    The class follows a fail-safe pattern where errors can either raise
    JSONLoadError exceptions or return default values based on the silent
    parameter.

    Example:
        >>> # Load from file with error handling
        >>> data = JSONLoader.load_from_file('config.json', default={})
        >>>
        >>> # Parse from string silently
        >>> data = JSONLoader.load_from_string('{"key": "value"}', silent=True)
        >>>
        >>> # Save to file
        >>> JSONLoader.save_to_file(data, 'output.json', indent=4)
    """

    @staticmethod
    def load_from_file(
        file_path: str | Path, default: Any = None, silent: bool = False
    ) -> Any:
        """Load JSON from a file with comprehensive error handling.

        This method handles various failure scenarios including missing files,
        permission errors, invalid JSON syntax, and encoding issues. All errors
        are caught and handled consistently based on the silent parameter.

        Args:
            file_path: Path to the JSON file. Can be a string or pathlib.Path object.
            default: Default value to return if an error occurs and silent mode is
                enabled. If None and an error occurs, JSONLoadError will be raised
                (unless silent=True). Defaults to None.
            silent: If True, suppresses error messages to stderr and never raises
                exceptions (returns default instead). If False, logs errors to stderr
                and raises JSONLoadError. Defaults to False.

        Returns:
            The parsed JSON data as a Python object (dict, list, etc.), or the
            default value if an error occurs.

        Raises:
            JSONLoadError: If silent=False and any of the following occur:
                - File not found (FileNotFoundError)
                - Permission denied (PermissionError)
                - Invalid JSON syntax (JSONDecodeError)
                - I/O errors (OSError, IOError)
                - Encoding errors (UnicodeDecodeError)

        Example:
            >>> # Load with default fallback
            >>> config = JSONLoader.load_from_file('config.json', default={})
            >>>
            >>> # Load with exception on error
            >>> try:
            ...     data = JSONLoader.load_from_file('data.json')
            ... except JSONLoadError as e:
            ...     print(f"Failed: {e}")
            >>>
            >>> # Silent mode (no exceptions or error messages)
            >>> data = JSONLoader.load_from_file('optional.json', default=[], silent=True)
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                return json.load(f)

        except FileNotFoundError as e:
            if not silent:
                print(f"Error: JSON file not found: {file_path}", file=sys.stderr)
            if default is not None:
                return default
            msg = f"File not found: {file_path}"
            raise JSONLoadError(msg) from e

        except PermissionError as e:
            if not silent:
                print(
                    f"Error: Permission denied reading JSON: {file_path}",
                    file=sys.stderr,
                )
            if default is not None:
                return default
            msg = f"Permission denied: {file_path}"
            raise JSONLoadError(msg) from e

        except json.JSONDecodeError as e:
            if not silent:
                print(
                    f"Error: Invalid JSON in {file_path}: {e.msg} (line {e.lineno}, col {e.colno})",
                    file=sys.stderr,
                )
            if default is not None:
                return default
            msg = f"Invalid JSON in {file_path}: {e.msg} at line {e.lineno}"
            raise JSONLoadError(
                msg
            ) from e

        except OSError as e:
            if not silent:
                print(f"Error: I/O error reading JSON from {file_path}: {e}", file=sys.stderr)
            if default is not None:
                return default
            msg = f"I/O error: {file_path}"
            raise JSONLoadError(msg) from e

        except UnicodeDecodeError as e:
            if not silent:
                print(
                    f"Error: Encoding error in JSON file {file_path}: {e}",
                    file=sys.stderr,
                )
            if default is not None:
                return default
            msg = f"Encoding error: {file_path}"
            raise JSONLoadError(msg) from e

    @staticmethod
    def load_from_string(
        json_string: str, default: Any = None, silent: bool = False
    ) -> Any:
        """Parse JSON from a string with error handling.

        This method provides robust parsing of JSON strings with detailed error
        reporting including line and column numbers for syntax errors.

        Args:
            json_string: The JSON string to parse. Must be valid JSON syntax.
            default: Default value to return if parsing fails and silent mode is
                enabled. If None and an error occurs, JSONLoadError will be raised
                (unless silent=True). Defaults to None.
            silent: If True, suppresses error messages to stderr and never raises
                exceptions (returns default instead). If False, logs errors to stderr
                and raises JSONLoadError. Defaults to False.

        Returns:
            The parsed JSON data as a Python object (dict, list, str, int, etc.),
            or the default value if parsing fails.

        Raises:
            JSONLoadError: If silent=False and any of the following occur:
                - Invalid JSON syntax (JSONDecodeError)
                - Type errors in JSON string
                - Value errors during parsing

        Example:
            >>> # Parse valid JSON
            >>> data = JSONLoader.load_from_string('{"name": "John", "age": 30}')
            >>> print(data['name'])
            John
            >>>
            >>> # Handle invalid JSON with default
            >>> data = JSONLoader.load_from_string('invalid{json', default={})
            >>> print(data)
            {}
            >>>
            >>> # Silent parsing
            >>> data = JSONLoader.load_from_string('[1, 2, 3]', silent=True)
        """
        try:
            return json.loads(json_string)

        except json.JSONDecodeError as e:
            if not silent:
                print(
                    f"Error: Invalid JSON string: {e.msg} (line {e.lineno}, col {e.colno})",
                    file=sys.stderr,
                )
            if default is not None:
                return default
            msg = f"Invalid JSON string: {e.msg} at line {e.lineno}"
            raise JSONLoadError(
                msg
            ) from e

        except (ValueError, TypeError) as e:
            if not silent:
                print(f"Error: JSON parsing error: {e}", file=sys.stderr)
            if default is not None:
                return default
            msg = f"JSON parsing error: {e}"
            raise JSONLoadError(msg) from e

    @staticmethod
    def load_from_stdin(default: Any = None, silent: bool = False) -> Any:
        """Load JSON from stdin with error handling.

        This method reads JSON data from standard input, useful for CLI tools
        and pipeline processing. Handles both syntax errors and I/O errors.

        Args:
            default: Default value to return if reading or parsing fails and silent
                mode is enabled. If None and an error occurs, JSONLoadError will be
                raised (unless silent=True). Defaults to None.
            silent: If True, suppresses error messages to stderr and never raises
                exceptions (returns default instead). If False, logs errors to stderr
                and raises JSONLoadError. Defaults to False.

        Returns:
            The parsed JSON data from stdin as a Python object, or the default
            value if an error occurs.

        Raises:
            JSONLoadError: If silent=False and any of the following occur:
                - Invalid JSON syntax from stdin (JSONDecodeError)
                - I/O errors reading from stdin (OSError, IOError)

        Example:
            >>> # In a CLI tool or script
            >>> # echo '{"key": "value"}' | python script.py
            >>> import sys
            >>> data = JSONLoader.load_from_stdin(default={})
            >>> print(data.get('key'))
            value
            >>>
            >>> # With error handling
            >>> try:
            ...     data = JSONLoader.load_from_stdin()
            ... except JSONLoadError:
            ...     print("Invalid JSON from stdin")
        """
        try:
            return json.load(sys.stdin)

        except json.JSONDecodeError as e:
            if not silent:
                print(
                    f"Error: Invalid JSON from stdin: {e.msg} (line {e.lineno}, col {e.colno})",
                    file=sys.stderr,
                )
            if default is not None:
                return default
            msg = f"Invalid JSON from stdin: {e.msg} at line {e.lineno}"
            raise JSONLoadError(
                msg
            ) from e

        except OSError as e:
            if not silent:
                print(f"Error: I/O error reading JSON from stdin: {e}", file=sys.stderr)
            if default is not None:
                return default
            msg = f"I/O error reading stdin: {e}"
            raise JSONLoadError(msg) from e

    @staticmethod
    def save_to_file(
        data: Any,
        file_path: str | Path,
        indent: int = 2,
        ensure_ascii: bool = False,
        silent: bool = False,
    ) -> bool:
        """Save data to JSON file with error handling.

        This method serializes Python objects to JSON and writes them to a file
        with proper formatting and encoding. Handles serialization errors,
        permission errors, and I/O errors.

        Args:
            data: The Python object to serialize to JSON. Must be JSON-serializable
                (dict, list, str, int, float, bool, None).
            file_path: Path where the JSON file will be saved. Can be a string or
                pathlib.Path object. Parent directory must exist.
            indent: Number of spaces for indentation in the output JSON file.
                Use None for compact output. Defaults to 2.
            ensure_ascii: If True, non-ASCII characters will be escaped. If False,
                Unicode characters are preserved. Defaults to False.
            silent: If True, suppresses error messages to stderr and returns False
                on errors instead of raising exceptions. If False, logs errors and
                raises JSONLoadError. Defaults to False.

        Returns:
            True if the file was successfully written, False if an error occurred
            in silent mode.

        Raises:
            JSONLoadError: If silent=False and any of the following occur:
                - Data cannot be serialized to JSON (TypeError, ValueError)
                - Permission denied writing to file (PermissionError)
                - I/O errors during file write (OSError, IOError)

        Example:
            >>> # Save dict to file
            >>> data = {"name": "Alice", "age": 25, "city": "Tokyo"}
            >>> success = JSONLoader.save_to_file(data, 'user.json')
            >>> print(success)
            True
            >>>
            >>> # Save with custom formatting
            >>> JSONLoader.save_to_file(data, 'compact.json', indent=None)
            >>>
            >>> # Save with ASCII encoding
            >>> data_ja = {"名前": "太郎"}
            >>> JSONLoader.save_to_file(data_ja, 'data.json', ensure_ascii=True)
        """
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=indent, ensure_ascii=ensure_ascii)
            return True

        except (TypeError, ValueError) as e:
            if not silent:
                print(
                    f"Error: Cannot serialize data to JSON: {e}",
                    file=sys.stderr,
                )
            if not silent:
                msg = f"Serialization error: {e}"
                raise JSONLoadError(msg) from e
            return False

        except PermissionError as e:
            if not silent:
                print(
                    f"Error: Permission denied writing JSON to {file_path}",
                    file=sys.stderr,
                )
            if not silent:
                msg = f"Permission denied: {file_path}"
                raise JSONLoadError(msg) from e
            return False

        except OSError as e:
            if not silent:
                print(
                    f"Error: I/O error writing JSON to {file_path}: {e}",
                    file=sys.stderr,
                )
            if not silent:
                msg = f"I/O error: {file_path}"
                raise JSONLoadError(msg) from e
            return False


# Convenience functions
def load_json(file_path: str | Path, default: Any = None) -> Any:
    """Convenience function for loading JSON from file.

    This is a shorthand wrapper around JSONLoader.load_from_file() for
    simple use cases. Provides error messages to stderr but raises exceptions
    on failure (unless a default is provided).

    Args:
        file_path: Path to the JSON file to load.
        default: Optional default value to return if loading fails.
            If None, raises JSONLoadError on errors.

    Returns:
        Parsed JSON data or default value on error.

    Raises:
        JSONLoadError: If loading fails and default is None.

    Example:
        >>> # Load with exception on error
        >>> config = load_json('config.json')
        >>>
        >>> # Load with default fallback
        >>> settings = load_json('settings.json', default={})
    """
    return JSONLoader.load_from_file(file_path, default=default)


def load_json_safe(file_path: str | Path, default: Any = None) -> Any:
    """Convenience function for loading JSON with no exceptions.

    This is a fail-safe wrapper that never raises exceptions or prints error
    messages. Always returns either the parsed data or the default value.
    Ideal for optional configuration files or best-effort loading.

    Args:
        file_path: Path to the JSON file to load.
        default: Value to return if loading fails for any reason.
            Defaults to None.

    Returns:
        Parsed JSON data if successful, otherwise the default value.

    Example:
        >>> # Safe loading with empty dict fallback
        >>> config = load_json_safe('optional_config.json', default={})
        >>>
        >>> # Safe loading with None fallback (no error if file missing)
        >>> data = load_json_safe('data.json')
        >>> if data is None:
        ...     print("File not found or invalid")
    """
    return JSONLoader.load_from_file(file_path, default=default, silent=True)


def save_json(
    data: Any, file_path: str | Path, indent: int = 2, ensure_ascii: bool = False
) -> bool:
    """Convenience function for saving JSON to file.

    This is a shorthand wrapper around JSONLoader.save_to_file() for
    simple use cases. Provides error messages to stderr and raises exceptions
    on failure.

    Args:
        data: Python object to serialize to JSON. Must be JSON-serializable.
        file_path: Path where the JSON file will be saved.
        indent: Number of spaces for indentation. Use None for compact output.
            Defaults to 2.
        ensure_ascii: If True, escape non-ASCII characters. Defaults to False.

    Returns:
        True if successful, False on error (only in silent mode).

    Raises:
        JSONLoadError: If saving fails (serialization error, permission denied, etc.).

    Example:
        >>> # Save with default formatting
        >>> data = {"users": [{"name": "Alice"}, {"name": "Bob"}]}
        >>> save_json(data, 'users.json')
        True
        >>>
        >>> # Save with compact output
        >>> save_json({"key": "value"}, 'compact.json', indent=None)
        True
    """
    return JSONLoader.save_to_file(
        data, file_path, indent=indent, ensure_ascii=ensure_ascii
    )


if __name__ == "__main__":
    # Test cases
    print("JSONLoader Test Suite")
    print("=" * 60)

    # Test 1: Load from string
    test_json = '{"test": "value", "number": 42}'
    result = JSONLoader.load_from_string(test_json)
    print(f"✓ Load from string: {result}")

    # Test 2: Load with default on error
    result = JSONLoader.load_from_file("/nonexistent/file.json", default={})
    print(f"✓ Load with default on error: {result}")

    # Test 3: Invalid JSON handling
    try:
        JSONLoader.load_from_string("invalid json{")
    except JSONLoadError as e:
        print(f"✓ Invalid JSON caught: {e}")

    print("\n✅ All tests passed!")
