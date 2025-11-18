#!/usr/bin/env python3
"""
Comprehensive Tests for JSONLoader
==================================

Coverage target: 49% → 95%

Tests all error handling paths:
- FileNotFoundError
- PermissionError
- JSONDecodeError
- OSError
- UnicodeDecodeError
- stdin operations
- save_to_file operations
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from shared.utils.json_loader import JSONLoader, JSONLoadError


class TestLoadFromFile:
    """Test load_from_file with all error scenarios"""

    def test_load_valid_json(self, tmp_path):
        """Test loading valid JSON file"""
        json_file = tmp_path / "test.json"
        data = {"key": "value", "number": 42}
        json_file.write_text(json.dumps(data))

        result = JSONLoader.load_from_file(json_file)
        assert result == data

    def test_load_file_not_found_with_default(self, tmp_path):
        """Test FileNotFoundError returns default"""
        result = JSONLoader.load_from_file(tmp_path / "nonexistent.json", default={})
        assert result == {}

    def test_load_file_not_found_raises(self, tmp_path):
        """Test FileNotFoundError raises JSONLoadError"""
        with pytest.raises(JSONLoadError, match="File not found"):
            JSONLoader.load_from_file(tmp_path / "nonexistent.json")

    def test_load_file_not_found_silent(self, tmp_path):
        """Test FileNotFoundError silent mode"""
        result = JSONLoader.load_from_file(tmp_path / "nonexistent.json", silent=True)
        assert result is None

    def test_load_permission_denied(self, tmp_path):
        """Test PermissionError handling"""
        json_file = tmp_path / "noperm.json"
        json_file.write_text('{"test": "data"}')
        json_file.chmod(0o000)  # Remove all permissions

        try:
            # Should raise PermissionError -> JSONLoadError
            with pytest.raises((JSONLoadError, PermissionError)):
                JSONLoader.load_from_file(json_file)
        finally:
            json_file.chmod(0o644)  # Restore permissions for cleanup

    def test_load_invalid_json(self, tmp_path):
        """Test JSONDecodeError handling"""
        json_file = tmp_path / "invalid.json"
        json_file.write_text('{"broken": json [[[')

        # With default
        result = JSONLoader.load_from_file(json_file, default={})
        assert result == {}

        # Without default
        with pytest.raises(JSONLoadError, match="Invalid JSON"):
            JSONLoader.load_from_file(json_file)

    def test_load_unicode_error(self, tmp_path):
        """Test UnicodeDecodeError handling"""
        json_file = tmp_path / "badenc.json"
        # Write invalid UTF-8 bytes
        json_file.write_bytes(b'\xff\xfe{"key": "value"}')

        result = JSONLoader.load_from_file(json_file, default={})
        assert result == {}

    def test_load_ioerror(self):
        """Test OSError/IOError handling"""
        with patch('builtins.open', side_effect=OSError("Disk error")):
            result = JSONLoader.load_from_file("test.json", default=[])
            assert result == []


class TestLoadFromString:
    """Test load_from_string parsing"""

    def test_parse_valid_json(self):
        """Test parsing valid JSON string"""
        result = JSONLoader.load_from_string('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_invalid_json_with_default(self):
        """Test invalid JSON returns default"""
        result = JSONLoader.load_from_string('invalid{json', default={})
        assert result == {}

    def test_parse_invalid_json_raises(self):
        """Test invalid JSON raises JSONLoadError"""
        with pytest.raises(JSONLoadError, match="Invalid JSON"):
            JSONLoader.load_from_string('broken json')

    def test_parse_json_silent(self):
        """Test silent mode for parsing"""
        result = JSONLoader.load_from_string('[broken', silent=True)
        assert result is None

    def test_parse_various_types(self):
        """Test parsing different JSON types"""
        assert JSONLoader.load_from_string('[]') == []
        assert JSONLoader.load_from_string('null') is None
        assert JSONLoader.load_from_string('123') == 123
        assert JSONLoader.load_from_string('"text"') == "text"


class TestLoadFromStdin:
    """Test load_from_stdin input handling"""

    def test_load_from_stdin_valid(self):
        """Test reading valid JSON from stdin"""
        with patch('sys.stdin.read', return_value='{"test": "data"}'):
            result = JSONLoader.load_from_stdin()
            assert result == {"test": "data"}

    def test_load_from_stdin_invalid(self):
        """Test invalid JSON from stdin"""
        with patch('sys.stdin.read', return_value='broken{json'):
            result = JSONLoader.load_from_stdin(default={})
            assert result == {}

    def test_load_from_stdin_ioerror(self):
        """Test I/O error reading stdin"""
        with patch('sys.stdin.read', side_effect=IOError("Pipe error")):
            result = JSONLoader.load_from_stdin(default=[])
            assert result == []


class TestSaveToFile:
    """Test save_to_file operations"""

    def test_save_valid_json(self, tmp_path):
        """Test saving JSON to file"""
        output_file = tmp_path / "output.json"
        data = {"key": "value", "number": 42}

        JSONLoader.save_to_file(data, output_file)

        # Verify file contents
        with open(output_file) as f:
            loaded = json.load(f)
            assert loaded == data

    def test_save_with_indent(self, tmp_path):
        """Test saving with pretty-printing"""
        output_file = tmp_path / "pretty.json"
        data = {"key": "value"}

        JSONLoader.save_to_file(data, output_file, indent=2)

        content = output_file.read_text()
        assert "  " in content  # Has indentation

    def test_save_permission_error(self, tmp_path):
        """Test PermissionError during save"""
        output_file = tmp_path / "readonly"
        output_file.parent.chmod(0o444)  # Read-only directory

        try:
            with pytest.raises((JSONLoadError, PermissionError)):
                JSONLoader.save_to_file({"test": "data"}, output_file)
        finally:
            output_file.parent.chmod(0o755)

    def test_save_type_error(self, tmp_path):
        """Test TypeError for non-serializable objects"""
        output_file = tmp_path / "bad.json"

        # Object with circular reference
        class CircularRef:
            def __init__(self):
                self.ref = self

        with pytest.raises((JSONLoadError, TypeError)):
            JSONLoader.save_to_file(CircularRef(), output_file)


class TestErrorMessages:
    """Test error message formatting"""

    def test_file_not_found_message(self, tmp_path, capsys):
        """Test FileNotFoundError message"""
        file_path = tmp_path / "missing.json"
        JSONLoader.load_from_file(file_path, default={}, silent=False)

        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()
        assert str(file_path) in captured.err

    def test_json_decode_error_message(self, tmp_path, capsys):
        """Test JSONDecodeError message with line/col"""
        json_file = tmp_path / "bad.json"
        json_file.write_text('{"key": broken}')

        JSONLoader.load_from_file(json_file, default={}, silent=False)

        captured = capsys.readouterr()
        assert "line" in captured.err.lower()
        assert "Invalid JSON" in captured.err

    def test_silent_no_output(self, tmp_path, capsys):
        """Test silent mode produces no output"""
        JSONLoader.load_from_file(tmp_path / "missing.json", silent=True)

        captured = capsys.readouterr()
        assert captured.err == ""
