"""
Unit tests for shared.utils.json_loader module

Tests the JSONLoader class and related convenience functions.
"""

import json
from pathlib import Path

import pytest

from shared.utils import JSONLoader, JSONLoadError, load_json, save_json


class TestJSONLoader:
    """Test cases for JSONLoader class"""

    def test_load_from_file_success(self, tmp_path, sample_json_data):
        """Test successful JSON file loading"""
        # Arrange
        test_file = tmp_path / "test.json"
        with open(test_file, "w") as f:
            json.dump(sample_json_data, f)

        # Act
        result = JSONLoader.load_from_file(test_file)

        # Assert
        assert result == sample_json_data
        assert result["version"] == "1.0"
        assert "personas" in result

    def test_load_from_file_not_found(self, tmp_path):
        """Test loading from non-existent file with default"""
        # Arrange
        non_existent = tmp_path / "missing.json"

        # Act
        result = JSONLoader.load_from_file(non_existent, default={})

        # Assert
        assert result == {}

    def test_load_from_file_not_found_no_default(self, tmp_path):
        """Test loading from non-existent file without default raises error"""
        # Arrange
        non_existent = tmp_path / "missing.json"

        # Act & Assert
        with pytest.raises(JSONLoadError) as exc_info:
            JSONLoader.load_from_file(non_existent)

        assert "File not found" in str(exc_info.value)

    def test_load_from_file_invalid_json(self, tmp_path):
        """Test loading invalid JSON file"""
        # Arrange
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")

        # Act & Assert
        with pytest.raises(JSONLoadError) as exc_info:
            JSONLoader.load_from_file(invalid_file)

        assert "Invalid JSON" in str(exc_info.value)

    def test_load_from_file_invalid_json_with_default(self, tmp_path):
        """Test loading invalid JSON with default"""
        # Arrange
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")

        # Act
        result = JSONLoader.load_from_file(invalid_file, default={"fallback": True})

        # Assert
        assert result == {"fallback": True}

    def test_load_from_file_silent_mode(self, tmp_path, capsys):
        """Test silent mode suppresses error messages"""
        # Arrange
        non_existent = tmp_path / "missing.json"

        # Act
        result = JSONLoader.load_from_file(non_existent, default={}, silent=True)
        captured = capsys.readouterr()

        # Assert
        assert result == {}
        assert "Error" not in captured.err

    def test_load_from_string_success(self, sample_json_data):
        """Test loading JSON from string"""
        # Arrange
        json_string = json.dumps(sample_json_data)

        # Act
        result = JSONLoader.load_from_string(json_string)

        # Assert
        assert result == sample_json_data

    def test_load_from_string_invalid(self):
        """Test loading invalid JSON string"""
        # Arrange
        invalid_string = "{ invalid json }"

        # Act & Assert
        with pytest.raises(JSONLoadError):
            JSONLoader.load_from_string(invalid_string)

    def test_load_from_string_with_default(self):
        """Test loading invalid JSON string with default"""
        # Arrange
        invalid_string = "{ invalid json }"

        # Act
        result = JSONLoader.load_from_string(invalid_string, default={"error": False})

        # Assert
        assert result == {"error": False}

    def test_save_to_file_success(self, tmp_path, sample_json_data):
        """Test saving JSON to file"""
        # Arrange
        output_file = tmp_path / "output.json"

        # Act
        success = JSONLoader.save_to_file(sample_json_data, output_file, indent=2)

        # Assert
        assert success is True
        assert output_file.exists()

        # Verify content
        with open(output_file) as f:
            loaded = json.load(f)
        assert loaded == sample_json_data

    def test_save_to_file_permission_error(self, tmp_path, sample_json_data):
        """Test saving to read-only directory"""
        # Arrange
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)
        output_file = readonly_dir / "output.json"

        # Act - silent=True to get False return instead of exception
        success = JSONLoader.save_to_file(sample_json_data, output_file, silent=True)

        # Assert
        assert success is False

        # Cleanup
        readonly_dir.chmod(0o755)

    def test_save_to_file_pretty_print(self, tmp_path, sample_json_data):
        """Test pretty-printing JSON output"""
        # Arrange
        output_file = tmp_path / "pretty.json"

        # Act
        JSONLoader.save_to_file(sample_json_data, output_file, indent=4)

        # Assert
        content = output_file.read_text()
        assert "    " in content  # 4-space indentation
        assert "\\n" not in content  # No escaped newlines (pretty printed)


class TestConvenienceFunctions:
    """Test convenience functions for JSON operations"""

    def test_load_json_success(self, tmp_path, sample_json_data):
        """Test load_json convenience function"""
        # Arrange
        test_file = tmp_path / "test.json"
        with open(test_file, "w") as f:
            json.dump(sample_json_data, f)

        # Act
        result = load_json(test_file)

        # Assert
        assert result == sample_json_data

    def test_load_json_with_default(self, tmp_path):
        """Test load_json with default value"""
        # Arrange
        non_existent = tmp_path / "missing.json"

        # Act
        result = load_json(non_existent, default={"loaded": False})

        # Assert
        assert result == {"loaded": False}

    def test_save_json_success(self, tmp_path, sample_json_data):
        """Test save_json convenience function"""
        # Arrange
        output_file = tmp_path / "output.json"

        # Act
        success = save_json(sample_json_data, output_file)

        # Assert
        assert success is True
        assert output_file.exists()


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_load_empty_json_file(self, tmp_path):
        """Test loading empty JSON file"""
        # Arrange
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("{}")

        # Act
        result = JSONLoader.load_from_file(empty_file)

        # Assert
        assert result == {}

    def test_load_json_with_unicode(self, tmp_path):
        """Test loading JSON with Unicode characters"""
        # Arrange
        unicode_data = {"message": "こんにちは世界", "emoji": "🚀"}
        test_file = tmp_path / "unicode.json"
        with open(test_file, "w", encoding="utf-8") as f:
            json.dump(unicode_data, f, ensure_ascii=False)

        # Act
        result = JSONLoader.load_from_file(test_file)

        # Assert
        assert result == unicode_data
        assert result["message"] == "こんにちは世界"
        assert result["emoji"] == "🚀"

    def test_load_json_with_special_characters(self, tmp_path):
        """Test loading JSON with special characters"""
        # Arrange
        special_data = {
            "path": "/path/to/file",
            "regex": r"\\d+",
            "quotes": 'He said "Hello"'
        }
        test_file = tmp_path / "special.json"
        with open(test_file, "w") as f:
            json.dump(special_data, f)

        # Act
        result = JSONLoader.load_from_file(test_file)

        # Assert
        assert result == special_data

    def test_load_large_json_file(self, tmp_path):
        """Test loading large JSON file"""
        # Arrange
        large_data = {"items": [{"id": i, "value": f"item_{i}"} for i in range(10000)]}
        test_file = tmp_path / "large.json"
        with open(test_file, "w") as f:
            json.dump(large_data, f)

        # Act
        result = JSONLoader.load_from_file(test_file)

        # Assert
        assert len(result["items"]) == 10000
        assert result["items"][0]["id"] == 0
        assert result["items"][9999]["id"] == 9999


@pytest.mark.parametrize("invalid_input,expected_error", [
    ("", "Invalid JSON"),
    ("[1, 2, 3", "Invalid JSON"),
    ("{'single': 'quotes'}", "Invalid JSON"),
])
def test_invalid_json_strings(invalid_input, expected_error):
    """Test various invalid JSON string inputs

    Note: 'null' is valid JSON (primitive value) and is correctly parsed by json.loads(),
    so it has been removed from invalid test cases.
    """
    with pytest.raises(JSONLoadError) as exc_info:
        JSONLoader.load_from_string(invalid_input)
    assert expected_error in str(exc_info.value)
