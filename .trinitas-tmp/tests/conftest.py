"""
Pytest configuration and shared fixtures for Trinitas test suite

This file provides common fixtures and configuration for all tests.
"""

import sys
from pathlib import Path

import pytest

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def project_root():
    """Provide project root directory path"""
    return PROJECT_ROOT


@pytest.fixture
def temp_config_dir(tmp_path):
    """Create a temporary configuration directory for testing"""
    config_dir = tmp_path / ".opencode" / "config"
    config_dir.mkdir(parents=True)
    return config_dir


@pytest.fixture
def temp_memory_dir(tmp_path):
    """Create a temporary memory directory for testing"""
    memory_dir = tmp_path / ".claude" / "memory"
    memory_dir.mkdir(parents=True)

    # Create subdirectories
    (memory_dir / "core").mkdir()
    (memory_dir / "agents").mkdir()
    (memory_dir / "contexts").mkdir()
    (memory_dir / "sessions").mkdir()

    return memory_dir


@pytest.fixture
def sample_json_data():
    """Provide sample JSON data for testing"""
    return {
        "version": "1.0",
        "name": "test_config",
        "settings": {
            "enabled": True,
            "level": "debug"
        },
        "personas": [
            "athena-conductor",
            "artemis-optimizer"
        ]
    }


@pytest.fixture
def sample_markdown_content():
    """Provide sample markdown content for testing"""
    return """# Test Document

This is a test document for file loading tests.

## Section 1
Content here.

## Section 2
More content here.
"""
