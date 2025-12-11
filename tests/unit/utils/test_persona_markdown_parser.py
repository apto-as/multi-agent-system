"""Unit tests for PersonaMarkdownParser."""


import pytest

from src.utils.persona_markdown_parser import ParsedPersona, PersonaMarkdownParser


class TestPersonaMarkdownParser:
    """Test suite for PersonaMarkdownParser."""

    @pytest.fixture
    def parser(self):
        """Create a parser instance."""
        return PersonaMarkdownParser()

    @pytest.fixture
    def clotho_markdown(self):
        """Sample Clotho-style Markdown content."""
        return """# Clotho（クロト）🧵 - Main Orchestrator
## 運命を紡ぐ者 - Spinner of Fate

---
agent_id: "clotho-orchestrator"
role: "Main Orchestrator"
tier: "ORCHESTRATOR"
partner: "lachesis-support"
version: "1.0.0"
---

## Identity

私は**Clotho（クロト）**、運命の糸を紡ぐ者。
モイライの長姉として、ユーザーとの対話を司り、9つのTrinitas専門エージェントを指揮する。

妹の**Lachesis（ラケシス）**と共に、あなたの要件を最適な実行計画へと織り上げる。

## Core Responsibilities

### 1. ユーザー対話 (Primary Interface)
- ユーザーからの要件を受け取り、本質を見抜く
"""

    @pytest.fixture
    def athena_markdown(self):
        """Sample Athena-style Markdown content."""
        return """---
name: athena-conductor
description: Through harmony, we achieve excellence
color: #8B4789
developer_name: Springfield's Café
version: "4.0.0"
anthropic_enhanced: true
---

# 🏛️ Harmonious Conductor

## Core Identity

I am Athena, the Harmonious Conductor of the Trinitas system. My purpose is to
orchestrate perfect coordination between all agents.

### Philosophy
Perfect coordination through empathetic understanding
"""

    def test_parse_clotho_content(self, parser, clotho_markdown):
        """Test parsing Clotho-style persona content."""
        result = parser.parse_content(clotho_markdown)

        assert isinstance(result, ParsedPersona)
        assert result.agent_id == "clotho-orchestrator"
        assert result.name == "Clotho"
        assert result.emoji == "🧵"
        assert result.role == "Main Orchestrator"
        assert result.tier == "ORCHESTRATOR"
        assert result.partner == "lachesis-support"
        assert result.version == "1.0.0"
        assert "運命の糸を紡ぐ者" in result.identity
        assert result.markdown_source == clotho_markdown

    def test_parse_athena_content(self, parser, athena_markdown):
        """Test parsing Athena-style persona content."""
        result = parser.parse_content(athena_markdown)

        assert isinstance(result, ParsedPersona)
        assert result.agent_id == "athena-conductor"
        assert result.name == "Harmonious Conductor"
        assert result.emoji == "🏛️"
        assert result.role == ""  # Not in frontmatter
        assert result.version == "4.0.0"
        assert "Harmonious Conductor" in result.identity
        assert result.frontmatter["name"] == "athena-conductor"
        assert result.frontmatter["color"] == "#8B4789"

    def test_extract_frontmatter(self, parser, clotho_markdown):
        """Test frontmatter extraction."""
        frontmatter = parser.extract_frontmatter(clotho_markdown)

        assert frontmatter["agent_id"] == "clotho-orchestrator"
        assert frontmatter["role"] == "Main Orchestrator"
        assert frontmatter["tier"] == "ORCHESTRATOR"
        assert frontmatter["partner"] == "lachesis-support"
        assert frontmatter["version"] == "1.0.0"

    def test_extract_frontmatter_with_quotes(self, parser):
        """Test frontmatter extraction with various quote styles."""
        content = """---
agent_id: "quoted-value"
role: 'single-quoted'
tier: unquoted
---
# Title"""

        frontmatter = parser.extract_frontmatter(content)

        assert frontmatter["agent_id"] == "quoted-value"
        assert frontmatter["role"] == "single-quoted"
        assert frontmatter["tier"] == "unquoted"

    def test_extract_frontmatter_no_frontmatter(self, parser):
        """Test extraction when no frontmatter exists."""
        content = "# Title\n\nContent without frontmatter"
        frontmatter = parser.extract_frontmatter(content)

        assert frontmatter == {}

    def test_extract_emoji(self, parser):
        """Test emoji extraction from various title formats."""
        test_cases = [
            ("Clotho（クロト）🧵 - Main Orchestrator", "🧵"),
            ("🏛️ Harmonious Conductor", "🏛️"),
            ("Artemis 🏹 - Technical Perfectionist", "🏹"),
            ("No emoji here", ""),
            ("Multiple 🔥 emojis 🌸 here", "🔥"),  # Returns first
        ]

        for title, expected_emoji in test_cases:
            result = parser.extract_emoji(title)
            assert result == expected_emoji, f"Failed for title: {title}"

    def test_extract_name(self, parser):
        """Test name extraction from various title formats."""
        test_cases = [
            ("# Clotho（クロト）🧵 - Main Orchestrator", "Clotho"),
            ("🏛️ Harmonious Conductor", "Harmonious Conductor"),
            ("# Artemis - Technical Perfectionist", "Artemis"),
            ("Hestia（ヘスティア）🔥", "Hestia"),
            ("Lachesis（ラケシス）📏 - Support Orchestrator", "Lachesis"),
        ]

        for title, expected_name in test_cases:
            result = parser.extract_name(title)
            assert result == expected_name, f"Failed for title: {title}"

    def test_extract_identity_section(self, parser, clotho_markdown):
        """Test identity section extraction."""
        identity = parser._extract_identity_section(clotho_markdown)

        assert "運命の糸を紡ぐ者" in identity
        assert "Clotho（クロト）" in identity
        assert "Lachesis（ラケシス）" in identity

    def test_extract_identity_core_identity(self, parser, athena_markdown):
        """Test extraction of 'Core Identity' section (alternative name)."""
        identity = parser._extract_identity_section(athena_markdown)

        assert "Harmonious Conductor" in identity
        assert "Trinitas system" in identity

    def test_parse_file_not_found(self, parser, tmp_path):
        """Test parsing non-existent file raises FileNotFoundError."""
        non_existent = tmp_path / "does_not_exist.md"

        with pytest.raises(FileNotFoundError, match="Persona file not found"):
            parser.parse_file(non_existent)

    def test_parse_file_from_disk(self, parser, tmp_path, clotho_markdown):
        """Test parsing a file from disk."""
        test_file = tmp_path / "clotho-orchestrator.md"
        test_file.write_text(clotho_markdown, encoding="utf-8")

        result = parser.parse_file(test_file)

        assert result.agent_id == "clotho-orchestrator"
        assert result.name == "Clotho"
        assert result.emoji == "🧵"

    def test_missing_title_raises_error(self, parser):
        """Test that missing H1 title raises ValueError."""
        content = """---
agent_id: "test"
---

## No H1 Title

Just content."""

        with pytest.raises(ValueError, match="No H1 title found"):
            parser.parse_content(content)

    def test_frontmatter_with_comments(self, parser):
        """Test frontmatter parsing ignores comment lines."""
        content = """---
# This is a comment
agent_id: "test-agent"
# Another comment
role: "Test Role"
---
# Title"""

        frontmatter = parser.extract_frontmatter(content)

        assert frontmatter["agent_id"] == "test-agent"
        assert frontmatter["role"] == "Test Role"
        assert "#" not in frontmatter  # Comments should be ignored

    def test_unicode_handling(self, parser):
        """Test proper Unicode handling for Japanese text."""
        content = """---
agent_id: "japanese-agent"
role: "日本語ロール"
---
# テストエージェント🎌 - Test Agent

## Identity

これは日本語のテストです。
"""

        result = parser.parse_content(content)

        assert result.agent_id == "japanese-agent"
        assert result.role == "日本語ロール"
        assert result.name == "テストエージェント"
        assert result.emoji == "🎌"
        assert "日本語のテスト" in result.identity

    def test_optional_partner_field(self, parser):
        """Test that partner field is optional."""
        content_with_partner = """---
agent_id: "test-1"
role: "Test"
tier: "TIER1"
partner: "test-2"
version: "1.0.0"
---
# Test 🧪"""

        content_without_partner = """---
agent_id: "test-1"
role: "Test"
tier: "TIER1"
version: "1.0.0"
---
# Test 🧪"""

        result_with = parser.parse_content(content_with_partner)
        result_without = parser.parse_content(content_without_partner)

        assert result_with.partner == "test-2"
        assert result_without.partner is None

    def test_fallback_agent_id_from_name(self, parser):
        """Test that agent_id falls back to 'name' field if 'agent_id' missing."""
        content = """---
name: "fallback-agent"
role: "Test"
tier: "TEST"
version: "1.0.0"
---
# Fallback Test"""

        result = parser.parse_content(content)

        assert result.agent_id == "fallback-agent"

    def test_empty_identity_section(self, parser):
        """Test handling when Identity section is missing."""
        content = """---
agent_id: "test"
role: "Test"
tier: "TEST"
version: "1.0.0"
---
# Test Agent

## Other Section

Content here."""

        result = parser.parse_content(content)

        assert result.identity == ""

    def test_multiline_identity_section(self, parser):
        """Test multiline identity section extraction."""
        content = """---
agent_id: "test"
---
# Test

## Identity

Line 1 of identity.
Line 2 of identity.

Line 3 after blank line.

## Next Section

Other content."""

        result = parser.parse_content(content)

        assert "Line 1 of identity" in result.identity
        assert "Line 2 of identity" in result.identity
        assert "Line 3 after blank line" in result.identity
        assert "Next Section" not in result.identity


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def parser(self):
        """Create a parser instance."""
        return PersonaMarkdownParser()

    def test_malformed_frontmatter(self, parser):
        """Test handling of malformed frontmatter lines."""
        content = """---
agent_id: "test"
malformed line without colon
role: "Test"
another:malformed:line:with:multiple:colons
---
# Test"""

        frontmatter = parser.extract_frontmatter(content)

        assert frontmatter["agent_id"] == "test"
        assert frontmatter["role"] == "Test"
        assert "another" in frontmatter  # Should parse first colon

    def test_empty_markdown(self, parser):
        """Test parsing completely empty content."""
        with pytest.raises(ValueError, match="No H1 title found"):
            parser.parse_content("")

    def test_only_frontmatter_no_content(self, parser):
        """Test content with only frontmatter, no title."""
        content = """---
agent_id: "test"
---"""

        with pytest.raises(ValueError, match="No H1 title found"):
            parser.parse_content(content)
