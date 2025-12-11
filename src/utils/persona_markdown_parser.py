"""PersonaMarkdownParser - Parse Trinitas persona Markdown files.

This module provides utilities to parse persona definition files in Markdown format,
extracting structured metadata and content sections.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ParsedPersona:
    """Structured representation of a parsed persona Markdown file."""

    agent_id: str
    name: str  # Extracted from title (e.g., "Clotho")
    display_name: str  # Full title line
    emoji: str  # Extracted emoji (🧵)
    role: str  # From frontmatter
    tier: str  # From frontmatter (ORCHESTRATOR, STRATEGIC, etc.)
    version: str  # From frontmatter
    partner: str | None = None  # Optional partner persona
    identity: str = ""  # Identity section content
    markdown_source: str = ""  # Full markdown content
    frontmatter: dict = field(default_factory=dict)  # All frontmatter data


class PersonaMarkdownParser:
    """Parser for Trinitas persona Markdown files.

    This parser handles two types of persona file formats:
    1. YAML-like frontmatter between --- markers
    2. Different title formats with emojis and multilingual names

    Example usage:
        parser = PersonaMarkdownParser()
        persona = parser.parse_file(Path("agents/clotho-orchestrator.md"))
        print(persona.name)  # "Clotho"
        print(persona.emoji)  # "🧵"
    """

    # Regex patterns
    FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL | re.MULTILINE)
    # Extended emoji pattern to capture emoji + variation selectors + ZWJ sequences
    EMOJI_PATTERN = re.compile(
        r"[\U0001F300-\U0001F9FF][\uFE00-\uFE0F]?|"  # Basic emoji + variation selector
        r"[\u2600-\u27BF][\uFE00-\uFE0F]?|"  # Misc symbols
        r"[\u2300-\u23FF][\uFE00-\uFE0F]?|"  # Misc technical
        r"[\u2B50][\uFE00-\uFE0F]?"  # Star emoji
    )
    IDENTITY_SECTION_PATTERN = re.compile(
        r"##\s*(?:Identity|Core Identity)\s*\n(.*?)(?=\n##|\Z)", re.DOTALL | re.IGNORECASE
    )

    def parse_file(self, file_path: Path) -> ParsedPersona:
        """Parse a persona Markdown file from disk.

        Args:
            file_path: Path to the Markdown file

        Returns:
            ParsedPersona object with extracted metadata

        Raises:
            FileNotFoundError: If file does not exist
            ValueError: If required frontmatter fields are missing
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Persona file not found: {file_path}")

        content = file_path.read_text(encoding="utf-8")
        return self.parse_content(content)

    def parse_content(self, content: str) -> ParsedPersona:
        """Parse persona Markdown content string.

        Args:
            content: Markdown content as string

        Returns:
            ParsedPersona object with extracted metadata

        Raises:
            ValueError: If required frontmatter fields are missing
        """
        # Extract frontmatter
        frontmatter = self.extract_frontmatter(content)

        # Extract title (first H1 line)
        title_line = self._extract_title_line(content)

        # Extract components from title
        emoji = self.extract_emoji(title_line)
        name = self.extract_name(title_line)
        display_name = title_line

        # Extract identity section
        identity = self._extract_identity_section(content)

        # Build ParsedPersona
        return ParsedPersona(
            agent_id=frontmatter.get("agent_id", frontmatter.get("name", "")),
            name=name,
            display_name=display_name,
            emoji=emoji,
            role=frontmatter.get("role", ""),
            tier=frontmatter.get("tier", ""),
            version=frontmatter.get("version", ""),
            partner=frontmatter.get("partner"),
            identity=identity,
            markdown_source=content,
            frontmatter=frontmatter,
        )

    def extract_frontmatter(self, content: str) -> dict:
        """Extract YAML-like frontmatter between --- markers.

        Args:
            content: Markdown content

        Returns:
            Dictionary of frontmatter key-value pairs

        Examples:
            >>> parser = PersonaMarkdownParser()
            >>> content = '''---
            ... agent_id: "clotho-orchestrator"
            ... role: "Main Orchestrator"
            ... tier: "ORCHESTRATOR"
            ... ---
            ... # Title'''
            >>> fm = parser.extract_frontmatter(content)
            >>> fm['agent_id']
            'clotho-orchestrator'
        """
        match = self.FRONTMATTER_PATTERN.search(content)
        if not match:
            return {}

        frontmatter_text = match.group(1)
        frontmatter = {}

        # Parse YAML-like key: value pairs
        for line in frontmatter_text.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")  # Remove quotes
                frontmatter[key] = value

        return frontmatter

    def extract_emoji(self, title: str) -> str:
        """Extract emoji from title line.

        Args:
            title: Title line string

        Returns:
            First emoji found, or empty string if none

        Examples:
            >>> parser = PersonaMarkdownParser()
            >>> parser.extract_emoji("Clotho（クロト）🧵 - Main Orchestrator")
            '🧵'
            >>> parser.extract_emoji("🏛️ Harmonious Conductor")
            '🏛️'
        """
        match = self.EMOJI_PATTERN.search(title)
        return match.group(0) if match else ""

    def extract_name(self, title: str) -> str:
        """Extract persona name from title.

        Handles various title formats:
        - "Clotho（クロト）🧵 - Main Orchestrator" -> "Clotho"
        - "🏛️ Harmonious Conductor" -> "Harmonious Conductor"
        - "# Clotho - Main" -> "Clotho"

        Args:
            title: Title line string

        Returns:
            Extracted persona name

        Examples:
            >>> parser = PersonaMarkdownParser()
            >>> parser.extract_name("# Clotho（クロト）🧵 - Main Orchestrator")
            'Clotho'
            >>> parser.extract_name("🏛️ Harmonious Conductor")
            'Harmonious Conductor'
        """
        # Remove leading # and whitespace
        title = title.lstrip("#").strip()

        # Remove emoji
        title = self.EMOJI_PATTERN.sub("", title).strip()

        # Remove parenthetical (e.g., "（クロト）")
        title = re.sub(r"[（(][^)）]*[)）]", "", title).strip()

        # Split by " - " and take first part (name before role)
        if " - " in title:
            title = title.split(" - ")[0].strip()

        return title

    def _extract_title_line(self, content: str) -> str:
        """Extract the first H1 title line from content.

        Args:
            content: Markdown content

        Returns:
            First H1 line without the # prefix

        Raises:
            ValueError: If no H1 title found
        """
        for line in content.split("\n"):
            if line.strip().startswith("# "):
                return line.strip()

        raise ValueError("No H1 title found in persona Markdown")

    def _extract_identity_section(self, content: str) -> str:
        """Extract content from Identity or Core Identity section.

        Args:
            content: Markdown content

        Returns:
            Identity section content, or empty string if not found
        """
        match = self.IDENTITY_SECTION_PATTERN.search(content)
        return match.group(1).strip() if match else ""
