#!/usr/bin/env python3
"""Demo script for PersonaMarkdownParser.

This script demonstrates how to use the PersonaMarkdownParser utility
to parse Trinitas persona Markdown files.
"""

from pathlib import Path
from src.utils.persona_markdown_parser import PersonaMarkdownParser


def main():
    """Run persona parser demo."""
    parser = PersonaMarkdownParser()

    # Parse all persona files in dist-config/claudecode/agents/
    agents_dir = Path("dist-config/claudecode/agents")

    if not agents_dir.exists():
        print(f"Error: {agents_dir} not found")
        return

    print("=" * 80)
    print("PersonaMarkdownParser Demo")
    print("=" * 80)
    print()

    # Find all .md files
    persona_files = sorted(agents_dir.glob("*.md"))

    for persona_file in persona_files:
        try:
            persona = parser.parse_file(persona_file)

            print(f"📄 File: {persona_file.name}")
            print(f"   Agent ID: {persona.agent_id}")
            print(f"   Name: {persona.emoji} {persona.name}")
            print(f"   Role: {persona.role}")
            print(f"   Tier: {persona.tier}")
            print(f"   Version: {persona.version}")
            if persona.partner:
                print(f"   Partner: {persona.partner}")

            # Show first line of identity
            if persona.identity:
                first_line = persona.identity.split("\n")[0]
                print(f"   Identity: {first_line[:60]}...")

            print()

        except Exception as e:
            print(f"❌ Error parsing {persona_file.name}: {e}")
            print()

    print("=" * 80)
    print(f"Successfully parsed {len(persona_files)} persona files")
    print("=" * 80)


if __name__ == "__main__":
    main()
