# PersonaMarkdownParser Utility

## Overview

The `PersonaMarkdownParser` utility provides robust parsing of Trinitas persona Markdown files, extracting structured metadata and content from persona definition files in `dist-config/claudecode/agents/`.

**Location**: `src/utils/persona_markdown_parser.py`

## Features

- **YAML-like Frontmatter Parsing**: Extracts metadata from `---` delimited frontmatter
- **Emoji Extraction**: Handles composite emojis (e.g., 🏛️) with variation selectors
- **Multilingual Support**: Correctly processes Japanese and English text
- **Flexible Title Parsing**: Handles various title formats
- **Identity Section Extraction**: Captures "Identity" or "Core Identity" content
- **Comprehensive Error Handling**: Clear exceptions for missing files or malformed content

## Data Model

```python
@dataclass
class ParsedPersona:
    """Structured representation of a parsed persona Markdown file."""

    agent_id: str           # Unique agent identifier
    name: str               # Extracted from title (e.g., "Clotho")
    display_name: str       # Full title line
    emoji: str              # Extracted emoji (🧵)
    role: str               # From frontmatter
    tier: str               # From frontmatter (ORCHESTRATOR, STRATEGIC, etc.)
    version: str            # From frontmatter
    partner: str | None     # Optional partner persona
    identity: str           # Identity section content
    markdown_source: str    # Full markdown content
    frontmatter: dict       # All frontmatter data
```

## Usage

### Basic Usage

```python
from pathlib import Path
from src.utils.persona_markdown_parser import PersonaMarkdownParser

# Initialize parser
parser = PersonaMarkdownParser()

# Parse a file
persona = parser.parse_file(Path("dist-config/claudecode/agents/clotho-orchestrator.md"))

# Access parsed data
print(f"{persona.emoji} {persona.name}")  # 🧵 Clotho
print(f"Role: {persona.role}")             # Main Orchestrator
print(f"Tier: {persona.tier}")             # ORCHESTRATOR
```

### Parse All Persona Files

```python
from pathlib import Path
from src.utils.persona_markdown_parser import PersonaMarkdownParser

parser = PersonaMarkdownParser()
agents_dir = Path("dist-config/claudecode/agents")

for persona_file in agents_dir.glob("*.md"):
    persona = parser.parse_file(persona_file)
    print(f"{persona.emoji} {persona.name} - {persona.role}")
```

### Parse from String

```python
from src.utils.persona_markdown_parser import PersonaMarkdownParser

parser = PersonaMarkdownParser()

markdown_content = """---
agent_id: "test-agent"
role: "Test Role"
tier: "TEST"
version: "1.0.0"
---

# Test Agent 🧪 - Testing

## Identity

This is a test agent.
"""

persona = parser.parse_content(markdown_content)
print(persona.name)  # "Test Agent"
```

## Supported Frontmatter Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `agent_id` | Yes* | str | Unique agent identifier |
| `name` | No | str | Alternative to agent_id |
| `role` | No | str | Agent's role description |
| `tier` | No | str | Agent tier (ORCHESTRATOR, STRATEGIC, etc.) |
| `version` | No | str | Version string |
| `partner` | No | str | Partner agent ID |

*Falls back to `name` field if `agent_id` is missing.

## Title Format Support

The parser handles various title formats:

```markdown
# Clotho（クロト）🧵 - Main Orchestrator
# 🏛️ Harmonious Conductor
# Artemis 🏹 - Technical Perfectionist
# Test Agent
```

All are correctly parsed to extract:
- Emoji (if present)
- Name (without emoji or role)
- Full display name

## Error Handling

### FileNotFoundError
```python
parser.parse_file(Path("non_existent.md"))
# Raises: FileNotFoundError: Persona file not found: non_existent.md
```

### ValueError
```python
parser.parse_content("No title here")
# Raises: ValueError: No H1 title found in persona Markdown
```

## Testing

Comprehensive test suite with 21 tests covering:
- Frontmatter parsing (various formats)
- Emoji extraction (composite emojis)
- Name extraction (multilingual)
- Identity section extraction
- Edge cases and error handling
- Unicode/Japanese text handling

**Test Coverage**: 100%

**Run tests**:
```bash
python -m pytest tests/unit/utils/test_persona_markdown_parser.py -v
```

## Demo Script

See `examples/persona_parser_demo.py` for a working example that parses all persona files:

```bash
python examples/persona_parser_demo.py
```

## Implementation Notes

### Emoji Pattern

The parser uses an extended emoji regex pattern to handle:
- Basic emoji (U+1F300-1F9FF)
- Variation selectors (U+FE00-FE0F)
- Miscellaneous symbols (U+2600-27BF)
- Technical symbols (U+2300-23FF)

This ensures composite emojis like 🏛️ (building + variation selector) are correctly matched.

### Frontmatter Parsing

- Supports both quoted and unquoted values
- Ignores comment lines starting with `#`
- Handles malformed lines gracefully
- Strips surrounding quotes from values

### Identity Extraction

Matches either:
- `## Identity`
- `## Core Identity`

Extracts content until the next `##` heading or end of file.

## Integration with Issue #59

This utility is part of Issue #59 Phase 2.2 and will be used by:
- Phase 2.3: PersonaLoader implementation
- Phase 2.4: Persona integration into agent initialization

## Related Files

- `/Users/apto-as/workspace/github.com/apto-as/tmws/src/utils/persona_markdown_parser.py` - Implementation
- `/Users/apto-as/workspace/github.com/apto-as/tmws/tests/unit/utils/test_persona_markdown_parser.py` - Tests
- `/Users/apto-as/workspace/github.com/apto-as/tmws/examples/persona_parser_demo.py` - Demo script
- `/Users/apto-as/workspace/github.com/apto-as/tmws/dist-config/claudecode/agents/*.md` - Persona files

## Version History

- **1.0.0** (2025-12-11): Initial implementation
  - Frontmatter parsing
  - Emoji extraction (composite emoji support)
  - Multilingual name parsing
  - Identity section extraction
  - 100% test coverage
