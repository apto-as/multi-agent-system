# Trinitas Multi-Agent System

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.4.12-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/License-90_Day_Trial-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Ubuntu%20%7C%20macOS%20%7C%20WSL2-lightgrey.svg" alt="Platform">
</p>

**Trinitas** is a sophisticated multi-agent AI system that enhances Claude Code with 9 specialized AI personas, persistent memory, and advanced workflow orchestration.

## Features

- **9 Specialized AI Personas**: Athena (Conductor), Artemis (Optimizer), Hestia (Auditor), Hera (Strategist), Eris (Coordinator), Muses (Documenter), Aphrodite (Designer), Metis (Developer), Aurora (Researcher)
- **Persistent Memory**: TMWS (Trinitas Memory & Workflow System) provides semantic search and cross-session knowledge retention
- **Phase-Based Execution**: Strategic planning with approval gates ensures quality
- **42 MCP Tools**: Memory management, verification, skills, agent coordination
- **90-Day ENTERPRISE Trial**: Full functionality included

## Quick Start

### One-Line Installation

```bash
curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash
```

### Manual Installation

```bash
git clone https://github.com/apto-as/multi-agent-system.git
cd multi-agent-system
./install.sh
```

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker | 20.10+ | Required for TMWS |
| Git | 2.0+ | For repository management |
| Ollama | Latest | For embedding generation |
| Claude Code | Latest | Anthropic's CLI |

### Installing Prerequisites

**Ubuntu/Debian:**
```bash
# Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER

# Ollama
curl -fsSL https://ollama.ai/install.sh | sh
ollama serve &
ollama pull zylonai/multilingual-e5-large
```

**macOS:**
```bash
# Docker
brew install --cask docker

# Ollama
brew install ollama
ollama serve &
ollama pull zylonai/multilingual-e5-large
```

## What Gets Installed

| Location | Purpose |
|----------|---------|
| `~/.trinitas/` | TMWS configuration and Docker Compose |
| `~/.claude/` | Claude Code agent configurations |
| `~/.tmws/` | Database, logs, and vector storage |

## Usage

After installation, start Claude Code in any project:

```bash
claude
```

### Basic Commands

```bash
# Execute specific agent
/trinitas execute artemis "Optimize this code"

# Parallel analysis with multiple agents
/trinitas analyze "System review" --personas athena,artemis,hestia

# Store in memory
/trinitas remember security_finding "SQL injection vulnerability" --importance 1.0

# Search memories
/trinitas recall "security patterns" --semantic
```

### Trinitas Full Mode

For complex tasks requiring multi-phase coordination:

```
Phase 1: Strategic Planning (Hera + Athena)
  └─ Approval Gate: Both agents agree

Phase 2: Implementation (Artemis + Metis)
  └─ Approval Gate: Tests pass

Phase 3: Verification (Hestia)
  └─ Final Approval: Security sign-off

Phase 4: Documentation (Muses)
```

## AI Personas

### Core 6 Agents

| Agent | Role | Specialty |
|-------|------|-----------|
| **Athena** 🏛️ | Conductor | System orchestration & harmony |
| **Artemis** 🏹 | Optimizer | Performance & code quality |
| **Hestia** 🔥 | Auditor | Security & risk assessment |
| **Hera** 🎭 | Strategist | Architecture & planning |
| **Eris** ⚔️ | Coordinator | Tactical coordination |
| **Muses** 📚 | Documenter | Knowledge architecture |

### Support 3 Agents

| Agent | Role | Specialty |
|-------|------|-----------|
| **Aphrodite** 🌸 | Designer | UI/UX & visual design |
| **Metis** 🔧 | Developer | Implementation & testing |
| **Aurora** 🌅 | Researcher | Search & context retrieval |

## License Information

This distribution includes a **90-day ENTERPRISE trial license**.

| Feature | Trial | Full License |
|---------|-------|--------------|
| All 9 AI Personas | ✅ | ✅ |
| 42 MCP Tools | ✅ | ✅ |
| Semantic Memory | ✅ | ✅ |
| Verification System | ✅ | ✅ |
| Duration | 90 days | Perpetual |

**Trial Expiration**: 2026-03-03

Contact [apto-as](https://github.com/apto-as) for extended licensing.

## Troubleshooting

### Docker Issues

```bash
# Check if Docker is running
docker info

# Restart TMWS container
cd ~/.trinitas && docker compose restart

# View logs
docker logs -f tmws-app
```

### Ollama Issues

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama
ollama serve

# Pull required model
ollama pull zylonai/multilingual-e5-large
```

### License Verification

```bash
curl http://localhost:8000/api/v1/license/status
```

## Uninstallation

```bash
# Stop and remove container
docker stop tmws-app && docker rm tmws-app

# Remove configurations (optional)
rm -rf ~/.trinitas ~/.tmws
# Note: Keep ~/.claude if using Claude Code for other projects
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Claude Code                           │
│                   (AI Interface)                         │
└─────────────────────┬───────────────────────────────────┘
                      │ MCP Protocol
┌─────────────────────▼───────────────────────────────────┐
│                 TMWS Container                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ MCP Server  │  │  REST API   │  │  Services   │     │
│  │   :8892     │  │   :8000     │  │             │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│  ┌─────────────────────────────────────────────────┐   │
│  │               SQLite + ChromaDB                  │   │
│  │           (Memory & Vector Storage)              │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│                    Ollama                                │
│            (Embedding Generation)                        │
│         zylonai/multilingual-e5-large                   │
└─────────────────────────────────────────────────────────┘
```

## Contributing

This is a proprietary system. For bug reports and feature requests, please contact [apto-as](https://github.com/apto-as).

## Version History

- **v2.4.12** (2025-12-03): Option B distribution, 90-day ENTERPRISE trial
- **v2.4.8** (2025-12-01): Orchestration layer, 128 tests
- **v2.4.0** (2025-11-24): Memory management API
- **v2.3.0** (2025-11-11): Verification-Trust integration

---

<p align="center">
  <strong>Trinitas Multi-Agent System</strong><br>
  9 Agents • 42 MCP Tools • Semantic Memory<br>
  <em>Powered by TMWS v2.4.12</em>
</p>
