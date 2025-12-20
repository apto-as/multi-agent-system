# Trinitas Multi-Agent System

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.4.22-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/License-ENTERPRISE-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Ubuntu%20%7C%20macOS%20%7C%20WSL2-lightgrey.svg" alt="Platform">
</p>

**Trinitas** is a sophisticated multi-agent AI system that enhances Claude Code and OpenCode with 11 specialized AI personas (including Clotho & Lachesis orchestrators), persistent memory, and advanced workflow orchestration.

> **詳細な導入手順**: [INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md) - Linux/macOS 環境向けのステップバイステップガイド

## Features

- **11 AI Personas**: 2 Orchestrators (Clotho, Lachesis) + 9 Specialists (Athena, Artemis, Hestia, Hera, Eris, Muses, Aphrodite, Metis, Aurora)
- **Persistent Memory**: TMWS (Trinitas Memory & Workflow System) provides semantic search and cross-session knowledge retention
- **Phase-Based Execution**: Strategic planning with approval gates ensures quality
- **42 MCP Tools**: Memory management, verification, skills, agent coordination
- **Full Functionality**: All features included
- **Upgrade Support**: Automatic backup and seamless upgrade from previous versions

## Quick Start

### For Claude Code (macOS/Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash
```

### For OpenCode (macOS/Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install-opencode.sh | bash
```

### For Windows (WSL2)

```powershell
# Run in PowerShell as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
irm https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install-wsl.ps1 | iex
```

Or download and run manually:

```powershell
# Download installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install-wsl.ps1" -OutFile "install-wsl.ps1"

# Run with options
.\install-wsl.ps1                    # For Claude Code (default)
.\install-wsl.ps1 -TargetIDE opencode  # For OpenCode
.\install-wsl.ps1 -Force             # Skip confirmation prompts
.\install-wsl.ps1 -SkipBackup        # Skip backup on upgrade
```

## Prerequisites

| Requirement | Version | Claude Code | OpenCode | Notes |
|-------------|---------|-------------|----------|-------|
| Docker | 20.10+ | Required | Required | For TMWS |
| Git | 2.0+ | Required | Required | For repository management |
| Ollama | Latest | Required | Required | For embedding generation |
| Claude Code | Latest | Required | - | Anthropic's CLI |
| OpenCode | Latest | - | Required | Open-source AI CLI |

### Installing Claude Code

Claude Code is Anthropic's official CLI tool for AI-assisted development. You must install it before running the Trinitas installer.

**Download & Install:**

Visit the official Claude Code page: https://claude.ai/download

Or install via npm:

```bash
npm install -g @anthropic-ai/claude-code
```

**Verify Installation:**

```bash
claude --version
```

If the `claude` command is not found, ensure it's in your PATH:

```bash
# Find where Claude Code was installed
which claude || npm root -g

# Add to PATH if needed (add to ~/.bashrc or ~/.zshrc)
export PATH="$PATH:$(npm root -g)/.bin"
```

### Installing OpenCode

OpenCode is an open-source AI CLI tool. Install it before running the Trinitas OpenCode installer.

```bash
npm install -g opencode
```

**Verify Installation:**

```bash
opencode --version
```

### Platform-Specific Requirements

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

**Windows (WSL2):**
- Windows 10 version 2004+ or Windows 11
- WSL2 enabled (`wsl --install`)
- Docker Desktop with WSL2 backend
- Ubuntu or Debian distro in WSL2

## What Gets Installed

### Claude Code Installation

| Location | Purpose |
|----------|---------|
| `~/.trinitas/` | TMWS configuration and Docker Compose |
| `~/.claude/` | Agent configurations and MCP settings |
| `~/.tmws/` | Database, logs, and vector storage |

### OpenCode Installation

| Location | Purpose |
|----------|---------|
| `~/.trinitas/` | TMWS configuration and Docker Compose |
| `~/.config/opencode/` | Agent configs, plugins, and commands |
| `~/.tmws/` | Database, logs, and vector storage |

## Upgrade Support

All installers support seamless upgrades from previous versions:

1. **Automatic Detection**: Detects existing Trinitas/TMWS installations
2. **Backup Creation**: Creates timestamped backup to `~/.trinitas-backup/`
3. **Container Management**: Stops and removes old TMWS containers
4. **Configuration Migration**: Preserves existing settings and data

To force upgrade without prompts:
```bash
./install.sh --force          # Claude Code
./install-opencode.sh --force  # OpenCode
.\install-wsl.ps1 -Force       # Windows WSL
```

## Usage

After installation, start your AI CLI in any project:

```bash
claude     # For Claude Code
opencode   # For OpenCode
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

### Tier 0: Orchestrators

| Agent | Role | Specialty |
|-------|------|-----------|
| **Clotho** 🧵 | Main Orchestrator | User interaction, task optimization, team direction |
| **Lachesis** 📏 | Support Orchestrator | Over-optimization check, intent verification, history review |

### Tier 1: Strategic Agents

| Agent | Role | Specialty |
|-------|------|-----------|
| **Athena** 🏛️ | Conductor | System orchestration & harmony |
| **Hera** 🎭 | Strategist | Architecture & planning |

### Tier 2: Specialist Agents

| Agent | Role | Specialty |
|-------|------|-----------|
| **Artemis** 🏹 | Optimizer | Performance & code quality |
| **Hestia** 🔥 | Auditor | Security & risk assessment |
| **Eris** ⚔️ | Coordinator | Tactical coordination |
| **Muses** 📚 | Documenter | Knowledge architecture |

### Tier 3: Support Agents

| Agent | Role | Specialty |
|-------|------|-----------|
| **Aphrodite** 🌸 | Designer | UI/UX & visual design |
| **Metis** 🔧 | Developer | Implementation & testing |
| **Aurora** 🌅 | Researcher | Search & context retrieval |

## TMWS-Go Migration

Starting with v2.5.0, Trinitas is transitioning to **TMWS-Go** - a high-performance Go implementation of the Trinitas Memory & Workflow System.

### Key Benefits

| Aspect | Python (Current) | Go (New) |
|--------|------------------|----------|
| Startup Time | ~3s | <500ms |
| Memory Usage | ~200MB | ~50MB |
| Binary Distribution | Docker required | Single binary option |
| Concurrency | GIL-limited | Native goroutines |

### Migration Timeline

- **Current**: Python-based TMWS (v2.4.x) - fully supported
- **Q1 2025**: TMWS-Go beta available for testing
- **Q2 2025**: TMWS-Go stable release (v2.5.0)

Existing installations will continue to work. Migration tools will be provided for seamless transition.

## License Information

This distribution includes a **pre-activated 90-day ENTERPRISE license**.

| License Detail | Value |
|----------------|-------|
| License Type | ENTERPRISE (90-day) |
| Valid Until | **2026-03-21** |
| Activation | Pre-activated |

### Included Features

| Feature | Included |
|---------|----------|
| All 11 AI Personas | ✅ |
| 42 MCP Tools | ✅ |
| Semantic Memory | ✅ |
| Verification System | ✅ |
| Phase-Based Orchestration | ✅ |
| TMWS-Go Early Access | ✅ |

Contact [apto-as](https://github.com/apto-as) for license renewal or support.

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
curl http://localhost:11434/api/version

# Check Ollama process
pgrep -a ollama

# Pull required model
ollama pull zylonai/multilingual-e5-large
```

**Important for SSH/Remote Servers:**

Running `ollama serve &` in a terminal will terminate when the SSH session disconnects. For persistent operation, use systemd:

```bash
# Start Ollama as a systemd service (recommended)
sudo systemctl enable ollama
sudo systemctl start ollama

# Verify it's running
systemctl status ollama

# Check if auto-start is enabled
systemctl is-enabled ollama
```

> **Note:** The Ollama installer (`curl -fsSL https://ollama.ai/install.sh | sh`) typically registers a systemd service automatically. If not, use `nohup ollama serve > /dev/null 2>&1 &` as an alternative.

### License Verification

```bash
curl http://localhost:8000/api/v1/license/status
```

### WSL2 Issues (Windows)

```powershell
# Check WSL2 status
wsl --status

# List installed distributions
wsl -l -v

# Ensure Docker Desktop uses WSL2 backend
# Settings > General > Use WSL 2 based engine
```

## Uninstallation

```bash
# Stop and remove container
docker stop tmws-app && docker rm tmws-app

# Remove configurations (optional)
rm -rf ~/.trinitas ~/.tmws

# For Claude Code
# Note: Keep ~/.claude if using Claude Code for other projects

# For OpenCode
# Note: Keep ~/.config/opencode if using OpenCode for other purposes
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Claude Code / OpenCode                      │
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

- **v2.4.22** (2025-12-17): MCP startup optimization, Issue #96 fix, Agent source hierarchy fix (#97)
- **v2.4.20** (2025-12-14): Narrative system for dynamic agent background stories
- **v2.4.19** (2025-12-13): Orchestrator-First Architecture (Clotho + Lachesis), ChromaDB Extension, Persona Linguistic Calibration
- **v2.4.16** (2025-12-05): Tool Search + MCP Hub, Adaptive Ranking, Security Hardening
- **v2.4.12** (2025-12-03): Option B distribution, OpenCode support, WSL installer, upgrade support
- **v2.4.8** (2025-12-01): Orchestration layer, 128 tests
- **v2.4.0** (2025-11-24): Memory management API
- **v2.3.0** (2025-11-11): Verification-Trust integration

---

<p align="center">
  <strong>Trinitas Multi-Agent System</strong><br>
  11 Agents • 42 MCP Tools • Semantic Memory<br>
  <em>Powered by TMWS v2.4.22</em>
</p>
