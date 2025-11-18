# Trinitas v2.2.4 Installation Guide

**Version**: 2.2.4
**Target Platforms**: Claude Code CLI, OpenCode

## Quick Start

Choose the installation method that matches your setup:

| You use... | Installation Method | Time | Guide |
|-----------|-------------------|------|-------|
| **Claude Code CLI** | Script Installation | 3 min | [Claude Code Guide](#claude-code-script-installation) ⭐ **Recommended** |
| **OpenCode** | Script Installation | 3 min | [OpenCode Guide](#opencode-installation) |

---

## Installation Methods Comparison

### Feature Matrix

| Feature | Claude Code Script | OpenCode Script |
|---------|-------------------|----------------|
| **Integration** | File-based config | Plugin-based |
| **Tool Access** | Via context | Custom tools |
| **Auto-updates** | Reinstall script | Restart required |
| **Setup Time** | 3 minutes | 3 minutes |
| **Prerequisites** | Bash, Claude Code CLI | Bash, OpenCode |
| **Memory System** | ✓ File-based | ✓ Plugin hooks |
| **Agent Switching** | ✓ Via context | ✓ Via agents |
| **Resources** | ✓ File reads | ✓ Plugin API |

### When to Use Each Method

#### Claude Code Script Installation - **Recommended for most users**

✅ **Use when**:
- You use Claude Code CLI as your primary interface
- You want minimal setup with file-based memory system
- You prefer file-based configuration
- You want the simplest installation

❌ **Don't use when**:
- You use OpenCode instead

**Key Benefits**:
- Simple bash script installation
- File-based memory system (no external dependencies)
- Direct file configuration
- Works with existing Claude Code workflows
- No external dependencies required

#### OpenCode Installation

✅ **Use when**:
- You use OpenCode (SST's CLI)
- You want plugin-based integration
- You need agent definitions in OpenCode format

❌ **Don't use when**:
- You use Claude Code CLI

**Key Benefits**:
- OpenCode-native plugin system
- 6 agent definitions + 4 plugins
- Event hooks (session.start, tool.execute, etc.)
- Compatible with existing OpenCode plugins
- Automatic Mem0 setup

---

## Claude Code Script Installation

### Prerequisites

- **Claude Code CLI** installed
- **Bash** shell (macOS/Linux/WSL)

### Quick Install

```bash
# Navigate to trinitas-agents directory
cd /path/to/trinitas-agents

# Run the installer
./install_trinitas_config_v2.2.4.sh

# Restart Claude Code
claude
```

### What Gets Installed

```
~/.claude/
├── CLAUDE.md             # Global configuration
├── AGENTS.md             # Agent coordination
├── contexts/             # Additional context files
│   ├── performance.md
│   ├── security.md
│   └── mcp-tools.md
└── mcp_servers.json      # MCP server configurations

~/.claude/memory/         # File-based memory storage
├── agents/               # Per-persona memories
│   ├── athena/
│   ├── artemis/
│   ├── hestia/
│   ├── eris/
│   ├── hera/
│   └── muses/
└── shared/               # Shared memories
```

### Memory System

Trinitas-agents uses a **file-based memory system**:
- **No external dependencies** - Works immediately after installation
- **No API keys required** - Fully self-contained
- **Fully private and local** - All data stays on your machine
- **Simple file structure** - Easy to backup and inspect

**Storage Locations**:
- Claude Code: `~/.claude/memory/`
- OpenCode: `~/.config/opencode/memory/`

**Future**: TMWS MCP Server integration will provide advanced memory features including semantic search and vector-based storage

### Usage

Configuration is automatically loaded when you start Claude Code:

```bash
# Start Claude Code
claude

# Trinitas agents are now available via context
# Use commands like:
# "Execute this task with artemis"
# "Have athena analyze this architecture"
# "Remember this design decision"
# "Recall similar optimization patterns"
```

### Full Documentation

Script includes comprehensive inline documentation. Run:

```bash
./install_trinitas_config_v2.2.4.sh --help
```

---

## OpenCode Installation

### Prerequisites

- **OpenCode** v0.14.1+ installed
- **Bash** shell (macOS/Linux/WSL)
- **Python 3.9+** (for Mem0)
- **Homebrew** (macOS) or **curl** (Linux) for Ollama

### Quick Install

```bash
# Navigate to trinitas-agents directory
cd /path/to/trinitas-agents

# Run the installer (includes Mem0 auto-setup)
./install_opencode.sh

# Restart OpenCode
opencode
```

### What Gets Installed

```
.opencode/
├── agent/                          # 6 agent definitions
│   ├── athena-conductor.md
│   ├── artemis-optimizer.md
│   ├── hestia-auditor.md
│   ├── eris-coordinator.md
│   ├── hera-strategist.md
│   └── muses-documenter.md
├── plugin/                         # 4 JavaScript plugins
│   ├── dynamic-context-loader.js
│   ├── narrative-engine.js
│   ├── performance-monitor.js
│   └── quality-enforcer.js
└── AGENTS.md                      # System instructions

~/.opencode/opencode.json           # Mem0 MCP configuration (updated)

~/.trinitas/mem0/
└── data/                           # Mem0 vector storage (LanceDB)
```

### Usage

```bash
# Start OpenCode
opencode

# Switch agents with Tab key
# Or specify agent at startup:
opencode --agent athena

# Plugins automatically load on session start
# Mem0 semantic memory is available via MCP
```

### Full Documentation

See [README-OPENCODE.md](README-OPENCODE.md) for complete guide.

---

## Trinitas Agents Overview

All installation methods provide access to 6 specialized AI agents:

| Agent | Icon | Role | Specialization |
|-------|------|------|----------------|
| **Athena** | 🏛️ | Harmonious Conductor | System architecture, strategic design, coordination |
| **Artemis** | 🏹 | Technical Perfectionist | Performance optimization, code quality, algorithms |
| **Hestia** | 🔥 | Security Guardian | Security analysis, risk assessment, auditing |
| **Eris** | ⚔️ | Tactical Coordinator | Team coordination, conflict resolution, workflow |
| **Hera** | 🎭 | Strategic Commander | Strategic planning, orchestration, roadmaps |
| **Muses** | 📚 | Knowledge Architect | Documentation, knowledge management, archiving |

### Agent Selection Guide

**Choose agent based on task type**:

- 📐 **Architecture/Design** → Athena
- ⚡ **Performance/Optimization** → Artemis
- 🔒 **Security/Audit** → Hestia
- 🤝 **Team Coordination** → Eris
- 🎯 **Strategic Planning** → Hera
- 📖 **Documentation** → Muses

**For complex tasks**, use **parallel analysis** with multiple agents.

---

## Security Best Practices

### Environment Variables

**Never commit sensitive data to version control!**

1. **Use .env files for local development**:
   ```bash
   # .env (add to .gitignore)
   TMWS_AUTH_USER=your_username
   TMWS_AUTH_PASSWORD=your_password
   TMWS_DATABASE_URL=sqlite:///~/.tmws/tmws.db
   ```

2. **Verify .gitignore includes sensitive files**:
   ```gitignore
   .env
   .env.local
   .env.production
   .env.*.local
   .tmws/
   data/tmws/
   *.db
   ```

3. **Use strong, unique passwords**:
   - Minimum 16 characters
   - Mix of uppercase, lowercase, numbers, symbols
   - Use password manager (1Password, Bitwarden)

### Production Deployment

For production environments, use:
- **JWT** with short expiration (1 hour)
- **OAuth2** for third-party integrations
- **mTLS** (mutual TLS) for secure MCP connections
- **Regular credential rotation** (every 90 days)

---

## Troubleshooting

### Common Issues

#### "OpenCode doesn't load plugins"

**Problem**: Plugin files not copied or OpenCode not restarted

**Solutions**:
1. Verify plugins exist:
   ```bash
   ls -la .opencode/plugin/*.js
   # Should show 4 .js files
   ```

2. Restart OpenCode:
   ```bash
   # Kill any running instance
   pkill opencode

   # Start fresh
   opencode
   ```

#### "Permission denied" errors

**Problem**: Installation script not executable

**Solution**:
```bash
# Make scripts executable
chmod +x install_trinitas_config_v2.2.4.sh
chmod +x install_opencode.sh
chmod +x scripts/setup_mem0_auto.sh
```

#### "pip3: command not found"

**Problem**: Python 3 not installed or not in PATH

**Solution**:
```bash
# macOS
brew install python3

# Ubuntu/Debian
sudo apt install python3 python3-pip

# Verify
python3 --version
pip3 --version
```

---

## Uninstallation

### Claude Code Script

```bash
# Remove configuration files
rm -rf ~/.claude/CLAUDE.md ~/.claude/AGENTS.md ~/.claude/contexts ~/.claude/mcp_servers.json

# Remove Mem0 data (optional - keeps your memory)
rm -rf ~/.trinitas/mem0

# Uninstall Ollama (optional)
# macOS:
brew uninstall ollama

# Linux:
sudo rm /usr/local/bin/ollama

# Restart Claude Code
```

### OpenCode

```bash
# Remove OpenCode configuration
rm -rf .opencode/agent/*.md
rm -rf .opencode/plugin/*.js
rm .opencode/AGENTS.md

# Remove Mem0 data (optional)
rm -rf ~/.trinitas/mem0

# Restart OpenCode
```

---

## Advanced Configuration

### Running Multiple Projects

You can install Trinitas for multiple projects:

#### Claude Code
Each project can have its own configuration in `~/.claude/`, but note that only one global config is active at a time. For project-specific configs, use project-local `.claude/` directories.

#### OpenCode
Just run the installer in each project directory - OpenCode will load the local `.opencode/` configuration.

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | macOS 10.15+, Ubuntu 20.04+, Windows 10+ (WSL) |
| **Python** | 3.9+ (for Mem0) |
| **Disk Space** | 500MB (includes Ollama + model) |
| **Memory** | 512MB available RAM |

### Recommended Requirements

| Component | Recommendation |
|-----------|---------------|
| **OS** | macOS 13+, Ubuntu 22.04+ |
| **Python** | 3.11+ |
| **Disk Space** | 1GB |
| **Memory** | 1GB available RAM |

---

## Support

### Getting Help

1. **Check documentation**:
   - [README-OPENCODE.md](README-OPENCODE.md)
   - [docs/mem0-setup-guide.md](docs/mem0-setup-guide.md)

2. **Review logs**:
   - Ollama logs: Check with `ollama logs` (if available)
   - OpenCode: Check console output

3. **Verify installation**:
   ```bash
   # Check Ollama
   ollama list

   # Check Mem0 Python package
   pip3 show mem0ai

   # Check configuration files
   ls -la ~/.claude/
   ls -la .opencode/
   ```

### Security

All installation methods have been audited by Hestia (Security Guardian). See [docs/security-audit-report.md](docs/security-audit-report.md) for details.

✅ **Status**: All security checks PASSED

---

## Version History

- **v2.2.4** - Added automatic Mem0 integration, removed Claude Desktop support
- **v2.2.3** - OpenCode integration
- **v2.2.0** - Script installation method
- **v2.1.0** - Initial release

---

## License

Part of Trinitas Agents system. See main project LICENSE for details.

---

**Installation complete! 🎉**

Choose your method above and start using Trinitas Agents with semantic memory to supercharge your AI-assisted development workflow.
