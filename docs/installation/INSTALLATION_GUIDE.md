# Trinitas Agent System - Installation Guide

## Cross-Platform Installation Guide for Claude Code & OpenCode

**Version**: 2.5.0
**Last Updated**: 2025-11-30
**Platforms**: macOS, Linux, Windows
**Source**: TMWS (Trinitas Memory & Workflow System)

---

## Quick Start

### macOS / Linux

```bash
# Clone the TMWS repository
git clone https://github.com/apto-as/tmws.git
cd tmws

# Run unified installer
./install_trinitas.sh
```

### Windows (PowerShell)

```powershell
# Clone the TMWS repository
git clone https://github.com/apto-as/tmws.git
cd tmws

# Run Windows installer
.\Install-Trinitas.ps1
```

---

## Installation Options

### Interactive Mode (Default)

```bash
./install_trinitas.sh
```

The installer will prompt you to select:
1. **Claude Code only** - Installs to `~/.claude/`
2. **OpenCode only** - Installs to `~/.config/opencode/`
3. **Both platforms** - Installs to both directories

### Non-Interactive Mode

```bash
# Claude Code only
./install_trinitas.sh --platform claude --yes

# OpenCode only
./install_trinitas.sh --platform opencode --yes

# Both platforms
./install_trinitas.sh --platform both --yes
```

### Windows PowerShell

```powershell
# Interactive
.\Install-Trinitas.ps1

# Non-interactive
.\Install-Trinitas.ps1 -Platform claude -Force
.\Install-Trinitas.ps1 -Platform opencode -Force
.\Install-Trinitas.ps1 -Platform both -Force
```

---

## What Gets Installed

### Agents (9 Total)

| Agent | Type | Description |
|-------|------|-------------|
| **Athena** | Core | Harmonious Conductor - System orchestration |
| **Artemis** | Core | Technical Perfectionist - Performance optimization |
| **Hestia** | Core | Security Guardian - Security auditing |
| **Eris** | Core | Tactical Coordinator - Team coordination |
| **Hera** | Core | Strategic Commander - Strategic planning |
| **Muses** | Core | Knowledge Architect - Documentation |
| **Aphrodite** | Support | UI/UX Designer - Interface design |
| **Metis** | Support | Development Assistant - Code implementation |
| **Aurora** | Support | Research Assistant - Knowledge research |

### TMWS Project Structure (Source)

```
tmws/
├── src/trinitas/agents/   # Claude Code agent definitions (9 agents)
│   ├── athena-conductor.md
│   ├── artemis-optimizer.md
│   ├── hestia-auditor.md
│   ├── eris-coordinator.md
│   ├── hera-strategist.md
│   ├── muses-documenter.md
│   ├── aphrodite-designer.md
│   ├── metis-developer.md
│   └── aurora-researcher.md
├── .opencode/             # OpenCode configuration
│   ├── agent/             # OpenCode agent definitions (9 agents)
│   ├── docs/              # Documentation
│   └── AGENTS.md          # System instructions
├── hooks/                 # Python hooks for Claude Code
│   ├── core/
│   │   ├── protocol_injector.py
│   │   └── dynamic_context_loader.py
│   └── settings_*.json    # Hook configuration templates
└── install_trinitas.sh    # Unified installer (Bash)
└── Install-Trinitas.ps1   # Unified installer (PowerShell)
```

### Claude Code Installation Target (`~/.claude/`)

```
~/.claude/
├── CLAUDE.md          # Global system instructions (preserved if exists)
├── AGENTS.md          # Agent coordination rules (installed)
├── settings.json      # Hook configuration (generated)
├── agents/            # 9 agent definitions (installed)
├── hooks/core/        # Python hooks (installed)
├── shared/utils/      # Shared utilities (installed)
└── backup/            # Automatic backups
```

### OpenCode (`~/.config/opencode/`)

```
~/.config/opencode/
├── AGENTS.md          # System instructions
├── agent/             # 9 agent definitions
│   ├── athena.md
│   ├── artemis.md
│   ├── hestia.md
│   ├── eris.md
│   ├── hera.md
│   ├── muses.md
│   ├── aphrodite.md
│   ├── metis.md
│   └── aurora.md
└── docs/              # Documentation (optional)
```

---

## Platform-Specific Usage

### Claude Code

After installation:

1. **Restart Claude Code** to load the new configuration
2. **Test the system**:
   ```
   Trinitasシステムの動作確認
   ```
3. **Test persona detection**:
   ```
   optimize this code  → Artemis will be detected
   security audit      → Hestia will be detected
   document this       → Muses will be detected
   ```

### OpenCode

After installation:

1. **Start OpenCode**:
   ```bash
   opencode
   ```

2. **Use a specific agent**:
   ```bash
   opencode --agent athena   # Start with Athena
   opencode --agent artemis  # Start with Artemis
   opencode --agent hestia   # Start with Hestia
   ```

3. **Switch agents**: Press `Tab` while running to switch agents

---

## Updating an Existing Installation

```bash
# Update while preserving backups
./install_trinitas.sh --platform both --yes
```

The installer automatically:
- Creates timestamped backups before installation
- Preserves your custom modifications in backups
- Overwrites only the standard configuration files

---

## Restoring from Backup

If you need to restore your previous configuration:

```bash
# macOS/Linux
./install_trinitas.sh --uninstall

# Windows
.\Install-Trinitas.ps1 -Uninstall
```

This restores from the latest automatic backup.

### Manual Backup Location

- **Claude Code**: `~/.claude/backup/`
- **OpenCode**: `~/.config/opencode.backup.YYYYMMDD_HHMMSS/`

---

## Command Reference

### Bash (macOS/Linux)

| Command | Description |
|---------|-------------|
| `./install_trinitas.sh` | Interactive installation |
| `./install_trinitas.sh --help` | Show help |
| `./install_trinitas.sh --version` | Show version |
| `./install_trinitas.sh --platform claude` | Claude Code only |
| `./install_trinitas.sh --platform opencode` | OpenCode only |
| `./install_trinitas.sh --platform both` | Both platforms |
| `./install_trinitas.sh --yes` | Skip confirmation |
| `./install_trinitas.sh --uninstall` | Restore from backup |

### PowerShell (Windows)

| Command | Description |
|---------|-------------|
| `.\Install-Trinitas.ps1` | Interactive installation |
| `.\Install-Trinitas.ps1 -Version` | Show version |
| `.\Install-Trinitas.ps1 -Platform claude` | Claude Code only |
| `.\Install-Trinitas.ps1 -Platform opencode` | OpenCode only |
| `.\Install-Trinitas.ps1 -Platform both` | Both platforms |
| `.\Install-Trinitas.ps1 -Force` | Skip confirmation |
| `.\Install-Trinitas.ps1 -Uninstall` | Restore from backup |

---

## Troubleshooting

### "Source directory not found"

Run the installer from the TMWS repository root:

```bash
cd /path/to/tmws
./install_trinitas.sh
```

### "Permission denied"

Make the script executable:

```bash
chmod +x install_trinitas.sh
```

### Agents not appearing

1. **Claude Code**: Restart the application
2. **OpenCode**: Verify with `ls ~/.config/opencode/agent/`

### Windows: "Execution policy" error

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Agent Trigger Keywords

Each agent is automatically detected based on keywords in your prompts:

| Agent | Trigger Keywords |
|-------|------------------|
| Athena | orchestration, workflow, coordination, 調整 |
| Artemis | optimization, performance, quality, 最適化 |
| Hestia | security, audit, vulnerability, セキュリティ |
| Eris | coordinate, team, tactical, チーム調整 |
| Hera | strategy, planning, architecture, 戦略 |
| Muses | documentation, knowledge, record, ドキュメント |
| Aphrodite | design, ui, ux, interface, デザイン |
| Metis | implement, code, develop, test, 実装 |
| Aurora | search, research, context, 検索 |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.5.0 | 2025-11-29 | Unified installer, 9 agents support |
| 2.2.4 | 2025-11 | Support agents added |
| 2.2.0 | 2025-10 | Initial public release |

---

## Support

- **GitHub Issues**: [apto-as/tmws](https://github.com/apto-as/tmws/issues)
- **Documentation**: `/docs/` directory

---

*Trinitas Agent System - AI Personas for Claude Code & OpenCode*
*Part of TMWS (Trinitas Memory & Workflow System)*
