# Trinitas Installation Guide

**Version**: 2.2.4
**Platforms**: Claude Code, OpenCode
**Supported OS**: Linux, macOS, Windows (WSL)

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Installation](#quick-installation)
3. [Platform-Specific Guides](#platform-specific-guides)
4. [Verification](#verification)
5. [Troubleshooting](#troubleshooting)
6. [Uninstallation](#uninstallation)

---

## Prerequisites

### All Platforms

- **Git**: Version 2.0 or higher
- **Bash**: Version 4.0 or higher
- **Disk Space**: 50MB minimum, 100MB recommended
- **Internet**: Required for initial download only

### Claude Code Specific

- **Claude Code**: Latest version
- **Python**: 3.8+ (for hook scripts)

### OpenCode Specific

- **OpenCode**: v0.14.1 or higher
- **Bun**: Latest version (automatically used by OpenCode)

---

## Quick Installation

### Claude Code (Recommended for Most Users)

**Time**: 3-5 minutes

```bash
# 1. Clone repository
git clone https://github.com/apto-as/multi-agent-system.git
cd multi-agent-system

# 2. Run installer
chmod +x install-claude.sh
./install-claude.sh

# 3. Restart Claude
# Installation complete!
```

**What gets installed**:
```
~/.claude/
├── CLAUDE.md             # System configuration
├── AGENTS.md             # Agent coordination
├── agents/               # 6 persona definitions
│   ├── athena-conductor.md
│   ├── artemis-optimizer.md
│   ├── hestia-auditor.md
│   ├── eris-coordinator.md
│   ├── hera-strategist.md
│   └── muses-documenter.md
├── hooks/
│   └── core/             # Hook scripts
│       ├── protocol_injector.py
│       └── dynamic_context_loader.py
└── memory/               # Memory storage (created on first use)
```

---

### OpenCode

**Time**: 3-5 minutes

```bash
# 1. Clone repository
git clone https://github.com/apto-as/multi-agent-system.git
cd multi-agent-system

# 2. Run installer
chmod +x install-opencode.sh
./install-opencode.sh

# 3. Restart OpenCode
# Installation complete!
```

**What gets installed**:
```
.opencode/
├── agent/                # 6 agent definitions
│   ├── athena-conductor.md
│   ├── artemis-optimizer.md
│   ├── hestia-auditor.md
│   ├── eris-coordinator.md
│   ├── hera-strategist.md
│   └── muses-documenter.md
├── plugin/               # JavaScript plugins
│   ├── dynamic-context-loader.js
│   ├── performance-monitor.js
│   └── quality-enforcer.js
└── AGENTS.md             # System instructions

~/.claude/memory/         # Shared memory storage
```

---

## Platform-Specific Guides

### Linux Installation

See [docs/installation/linux.md](../installation/linux.md) for:
- Ubuntu/Debian specific instructions
- Fedora/RHEL specific instructions
- Arch Linux specific instructions
- Permission configuration
- SELinux considerations

### macOS Installation

See [docs/installation/macos.md](../installation/macos.md) for:
- Homebrew integration
- macOS permissions (Gatekeeper)
- Apple Silicon (M1/M2) notes
- Xcode Command Line Tools

### Windows (WSL) Installation

See [docs/installation/windows-wsl.md](../installation/windows-wsl.md) for:
- WSL2 setup
- Ubuntu on WSL configuration
- Windows Terminal setup
- Path considerations

---

## Verification

After installation, verify Trinitas is working correctly.

### Step 1: Check Installation

```bash
# Verify files exist
ls -la ~/.claude/
# Should show: CLAUDE.md, AGENTS.md, agents/, hooks/, memory/
```

### Step 2: Test Claude

**Start Claude:**
```bash
claude  # or 'opencode' for OpenCode
```

**Test Command:**
```
Explain the Trinitas system
```

**Expected Response:**
```
Trinitas is a multi-agent AI system with six specialized personas:

1. Athena (🏛️) - Harmonious Conductor: System architecture and strategic design
2. Artemis (🏹) - Technical Perfectionist: Performance and code quality
3. Hestia (🔥) - Security Guardian: Security auditing and risk management
4. Eris (⚔️) - Tactical Coordinator: Team coordination and workflows
5. Hera (🎭) - Strategic Commander: Strategic planning and orchestration
6. Muses (📚) - Knowledge Architect: Documentation and knowledge management

Each persona can work independently or collaborate for comprehensive analysis.
```

✅ **Success**: If you see a response explaining the personas, installation is complete!

### Step 3: Test Persona Selection

```
Use Athena to explain microservices architecture
```

**Expected**: Athena provides an architectural explanation.

```
Artemis, what makes code performant?
```

**Expected**: Artemis discusses performance best practices.

### Step 4: Test Memory System

```
Remember: We use PostgreSQL for our database
```

**Expected**: Confirmation that information is stored.

```
What database do we use?
```

**Expected**: Response mentions PostgreSQL.

✅ **All tests passed**: Trinitas is fully operational!

---

## Troubleshooting

### Installation Issues

#### "Permission denied" error

**Problem**: Installation script not executable

**Solution**:
```bash
chmod +x install-claude.sh
# or
chmod +x install-opencode.sh
```

#### "Git not found" error

**Problem**: Git not installed

**Solutions by Platform**:

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install git
```

**macOS**:
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Or via Homebrew
brew install git
```

**Windows (WSL)**:
```bash
sudo apt update
sudo apt install git
```

#### "Python not found" (Claude Code only)

**Problem**: Python 3.8+ not available

**Solutions**:

**Ubuntu/Debian**:
```bash
sudo apt install python3 python3-pip
```

**macOS**:
```bash
brew install python3
```

**Windows (WSL)**:
```bash
sudo apt install python3 python3-pip
```

### Runtime Issues

#### Personas don't respond correctly

**Symptoms**: Generic responses instead of specialized persona behavior

**Solutions**:
1. Restart Claude/OpenCode
2. Verify configuration files exist:
   ```bash
   ls ~/.claude/CLAUDE.md
   ls ~/.claude/AGENTS.md
   ```
3. Re-run installer:
   ```bash
   ./install-claude.sh --force
   ```

#### Memory not working

**Symptoms**: Previous context not recalled

**Solutions**:
1. Check memory directory exists:
   ```bash
   mkdir -p ~/.claude/memory/
   ```
2. Verify write permissions:
   ```bash
   ls -ld ~/.claude/memory/
   # Should show: drwxr-xr-x
   ```
3. Test manual save:
   ```bash
   echo "Test memory" > ~/.claude/memory/test.md
   cat ~/.claude/memory/test.md
   ```

#### Hooks not executing (Claude Code)

**Symptoms**: No pre/post execution behavior

**Solutions**:
1. Check hook files:
   ```bash
   ls -la ~/.claude/hooks/core/
   ```
2. Verify Python execution:
   ```bash
   python3 --version
   ```
3. Test hook manually:
   ```bash
   python3 ~/.claude/hooks/core/protocol_injector.py --test
   ```

### Platform-Specific Issues

For platform-specific troubleshooting, see:
- [Linux Troubleshooting](../installation/linux.md#troubleshooting)
- [macOS Troubleshooting](../installation/macos.md#troubleshooting)
- [Windows Troubleshooting](../installation/windows-wsl.md#troubleshooting)

---

## Uninstallation

### Claude Code

```bash
# 1. Remove configuration files
rm -rf ~/.claude/CLAUDE.md
rm -rf ~/.claude/AGENTS.md
rm -rf ~/.claude/agents/
rm -rf ~/.claude/hooks/

# 2. (Optional) Remove memory files
# WARNING: This deletes all saved context
rm -rf ~/.claude/memory/

# 3. Restart Claude
```

### OpenCode

```bash
# 1. Remove agent definitions
rm -rf .opencode/agent/athena-conductor.md
rm -rf .opencode/agent/artemis-optimizer.md
rm -rf .opencode/agent/hestia-auditor.md
rm -rf .opencode/agent/eris-coordinator.md
rm -rf .opencode/agent/hera-strategist.md
rm -rf .opencode/agent/muses-documenter.md

# 2. Remove plugins
rm -rf .opencode/plugin/dynamic-context-loader.js
rm -rf .opencode/plugin/performance-monitor.js
rm -rf .opencode/plugin/quality-enforcer.js

# 3. Remove system instructions
rm -rf .opencode/AGENTS.md

# 4. (Optional) Remove shared memory
rm -rf ~/.claude/memory/

# 5. Restart OpenCode
```

---

## Advanced Installation

### Custom Installation Directory

**Claude Code**:
```bash
CLAUDE_HOME=/custom/path ./install-claude.sh
```

**OpenCode**:
```bash
OPENCODE_DIR=/custom/path ./install-opencode.sh
```

### Silent Installation

```bash
# Non-interactive mode
./install-claude.sh --yes --quiet

# or
./install-opencode.sh --yes --quiet
```

### Development Installation

For contributing or development:

```bash
# 1. Clone with all branches
git clone --branch develop https://github.com/apto-as/multi-agent-system.git
cd multi-agent-system

# 2. Install in development mode
./install-claude.sh --dev

# 3. Install development dependencies
pip install -r requirements-dev.txt  # For Claude Code
# or
npm install  # For OpenCode
```

See [Contributing Guide](../../CONTRIBUTING.md) for full development setup.

---

## Updating

### Update to Latest Version

```bash
# 1. Navigate to repository
cd multi-agent-system

# 2. Pull latest changes
git pull origin main

# 3. Re-run installer
./install-claude.sh
# or
./install-opencode.sh

# 4. Restart Claude/OpenCode
```

### Version-Specific Updates

```bash
# Update to specific version
git checkout v2.2.4
./install-claude.sh
```

### Migration Between Versions

For major version changes, see migration guides:
- [v2.2.1 → v2.2.4](../migration/v2.2.1-to-v2.2.4.md)

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Linux (any), macOS 10.15+, Windows 10+ (WSL2) |
| **CPU** | Any modern CPU (x86_64 or ARM64) |
| **Memory** | 512MB available RAM |
| **Disk** | 50MB free space |
| **Network** | Internet (initial installation only) |

### Recommended Requirements

| Component | Recommendation |
|-----------|----------------|
| **OS** | Ubuntu 22.04+, macOS 13+, Windows 11 (WSL2) |
| **Memory** | 1GB+ available RAM |
| **Disk** | 100MB+ free space |
| **Network** | Broadband connection |

---

## Security Considerations

### Installation Security

1. **Verify Repository**:
   ```bash
   # Check repository URL
   git remote -v
   # Should show: github.com/apto-as/multi-agent-system
   ```

2. **Review Scripts**:
   ```bash
   # Review installer before running
   less install-claude.sh
   ```

3. **File Permissions**:
   ```bash
   # Verify proper permissions
   ls -la ~/.claude/
   # Should NOT show world-writable permissions
   ```

### Runtime Security

- All data stored locally in `~/.claude/`
- No external API calls or telemetry
- File-based memory is user-readable and editable
- Hooks run with user permissions only

See [SECURITY.md](../../SECURITY.md) for security policy.

---

## FAQ

### Can I install on multiple machines?

Yes, clone and install on each machine independently.

### Can I sync configuration between machines?

Yes, you can version control `~/.claude/` with Git (exclude sensitive data).

### Does installation require sudo/admin?

No, installation uses user-level directories only.

### Can I run Claude Code and OpenCode simultaneously?

Yes, they share the `~/.claude/memory/` directory but have separate configs.

### What happens to my existing Claude configuration?

Installation creates/updates Trinitas-specific files only. Your other configuration remains unchanged.

---

## Getting Help

### Documentation
- 📖 [Quick Start Guide](../../QUICKSTART.md)
- 📚 [User Guide](../user-guide/)
- ❓ [FAQ](../reference/faq.md)
- 🐛 [Troubleshooting](../user-guide/troubleshooting.md)

### Community
- 💬 [GitHub Discussions](https://github.com/apto-as/multi-agent-system/discussions)
- 🐛 [Issue Tracker](https://github.com/apto-as/multi-agent-system/issues)

### Support
- 📧 Email: support@trinitas-project.example

---

## Next Steps

Installation complete! Here's what to do next:

1. 📘 **Read the Quick Start**: [QUICKSTART.md](../../QUICKSTART.md)
2. 🎓 **Try Basic Tutorials**: [docs/user-guide/tutorials/](../user-guide/tutorials/)
3. 💡 **Explore Examples**: [examples/](../../examples/)
4. 🔧 **Customize**: [docs/advanced/customization.md](../advanced/customization.md)

---

*Trinitas v2.2.4 - Six Minds, Unified Intelligence*
