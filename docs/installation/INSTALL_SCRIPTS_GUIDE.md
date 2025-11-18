# Installation Scripts Guide

This document clarifies the purpose of each installation and verification script in the Trinitas project.

## Installation Scripts

### 1. `install_opencode.sh` ⚡ **PRIMARY (OpenCode Users)**

**Purpose**: Install Trinitas agents for **OpenCode** users
**Target Directory**: `~/.config/opencode/`
**What it installs**:
- Agent definitions (`.opencode/agent/*.md`) → `~/.config/opencode/agent/`
- Configuration files (`.opencode/config/*.json`) → `~/.config/opencode/config/`
- Plugins (`.opencode/plugin/*.js`) → `~/.config/opencode/plugin/`

**When to use**: If you are using **OpenCode** editor/IDE

```bash
./install_opencode.sh
```

---

### 2. `install_trinitas_config.sh` 🏛️ **PRIMARY (Claude Code Users)**

**Purpose**: Install Trinitas system-wide configuration for **Claude Code** users
**Target Directory**: `~/.claude/`
**What it installs**:
- `CLAUDE.md` - Global instructions
- `AGENTS.md` - Agent coordination patterns
- Hooks (Python scripts for session lifecycle)

**When to use**: If you are using **Claude Code** (Anthropic's official CLI)

```bash
./install_trinitas_config.sh
```

---

### 3. `install_trinitas.py` ⚠️ **LEGACY (Deprecated)**

**Purpose**: Original Python-based installer (v1.0 era)
**Status**: **Deprecated** - kept for reference only
**Size**: 565 lines (overly complex)

**Do NOT use**: This script is from the legacy Trinitas system before OpenCode migration.

**Replacement**:
- For OpenCode: Use `install_opencode.sh`
- For Claude Code: Use `install_trinitas_config.sh`

---

## Verification Scripts

### 1. `scripts/verify_installation.sh` ✅ **CURRENT**

**Purpose**: Verify Trinitas installation for both OpenCode and Claude Code
**Checks**:
- OpenCode configuration (`~/.config/opencode/`)
- Claude Code configuration (`~/.claude/`)
- Agent files, plugins, hooks
- File permissions and syntax validation

**When to use**: After running any installation script

```bash
./scripts/verify_installation.sh
```

---

### 2. `verify_installation.py` ⚠️ **LEGACY (Deprecated)**

**Purpose**: Original Python-based verification (v1.0 era)
**Status**: **Deprecated** - kept for reference only

**Do NOT use**: Replaced by `scripts/verify_installation.sh`

---

## Quick Reference

| Script | Status | Platform | Purpose |
|--------|--------|----------|---------|
| `install_opencode.sh` | ✅ **Current** | OpenCode | Install agents to `~/.config/opencode/` |
| `install_trinitas_config.sh` | ✅ **Current** | Claude Code | Install config to `~/.claude/` |
| `install_trinitas.py` | ⚠️ Deprecated | Legacy | Old unified installer (v1.0) |
| `scripts/verify_installation.sh` | ✅ **Current** | Both | Verify installation |
| `verify_installation.py` | ⚠️ Deprecated | Legacy | Old verification script (v1.0) |

---

## Recommended Workflow

### For OpenCode Users:
```bash
# 1. Install
./install_opencode.sh

# 2. Verify
./scripts/verify_installation.sh
```

### For Claude Code Users:
```bash
# 1. Install
./install_trinitas_config.sh

# 2. Verify
./scripts/verify_installation.sh
```

---

## Archive Legacy Scripts?

**Recommendation**: Archive the following deprecated scripts to reduce confusion:

- `install_trinitas.py` → `docs/archive/legacy_installers/`
- `verify_installation.py` → `docs/archive/legacy_installers/`

These scripts are from the v1.0 era (before OpenCode migration) and are no longer maintained.

---

## Version Information

- **Current Installer Version**: 1.2.0 (OpenCode), 2.0.0 (Claude Code)
- **Legacy Installer**: v1.0 (Python-based, deprecated)
- **Migration Date**: 2025-09-22 (OpenCode Phase 1 complete)

---

**Last Updated**: 2025-10-04
