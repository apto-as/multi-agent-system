# Archived Installation Scripts

This directory contains deprecated installation scripts that are no longer actively maintained but preserved for historical reference.

## Archived Scripts

### install_trinitas_config.sh (Archived: 2025-10-15)

**Version**: Pre-v2.2.4
**Status**: ❌ Deprecated (TMWS-based)
**Replaced By**: `install_trinitas_config_v2.2.4.sh`

**Reason for Archival**:
- Uses TMWS (Trinitas Memory & Workflow Service) which was replaced by Mem0 MCP in v2.2.4
- Superseded by the v2.2.4 installer with improved architecture
- 83% faster setup time with Mem0 (5 min vs 30 min)
- 80% fewer dependencies (1 service vs 5 services)

**Historical Context**:
This was the primary Trinitas installer for versions prior to v2.2.4. It featured:
- TMWS-based semantic memory
- Multi-service architecture (PostgreSQL, Redis, FastAPI, MCP, WebSocket)
- Manual configuration required

### verify_installation.sh (Archived: 2025-10-15)

**Version**: v2.2.0
**Status**: ❌ Deprecated (outdated checks)
**Replaced By**: Built-in verification in v2.2.4 installer

**Reason for Archival**:
- Checks for TMWS components no longer used in v2.2.4
- v2.2.4 installer includes built-in verification
- Plugin installation provides automatic validation
- Manual verification steps documented in README.md

**Historical Context**:
This script provided comprehensive installation verification for v2.2.0:
- TMWS service health checks
- Database connectivity validation
- Redis connection testing
- Hook system verification

## Current Active Scripts

For current installation methods, use:

### Claude Code (Recommended)
- **Primary**: `install_trinitas_config_v2.2.4.sh`
  - Mem0 MCP-based semantic memory
  - Ollama embeddings (no API key required)
  - Interactive setup with multiple providers

### Open Code
- **Dedicated**: `install_opencode.sh`
  - Open Code-specific configuration
  - Agent definitions only (no plugin support)
  - Simplified installation

### Plugin Installation (Automated)
- **Auto-setup**: `scripts/setup_mem0_auto.sh`
  - Executed by Claude Code Plugin system
  - Zero user interaction required
  - Automatic Ollama + Mem0 setup

## Migration Notes

If you're using a TMWS-based installation:
1. See [MIGRATION.md](../../../MIGRATION.md) for detailed migration guide
2. Run `install_trinitas_config_v2.2.4.sh` for clean v2.2.4 setup
3. Mem0 provides better performance with simpler architecture

## Why Archive Instead of Delete?

These scripts are preserved for:
1. **Historical Reference**: Understanding system evolution
2. **Migration Support**: Helping users understand changes from old versions
3. **Git History**: Maintaining complete project history
4. **Learning**: Examples of different architecture approaches

---

**Archived**: Phase 1 Day 5 (2025-10-15)
**Part of**: Trinitas v2.2.4 Code Quality Remediation
