# TMWS README.md に追加するセクション

## 🏛️ Trinitas Agents (v2.4.0+)

TMWS v2.4.0+ includes **Trinitas Agents** - a system of 6 specialized AI personas for enhanced multi-agent coordination.

### Available Personas

| Persona | Role | Specialization |
|---------|------|----------------|
| 🏛️ **Athena** | Harmonious Conductor | Orchestration, workflow automation |
| 🏹 **Artemis** | Technical Perfectionist | Performance optimization, code quality |
| 🔥 **Hestia** | Security Guardian | Security audit, vulnerability assessment |
| ⚔️ **Eris** | Tactical Coordinator | Team coordination, conflict resolution |
| 🎭 **Hera** | Strategic Commander | Strategic planning, architecture design |
| 📚 **Muses** | Knowledge Architect | Documentation, knowledge management |

### License Requirements

| License Tier | Trinitas Status | Content Level |
|--------------|-----------------|---------------|
| **FREE** | ❌ Disabled | N/A |
| **PRO** | ✅ Enabled | 85% content |
| **ENTERPRISE** | ✅ Enabled | 100% content |

### Quick Start

```bash
# 1. Enable Trinitas in .env
echo "TMWS_ENABLE_TRINITAS=true" >> .env

# 2. Deploy with Docker
docker-compose up -d

# 3. Verify startup logs
docker logs tmws | grep "Trinitas"
# Expected output:
# ✅ Trinitas Agents loaded successfully
#    Tier: PRO
#    Agents loaded: 6/6
```

### Integration Details

Trinitas was **fully integrated** from the [trinitas-agents](https://github.com/apto-as/trinitas-agents) repository (now archived) via Git Subtree merge on 2025-11-18.

**Features**:
- License-gated agent loading
- DB-based generation with tier filtering
- SHA-256 integrity verification
- Docker bytecode protection (9.2/10)

**Documentation**: See [docs/trinitas/](./docs/trinitas/) for detailed guides.

---
