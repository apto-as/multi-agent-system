# TMWS Quick Start Guide
## Get Started with TMWS in 5 Minutes

**Version**: v2.3.0

---

## 🚀 Quick Start (MCP Server for Claude Code)

### Step 1: Install Prerequisites (2 minutes)

```bash
# Install Ollama (if not already installed)
# macOS:
brew install ollama

# Linux:
curl -fsSL https://ollama.ai/install.sh | sh

# Pull embedding model
ollama pull zylonai/multilingual-e5-large

# Start Ollama server
ollama serve
```

### Step 2: Install TMWS (1 minute)

```bash
# Clone and setup
git clone https://github.com/apto-as/tmws.git
cd tmws
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Initialize database
alembic upgrade head

# Set environment variables
export TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
export TMWS_SECRET_KEY="$(openssl rand -hex 32)"
export TMWS_ENVIRONMENT="development"
```

### Step 3: Configure Claude Code (1 minute)

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tmws": {
      "command": "/absolute/path/to/tmws/.venv/bin/python",
      "args": ["-m", "src.mcp_server"],
      "cwd": "/absolute/path/to/tmws",
      "env": {
        "TMWS_DATABASE_URL": "sqlite+aiosqlite:///./data/tmws.db",
        "TMWS_SECRET_KEY": "your-generated-secret-key",
        "TMWS_ENVIRONMENT": "development"
      }
    }
  }
}
```

**⚠️ Important**: Replace `/absolute/path/to/tmws` with actual path.

### Step 4: Test It! (1 minute)

Restart Claude Code, then try:

```bash
# Test 1: Get system status
/tmws get_memory_stats

# Test 2: Store a memory
/tmws store_memory \
  --content "TMWS installation completed successfully!" \
  --importance_score 0.9 \
  --tags "milestone,setup"

# Test 3: Search for it
/tmws search_memories --query "installation"
```

**Expected Output**:
```json
{
  "results": [
    {
      "content": "TMWS installation completed successfully!",
      "similarity": 0.98,
      "tags": ["milestone", "setup"]
    }
  ],
  "search_time_ms": 0.5
}
```

---

## 🎯 Essential Commands

### Store Information
```bash
/tmws store_memory \
  --content "Phase 1 API completed with all tests passing" \
  --importance_score 0.95 \
  --tags "milestone,phase1,api"
```

### Search Information
```bash
/tmws search_memories \
  --query "How did we implement authentication?" \
  --limit 5
```

### Create Task
```bash
/tmws create_task \
  --title "Implement Phase 2 features" \
  --priority "high" \
  --assigned_agent_id "artemis-optimizer"
```

### Verify Agent Claims
```bash
/tmws verify_and_record \
  --agent_id "artemis-optimizer" \
  --claim_type "test_result" \
  --claim_content '{"passed": 150, "failed": 0}' \
  --verification_command "pytest tests/unit/ -v"
```

### Check Agent Trust
```bash
/tmws get_agent_trust_score --agent_id "artemis-optimizer"
```

---

## 📊 Available Tools (21 Total)

| Category | Tools | Purpose |
|----------|-------|---------|
| **Core Memory** | 3 tools | store_memory, search_memories, create_task |
| **System** | 3 tools | get_agent_status, get_memory_stats, invalidate_cache |
| **Expiration** | 10 tools | Memory cleanup, TTL management, scheduler |
| **Verification** | 5 tools | Agent trust, verification, history |

**Full Documentation**: `docs/TMWS_USAGE_GUIDE.md`

---

## 🔧 Common Issues & Solutions

### Issue: "MCP server tmws failed to start"
**Solution**:
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Test MCP server manually
cd /path/to/tmws
source .venv/bin/activate
python -m src.mcp_server
```

### Issue: "Embedding service error"
**Solution**:
```bash
# Ensure model is installed
ollama pull zylonai/multilingual-e5-large
ollama list | grep multilingual-e5-large
```

### Issue: "Database is locked"
**Solution**:
```bash
# Enable WAL mode
sqlite3 data/tmws.db "PRAGMA journal_mode=WAL;"
```

---

## 🚀 Next Steps

1. **Read Full Guide**: `docs/TMWS_USAGE_GUIDE.md`
2. **Try Examples**: See "Common Use Cases" section
3. **Explore Tools**: Test all 21 MCP tools
4. **Set Up Automation**: Configure memory expiration scheduler
5. **Deploy to Production**: Follow `docs/deployment/MCP_API_DEPLOYMENT.md`

---

## 📚 Documentation

- **Complete Usage Guide**: `docs/TMWS_USAGE_GUIDE.md`
- **API Reference**: `docs/api/MCP_CONNECTION_API.md`
- **Authentication**: `docs/guides/AUTHENTICATION_GUIDE.md`
- **Rate Limiting**: `docs/guides/RATE_LIMITING_GUIDE.md`
- **Deployment**: `docs/deployment/MCP_API_DEPLOYMENT.md`

---

## 🎉 You're Ready!

TMWS is now running and integrated with Claude Code. Start storing memories, creating tasks, and building your knowledge base!

**Happy Knowledge Management! 🧠✨**
