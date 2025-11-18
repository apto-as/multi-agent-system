# TMWS v2.3.0 Troubleshooting Guide

**Version**: v2.3.0
**Date**: 2024-11-04
**Audience**: Trinitas Users & Developers

---

## Table of Contents
1. [Common Issues](#common-issues)
2. [Error Messages](#error-messages)
3. [Diagnostic Commands](#diagnostic-commands)
4. [Performance Issues](#performance-issues)
5. [Data Issues](#data-issues)
6. [Recovery Procedures](#recovery-procedures)

---

## Common Issues

### 1. Hook Not Executing

**Symptoms**:
- No logs from `decision_check.py` or `precompact_memory_injection.py`
- Memories not being recorded
- No memory injection before compaction

**Diagnostic Steps**:

```bash
# Step 1: Check if hooks are installed
ls -la ~/.claude/hooks/core/ | grep -E "(decision_check|precompact)"

# Step 2: Check if hooks are registered in settings
cat ~/.claude/hooks/settings.json | grep -E "(decision_check|precompact)"

# Step 3: Check file permissions
ls -la ~/.claude/hooks/core/decision_check.py
ls -la ~/.claude/hooks/core/precompact_memory_injection.py

# Step 4: Test hook execution manually
echo '{"prompt": {"text": "test"}}' | python3 ~/.claude/hooks/core/decision_check.py
```

**Solutions**:

1. **Reinstall Hooks**:
   ```bash
   cd /path/to/trinitas-agents/
   ./install_trinitas_config.sh
   ```

2. **Fix Permissions**:
   ```bash
   chmod +x ~/.claude/hooks/core/decision_check.py
   chmod +x ~/.claude/hooks/core/precompact_memory_injection.py
   ```

3. **Verify Python Path**:
   ```bash
   which python3
   # Update shebang in hooks if needed
   ```

---

### 2. TMWS Connection Failed

**Symptoms**:
- Error: "Failed to connect to TMWS MCP Server"
- Timeout errors in logs
- Memories not persisting across sessions

**Diagnostic Steps**:

```bash
# Step 1: Check if TMWS MCP Server is running
curl http://localhost:8000/health
# Expected: {"status": "healthy"}

# Step 2: Check MCP configuration
cat ~/.claude/settings.json | grep -A 5 tmws

# Step 3: Check TMWS logs
tail -50 ~/.tmws/logs/server.log
```

**Solutions**:

1. **Start TMWS MCP Server**:
   ```bash
   # Option A: Using systemd (Linux)
   systemctl --user start tmws-mcp-server

   # Option B: Manual start
   tmws-mcp-server start

   # Option C: Docker
   docker start tmws-mcp-server
   ```

2. **Fix MCP Configuration**:
   Edit `~/.claude/settings.json`:
   ```json
   {
     "mcpServers": {
       "tmws": {
         "command": "tmws-mcp-server",
         "args": [],
         "env": {
           "TMWS_AGENT_ID": "trinitas-default",
           "TMWS_NAMESPACE": "default"
         }
       }
     }
   }
   ```

3. **Check Firewall**:
   ```bash
   # Allow localhost:8000
   sudo ufw allow from 127.0.0.1 to 127.0.0.1 port 8000
   ```

---

### 3. No Memories Injected

**Symptoms**:
- PreCompact hook runs without errors
- No `<system-reminder>` blocks visible
- Agent doesn't recall past conversations

**Diagnostic Steps**:

```bash
# Step 1: Check if memories exist
python3 << EOF
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / ".claude/hooks/core"))
from decision_memory import TrinitasDecisionMemory

async def check():
    mem = TrinitasDecisionMemory()
    results = await mem.query_similar_decisions("test query", limit=10)
    print(f"Found {len(results)} memories in TMWS")
    for r in results[:3]:
        print(f"  - {r.decision_id}: {r.context[:50]}...")

asyncio.run(check())
EOF

# Step 2: Check similarity threshold
grep "min_similarity" ~/.claude/hooks/core/precompact_memory_injection.py

# Step 3: Check TMWS database
ls -lh ~/.tmws/data/
```

**Solutions**:

1. **Lower Similarity Threshold** (temporarily for testing):
   Edit `~/.claude/hooks/core/precompact_memory_injection.py`:
   ```python
   # Change from:
   min_similarity=0.7

   # To:
   min_similarity=0.5  # More lenient
   ```

2. **Verify Memory Recording**:
   ```bash
   # Watch logs while submitting prompts
   tail -f ~/.claude/logs/hooks.log | grep decision_check
   ```

3. **Check ChromaDB**:
   ```bash
   python3 << EOF
   import chromadb
   client = chromadb.PersistentClient(path=str(Path.home() / ".tmws/chroma"))
   collections = client.list_collections()
   print(f"Collections: {[c.name for c in collections]}")

   if collections:
       coll = collections[0]
       print(f"Collection '{coll.name}' has {coll.count()} items")
   EOF
   ```

---

### 4. Rate Limiting Errors

**Symptoms**:
- Error: "Rate limit exceeded. Retry after Xs"
- Hook execution rejected
- Logs show many rapid requests

**Diagnostic Steps**:

```bash
# Check rate limiter settings
grep -A 5 "ThreadSafeRateLimiter" ~/.claude/hooks/core/decision_check.py
```

**Solutions**:

1. **Increase Rate Limit** (if legitimate usage):
   Edit `~/.claude/hooks/core/decision_check.py`:
   ```python
   # Change from:
   self.rate_limiter = ThreadSafeRateLimiter(
       max_calls=100,
       window_seconds=60,
       burst_size=10
   )

   # To:
   self.rate_limiter = ThreadSafeRateLimiter(
       max_calls=200,  # Doubled
       window_seconds=60,
       burst_size=20   # Doubled
   )
   ```

2. **Check for Loops**:
   ```bash
   # If you see rapid-fire requests, check for infinite loops
   ps aux | grep python | grep claude
   ```

---

### 5. Import Errors

**Symptoms**:
- Error: "No module named 'httpx'" or similar
- Hook crashes on startup
- Missing dependencies

**Diagnostic Steps**:

```bash
# Step 1: Check Python environment
python3 -c "import httpx, aiofiles, chromadb; print('All imports OK')"

# Step 2: Check installed packages
pip3 list | grep -E "(httpx|aiofiles|chromadb)"
```

**Solutions**:

1. **Install Missing Dependencies**:
   ```bash
   pip3 install httpx aiofiles chromadb sentence-transformers
   ```

2. **Use Virtual Environment**:
   ```bash
   # Create venv for Claude hooks
   python3 -m venv ~/.claude/venv
   source ~/.claude/venv/bin/activate
   pip3 install -r ~/.claude/requirements.txt

   # Update hook shebang
   # Change: #!/usr/bin/env python3
   # To: #!/Users/your-user/.claude/venv/bin/python3
   ```

---

## Error Messages

### Error: "Symlink access denied (CWE-61)"

**Meaning**: Security check detected symlink traversal attempt

**Solution**: This is a security feature. If legitimate, update `security_utils.py`:
```python
# Add allowed symlink path
ALLOWED_SYMLINK_PATHS = [
    "/path/to/legitimate/symlink"
]
```

---

### Error: "JSON parsing or validation error"

**Meaning**: Malformed JSON input to hook

**Diagnostic**:
```bash
# Check stdin data format
cat > test_input.json << EOF
{"prompt": {"text": "test"}}
EOF

python3 ~/.claude/hooks/core/decision_check.py < test_input.json
```

**Solution**: Update `safe_json_parse` limits if needed

---

### Error: "Failed to record decision: [...]"

**Meaning**: TMWS write operation failed

**Diagnostic**:
```bash
# Check TMWS write permissions
ls -la ~/.tmws/data/
touch ~/.tmws/data/test_write && rm ~/.tmws/data/test_write

# Check disk space
df -h ~/.tmws/
```

**Solution**: Fix permissions or free up disk space

---

## Diagnostic Commands

### Full System Check

```bash
#!/bin/bash
echo "=== TMWS v2.3.0 System Diagnostic ==="
echo ""

echo "1. Hook Files:"
ls -lh ~/.claude/hooks/core/{decision_check,precompact_memory_injection}.py

echo ""
echo "2. Hook Registration:"
grep -E "(decision_check|precompact)" ~/.claude/hooks/settings.json

echo ""
echo "3. TMWS MCP Server:"
curl -s http://localhost:8000/health || echo "❌ TMWS not responding"

echo ""
echo "4. Python Dependencies:"
python3 -c "import httpx, aiofiles, chromadb; print('✅ All imports OK')" || echo "❌ Missing dependencies"

echo ""
echo "5. TMWS Database:"
ls -lh ~/.tmws/data/*.db ~/.tmws/chroma/ 2>/dev/null || echo "⚠️ No database files found"

echo ""
echo "6. Recent Logs:"
tail -10 ~/.claude/logs/hooks.log 2>/dev/null || echo "⚠️ No logs found"

echo ""
echo "=== Diagnostic Complete ==="
```

---

### Memory Count Check

```bash
python3 << 'EOF'
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / ".claude/hooks/core"))
from decision_memory import TrinitasDecisionMemory

async def check():
    mem = TrinitasDecisionMemory()

    # Total count
    all_memories = await mem.query_similar_decisions("", limit=1000)
    print(f"Total memories: {len(all_memories)}")

    # By persona
    personas = {}
    for m in all_memories:
        personas[m.persona] = personas.get(m.persona, 0) + 1

    print("\nBy Persona:")
    for persona, count in sorted(personas.items(), key=lambda x: -x[1]):
        print(f"  {persona}: {count}")

    # By decision type
    types = {}
    for m in all_memories:
        types[m.decision_type.value] = types.get(m.decision_type.value, 0) + 1

    print("\nBy Decision Type:")
    for dtype, count in sorted(types.items(), key=lambda x: -x[1]):
        print(f"  {dtype}: {count}")

asyncio.run(check())
EOF
```

---

### Performance Profiling

```bash
# Enable debug logging
export TMWS_DEBUG=1

# Run hook with timing
time echo '{"prompt": {"text": "optimize database"}}' | \
  python3 ~/.claude/hooks/core/decision_check.py

# Check timing breakdown
grep "took" ~/.claude/logs/hooks.log | tail -20
```

---

## Performance Issues

### Hook Execution Too Slow (>500ms)

**Diagnostic**:
```bash
# Profile hook execution
python3 -m cProfile -o decision_check.prof \
  ~/.claude/hooks/core/decision_check.py < test_input.json

# Analyze profile
python3 << EOF
import pstats
stats = pstats.Stats('decision_check.prof')
stats.sort_stats('cumulative')
stats.print_stats(20)
EOF
```

**Solutions**:

1. **Reduce Search Limit**:
   ```python
   # In precompact_memory_injection.py
   memories = await self.decision_memory.query_similar_decisions(
       query=query,
       limit=3,  # Reduced from 5
       min_similarity=0.7
   )
   ```

2. **Increase Timeout**:
   ```python
   # In hook initialization
   self.decision_memory = TrinitasDecisionMemory(
       timeout=0.5  # Increased from 0.3
   )
   ```

3. **Use Faster Embedding Model**:
   - Switch from `multilingual-e5-large` to `multilingual-e5-base`
   - Trade-off: Slightly lower quality, much faster

---

### High Memory Usage

**Diagnostic**:
```bash
# Monitor Python process
ps aux | grep "decision_check\|precompact" | awk '{print $4, $6, $11}'
```

**Solutions**:

1. **Reduce Cache Size**:
   ```python
   self.decision_memory = TrinitasDecisionMemory(
       cache_size=50  # Reduced from 100
   )
   ```

2. **Clear Cache Periodically**:
   ```bash
   # Add to crontab
   0 */6 * * * rm -f ~/.tmws/cache/*
   ```

---

## Data Issues

### Duplicate Memories

**Diagnostic**:
```bash
python3 << 'EOF'
import asyncio
from pathlib import Path
import sys
sys.path.insert(0, str(Path.home() / ".claude/hooks/core"))
from decision_memory import TrinitasDecisionMemory

async def check_duplicates():
    mem = TrinitasDecisionMemory()
    memories = await mem.query_similar_decisions("", limit=1000)

    contexts = {}
    for m in memories:
        ctx_hash = hash(m.context[:100])
        if ctx_hash in contexts:
            print(f"Duplicate found:")
            print(f"  ID 1: {contexts[ctx_hash]}")
            print(f"  ID 2: {m.decision_id}")
            print(f"  Context: {m.context[:100]}...")
        else:
            contexts[ctx_hash] = m.decision_id

asyncio.run(check_duplicates())
EOF
```

**Solution**: Deduplication is built-in, but if duplicates persist:
```python
# Manual cleanup script
# Contact Muses for assistance
```

---

### Corrupted Database

**Symptoms**:
- SQLite errors
- ChromaDB index errors
- Inconsistent data

**Recovery**:
```bash
# Backup first
cp -r ~/.tmws/data ~/.tmws/data.backup.$(date +%Y%m%d)

# Option 1: Rebuild ChromaDB index
python3 << EOF
import chromadb
client = chromadb.PersistentClient(path="~/.tmws/chroma")
# Recreate collection (requires re-embedding all data)
EOF

# Option 2: Restore from backup
rm -rf ~/.tmws/data
cp -r ~/.tmws/data.backup.YYYYMMDD ~/.tmws/data
```

---

## Recovery Procedures

### Complete Reset (Nuclear Option)

⚠️ **WARNING**: This deletes all memories! Backup first!

```bash
# Backup
tar -czf ~/tmws-backup-$(date +%Y%m%d).tar.gz ~/.tmws/

# Delete data
rm -rf ~/.tmws/data/*.db ~/.tmws/chroma/

# Restart TMWS
tmws-mcp-server restart

# Verify clean state
python3 << EOF
import asyncio
from decision_memory import TrinitasDecisionMemory

async def check():
    mem = TrinitasDecisionMemory()
    results = await mem.query_similar_decisions("test", limit=10)
    print(f"Memory count: {len(results)} (should be 0)")

asyncio.run(check())
EOF
```

---

### Restore from Backup

```bash
# Stop TMWS
tmws-mcp-server stop

# Restore data
tar -xzf ~/tmws-backup-20241104.tar.gz -C ~/

# Restart TMWS
tmws-mcp-server start

# Verify restoration
python3 << EOF
import asyncio
from decision_memory import TrinitasDecisionMemory

async def check():
    mem = TrinitasDecisionMemory()
    results = await mem.query_similar_decisions("", limit=10)
    print(f"Restored {len(results)} memories")

asyncio.run(check())
EOF
```

---

## Support

### Getting Help

1. **Check Logs**:
   ```bash
   tail -100 ~/.claude/logs/hooks.log
   tail -100 ~/.tmws/logs/server.log
   ```

2. **Run Diagnostics**:
   ```bash
   bash diagnostic_script.sh > diagnostic_output.txt
   ```

3. **Contact Team**:
   - **Technical Issues**: Artemis (Technical Optimizer)
   - **Security Concerns**: Hestia (Security Guardian)
   - **Data Issues**: Muses (Knowledge Architect)
   - **General Questions**: Athena (Harmonious Conductor)

### Useful Resources

- **Integration Guide**: `docs/TMWS_v2.3.0_INTEGRATION_GUIDE.md`
- **TMWS Documentation**: `docs/TMWS_INQUIRY_RESPONSE.md`
- **Test Scripts**: `tests/test_*.py`

---

**Document Version**: 1.0
**Last Updated**: 2024-11-04
**Authors**: Trinitas Team
**License**: MIT
