# Trinitas v2.2.4 Test Plan

## Overview

This document outlines the comprehensive testing strategy for Trinitas v2.2.4 (Mem0 MCP integration).

**Test Scope**: Feature branch `feature/v2.2.4-mem0-integration`

**Test Environment**:
- macOS (primary)
- Linux (secondary)
- Claude Code latest version
- Open Code (optional)

---

## Test Categories

### 1. Installation Tests

#### 1.1 Plugin Installation Test (Primary Method)

**Objective**: Verify 1-command Plugin installation works correctly

**Prerequisites**:
- Claude Code with Plugin support
- Clean environment (no existing Trinitas installation)

**Test Steps**:
```bash
# Test A: Plugin marketplace installation
1. In Claude Code, run: /plugin marketplace add https://github.com/apto-as/trinitas-agents
2. Verify marketplace entry appears
3. Run: /plugin install trinitas-agents
4. Wait for automatic setup to complete (Ollama + Mem0)
5. Verify success message
```

**Expected Results**:
- ✅ Marketplace entry added successfully
- ✅ Plugin installation completes without errors
- ✅ Ollama installed and running
- ✅ nomic-embed-text model downloaded
- ✅ Mem0 MCP server installed
- ✅ Six agents activated
- ✅ MCP configuration generated at ~/.claude/mcp_servers.json

**Verification**:
```bash
# Check Ollama
ollama list | grep nomic-embed-text

# Check Mem0
pip3 show mem0ai

# Check MCP config
cat ~/.claude/mcp_servers.json | grep openmemory

# Check agents
ls ~/.claude/agents/ | grep -E "(athena|artemis|hestia|eris|hera|muses)"
```

**Pass Criteria**: All expected results achieved, installation time < 10 minutes

---

#### 1.2 Manual Installation Test (Secondary Method)

**Objective**: Verify manual installation script works correctly

**Prerequisites**:
- Clean environment (no existing Trinitas installation)
- Git installed

**Test Steps**:
```bash
# Test B: Manual installation
1. git clone https://github.com/apto-as/trinitas-agents.git
2. cd trinitas-agents
3. git checkout feature/v2.2.4-mem0-integration
4. chmod +x install_trinitas_config_v2.2.4.sh
5. ./install_trinitas_config_v2.2.4.sh --yes
6. Verify all components installed
```

**Expected Results**:
- ✅ Script completes successfully
- ✅ Ollama installed (if not already present)
- ✅ Embedding model downloaded
- ✅ Mem0 installed
- ✅ MCP configuration created
- ✅ All 6 agents installed

**Pass Criteria**: Same as Plugin installation, installation time < 10 minutes

---

### 2. Functional Tests

#### 2.1 Memory Operations Test

**Objective**: Verify Mem0 semantic memory works correctly

**Test Cases**:

**Test 2.1.1: Save Memory**
```
Input: "Remember this: We use TypeScript for development"
Expected: Success confirmation from Claude
```

**Test 2.1.2: Recall Memory (Exact Match)**
```
Input: "What programming language do we use?"
Expected: Claude responds "TypeScript"
```

**Test 2.1.3: Semantic Search**
```
Input: "Tell me about our technology stack"
Expected: Claude mentions TypeScript (and any other saved technologies)
```

**Test 2.1.4: Multiple Memories**
```
Input 1: "Remember: We use React for frontend"
Input 2: "Remember: We use PostgreSQL for database"
Query: "What technologies do we use?"
Expected: Claude mentions TypeScript, React, PostgreSQL
```

**Pass Criteria**: All memory operations work correctly, recall accuracy > 90%

---

#### 2.2 Agent Activation Test

**Objective**: Verify all six agents are properly activated

**Test Cases**:

**Test 2.2.1: Athena (Harmonious Conductor)**
```
Input: "Use Athena to design the system architecture"
Expected: Athena responds with architectural analysis
```

**Test 2.2.2: Artemis (Technical Perfectionist)**
```
Input: "Have Artemis optimize this code: [code snippet]"
Expected: Artemis provides optimization suggestions
```

**Test 2.2.3: Hestia (Security Guardian)**
```
Input: "Get Hestia to review security vulnerabilities"
Expected: Hestia performs security analysis
```

**Test 2.2.4: Eris (Tactical Coordinator)**
```
Input: "Use Eris to coordinate team tasks"
Expected: Eris provides tactical coordination
```

**Test 2.2.5: Hera (Strategic Commander)**
```
Input: "Have Hera plan the long-term strategy"
Expected: Hera provides strategic planning
```

**Test 2.2.6: Muses (Knowledge Architect)**
```
Input: "Get Muses to document this system"
Expected: Muses creates documentation
```

**Pass Criteria**: All 6 agents respond appropriately with persona-specific behavior

---

#### 2.3 Protocol Injector Test

**Objective**: Verify protocol_injector.py v2.2.4 works correctly

**Test Cases**:

**Test 2.3.1: Session Start Hook**
```bash
# Execute protocol injector manually
python3 ~/.claude/hooks/core/protocol_injector.py

# Expected: JSON output with systemMessage containing:
# - Trinitas v2.2.4 version string
# - Core memory loaded
# - Athena + Hera agents mentioned
# - No TMWS references
```

**Test 2.3.2: Pre-Compact Hook**
```bash
python3 ~/.claude/hooks/core/protocol_injector.py pre_compact

# Expected: Compact summary with:
# - Trinitas v2.2.4 version
# - Level 3 summary
# - No TMWS references
```

**Pass Criteria**: Both hooks execute successfully, output contains correct version, no TMWS references

---

### 3. Integration Tests

#### 3.1 Ollama Integration Test

**Objective**: Verify Ollama embeddings work correctly with Mem0

**Test Steps**:
```bash
# 1. Check Ollama service
brew services list | grep ollama  # macOS
sudo systemctl status ollama      # Linux

# 2. Verify model
ollama list | grep nomic-embed-text

# 3. Test embedding generation
curl http://localhost:11434/api/embeddings -d '{
  "model": "nomic-embed-text",
  "prompt": "test embedding"
}'
```

**Expected Results**:
- ✅ Ollama service running
- ✅ nomic-embed-text model available
- ✅ Embedding API responds with vector data

**Pass Criteria**: Ollama integration functional, embedding generation successful

---

#### 3.2 MCP Server Integration Test

**Objective**: Verify Mem0 MCP server communication

**Test Steps**:
```bash
# 1. Check if MCP server is configured
cat ~/.claude/mcp_servers.json | grep openmemory

# 2. Test MCP server connectivity (via Claude Code)
# Ask Claude: "Is the MCP server connected?"
# Expected: Claude should be able to access memory functions

# 3. Check MCP server logs
tail -f ~/.trinitas/mem0/logs/mem0.log  # If log file exists
```

**Expected Results**:
- ✅ MCP configuration exists
- ✅ Claude Code can communicate with MCP server
- ✅ No connection errors in logs

**Pass Criteria**: MCP server communication stable, no errors

---

### 4. Regression Tests

#### 4.1 TMWS Removal Verification

**Objective**: Ensure all TMWS references are removed

**Test Steps**:
```bash
# Search for TMWS references in codebase
grep -r "tmws" --include="*.py" --include="*.md" hooks/
grep -r "TMWS" --include="*.py" --include="*.md" hooks/

# Expected: No matches (except in documentation about migration)
```

**Expected Results**:
- ❌ No TMWS references in protocol_injector.py
- ❌ No TMWS context in context profiles
- ✅ TMWS only mentioned in MIGRATION.md

**Pass Criteria**: No active TMWS code references

---

#### 4.2 Backward Compatibility Test

**Objective**: Verify existing features still work

**Test Cases**:

**Test 4.2.1: Memory Cookbook Integration**
```
# Verify Memory Cookbook structure still exists
ls ~/.claude/memory/core/
ls ~/.claude/memory/agents/

# Expected: Directories exist and contain files
```

**Test 4.2.2: DF2 Behavioral Modifiers**
```bash
# Check if DF2 integration is preserved
grep -A 5 "load_df2_modifiers" hooks/core/protocol_injector.py

# Expected: Function still exists (even if not actively used)
```

**Pass Criteria**: Existing features preserved, no regressions

---

### 5. Performance Tests

#### 5.1 Setup Time Measurement

**Objective**: Verify 83% faster setup claim

**Test Steps**:
```bash
# Measure installation time
time ./install_trinitas_config_v2.2.4.sh --yes

# Expected: < 5 minutes for Plugin method
# Expected: < 10 minutes for Manual method
```

**Pass Criteria**:
- Plugin installation: < 10 minutes
- Manual installation: < 15 minutes

---

#### 5.2 Memory Query Performance

**Objective**: Verify memory operations are fast

**Test Steps**:
```
1. Save 100 test memories
2. Measure recall time for semantic search
3. Compare with baseline
```

**Expected Results**:
- Memory save: < 200ms per memory
- Memory recall: < 100ms per query
- Semantic search: < 500ms for 100 memories

**Pass Criteria**: Performance within expected ranges

---

### 6. Security Tests

#### 6.1 Data Privacy Verification

**Objective**: Verify all data stays local (Ollama mode)

**Test Steps**:
```bash
# 1. Monitor network traffic during memory operations
# (Use tcpdump or Wireshark)

# 2. Verify no external API calls
# Expected: Only localhost traffic (11434, 8765)

# 3. Check data directory permissions
ls -la ~/.trinitas/mem0/data
# Expected: 700 (owner read/write/execute only)
```

**Expected Results**:
- ✅ No external network traffic (except Ollama install)
- ✅ All data stored locally
- ✅ Secure file permissions

**Pass Criteria**: 100% local operation verified in Ollama mode

---

#### 6.2 Input Validation Test

**Objective**: Verify secure input handling

**Test Cases**:

**Test 6.2.1: SQL Injection Prevention**
```
Input: "Remember: '; DROP TABLE memories; --"
Expected: Stored safely, no SQL injection
```

**Test 6.2.2: XSS Prevention**
```
Input: "Remember: <script>alert('xss')</script>"
Expected: Sanitized or escaped, no XSS vulnerability
```

**Test 6.2.3: Path Traversal Prevention**
```
Input: "Remember: ../../../../etc/passwd"
Expected: No path traversal, file stays in designated directory
```

**Pass Criteria**: All malicious inputs handled safely

---

### 7. Compatibility Tests

#### 7.1 Open Code Compatibility

**Objective**: Verify Trinitas works with Open Code

**Test Steps**:
```bash
# 1. Install Trinitas for Open Code
./install_opencode.sh  # If script exists

# 2. Verify MCP configuration
cat ~/.opencode/opencode.json | grep openmemory

# 3. Test memory operations in Open Code
```

**Expected Results**:
- ✅ Installation succeeds for Open Code
- ✅ MCP configuration updated
- ✅ Memory operations work

**Pass Criteria**: Open Code compatibility maintained

---

#### 7.2 Cross-Platform Test

**Objective**: Verify installation works on different platforms

**Platforms**:
- macOS (Intel)
- macOS (Apple Silicon)
- Linux (Ubuntu 22.04+)
- Linux (Fedora 38+)

**Test Steps**:
```bash
# Run installation on each platform
./install_trinitas_config_v2.2.4.sh --yes

# Verify all components work
```

**Pass Criteria**: Installation successful on all supported platforms

---

## Test Execution Plan

### Phase 1: Smoke Tests (Day 1)
- [ ] Installation Test 1.1 (Plugin)
- [ ] Installation Test 1.2 (Manual)
- [ ] Memory Operations Test 2.1
- [ ] Agent Activation Test 2.2

### Phase 2: Integration Tests (Day 2)
- [ ] Ollama Integration Test 3.1
- [ ] MCP Server Integration Test 3.2
- [ ] Protocol Injector Test 2.3

### Phase 3: Regression & Performance (Day 3)
- [ ] TMWS Removal Verification 4.1
- [ ] Backward Compatibility Test 4.2
- [ ] Performance Tests 5.1, 5.2

### Phase 4: Security & Compatibility (Day 4)
- [ ] Security Tests 6.1, 6.2
- [ ] Compatibility Tests 7.1, 7.2

---

## Test Reporting

### Test Result Template

```markdown
## Test: [Test ID] - [Test Name]

**Date**: YYYY-MM-DD
**Tester**: [Name]
**Environment**: [OS, Claude Code version]

**Result**: PASS / FAIL / BLOCKED

**Details**:
- Step 1: [Result]
- Step 2: [Result]
- ...

**Issues Found**:
- [Issue description]

**Screenshots/Logs**:
[Attach if applicable]
```

### Bug Report Template

```markdown
## Bug: [Bug ID] - [Bug Title]

**Severity**: Critical / High / Medium / Low

**Steps to Reproduce**:
1. [Step 1]
2. [Step 2]
3. ...

**Expected Behavior**:
[Description]

**Actual Behavior**:
[Description]

**Environment**:
- OS: [macOS / Linux]
- Trinitas Version: v2.2.4
- Claude Code Version: [Version]
- Ollama Version: [Version if applicable]

**Logs**:
```
[Paste relevant logs]
```

**Screenshots**:
[Attach if applicable]
```

---

## Acceptance Criteria

### Must Pass (Blocking)
- ✅ Plugin installation test (1.1)
- ✅ Memory operations test (2.1)
- ✅ All 6 agents activation test (2.2)
- ✅ Ollama integration test (3.1)
- ✅ TMWS removal verification (4.1)

### Should Pass (Non-Blocking)
- ⚠️ Manual installation test (1.2)
- ⚠️ Performance tests (5.1, 5.2)
- ⚠️ Open Code compatibility (7.1)

### Nice to Have
- 💡 Cross-platform tests (7.2)
- 💡 Advanced security tests (6.2)

---

## Rollback Plan

If critical issues are found:

1. **Revert Commit**
   ```bash
   git revert 3ebda1d
   git push origin feature/v2.2.4-mem0-integration
   ```

2. **Notify Users**
   - Update GitHub issues
   - Post in discussions
   - Update README with known issues

3. **Fix and Re-test**
   - Address critical bugs
   - Re-run failed tests
   - Verify fixes

---

## Sign-Off

**Test Lead**: [Name]
**Date**: [Date]
**Status**: [Pending / In Progress / Complete]

**Summary**:
- Tests Passed: [X/Y]
- Tests Failed: [Z]
- Blocked: [W]

**Recommendation**: [Approve for merge / Requires fixes / Reject]

---

*This test plan covers comprehensive testing for Trinitas v2.2.4 with Mem0 MCP integration. All tests should be executed before merging to main branch.*
