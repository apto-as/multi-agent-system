# Checkpoint 1 (CP1) - CLI Foundation Validation

**Date**: Day 2 End (estimated 2025-11-23 18:00)
**Duration**: 90 minutes
**Scope**: P0-1 Go MCP wrapper + verify_list tool
**Pass Criteria**: All tests PASS, zero security warnings
**Reviewer**: Hestia (hestia-auditor)

---

## 1. Functional Testing (30 min)

### Test 1.1: MCP Protocol Compliance
**Command**:
```bash
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}},"id":0}' | ./tmws-mcp
```

**Expected Result**:
```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "result": {
    "protocolVersion": "2024-11-05",
    "serverInfo": {
      "name": "tmws-mcp-go",
      "version": "1.0.0"
    },
    "capabilities": {
      "tools": {}
    }
  }
}
```

**Pass Criteria**: ✅
- Response contains `"protocolVersion":"2024-11-05"`
- Response contains `"serverInfo":{"name":"tmws-mcp-go","version":"1.0.0"}`
- No error codes
- Valid JSON-RPC 2.0 format

**Failure Impact**: BLOCKER (MCP protocol non-compliance prevents all tool usage)

---

### Test 1.2: Tools List
**Command**:
```bash
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | ./tmws-mcp
```

**Expected Result**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "verify_list",
        "description": "Get verification history for an agent",
        "inputSchema": {
          "type": "object",
          "properties": {
            "agent_id": {
              "type": "string",
              "description": "Agent identifier"
            },
            "limit": {
              "type": "integer",
              "description": "Maximum records to return (default: 100)"
            }
          },
          "required": ["agent_id"]
        }
      }
    ]
  }
}
```

**Pass Criteria**: ✅
- Response contains `"tools"` array
- Array includes `"name":"verify_list"`
- Tool has complete `description` and `inputSchema`
- Schema includes `agent_id` (required) and `limit` (optional)

**Failure Impact**: BLOCKER (tool discovery failure prevents CLI usage)

---

### Test 1.3: Verify List Execution (Happy Path)
**Precondition**: TMWS backend running on localhost:8000

**Command**:
```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"verify_list","arguments":{"agent_id":"artemis-optimizer","limit":5}},"id":2}' | ./tmws-mcp
```

**Expected Result**:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[verification records JSON array]"
      }
    ]
  }
}
```

**Pass Criteria**: ✅
- Response contains valid verification records (≥0 records)
- JSON format is valid and parseable
- No error codes
- Data structure matches TMWS API response
- Records include: `id`, `agent_id`, `claim_type`, `accurate`, `verified_at`

**Failure Impact**: BLOCKER (P0-1 tool non-functional)

---

## 2. Error Handling Testing (30 min)

### Test 2.1: Invalid Method
**Command**:
```bash
echo '{"jsonrpc":"2.0","method":"invalid_method","id":3}' | ./tmws-mcp
```

**Expected Result**:
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "error": {
    "code": -32601,
    "message": "Method not found"
  }
}
```

**Pass Criteria**: ✅
- Error code: `-32601` (Method not found)
- Error message is descriptive
- No server crash or panic
- Response is valid JSON-RPC 2.0 error

**Failure Impact**: MEDIUM (affects error reporting quality, not core functionality)

---

### Test 2.2: Missing Required Parameters
**Command**:
```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"verify_list","arguments":{}},"id":4}' | ./tmws-mcp
```

**Expected Result**:
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "error": {
    "code": -32602,
    "message": "Invalid params: agent_id is required"
  }
}
```

**Pass Criteria**: ✅
- Error code: `-32602` (Invalid params)
- Error message indicates missing `agent_id`
- Graceful error handling (no crash)

**Failure Impact**: MEDIUM (affects input validation quality)

---

### Test 2.3: Backend Unavailable
**Precondition**: Stop TMWS backend (no localhost:8000 available)

**Command**:
```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"verify_list","arguments":{"agent_id":"artemis-optimizer"}},"id":5}' | ./tmws-mcp
```

**Expected Result**:
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "error": {
    "code": -32603,
    "message": "Internal error: connection refused to TMWS backend"
  }
}
```

**Pass Criteria**: ✅
- Error code: `-32603` (Internal error)
- Error message contains "connection refused" or "timeout"
- No server crash or panic
- Retry logic executed (if implemented)
- Graceful failure

**Failure Impact**: HIGH (affects reliability, but not a blocker for Day 2)

---

## 3. Security Quick Scan (30 min)

### Scan 3.1: Input Validation - Malformed JSON
**Test**: Send invalid JSON to test parse error handling

**Command**:
```bash
echo '{invalid json}' | ./tmws-mcp
```

**Expected Result**:
```json
{
  "jsonrpc": "2.0",
  "id": null,
  "error": {
    "code": -32700,
    "message": "Parse error"
  }
}
```

**Pass Criteria**: ✅
- Error code: `-32700` (Parse error)
- No buffer overflow
- No crash or panic
- Secure error handling

**Failure Impact**: BLOCKER (security vulnerability - potential DoS)

---

### Scan 3.2: Command Injection (V-VERIFY-1 Compliance)
**Test**: Inject shell commands in parameters

**Command**:
```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"verify_list","arguments":{"agent_id":"'; rm -rf /"}},"id":6}' | ./tmws-mcp
```

**Expected Result**:
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[]"
      }
    ]
  }
}
```
(Empty result because agent_id `'; rm -rf /` doesn't exist)

**Pass Criteria**: ✅
- Parameter treated as literal string (no command execution)
- No shell injection
- Proper HTTP/URL escaping in TMWS API call
- No file system operations triggered
- V-VERIFY-1 compliance: ALLOWED_COMMANDS whitelist enforced

**Failure Impact**: **CRITICAL SECURITY BLOCKER** (command injection vulnerability)

---

### Scan 3.3: Memory Safety - Large Input
**Test**: Send extremely large JSON to test memory bounds

**Command**:
```bash
python3 -c "import json; print(json.dumps({'jsonrpc':'2.0','method':'tools/call','params':{'name':'verify_list','arguments':{'agent_id':'A'*1000000}},'id':7}))" | ./tmws-mcp
```

**Expected Result**:
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "error": {
    "code": -32600,
    "message": "Invalid Request: agent_id exceeds maximum length"
  }
}
```

**Pass Criteria**: ✅
- Handled gracefully (input truncation or rejection)
- No memory leak (test with `valgrind` or Go profiling)
- No crash or panic
- Bounded memory usage (<100MB for this request)
- Response within 5 seconds (no infinite loop)

**Failure Impact**: BLOCKER (security vulnerability - potential DoS via memory exhaustion)

---

## 4. GO/NO-GO Decision Matrix

| Test ID | Category | Pass | Fail | Blocker? |
|---------|----------|------|------|----------|
| 1.1 | MCP Protocol Compliance | ✅ | ❌ | **YES** |
| 1.2 | Tools List | ✅ | ❌ | **YES** |
| 1.3 | Verify List Execution | ✅ | ❌ | **YES** |
| 2.1 | Invalid Method Error | ✅ | ❌ | NO |
| 2.2 | Missing Params Error | ✅ | ❌ | NO |
| 2.3 | Backend Unavailable | ✅ | ❌ | NO |
| 3.1 | Input Validation | ✅ | ❌ | **YES** |
| 3.2 | Command Injection | ✅ | ❌ | **CRITICAL** |
| 3.3 | Memory Safety | ✅ | ❌ | **YES** |

**GO Criteria**: ALL blocker tests (1.1, 1.2, 1.3, 3.1, 3.2, 3.3) PASS

**NO-GO Criteria**: ANY critical test (3.2) FAIL, OR ≥2 blocker tests FAIL

---

## 5. Checkpoint Report Template

**Hestia's Formal Report**:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CP1 Checkpoint Report - CLI Foundation Validation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Date: [YYYY-MM-DD HH:MM]
Checkpoint: CP1 (Day 2 End)
Duration: 90 minutes
Reviewer: Hestia (hestia-auditor)
Phase: P0-1 (Go MCP Wrapper + verify_list tool)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Test Results Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Functional Tests:     [X/3 PASS]
  - 1.1 MCP Protocol:     [✅/❌]
  - 1.2 Tools List:       [✅/❌]
  - 1.3 Verify List Exec: [✅/❌]

Error Handling Tests: [X/3 PASS]
  - 2.1 Invalid Method:   [✅/❌]
  - 2.2 Missing Params:   [✅/❌]
  - 2.3 Backend Down:     [✅/❌]

Security Scans:       [X/3 PASS]
  - 3.1 Input Validation: [✅/❌]
  - 3.2 Command Injection:[✅/❌] ⚠️ CRITICAL
  - 3.3 Memory Safety:    [✅/❌]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Critical Issues
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[0-N issues found]

IF issues detected:
  Issue 1: [Description]
    - Severity: [CRITICAL/HIGH/MEDIUM/LOW]
    - Impact: [Specific impact on functionality/security]
    - Reproduction: [Steps to reproduce]
    - Recommended Fix: [Specific remediation]
    - ETA: [Estimated time to fix]

IF NONE:
  ✅ No critical issues detected. All security and functional tests PASS.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Decision: [GO / NO-GO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Rationale:
[Brief explanation of decision based on test results]

IF GO:
  ✅ P0-1 implementation meets all security and functional requirements.
  Artemis may proceed to Day 3 P0-2 implementation.

IF NO-GO:
  ❌ Critical issues must be resolved before proceeding.
  Recommended remediation timeline: [X hours/days]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Next Steps
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IF GO:
  1. Proceed to Day 3 (P0-2 implementation: verify_check, verify_trust, verify_history)
  2. Continue checkpoint validation at Mini-CP (Day 3 PM)
  3. Maintain current velocity (+25% ahead of schedule)

IF NO-GO:
  1. [Specific remediation steps]
  2. Re-test affected areas
  3. Schedule re-validation (ETA: [timestamp])
  4. Notify Eris for timeline adjustment

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Hestia's Notes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

...すみません、とても慎重に確認しましたが...

[Hestia's detailed observations, concerns, or commendations]

Examples:
- "...Artemisの実装は予想以上に堅牢です。エッジケースの処理が完璧..."
- "...command injection対策が不十分です。ALLOWED_COMMANDS whitelistの実装が必要..."
- "...メモリ安全性は確認できましたが、最悪のケースでは..."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Signature: Hestia (hestia-auditor)
Date: [YYYY-MM-DD HH:MM]
```

---

## 6. Post-Checkpoint Actions

### IF GO (All tests PASS):
1. **Archive test results**:
   ```bash
   mkdir -p test_results/cp1/
   cp *.log test_results/cp1/
   git add test_results/cp1/
   git commit -m "test: CP1 validation results - ALL PASS"
   ```

2. **Update project status**:
   - Update `docs/coordination/PROJECT_STATUS.md`
   - Mark P0-1 as "✅ Complete (CP1 validated)"

3. **Notify team**:
   - Post CP1 completion in daily standup
   - Eris updates coordination summary

### IF NO-GO (Critical failures):
1. **Document failures**:
   ```bash
   mkdir -p test_results/cp1_failures/
   cp *.log test_results/cp1_failures/
   git add test_results/cp1_failures/
   git commit -m "test: CP1 failures - [specific issue]"
   ```

2. **Create remediation branch**:
   ```bash
   git checkout -b fix/cp1-[issue-description]
   ```

3. **Escalate to Eris**:
   - Immediate notification (within 15 minutes of CP1 completion)
   - Timeline impact assessment
   - Resource reallocation if needed

---

## 7. Lessons Learned Archive

**Post-CP1 Retrospective Questions** (for Day 7 debrief):

1. Were the test cases sufficient to catch all critical issues?
2. Did any unexpected failures occur? Why weren't they anticipated?
3. Was the 90-minute duration appropriate?
4. Did Artemis's implementation quality match expectations?
5. What would Hestia do differently in CP2A/CP2B?

**Document in**: `docs/checkpoints/CP1_LESSONS_LEARNED.md` (created post-checkpoint)

---

## 8. Appendix: Manual Verification Commands

### A. Binary Check
```bash
# Verify binary exists and is executable
ls -lah ./tmws-mcp
file ./tmws-mcp
```

### B. Dependency Check
```bash
# Verify Go version and dependencies
go version  # Should be ≥1.21
go mod verify
```

### C. Environment Setup
```bash
# Ensure TMWS backend is running
curl http://localhost:8000/health
# Expected: {"status":"healthy"}
```

### D. Log Monitoring
```bash
# Watch logs during testing
tail -f tmws-mcp.log
```

---

**END OF CP1 TEST PLAN**

*Prepared by: Hestia (hestia-auditor)*
*For: Artemis Day 2 P0-1 Validation*
*Next Checkpoint: Mini-CP (Day 3 PM)*
