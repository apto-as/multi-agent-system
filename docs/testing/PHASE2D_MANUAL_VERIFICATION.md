# Phase 2D Manual Verification Checklist
## TMWS v2.3.0 Security Implementation

**Purpose**: Manual verification of security features not covered by automated tests.
**Version**: v2.3.0
**Date**: 2025-11-05
**Status**: Pre-release verification required

---

## Overview

Phase 2D automated tests cover:
- ✅ 5 critical security tests (real DB)
- ✅ 15 mock-based unit tests
- ✅ Coverage: ~70% automated

This checklist covers:
- ⚠️ ~30% manual verification required
- ⚠️ Real-world MCP client scenarios
- ⚠️ Security edge cases and integration points

---

## Checklist Categories

### 1. Authentication Verification (REQ-1)

#### 1.1 API Key Authentication
- [ ] **Test**: Create agent with API key via MCP client
  - **Steps**: Use `create_agent` tool with generated API key
  - **Expected**: Agent created successfully, API key stored securely
  - **Verify**: API key not visible in response, only confirmation

- [ ] **Test**: Invoke MCP tool with valid API key
  - **Steps**: Call `search_memories` with valid API key in header
  - **Expected**: Tool executes successfully, returns results
  - **Verify**: Response includes data, no auth errors

- [ ] **Test**: Invoke MCP tool with invalid API key
  - **Steps**: Call `search_memories` with `X-API-Key: invalid-key-123`
  - **Expected**: Authentication error with clear message
  - **Verify**: Error message: "Invalid API key" OR "Authentication failed"

- [ ] **Test**: Invoke MCP tool with expired API key
  - **Steps**: Use API key expired >90 days ago
  - **Expected**: Authentication error with "API key expired" message
  - **Verify**: Error suggests regenerating API key

- [ ] **Test**: Invoke MCP tool with missing API key
  - **Steps**: Call tool without `X-API-Key` header
  - **Expected**: Authentication error "API key required"
  - **Verify**: Error indicates authentication method expected

#### 1.2 JWT Authentication
- [ ] **Test**: Generate JWT token for agent
  - **Steps**: Use token generation endpoint with agent credentials
  - **Expected**: Valid JWT token returned
  - **Verify**: Token contains agent_id, namespace claims

- [ ] **Test**: Invoke MCP tool with valid JWT
  - **Steps**: Call `store_memory` with `Authorization: Bearer <token>`
  - **Expected**: Tool executes successfully
  - **Verify**: Memory created with correct agent_id

- [ ] **Test**: Invoke MCP tool with expired JWT
  - **Steps**: Use JWT expired >24 hours ago
  - **Expected**: Authentication error "JWT expired"
  - **Verify**: Error suggests obtaining new token

- [ ] **Test**: Invoke MCP tool with tampered JWT
  - **Steps**: Modify JWT signature or payload
  - **Expected**: Authentication error "Invalid JWT signature"
  - **Verify**: Security audit log records tampering attempt

---

### 2. Authorization Verification (REQ-2, REQ-5)

#### 2.1 Namespace Isolation (CRITICAL - REQ-2)
- [ ] **Test**: Create Memory as Agent A in namespace "project-x"
  - **Steps**:
    1. Authenticate as `agent-a` (namespace: "project-x")
    2. Call `store_memory` with content "Secret data"
  - **Expected**: Memory created successfully
  - **Verify**: Memory has namespace="project-x"

- [ ] **Test**: Attempt to read Memory as Agent B in namespace "project-y"
  - **Steps**:
    1. Authenticate as `agent-b` (namespace: "project-y")
    2. Attempt to search for "Secret data" created by Agent A
  - **Expected**: Authorization error OR memory not in results
  - **Verify**: Cross-tenant access blocked completely

- [ ] **Test**: Share Memory from Agent A to Agent B
  - **Steps**:
    1. As Agent A, create memory with access_level="SHARED"
    2. Add Agent B to shared_with list
  - **Expected**: Memory shared successfully
  - **Verify**: Shared memory visible to Agent B

- [ ] **Test**: Agent B reads shared Memory
  - **Steps**: As Agent B, search for shared memory from Agent A
  - **Expected**: Success, memory content accessible
  - **Verify**: Only explicitly shared memories visible

- [ ] **Test**: Namespace in JWT claims vs database mismatch
  - **Steps**:
    1. Create JWT with namespace="project-x"
    2. Update agent in DB to namespace="project-y"
    3. Attempt tool invocation
  - **Expected**: Authorization uses DB namespace (project-y), not JWT claim
  - **Verify**: Security fix from Phase 2A enforced

#### 2.2 RBAC Enforcement (REQ-5)
- [ ] **Test**: Agent with AGENT role tries `configure_scheduler`
  - **Steps**: Authenticate as agent with role=AGENT, call tool
  - **Expected**: Authorization error "Insufficient permissions"
  - **Verify**: Error indicates SYSTEM_ADMIN role required

- [ ] **Test**: Agent with SYSTEM_ADMIN role tries `configure_scheduler`
  - **Steps**: Authenticate as agent with role=SYSTEM_ADMIN, call tool
  - **Expected**: Success OR "Scheduler not available" (acceptable)
  - **Verify**: No authorization error

- [ ] **Test**: Agent with AGENT role tries `cleanup_namespace`
  - **Steps**: Authenticate as agent with role=AGENT, call tool
  - **Expected**: Authorization error "Insufficient permissions"
  - **Verify**: Error indicates NAMESPACE_ADMIN or SYSTEM_ADMIN required

- [ ] **Test**: Agent with NAMESPACE_ADMIN tries `cleanup_namespace`
  - **Steps**: Authenticate as agent with role=NAMESPACE_ADMIN, call tool
  - **Expected**: Success, namespace cleaned
  - **Verify**: Only namespace-scoped data affected

- [ ] **Test**: Cross-namespace admin access
  - **Steps**:
    1. Authenticate as NAMESPACE_ADMIN in "project-x"
    2. Attempt to cleanup "project-y"
  - **Expected**: Authorization error OR only "project-x" cleaned
  - **Verify**: NAMESPACE_ADMIN cannot affect other namespaces

#### 2.3 Access Level Enforcement
- [ ] **Test**: PRIVATE memory access by non-owner
  - **Steps**:
    1. Agent A creates PRIVATE memory
    2. Agent B attempts to search/read
  - **Expected**: Memory not visible to Agent B
  - **Verify**: Privacy enforced

- [ ] **Test**: TEAM memory access within namespace
  - **Steps**:
    1. Agent A creates TEAM memory (namespace: "project-x")
    2. Agent C (same namespace) searches
  - **Expected**: Memory visible to Agent C
  - **Verify**: Team collaboration enabled

- [ ] **Test**: PUBLIC memory access across namespaces
  - **Steps**:
    1. Agent A creates PUBLIC memory
    2. Agent B (different namespace) searches
  - **Expected**: Memory visible to all agents
  - **Verify**: Public knowledge sharing works

---

### 3. Rate Limiting Verification (REQ-4)

#### 3.1 Normal Operation (Redis Available)
- [ ] **Test**: Invoke `prune_expired_memories` 5 times in 1 hour
  - **Steps**: Call tool 5 times with valid auth
  - **Expected**: All 5 requests succeed (limit: 5/hour)
  - **Verify**: Rate limit counter increments correctly

- [ ] **Test**: Invoke `prune_expired_memories` 6th time
  - **Steps**: Immediately call tool after 5th request
  - **Expected**: Rate limit error "Rate limit exceeded: 5 per hour"
  - **Verify**: Error includes retry-after guidance (e.g., "Try again in 45 minutes")

- [ ] **Test**: Wait for rate limit window to expire
  - **Steps**: Wait >1 hour, invoke tool again
  - **Expected**: Success, rate limit counter reset
  - **Verify**: New rate limit window started

- [ ] **Test**: Multiple agents with independent limits
  - **Steps**:
    1. Agent A calls tool 5 times (hits limit)
    2. Agent B calls same tool
  - **Expected**: Agent B succeeds (independent limit)
  - **Verify**: Rate limits are per-agent, not global

#### 3.2 FAIL-SECURE Fallback (Redis Unavailable)
- [ ] **Test**: Stop Redis and invoke rate-limited tool
  - **Steps**:
    1. Stop Redis: `docker stop redis` OR `systemctl stop redis`
    2. Call `prune_expired_memories`
  - **Expected**: Fallback to local limits (50% stricter = 2/hour)
  - **Verify**: Tool still executes, not blocked

- [ ] **Test**: Check logs for degraded mode warning
  - **Steps**: After Redis failure, check logs
  - **Expected**: Warning present: "Rate limiter degraded mode: Redis unavailable"
  - **Verify**: Log level is WARNING, not ERROR

- [ ] **Test**: Exceed fallback limit
  - **Steps**: Call tool 3 times with Redis down
  - **Expected**: 3rd request fails with rate limit error
  - **Verify**: Stricter fallback limit enforced (2/hour)

- [ ] **Test**: Redis recovery
  - **Steps**:
    1. Start Redis: `docker start redis`
    2. Wait 30 seconds for reconnection
    3. Call rate-limited tool
  - **Expected**: Normal limits restored (5/hour)
  - **Verify**: Log message "Rate limiter normal mode: Redis connected"

#### 3.3 Rate Limit Response Format
- [ ] **Test**: Verify rate limit error structure
  - **Steps**: Trigger rate limit error
  - **Expected**: Response includes:
    - `error_code`: "RATE_LIMIT_EXCEEDED"
    - `limit`: "5 per hour"
    - `retry_after`: seconds or timestamp
  - **Verify**: Client can parse retry guidance

---

### 4. Mass Deletion Confirmation (REQ-3)

#### 4.1 Confirmation Required Scenarios
- [ ] **Test**: Create 15 expired memories
  - **Steps**:
    1. Create 15 memories with `retention_days=0`
    2. Wait 1 second
  - **Expected**: All memories expired
  - **Verify**: Database query confirms expiration

- [ ] **Test**: Invoke `prune_expired_memories` without confirmation
  - **Steps**: Call tool with `confirm_mass_deletion=false` (or omitted)
  - **Expected**: Error with details:
    - "Mass deletion confirmation required"
    - Count: "15 memories will be deleted"
    - Instructions: "Set confirm_mass_deletion=true to proceed"
  - **Verify**: NO memories deleted

- [ ] **Test**: Invoke `prune_expired_memories` with confirmation
  - **Steps**: Call tool with `confirm_mass_deletion=true`
  - **Expected**: All 15 memories deleted successfully
  - **Verify**: Database confirms deletion, count=15 returned

#### 4.2 Threshold Edge Cases
- [ ] **Test**: Delete exactly 10 memories (threshold)
  - **Steps**: Create 10 expired memories, invoke tool
  - **Expected**: Confirmation required (threshold: ≥10)
  - **Verify**: Error message indicates confirmation needed

- [ ] **Test**: Delete 9 memories (below threshold)
  - **Steps**: Create 9 expired memories, invoke tool
  - **Expected**: Success without confirmation
  - **Verify**: All 9 deleted, no confirmation needed

#### 4.3 Namespace-Scoped Deletion
- [ ] **Test**: Mass deletion respects namespace
  - **Steps**:
    1. Agent A creates 15 expired memories (namespace: "project-x")
    2. Agent B calls `prune_expired_memories` (namespace: "project-y")
  - **Expected**: Agent B deletes 0 memories
  - **Verify**: Agent A's memories untouched

---

### 5. Security Audit Logging

#### 5.1 Successful Operations
- [ ] **Test**: Invoke any MCP tool successfully
  - **Steps**: Call `search_memories` with valid auth
  - **Expected**: Audit log entry created
  - **Verify**: Log contains:
    - Timestamp
    - `agent_id`
    - `event_type`: "tool_invocation"
    - `tool_name`: "search_memories"
    - `result`: "success"

#### 5.2 Authentication Failures
- [ ] **Test**: Authentication failure
  - **Steps**: Call tool with invalid API key
  - **Expected**: Audit log entry with:
    - `event_type`: "authentication_failed"
    - `reason`: "Invalid API key"
    - `ip_address`: requester IP
  - **Verify**: Sensitive data NOT logged (e.g., actual API key)

#### 5.3 Authorization Failures
- [ ] **Test**: Authorization failure
  - **Steps**: AGENT role tries admin-only tool
  - **Expected**: Audit log entry with:
    - `event_type`: "authorization_denied"
    - `tool_name`: tool attempted
    - `required_role`: "SYSTEM_ADMIN"
    - `actual_role`: "AGENT"
  - **Verify**: Denial reason clearly logged

#### 5.4 Rate Limit Events
- [ ] **Test**: Rate limit exceeded
  - **Steps**: Exceed rate limit for a tool
  - **Expected**: Audit log entry with:
    - `event_type`: "rate_limit_exceeded"
    - `tool_name`: tool attempted
    - `limit`: "5 per hour"
    - `attempts`: current attempt count
  - **Verify**: Pattern of abuse detectable

#### 5.5 Mass Deletion Events
- [ ] **Test**: Mass deletion execution
  - **Steps**: Successfully delete ≥10 memories
  - **Expected**: Audit log entry with:
    - `event_type`: "mass_deletion"
    - `count`: number deleted
    - `confirmed`: true
  - **Verify**: High-impact operations audited

#### 5.6 Log Format and Rotation
- [ ] **Test**: Check audit log file location
  - **Steps**: Execute any audited operation
  - **Expected**: Log written to `logs/security_audit.log`
  - **Verify**: File exists and is readable

- [ ] **Test**: Verify log rotation
  - **Steps**: Check log rotation configuration
  - **Expected**: Logs rotate daily or at 100MB
  - **Verify**: Old logs archived (e.g., `security_audit.log.2025-11-04`)

---

### 6. Scheduler Operations (Admin Only)

#### 6.1 Read-Only Operations (All Roles)
- [ ] **Test**: `get_scheduler_status` as AGENT role
  - **Steps**: Call tool as agent with role=AGENT
  - **Expected**: Success, status returned
  - **Verify**: Status includes job count, next run times

#### 6.2 Admin Operations (SYSTEM_ADMIN Only)
- [ ] **Test**: `start_scheduler` as AGENT role
  - **Steps**: Call tool as agent with role=AGENT
  - **Expected**: Authorization error "Insufficient permissions"
  - **Verify**: Scheduler state unchanged

- [ ] **Test**: `start_scheduler` as SYSTEM_ADMIN role
  - **Steps**: Call tool as agent with role=SYSTEM_ADMIN
  - **Expected**: Success OR "Scheduler not available" (acceptable limitation)
  - **Verify**: If successful, scheduler status changes to "running"

- [ ] **Test**: `stop_scheduler` as SYSTEM_ADMIN role
  - **Steps**: Call tool as admin while scheduler running
  - **Expected**: Success, scheduler stopped
  - **Verify**: Status changes to "stopped", jobs paused

- [ ] **Test**: `configure_scheduler` with valid config
  - **Steps**: Call tool with updated job intervals
  - **Expected**: Success, configuration applied
  - **Verify**: Next run times updated accordingly

#### 6.3 Scheduler Availability
- [ ] **Test**: Scheduler operations when scheduler unavailable
  - **Steps**: Ensure scheduler not initialized, call admin tool
  - **Expected**: Clear error "Scheduler not available in current deployment"
  - **Verify**: Not treated as authorization failure

---

### 7. Error Handling & User Experience

#### 7.1 Input Validation
- [ ] **Test**: Invoke tool with missing required parameter
  - **Steps**: Call `store_memory` without `content` parameter
  - **Expected**: Validation error "Missing required parameter: content"
  - **Verify**: Error indicates which parameter missing

- [ ] **Test**: Invoke tool with invalid parameter type
  - **Steps**: Call `store_memory` with `importance="high"` (should be float)
  - **Expected**: Validation error "Invalid type for importance: expected float, got string"
  - **Verify**: Type mismatch clearly communicated

- [ ] **Test**: Invoke tool with out-of-range value
  - **Steps**: Call `store_memory` with `importance=5.0` (valid range: 0.0-1.0)
  - **Expected**: Validation error "importance must be between 0.0 and 1.0"
  - **Verify**: Range constraints enforced

#### 7.2 Database Errors
- [ ] **Test**: Database connection failure
  - **Steps**: Stop SQLite database (e.g., corrupt file)
  - **Expected**: Graceful error "Database unavailable, please try again"
  - **Verify**: No stack trace exposed to client

- [ ] **Test**: Database query timeout
  - **Steps**: Simulate slow query (if possible)
  - **Expected**: Timeout error with retry guidance
  - **Verify**: System remains stable, no crash

#### 7.3 Network Errors
- [ ] **Test**: ChromaDB unavailable
  - **Steps**: Stop ChromaDB service
  - **Expected**: Error "Vector search unavailable"
  - **Verify**: Fallback behavior OR clear error

- [ ] **Test**: Ollama unavailable
  - **Steps**: Stop Ollama service, attempt embedding operation
  - **Expected**: Error "Embedding service unavailable: Ollama not running"
  - **Verify**: Error suggests starting Ollama

#### 7.4 Concurrent Operations
- [ ] **Test**: Concurrent memory updates
  - **Steps**: Update same memory from 2 clients simultaneously
  - **Expected**: One succeeds, one gets conflict error
  - **Verify**: Data integrity maintained (no corruption)

---

### 8. MCP Client Integration

#### 8.1 Claude Desktop Integration
- [ ] **Test**: Install TMWS MCP server in Claude Desktop
  - **Steps**: Add server to `claude_desktop_config.json`
  - **Expected**: Server appears in MCP tools list
  - **Verify**: All 10 tools visible

- [ ] **Test**: Invoke tool from Claude Desktop
  - **Steps**: Use natural language: "Search for memories about Python"
  - **Expected**: Claude invokes `search_memories` tool
  - **Verify**: Results displayed correctly

- [ ] **Test**: Authentication in Claude Desktop
  - **Steps**: Configure API key in server settings
  - **Expected**: All tool calls authenticated automatically
  - **Verify**: No auth errors in Claude conversation

#### 8.2 Error Display in MCP Client
- [ ] **Test**: Authentication error display
  - **Steps**: Trigger auth error, observe Claude response
  - **Expected**: Error displayed as user-friendly message
  - **Verify**: No stack trace, only actionable error

- [ ] **Test**: Rate limit error display
  - **Steps**: Trigger rate limit, observe Claude response
  - **Expected**: Claude explains rate limit, suggests wait time
  - **Verify**: Retry-after guidance communicated

---

## Verification Procedure

### Pre-Verification Setup

1. **Install TMWS v2.3.0 in test environment**
   ```bash
   git checkout v2.3.0
   uv sync --all-extras
   alembic upgrade head
   ```

2. **Create 3 test agents in database**
   ```sql
   -- Agent A: Standard agent in project-x
   INSERT INTO agents (id, name, namespace, role)
   VALUES ('agent-a-id', 'Agent A', 'project-x', 'AGENT');

   -- Agent B: Standard agent in project-y
   INSERT INTO agents (id, name, namespace, role)
   VALUES ('agent-b-id', 'Agent B', 'project-y', 'AGENT');

   -- Agent Admin: System administrator
   INSERT INTO agents (id, name, namespace, role)
   VALUES ('agent-admin-id', 'Agent Admin', 'admin', 'SYSTEM_ADMIN');
   ```

3. **Generate API keys**
   ```bash
   python scripts/generate_api_key.py --agent-id agent-a-id
   python scripts/generate_api_key.py --agent-id agent-b-id
   python scripts/generate_api_key.py --agent-id agent-admin-id
   ```

4. **Start required services**
   ```bash
   # Redis for rate limiting
   docker start redis

   # Ollama for embeddings
   ollama serve

   # TMWS MCP server
   python -m src.mcp_server
   ```

5. **Verify services running**
   ```bash
   # Check Redis
   redis-cli ping  # Should return PONG

   # Check Ollama
   curl http://localhost:11434/api/version

   # Check TMWS
   curl http://localhost:3000/health
   ```

### Verification Execution

1. **Work through checklist systematically**
   - Complete each category in order
   - Mark items as PASS/FAIL
   - Record detailed notes for FAIL items

2. **Document evidence**
   - Take screenshots of critical errors
   - Save log excerpts for security events
   - Record exact error messages

3. **For FAIL items**
   - Record in "Issues Found" section
   - Assign severity (CRITICAL/HIGH/MEDIUM/LOW)
   - Note reproduction steps

4. **Testing discipline**
   - Do not skip items
   - Do not assume PASS without verification
   - Test edge cases thoroughly

### Post-Verification

1. **Calculate pass rate**
   - Total items: 80+
   - Items PASS: _____
   - Pass rate: _____ %

2. **Release decision criteria**
   - Pass rate ≥ 95%: ✅ APPROVE
   - Pass rate 85-94%: ⚠️ APPROVE WITH CAUTION
   - Pass rate < 85%: ❌ BLOCK RELEASE

3. **Document findings**
   - Create issues for all FAIL items
   - Prioritize fixes by severity
   - Update known issues in CHANGELOG

---

## Issues Found

### Issue Template
```
Issue #X: [Short Descriptive Title]
- **Category**: [Authentication/Authorization/Rate Limiting/etc.]
- **Severity**: [CRITICAL/HIGH/MEDIUM/LOW]
- **Description**: [What happened - detailed]
- **Expected**: [What should have happened]
- **Actual**: [What actually happened]
- **Reproduction Steps**:
  1. Step one
  2. Step two
  3. Step three
- **Evidence**: [Screenshot filename, log excerpt, etc.]
- **Status**: [Open/In Progress/Fixed/Deferred]
- **Fix Required For Release**: [Yes/No]
```

### Severity Guidelines

| Severity | Definition | Examples |
|----------|------------|----------|
| CRITICAL | Security vulnerability, data loss, system crash | Cross-tenant data access, authentication bypass |
| HIGH | Feature completely broken, major security concern | Rate limiting not enforced, RBAC failure |
| MEDIUM | Feature partially broken, minor security concern | Unclear error message, degraded performance |
| LOW | Cosmetic issue, minor UX problem | Typo in error message, inconsistent formatting |

### Example Issues

```
Issue #1: Namespace Isolation Bypass via JWT Claims
- **Category**: Authorization (REQ-2)
- **Severity**: CRITICAL
- **Description**: Agent can access cross-tenant data by manipulating JWT namespace claim
- **Expected**: Authorization should verify namespace from database, not JWT
- **Actual**: Authorization trusted JWT claim, allowed cross-tenant access
- **Reproduction Steps**:
  1. Create memory as Agent A (namespace: "project-x")
  2. Generate JWT with namespace="project-x" for Agent B
  3. Agent B successfully reads Agent A's memory
- **Evidence**: audit_log_excerpt.txt, screenshot_cross_tenant_access.png
- **Status**: Fixed in commit abc123
- **Fix Required For Release**: Yes (security-critical)
```

```
Issue #2: Rate Limit Error Missing Retry-After
- **Category**: Rate Limiting (REQ-4)
- **Severity**: MEDIUM
- **Description**: Rate limit error does not include retry-after guidance
- **Expected**: Error should tell user when they can retry (e.g., "Try again in 45 minutes")
- **Actual**: Error only says "Rate limit exceeded"
- **Reproduction Steps**:
  1. Call rate-limited tool 6 times in 1 hour
  2. Observe 6th request error message
- **Evidence**: error_response.json
- **Status**: Open
- **Fix Required For Release**: No (UX improvement, not blocker)
```

---

## Sign-Off

### Manual Verification Completed By
- **Name**: _______________________
- **Date**: _______________________
- **Environment**: [Test/Staging/Production]
- **TMWS Version Tested**: v_______
- **Pass Rate**: ______ / ______ items (______ %)

### Release Decision
- [ ] ✅ **APPROVE** - Pass rate ≥ 95%, no CRITICAL or HIGH issues unfixed
- [ ] ⚠️ **APPROVE WITH CAUTION** - Pass rate 85-94%, document known issues in release notes
- [ ] ❌ **BLOCK RELEASE** - Pass rate < 85% OR any CRITICAL issues unfixed OR any HIGH issues without mitigation plan

### Approver Sign-Off
- **Approver Name**: _______________________
- **Approver Role**: [QA Lead/Security Lead/Project Manager]
- **Signature**: _______________________
- **Date**: _______________________

### Notes
[Additional observations, recommendations, concerns, or context that informed the release decision]

**Example Notes**:
- "3 MEDIUM issues deferred to v2.3.1 - documented in KNOWN_ISSUES.md"
- "Rate limiting fallback behavior needs monitoring in production"
- "Recommend security review of JWT handling in v2.4.0"

---

## Appendix: Quick Reference

### Test Agent Credentials (Example)

| Agent ID | Namespace | Role | API Key (Hash) |
|----------|-----------|------|----------------|
| agent-a-id | project-x | AGENT | `sha256:abc...` |
| agent-b-id | project-y | AGENT | `sha256:def...` |
| agent-admin-id | admin | SYSTEM_ADMIN | `sha256:ghi...` |

### Rate Limit Configurations

| Tool | Normal Limit | Fallback Limit | Window |
|------|--------------|----------------|--------|
| prune_expired_memories | 5 | 2 | 1 hour |
| cleanup_namespace | 3 | 1 | 1 hour |
| bulk_update_metadata | 10 | 5 | 1 hour |

### Expected Error Messages

| Scenario | Error Code | Error Message Pattern |
|----------|------------|----------------------|
| Invalid API key | AUTH_FAILED | "Invalid API key" |
| Expired JWT | AUTH_FAILED | "JWT expired" |
| Insufficient permissions | AUTHZ_DENIED | "Insufficient permissions. Required: SYSTEM_ADMIN" |
| Rate limit exceeded | RATE_LIMIT | "Rate limit exceeded: 5 per hour. Try again in X minutes." |
| Mass deletion without confirm | CONFIRMATION_REQUIRED | "Mass deletion confirmation required. X memories will be deleted." |
| Cross-tenant access | AUTHZ_DENIED | "Access denied: resource belongs to different namespace" |

---

**Document Status**: Ready for Use
**Last Updated**: 2025-11-05
**Document Version**: 1.0
**TMWS Version**: v2.3.0
**Maintained By**: Muses, Knowledge Architect

---

*This checklist serves as the final gate before release. Thoroughness here prevents production incidents.*

*"Perfect documentation is not about length, but about clarity and completeness."* - Muses 📚
