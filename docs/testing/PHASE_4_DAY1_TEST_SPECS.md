# Phase 4 Day 1 Test Specifications
## Comprehensive Test Plan for Tool Discovery Foundation

**Date**: 2025-11-22
**Tactical Coordinator**: Eris
**Implementation Lead**: Artemis
**Security Auditor**: Hestia (Task 1.4)

---

## Overview

This document specifies all test requirements for Task 1.2 (Foundation Implementation) and Task 1.3 (Complete Implementation + Unit Tests). Total: **33 tests** across Go and Python codebases.

### Test Coverage Targets

| Component | Unit Tests | Security Tests | Coverage Target |
|-----------|-----------|----------------|-----------------|
| Go Orchestrator | 15 | - | ≥80% |
| Python Schema | 10 | 8 | ≥80% |
| **Total** | **25** | **8** | **≥80%** |

### Performance Targets (from Hera's Design)

- **Go Discovery Scan**: <100ms P95 (50 tools)
- **Python Tool Insert**: <10ms P95
- **Python Tool Query**: <5ms P95

---

## Part 1: Go Orchestrator Tests (15 tests)

### File: `src/orchestrator/internal/orchestrator/service_test.go`

**Purpose**: Test orchestrator service lifecycle and graceful shutdown

#### Test 1.1: Service Initialization

```go
func TestNewService_Success(t *testing.T) {
    // Verify successful service initialization
    // Expected:
    // - Docker client initialized
    // - Discovery engine created
    // - gRPC preparation structures in place
    // - No errors returned
}
```

**Success Criteria**:
- Service struct returned with non-nil fields
- Docker client connection established
- Discovery engine ready

---

#### Test 1.2: Docker Client Failure Handling

```go
func TestNewService_DockerClientError(t *testing.T) {
    // Simulate Docker daemon unavailable
    // Expected:
    // - NewService returns error
    // - Error message indicates Docker connection issue
    // - Service struct is nil
}
```

**Success Criteria**:
- Error returned contains "docker"
- Service fails gracefully (no panic)

---

#### Test 1.3: Service Start - Discovery Success

```go
func TestServiceStart_DiscoverySuccess(t *testing.T) {
    // Start service with mock discovery engine
    // Mock returns 3 tools
    // Expected:
    // - Start() returns nil error
    // - Discovery engine invoked
    // - Tools registered in Python DB (mock gRPC call)
}
```

**Success Criteria**:
- `Start()` completes without error
- Discovery engine `Scan()` called once
- gRPC client mock receives 3 tool registrations

---

#### Test 1.4: Service Start - Empty Discovery

```go
func TestServiceStart_DiscoveryEmpty(t *testing.T) {
    // Discovery finds 0 tools
    // Expected:
    // - Start() returns nil error (not an error condition)
    // - No gRPC calls made
}
```

**Success Criteria**:
- No error returned
- gRPC client mock not invoked

---

#### Test 1.5: Service Stop - Clean Shutdown

```go
func TestServiceStop_CleanShutdown(t *testing.T) {
    // Start service, then stop
    // Expected:
    // - Docker client closed
    // - gRPC connection closed
    // - No resource leaks
}
```

**Success Criteria**:
- `Stop()` completes without error
- Docker client `Close()` called
- gRPC connection `Close()` called

---

#### Test 1.6: Service Stop - Idempotent

```go
func TestServiceStop_AlreadyStopped(t *testing.T) {
    // Call Stop() twice
    // Expected:
    // - Second call does not error
    // - Resources not double-freed
}
```

**Success Criteria**:
- Second `Stop()` call returns nil error
- No panic or resource errors

---

#### Test 1.7: Graceful Shutdown - SIGTERM

```go
func TestServiceGracefulShutdown_SIGTERM(t *testing.T) {
    // Send SIGTERM to running service
    // Expected:
    // - Context cancelled
    // - Service stops cleanly
    // - All resources released
}
```

**Success Criteria**:
- Signal handler invoked
- Context `Done()` channel closed
- Service stops within 5 seconds

---

#### Test 1.8: Graceful Shutdown - SIGINT

```go
func TestServiceGracefulShutdown_SIGINT(t *testing.T) {
    // Send SIGINT (Ctrl+C) to running service
    // Expected: Same as SIGTERM
}
```

**Success Criteria**: Same as Test 1.7

---

### File: `src/orchestrator/internal/orchestrator/discovery_test.go`

**Purpose**: Test tool discovery logic

#### Test 2.1: Discovery Scan - Tools Found

```go
func TestDiscoveryScan_ToolsFound(t *testing.T) {
    // Create test directory with 5 valid tools
    // Expected:
    // - Scan() returns 5 tools
    // - Each tool has required fields populated
}
```

**Success Criteria**:
- 5 tools returned
- All tools have `tool_id`, `name`, `version`, `source_path`

---

#### Test 2.2: Discovery Scan - Empty Directory

```go
func TestDiscoveryScan_EmptyDirectory(t *testing.T) {
    // Scan empty directory
    // Expected:
    // - Scan() returns 0 tools
    // - No error returned
}
```

**Success Criteria**:
- Empty slice returned
- No error

---

#### Test 2.3: Discovery Scan - Invalid Path

```go
func TestDiscoveryScan_InvalidPath(t *testing.T) {
    // Scan non-existent path
    // Expected:
    // - Error returned
}
```

**Success Criteria**:
- Error contains "path" or "not found"

---

#### Test 2.4: Tool Validation - Valid JSON

```go
func TestValidateTool_ValidJSON(t *testing.T) {
    // Validate tool with all required fields
    // Expected:
    // - validateTool() returns true
}
```

**Success Criteria**:
- Validation passes
- No error returned

---

#### Test 2.5: Tool Validation - Invalid JSON

```go
func TestValidateTool_InvalidJSON(t *testing.T) {
    // Malformed JSON
    // Expected:
    // - validateTool() returns false
    // - Error indicates JSON parsing failure
}
```

**Success Criteria**:
- Validation fails
- Error message clear

---

#### Test 2.6: Tool Validation - Missing Required Field

```go
func TestValidateTool_MissingRequiredField(t *testing.T) {
    // Tool missing "tool_id"
    // Expected:
    // - validateTool() returns false
    // - Error indicates missing field
}
```

**Success Criteria**:
- Validation fails
- Error specifies "tool_id"

---

#### Test 2.7: Discovery Performance - 50 Tools <100ms

```go
func TestDiscoveryScan_PerformanceTarget(t *testing.T) {
    // Create directory with 50 valid tools
    // Measure scan time
    // Expected:
    // - Scan completes in <100ms (P95 target)
}
```

**Success Criteria**:
- Scan time ≤100ms
- All 50 tools discovered

---

## Part 2: Python Schema Tests (10 tests)

### File: `tests/unit/services/test_tool_discovery_service.py`

**Purpose**: Test Python ToolDiscoveryService and DiscoveredTool model

#### Test 3.1: Register Tool - Success

```python
async def test_register_tool_success(db_session):
    """Tool registration succeeds with valid data"""
    service = ToolDiscoveryService(db_session)

    tool_data = {
        "tool_id": "test-tool-001",
        "name": "Test Tool",
        "version": "1.0.0",
        "category": "utility",
        "source_type": "docker",
        "source_path": "/tools/test-tool",
        "namespace": "default",
        "metadata": {"author": "test"}
    }

    tool = await service.register_tool(tool_data)

    assert tool.tool_id == "test-tool-001"
    assert tool.is_active is True
```

**Success Criteria**:
- Tool inserted into DB
- All fields match input
- `is_active` defaults to True

---

#### Test 3.2: Register Tool - Duplicate tool_id

```python
async def test_register_tool_duplicate_tool_id(db_session):
    """Unique constraint prevents duplicate tool_id"""
    service = ToolDiscoveryService(db_session)

    # Insert first tool
    await service.register_tool({"tool_id": "dup-test", ...})

    # Attempt duplicate
    with pytest.raises(IntegrityError):
        await service.register_tool({"tool_id": "dup-test", ...})
```

**Success Criteria**:
- IntegrityError raised
- Database transaction rolled back

---

#### Test 3.3: Get Tool - Found (Namespace Isolated)

```python
async def test_get_tool_found(db_session):
    """Tool lookup by ID succeeds within namespace"""
    service = ToolDiscoveryService(db_session)

    await service.register_tool({
        "tool_id": "find-me",
        "namespace": "team-a",
        ...
    })

    tool = await service.get_tool("find-me", namespace="team-a")

    assert tool is not None
    assert tool.tool_id == "find-me"
```

**Success Criteria**:
- Tool found
- Namespace parameter enforced

---

#### Test 3.4: Get Tool - Not Found

```python
async def test_get_tool_not_found(db_session):
    """Returns None for missing tool"""
    service = ToolDiscoveryService(db_session)

    tool = await service.get_tool("nonexistent", namespace="default")

    assert tool is None
```

**Success Criteria**:
- Returns None (not exception)

---

#### Test 3.5: Get Tool - Wrong Namespace (V-TOOL-1)

```python
async def test_get_tool_wrong_namespace(db_session):
    """Namespace isolation prevents cross-namespace access"""
    service = ToolDiscoveryService(db_session)

    await service.register_tool({
        "tool_id": "team-a-tool",
        "namespace": "team-a",
        ...
    })

    # Attempt access from team-b
    tool = await service.get_tool("team-a-tool", namespace="team-b")

    assert tool is None  # Namespace isolation enforced
```

**Success Criteria**:
- Returns None (cannot access other namespace's tool)
- V-TOOL-1 compliant

---

#### Test 3.6: List Tools - All in Namespace

```python
async def test_list_tools_all(db_session):
    """List all tools in namespace"""
    service = ToolDiscoveryService(db_session)

    # Insert 3 tools in team-a
    for i in range(3):
        await service.register_tool({
            "tool_id": f"tool-{i}",
            "namespace": "team-a",
            ...
        })

    # Insert 2 tools in team-b
    for i in range(2):
        await service.register_tool({
            "tool_id": f"tool-b-{i}",
            "namespace": "team-b",
            ...
        })

    tools = await service.list_tools(namespace="team-a")

    assert len(tools) == 3  # Only team-a tools
```

**Success Criteria**:
- Returns only tools from specified namespace
- Other namespaces not visible

---

#### Test 3.7: List Tools - Filter by Category

```python
async def test_list_tools_by_category(db_session):
    """Category filter works correctly"""
    service = ToolDiscoveryService(db_session)

    await service.register_tool({
        "tool_id": "util-1",
        "category": "utility",
        "namespace": "default",
        ...
    })

    await service.register_tool({
        "tool_id": "data-1",
        "category": "data-processing",
        "namespace": "default",
        ...
    })

    tools = await service.list_tools(
        namespace="default",
        category="utility"
    )

    assert len(tools) == 1
    assert tools[0].category == "utility"
```

**Success Criteria**:
- Filter returns only matching category
- Index used (performance <5ms)

---

#### Test 3.8: List Tools - Empty Namespace

```python
async def test_list_tools_empty(db_session):
    """Empty namespace returns empty list"""
    service = ToolDiscoveryService(db_session)

    tools = await service.list_tools(namespace="empty-namespace")

    assert tools == []
```

**Success Criteria**:
- Returns empty list (not None or exception)

---

#### Test 3.9: Soft Delete - Excluded from Listings

```python
async def test_soft_delete_excluded(db_session):
    """Tools with is_active=False not returned"""
    service = ToolDiscoveryService(db_session)

    tool = await service.register_tool({
        "tool_id": "soft-delete-test",
        "namespace": "default",
        ...
    })

    # Soft delete
    tool.is_active = False
    await db_session.commit()

    # List should not include inactive tools
    tools = await service.list_tools(namespace="default")

    assert len(tools) == 0
```

**Success Criteria**:
- Inactive tools not in results
- WHERE clause includes `is_active=True`

---

#### Test 3.10: Performance - Insert <10ms P95

```python
async def test_performance_insert_under_10ms(db_session):
    """Tool insert completes <10ms (P95 target)"""
    import time

    service = ToolDiscoveryService(db_session)

    timings = []
    for i in range(100):
        start = time.perf_counter()

        await service.register_tool({
            "tool_id": f"perf-{i}",
            "namespace": "default",
            ...
        })

        duration = (time.perf_counter() - start) * 1000  # ms
        timings.append(duration)

    p95 = sorted(timings)[94]  # 95th percentile

    assert p95 < 10.0, f"P95 insert time {p95:.2f}ms exceeds 10ms target"
```

**Success Criteria**:
- P95 ≤10ms
- Index performance verified

---

## Part 3: Security Tests (8 tests)

### File: `tests/security/test_tool_discovery_security.py`

**Purpose**: Verify security requirements V-TOOL-1, V-TOOL-3, V-TOOL-4, V-TOOL-5

#### Security Test 1: Namespace Isolation - Get Tool (V-TOOL-1)

```python
async def test_namespace_isolation_get_tool(db_session):
    """V-TOOL-1: Cannot access tools from other namespaces"""
    service = ToolDiscoveryService(db_session)

    # Team A creates tool
    await service.register_tool({
        "tool_id": "secret-tool",
        "namespace": "team-a",
        "metadata": {"secret": "confidential-data"}
    })

    # Team B attempts access
    tool = await service.get_tool("secret-tool", namespace="team-b")

    assert tool is None  # Access denied

    # Verify SQL query includes namespace WHERE clause
    # (Check SQLAlchemy query logs)
```

**Success Criteria**:
- Returns None for cross-namespace access
- SQL includes `WHERE namespace = 'team-b'`

---

#### Security Test 2: Namespace Isolation - List Tools (V-TOOL-1)

```python
async def test_namespace_isolation_list_tools(db_session):
    """V-TOOL-1: Listings are namespace-scoped"""
    service = ToolDiscoveryService(db_session)

    # Multiple namespaces with tools
    for ns in ["team-a", "team-b", "team-c"]:
        for i in range(3):
            await service.register_tool({
                "tool_id": f"{ns}-tool-{i}",
                "namespace": ns,
            })

    # Team B lists tools
    tools = await service.list_tools(namespace="team-b")

    assert len(tools) == 3
    assert all(t.namespace == "team-b" for t in tools)
```

**Success Criteria**:
- Only returns tools from specified namespace
- No leakage across namespaces

---

#### Security Test 3: SQL Injection - tool_id (V-TOOL-3)

```python
async def test_sql_injection_tool_id(db_session):
    """V-TOOL-3: Parameterized queries prevent SQL injection"""
    service = ToolDiscoveryService(db_session)

    # Malicious tool_id
    malicious_id = "'; DROP TABLE discovered_tools; --"

    tool = await service.get_tool(malicious_id, namespace="default")

    assert tool is None  # Query returns None, no SQL executed

    # Verify table still exists
    result = await db_session.execute(text("SELECT 1 FROM discovered_tools"))
    assert result is not None
```

**Success Criteria**:
- SQL injection attempt fails safely
- Table not dropped
- Parameterized query used

---

#### Security Test 4: SQL Injection - Category Filter (V-TOOL-3)

```python
async def test_sql_injection_category(db_session):
    """V-TOOL-3: Category filter uses parameterized queries"""
    service = ToolDiscoveryService(db_session)

    malicious_category = "' OR '1'='1"

    tools = await service.list_tools(
        namespace="default",
        category=malicious_category
    )

    assert tools == []  # No tools with that category
```

**Success Criteria**:
- Returns empty list (not all tools)
- Parameterized query prevents bypass

---

#### Security Test 5: Path Traversal - source_path (V-TOOL-4)

```python
async def test_path_traversal_source_path(db_session):
    """V-TOOL-4: Rejects path traversal in source_path"""
    service = ToolDiscoveryService(db_session)

    with pytest.raises(ValueError, match="path traversal"):
        await service.register_tool({
            "tool_id": "malicious-tool",
            "source_path": "/tools/../../../etc/passwd",
            "namespace": "default",
        })
```

**Success Criteria**:
- ValueError raised
- Tool not inserted

---

#### Security Test 6: Path Traversal - Validation (V-TOOL-4)

```python
async def test_path_traversal_validation(db_session):
    """V-TOOL-4: Whitelist enforcement for source paths"""
    service = ToolDiscoveryService(db_session)

    # Valid path (within whitelist)
    valid_tool = await service.register_tool({
        "tool_id": "valid-tool",
        "source_path": "/tools/valid-tool",
        "namespace": "default",
    })
    assert valid_tool is not None

    # Invalid path (outside whitelist)
    with pytest.raises(ValueError, match="path not in whitelist"):
        await service.register_tool({
            "tool_id": "invalid-tool",
            "source_path": "/var/www/html",
            "namespace": "default",
        })
```

**Success Criteria**:
- Whitelist paths accepted
- Non-whitelist paths rejected

---

#### Security Test 7: Input Validation - tool_id Length (V-TOOL-5)

```python
async def test_input_validation_tool_id_length(db_session):
    """V-TOOL-5: tool_id max length enforced"""
    service = ToolDiscoveryService(db_session)

    long_id = "a" * 101  # Exceeds 100 char limit

    with pytest.raises(ValueError, match="tool_id too long"):
        await service.register_tool({
            "tool_id": long_id,
            "namespace": "default",
        })
```

**Success Criteria**:
- ValueError raised for >100 chars
- Database constraint also enforces limit

---

#### Security Test 8: Input Validation - JSON Metadata (V-TOOL-5)

```python
async def test_input_validation_malicious_json(db_session):
    """V-TOOL-5: JSON metadata sanitized"""
    service = ToolDiscoveryService(db_session)

    malicious_metadata = {
        "__proto__": {"polluted": True},  # Prototype pollution attempt
        "nested": {"script": "<script>alert('xss')</script>"}
    }

    tool = await service.register_tool({
        "tool_id": "sanitize-test",
        "namespace": "default",
        "metadata": malicious_metadata
    })

    # Verify __proto__ not stored
    assert "__proto__" not in tool.metadata

    # Verify nested values sanitized
    assert "<script>" not in str(tool.metadata)
```

**Success Criteria**:
- Dangerous keys removed
- XSS payloads sanitized

---

## Coverage Analysis

### Expected Coverage by Component

**Go Orchestrator**:
- `internal/orchestrator/service.go`: 85%+ (8 tests)
- `internal/orchestrator/discovery.go`: 90%+ (7 tests)
- `internal/config/config.go`: 70%+ (tested via service tests)

**Python Schema**:
- `src/services/tool_discovery_service.py`: 85%+ (10 unit + 8 security tests)
- `src/models/discovered_tool.py`: 90%+ (tested via service)

### Uncovered Areas (Acceptable Gaps)

- gRPC client initialization (Task 1.3 - full implementation)
- Error recovery edge cases (Task 1.3 - integration tests)
- Docker image validation (Task 1.5 - validation layer)

---

## Test Execution Plan

### Phase 1: Unit Tests (Task 1.3)

**Artemis will execute**:
1. Go tests: `go test ./src/orchestrator/internal/...`
2. Python tests: `pytest tests/unit/services/test_tool_discovery_service.py -v`

**Expected Duration**: 60 minutes total
- Go test implementation: 30 min
- Python test implementation: 30 min

**Success Criteria**: 25/25 tests PASS

---

### Phase 2: Security Tests (Task 1.4)

**Hestia will execute**:
1. Security tests: `pytest tests/security/test_tool_discovery_security.py -v`
2. Security audit review

**Expected Duration**: 90 minutes total
- Test execution: 15 min
- Security review: 45 min
- Vulnerability scan: 30 min

**Success Criteria**: 8/8 tests PASS, 0 critical vulnerabilities

---

## Performance Benchmarks

### Measurement Methodology

**Go Performance** (Test 2.7):
```go
start := time.Now()
tools := discovery.Scan("/tools")
duration := time.Since(start)
assert.Less(t, duration.Milliseconds(), 100)
```

**Python Performance** (Test 3.10):
```python
timings = []
for i in range(100):
    start = time.perf_counter()
    await service.register_tool(...)
    timings.append(time.perf_counter() - start)

p95 = sorted(timings)[94]
assert p95 < 0.010  # 10ms in seconds
```

### Performance Targets Summary

| Operation | Target | Test Coverage |
|-----------|--------|---------------|
| Go Discovery Scan (50 tools) | <100ms | Test 2.7 |
| Python Tool Insert | <10ms P95 | Test 3.10 |
| Python Tool Query | <5ms P95 | Verified via index usage |

---

## Checkpoint 1 Criteria Alignment

**This test plan ensures**:
- ✅ Technical Quality: 33 tests (25 unit + 8 security)
- ✅ Code Coverage: ≥80% target for all components
- ✅ Security: 100% coverage of V-TOOL-1/3/4/5
- ✅ Performance: All P95 targets validated

**Tactical Coordinator Sign-Off**:
Eris confirms this test specification is comprehensive and aligned with Hera's architecture and Athena's resource plan.

---

**Next Steps**:
1. Artemis implements tests in Task 1.3 (150 min)
2. Hestia reviews security in Task 1.4 (90 min)
3. Checkpoint 1 validation at 17:00-18:00

**Status**: Test plan ready for execution.
