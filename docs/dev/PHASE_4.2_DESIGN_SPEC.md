# Phase 4.2: AsyncSecurityAuditLogger Refactoring
## Facade Pattern Implementation Specification

**Created**: 2025-10-28
**Target**: `src/security/audit_logger_async.py` (604 LOC)
**Strategy**: Facade Pattern with specialized subsystems
**Risk Level**: MEDIUM-HIGH
**Estimated Time**: 3-4 hours

---

## 📊 Current State Analysis

### Class Structure (AsyncSecurityAuditLogger)

**Total**: 604 lines (lines 27-604)
- **Methods**: 16
- **Variables**: 5
- **Complexity**: HIGH (multiple responsibilities)

### Responsibilities Identified

#### 1. Initialization & Setup (75 LOC)
```python
__init__                    # 13 lines (31-43)
initialize                  # 7 lines (45-51)
_init_database             # 35 lines (53-87)
_init_geoip                # 20 lines (89-108)
```

#### 2. Event Logging & Storage (256 LOC)
```python
log_event                   # 67 lines (110-176) - Main entry point
_store_event               # 99 lines (178-276) - Large, complex
_async_log_to_file         # 49 lines (364-412)
log_pattern_execution      # 41 lines (556-596)
```

#### 3. GeoIP & Location (32 LOC)
```python
_get_location_info         # 32 lines (284-315)
```

#### 4. Risk Analysis (96 LOC)
```python
_calculate_risk_score      # 46 lines (317-362)
_check_brute_force         # 45 lines (451-495)
_generate_event_hash       # 5 lines (278-282)
```

#### 5. Alert Management (29 LOC)
```python
_check_alert_conditions    # 14 lines (414-427)
_send_alert                # 15 lines (429-443)
```

#### 6. Query & Retrieval (57 LOC)
```python
get_recent_events          # 57 lines (498-554)
```

#### 7. Cleanup (7 LOC)
```python
cleanup                    # 7 lines (598-604)
```

---

## 🎯 Refactoring Goals

1. **Separation of Concerns**: Each subsystem handles one responsibility
2. **Testability**: Each service independently testable
3. **Maintainability**: Easier to modify individual components
4. **Extensibility**: Easy to add new alert types, risk patterns, etc.

**Expected Metrics**:
- LOC reduction: **-84 LOC** (604 → 520, -14%)
- Complexity reduction: **-40%** (per-file cyclomatic complexity)
- Test coverage improvement: **+10%** (easier to unit test)

---

## 🏗️ Proposed Architecture

### Facade Pattern Design

```
┌─────────────────────────────────────────────┐
│     SecurityAuditFacade (100 LOC)          │
│  - log_event()                              │
│  - log_pattern_execution()                  │
│  - get_recent_events()                      │
│  - cleanup()                                │
└──────────────┬──────────────────────────────┘
               │ coordinates
      ┌────────┴────────┐
      │                 │
      ▼                 ▼
┌─────────────┐   ┌─────────────┐
│  GeoIPSvc   │   │  RiskAnalyzer│
│  (70 LOC)   │   │  (100 LOC)   │
│             │   │              │
│ - lookup()  │   │ - assess()   │
│ - init()    │   │ - brute_force│
└─────────────┘   └─────────────┘
      ▼                 ▼
┌─────────────┐   ┌─────────────┐
│ AlertMgr    │   │ EventStore   │
│ (50 LOC)    │   │ (200 LOC)    │
│             │   │              │
│ - check()   │   │ - save()     │
│ - notify()  │   │ - query()    │
└─────────────┘   └─────────────┘
```

---

## 📁 File Structure

### New Files to Create

1. **`src/security/services/geo_ip_service.py`** (~70 LOC)
2. **`src/security/services/risk_analyzer.py`** (~100 LOC)
3. **`src/security/services/alert_manager.py`** (~50 LOC)
4. **`src/security/services/event_store.py`** (~200 LOC)
5. **`src/security/services/__init__.py`** (exports)
6. **`src/security/security_audit_facade.py`** (~100 LOC)

### Files to Modify

1. **`src/security/__init__.py`**: Update exports
2. **`src/security/security_middleware.py`**: Import facade instead
3. **`src/security/audit_logger.py`**: Update to use facade (deprecated wrapper)

### Files to Archive

1. **`src/security/audit_logger_async.py`**: Move to archive after migration

---

## 🔧 Implementation Plan

### Phase 4.2.3: Subsystem Implementation

#### Service 1: GeoIPService

**File**: `src/security/services/geo_ip_service.py`

**Responsibilities**:
- Initialize GeoIP2 reader from MaxMind database
- IP address → location data lookup
- Handle lookup failures gracefully

**Interface**:
```python
class GeoIPService:
    def __init__(self, geoip_db_path: str | None = None):
        """Initialize GeoIP reader."""

    async def initialize(self) -> None:
        """Async initialization if needed."""

    def lookup(self, ip_address: str) -> dict[str, Any] | None:
        """
        Lookup location info for IP address.

        Returns:
            {
                "country": str,
                "city": str | None,
                "latitude": float | None,
                "longitude": float | None,
                "isp": str | None
            }
        """
```

**Extracted Methods**:
- `_init_geoip()` → `initialize()`
- `_get_location_info()` → `lookup()`

---

#### Service 2: RiskAnalyzer

**File**: `src/security/services/risk_analyzer.py`

**Responsibilities**:
- Calculate risk scores based on event patterns
- Detect brute force attacks
- Generate event fingerprints (hashes)

**Interface**:
```python
class RiskAnalyzer:
    def __init__(self, db_session_maker):
        """Initialize risk analyzer."""

    async def calculate_risk_score(
        self,
        event_type: str,
        event_data: dict[str, Any],
        location_info: dict[str, Any] | None
    ) -> int:
        """
        Calculate risk score (0-100).

        Factors:
        - Event type severity
        - Location anomalies
        - Historical patterns
        - Brute force indicators
        """

    async def check_brute_force(
        self,
        agent_id: str,
        event_type: str,
        time_window: int = 300  # 5 minutes
    ) -> dict[str, Any]:
        """
        Check for brute force patterns.

        Returns:
            {
                "is_brute_force": bool,
                "attempt_count": int,
                "first_attempt": datetime,
                "last_attempt": datetime
            }
        """

    @staticmethod
    def generate_event_hash(event_data: dict[str, Any]) -> str:
        """Generate SHA-256 hash for event deduplication."""
```

**Extracted Methods**:
- `_calculate_risk_score()` → `calculate_risk_score()`
- `_check_brute_force()` → `check_brute_force()`
- `_generate_event_hash()` → `generate_event_hash()`

---

#### Service 3: AlertManager

**File**: `src/security/services/alert_manager.py`

**Responsibilities**:
- Check if event meets alert conditions
- Send alerts via configured channels (email, webhook, etc.)
- Track alert history to avoid spam

**Interface**:
```python
class AlertManager:
    def __init__(self, settings: Settings):
        """Initialize alert manager."""

    async def check_and_notify(
        self,
        event_type: str,
        risk_score: int,
        event_data: dict[str, Any],
        brute_force_info: dict[str, Any] | None = None
    ) -> bool:
        """
        Check if alert is needed and send if so.

        Returns:
            True if alert was sent, False otherwise
        """

    async def _should_alert(
        self,
        event_type: str,
        risk_score: int,
        brute_force_info: dict[str, Any] | None
    ) -> bool:
        """Determine if event meets alert conditions."""

    async def _send_alert(
        self,
        event_type: str,
        event_data: dict[str, Any],
        risk_score: int
    ) -> None:
        """Send alert via configured channels."""
```

**Extracted Methods**:
- `_check_alert_conditions()` → `_should_alert()`
- `_send_alert()` → `_send_alert()`

---

#### Service 4: EventStore

**File**: `src/security/services/event_store.py`

**Responsibilities**:
- Persist events to database
- Async file logging
- Query recent events
- Database initialization

**Interface**:
```python
class EventStore:
    def __init__(self, settings: Settings):
        """Initialize event store."""

    async def initialize(self) -> None:
        """Initialize database connection."""

    async def save(
        self,
        event_type: str,
        event_data: dict[str, Any],
        agent_id: str | None,
        user_id: str | None,
        ip_address: str | None,
        location_info: dict[str, Any] | None,
        risk_score: int,
        event_hash: str
    ) -> SecurityAuditLog:
        """
        Save event to database and file.

        Returns:
            Saved SecurityAuditLog model
        """

    async def get_recent(
        self,
        limit: int = 100,
        event_type: str | None = None,
        agent_id: str | None = None,
        min_risk_score: int | None = None
    ) -> list[SecurityAuditLog]:
        """Query recent events with filters."""

    async def cleanup(self) -> None:
        """Close database connections."""
```

**Extracted Methods**:
- `_init_database()` → `initialize()`
- `_store_event()` → `save()`
- `_async_log_to_file()` → internal to `save()`
- `get_recent_events()` → `get_recent()`

---

### Phase 4.2.4: Facade Implementation

**File**: `src/security/security_audit_facade.py`

**Responsibilities**:
- Coordinate all subsystems
- Provide simple public interface
- Maintain backward compatibility with AsyncSecurityAuditLogger

**Interface**:
```python
class SecurityAuditFacade:
    """
    Facade for security audit system.

    Coordinates GeoIP, risk analysis, alerting, and event storage.
    """

    def __init__(self):
        """Initialize all subsystems."""
        self.geo_ip = GeoIPService()
        self.risk_analyzer = RiskAnalyzer(...)
        self.alert_manager = AlertManager(...)
        self.event_store = EventStore(...)

    async def initialize(self) -> None:
        """Initialize all services."""
        await self.geo_ip.initialize()
        await self.event_store.initialize()

    async def log_event(
        self,
        event_type: str,
        event_data: dict[str, Any],
        agent_id: str | None = None,
        user_id: str | None = None,
        ip_address: str | None = None
    ) -> SecurityAuditLog:
        """
        Log security event (main entry point).

        Workflow:
        1. Lookup location (GeoIPService)
        2. Calculate risk score (RiskAnalyzer)
        3. Check brute force (RiskAnalyzer)
        4. Check alert conditions (AlertManager)
        5. Save event (EventStore)
        """
        # Step 1: GeoIP lookup
        location_info = None
        if ip_address:
            location_info = self.geo_ip.lookup(ip_address)

        # Step 2: Risk analysis
        risk_score = await self.risk_analyzer.calculate_risk_score(
            event_type, event_data, location_info
        )

        # Step 3: Brute force detection
        brute_force_info = None
        if agent_id and event_type in ["authentication_failed", "authorization_denied"]:
            brute_force_info = await self.risk_analyzer.check_brute_force(
                agent_id, event_type
            )

        # Step 4: Alert if needed
        await self.alert_manager.check_and_notify(
            event_type, risk_score, event_data, brute_force_info
        )

        # Step 5: Store event
        event_hash = RiskAnalyzer.generate_event_hash(event_data)
        return await self.event_store.save(
            event_type, event_data, agent_id, user_id,
            ip_address, location_info, risk_score, event_hash
        )

    async def log_pattern_execution(
        self,
        pattern_id: str,
        agent_id: str,
        status: str,
        execution_data: dict[str, Any]
    ) -> SecurityAuditLog:
        """Log pattern execution (simplified delegation)."""
        return await self.log_event(
            event_type="pattern_execution",
            event_data={
                "pattern_id": pattern_id,
                "status": status,
                **execution_data
            },
            agent_id=agent_id
        )

    async def get_recent_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        agent_id: str | None = None,
        min_risk_score: int | None = None
    ) -> list[SecurityAuditLog]:
        """Query recent events (direct delegation)."""
        return await self.event_store.get_recent(
            limit, event_type, agent_id, min_risk_score
        )

    async def cleanup(self) -> None:
        """Cleanup all services."""
        await self.event_store.cleanup()
```

---

## 🔄 Migration Strategy

### Step 1: Create Subsystems (Parallel)
- Implement GeoIPService
- Implement RiskAnalyzer
- Implement AlertManager
- Implement EventStore

### Step 2: Create Facade
- Implement SecurityAuditFacade
- Wire all subsystems together
- Add comprehensive docstrings

### Step 3: Update Imports
1. `src/security/__init__.py`:
   ```python
   from .security_audit_facade import SecurityAuditFacade as AsyncSecurityAuditLogger
   ```

2. `src/security/security_middleware.py`:
   ```python
   from .security_audit_facade import SecurityAuditFacade
   ```

3. `src/security/audit_logger.py`:
   ```python
   from .security_audit_facade import SecurityAuditFacade
   ```

### Step 4: Archive Old Implementation
```bash
mv src/security/audit_logger_async.py \
   src_archive_phase4.2_$(date +%Y%m%d)/audit_logger_async.py
```

---

## ✅ Verification Checklist

### Code Quality
- [ ] Ruff compliance: 100%
- [ ] Python syntax validation: pass
- [ ] No circular import issues
- [ ] Type hints complete

### Functional
- [ ] All 336+ unit tests pass
- [ ] Integration tests pass
- [ ] Manual smoke test: log_event() works
- [ ] Manual smoke test: get_recent_events() works
- [ ] Manual smoke test: alerting works (if configured)

### Performance
- [ ] log_event() latency < 50ms (no regression)
- [ ] Memory usage stable
- [ ] No resource leaks

### Documentation
- [ ] Updated CLAUDE.md
- [ ] Updated CHANGELOG.md
- [ ] Added inline docstrings
- [ ] Updated REFACTORING_MANUAL_v1.md with lessons

---

## 🚨 Risk Assessment

| Risk Factor | Level | Mitigation |
|-------------|-------|------------|
| **Usage Sites** | MEDIUM | 3 files (security_middleware, audit_logger, __init__) |
| **Complexity** | HIGH | 604 LOC, multiple responsibilities |
| **Dependencies** | HIGH | GeoIP2, database, alerting systems |
| **Test Coverage** | UNKNOWN | Verify before refactoring |
| **Production Impact** | HIGH | Security auditing is critical |

**Overall Risk**: **MEDIUM-HIGH**

**Recommended Approach**:
1. Implement in feature branch
2. Run full test suite after each subsystem
3. Manual testing with real events
4. Gradual rollout (canary deployment if possible)
5. Monitor error rates closely

---

## 📊 Success Metrics

| Metric | Baseline | Target | Method |
|--------|----------|--------|--------|
| **LOC** | 604 | 520 | File size comparison |
| **Complexity** | ~60 (class) | ~15 (per file) | Ruff C901 |
| **Test Coverage** | TBD | +10% | pytest --cov |
| **Import Time** | TBD | No regression | timeit |
| **log_event() Latency** | TBD | <50ms | benchmark |

---

## 📅 Timeline

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| 4.2.1 Investigation | ✅ 30 min | Phase 4.1 complete |
| 4.2.2 Design | ✅ 30 min | 4.2.1 complete |
| 4.2.3 Subsystem Impl | 90 min | 4.2.2 approved |
| 4.2.4 Facade Impl | 45 min | 4.2.3 complete |
| 4.2.5 Testing | 60 min | 4.2.4 complete |
| 4.2.6 Documentation | 30 min | 4.2.5 pass |
| **Total** | **~5 hours** | - |

---

## 🎓 Lessons for REFACTORING_MANUAL_v1.md

**What to add after Phase 4.2 completes**:
1. Facade Pattern implementation tips
2. How to handle complex initialization (multiple services)
3. Backward compatibility via aliasing
4. Testing strategies for coordinated systems
5. Performance regression detection

---

**End of Specification**

*Ready for implementation approval.*
