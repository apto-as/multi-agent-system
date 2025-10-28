# TMWS Refactoring Manual v1.0
## Safe, Testable, Incremental Code Improvement Guide

**Created**: 2025-10-28
**Based on**: Phase 4.1 ConfigLoader Removal Success
**Author**: Athena (Trinitas Conductor)
**Status**: Production-ready template

---

## 🎯 Purpose

This manual documents the **proven refactoring methodology** used in TMWS Phase 4.1 (ConfigLoader removal). It provides a step-by-step template for safely reducing code duplication, improving architecture, and maintaining 100% test coverage during refactoring.

**Success Metrics from Phase 4.1**:
- Lines of code removed: **-310 LOC**
- Ruff compliance maintained: **100%**
- Test ratio maintained: **336 passed** (no regression)
- Execution time: **~30 minutes** (investigation → implementation → verification)
- Risk level: **LOW** (no production incidents)

---

## 📋 Pre-Refactoring Checklist

Before starting ANY refactoring task, complete this checklist:

### ✅ Phase 0: Preparation

1. **Baseline Measurement**
   ```bash
   # Record current test results
   pytest tests/unit/ -v > baseline_tests.txt

   # Record current Ruff status
   ruff check src/ > baseline_ruff.txt

   # Record file sizes
   find src/ -name "*.py" -exec wc -l {} + > baseline_loc.txt
   ```

2. **Git Status Verification**
   ```bash
   # Ensure clean working directory
   git status
   # Expected: nothing to commit, working tree clean
   ```

3. **Backup Creation**
   ```bash
   # Optional but recommended for HIGH risk changes
   cp -r src/ src_backup_$(date +%Y%m%d_%H%M%S)/
   ```

4. **Dependency Analysis**
   - Identify all files that import the target code
   - Document expected impact radius
   - Estimate migration effort

---

## 🔍 Phase 1: Investigation

### Step 1.1: Identify All Usage Sites

Use **Serena MCP Server** for comprehensive code analysis:

```python
# Search for symbol references
mcp__serena-mcp-server__search_for_pattern(
    substring_pattern="TargetClassName",
    restrict_search_to_code_files=True
)

# Find direct imports
mcp__serena-mcp-server__search_for_pattern(
    substring_pattern="from .* import TargetClassName",
    restrict_search_to_code_files=True
)
```

**Example from Phase 4.1**:
```bash
# Found 2 locations:
# 1. src/core/config_loader.py (definition)
# 2. scripts/setup_security.py (usage)
```

### Step 1.2: Analyze Symbol Structure

```python
# Get detailed structure
mcp__serena-mcp-server__get_symbols_overview(
    relative_path="src/path/to/target_file.py"
)
```

**Document**:
- Class hierarchy
- Public methods
- Dependencies (incoming and outgoing)
- Line count and complexity

### Step 1.3: Risk Assessment Matrix

| Factor | LOW | MEDIUM | HIGH |
|--------|-----|--------|------|
| **Usage sites** | 1-2 files | 3-5 files | 6+ files |
| **Test coverage** | 90%+ | 70-90% | <70% |
| **Complexity** | <300 LOC | 300-600 LOC | >600 LOC |
| **Dependencies** | 0-2 imports | 3-5 imports | 6+ imports |

**Decision Rule**:
- **All LOW**: Proceed immediately (Phase 4.1 pattern)
- **1+ MEDIUM**: Add extra verification steps
- **1+ HIGH**: Consider breaking into sub-phases

---

## 🛠️ Phase 2: Implementation

### Strategy A: Direct Replacement (LOW risk)

**Use when**: Target code is a thin wrapper around existing functionality

**Pattern from Phase 4.1**:
```python
# BEFORE: Dict-based config access (ConfigLoader)
self.config = ConfigLoader.load_config(config_path)
secret_key = self.config["security"]["secret_key"]
auth_enabled = self.config["security"]["auth_enabled"]

# AFTER: Attribute-based settings access (Pydantic)
self.settings = settings
secret_key = self.settings.secret_key
auth_enabled = self.settings.auth_enabled
```

**Implementation Steps**:
1. **Import change**:
   ```python
   # Remove old import
   from core.config_loader import ConfigLoader

   # Add new import
   from core.config import Settings, settings
   ```

2. **Initialization change**:
   ```python
   # Replace initialization
   self.config = ConfigLoader.load_config(...)  # ❌
   self.settings = settings  # ✅
   ```

3. **Usage change** (systematic replacement):
   ```python
   # Pattern: config["section"]["key"] → settings.key

   # Find all instances
   rg 'self\.config\["' src/path/to/file.py

   # Replace systematically (one method at a time)
   ```

4. **Backward compatibility** (if needed):
   ```python
   def __init__(self, _deprecated_param: str = None):
       if _deprecated_param:
           logger.warning(
               "Parameter 'deprecated_param' is deprecated. "
               "Use environment variables instead."
           )
       # New implementation
   ```

### Strategy B: Facade Pattern (MEDIUM risk)

**Use when**: Target code has complex subsystems that need reorganization

**Pattern for Phase 4.2 (AsyncSecurityAuditLogger)**:
```python
# BEFORE: Monolithic 618-line class
class AsyncSecurityAuditLogger:
    def log_event(self, event):
        # GeoIP logic
        # Risk analysis logic
        # Alert logic
        # Event storage logic
        # (618 lines total)

# AFTER: Facade + specialized services
class SecurityAuditFacade:
    def __init__(self):
        self.geo_ip = GeoIPService()
        self.risk_analyzer = RiskAnalyzer()
        self.alert_manager = AlertManager()
        self.event_store = EventStore()

    def log_event(self, event):
        # Coordinate subsystems (50 lines)
        location = self.geo_ip.lookup(event.ip)
        risk = self.risk_analyzer.assess(event)
        self.alert_manager.notify_if_needed(risk)
        self.event_store.save(event, location, risk)
```

**Benefits**:
- Each service is independently testable
- Complexity reduced from 618 → 4×150 lines
- Clear separation of concerns

### Strategy C: Composition Pattern (MEDIUM risk)

**Use when**: Large configuration class needs decomposition

**Pattern for Phase 4.3 (Settings)**:
```python
# BEFORE: Monolithic 728-line Settings
class Settings(BaseSettings):
    # Database settings (50 lines)
    # Security settings (100 lines)
    # API settings (80 lines)
    # Logging settings (60 lines)
    # ... (438 more lines)

# AFTER: Domain-specific settings classes
class DatabaseSettings(BaseSettings):
    url: str
    pool_size: int = 10
    echo: bool = False

class SecuritySettings(BaseSettings):
    secret_key: str
    auth_enabled: bool = True
    rate_limit: int = 100

class Settings(BaseSettings):
    # Composition
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)

    # Backward compatibility via properties
    @property
    def database_url(self) -> str:
        return self.database.url
```

**Benefits**:
- Settings grouped by domain
- Easier to test (mock only relevant settings)
- Backward compatible via proxy properties

### Strategy D: Strategy + Template Method (HIGH risk)

**Use when**: Complex algorithm needs flexibility

**Pattern for Phase 4.4 (PatternExecutionEngine)**:
```python
# BEFORE: Monolithic 933-line class with embedded executors
class PatternExecutionEngine:
    def execute(self, pattern, mode):
        if mode == "infrastructure":
            # Infrastructure logic (200 lines)
        elif mode == "memory":
            # Memory logic (180 lines)
        elif mode == "hybrid":
            # Hybrid logic (220 lines)
        # (333 more lines of shared logic)

# AFTER: Strategy pattern
class ExecutionStrategy(ABC):
    @abstractmethod
    async def execute(self, pattern: Pattern) -> Result:
        pass

class InfrastructureStrategy(ExecutionStrategy):
    async def execute(self, pattern: Pattern) -> Result:
        # 200 lines focused on infrastructure

class MemoryStrategy(ExecutionStrategy):
    async def execute(self, pattern: Pattern) -> Result:
        # 180 lines focused on memory

class PatternExecutionEngine:
    def __init__(self):
        self.strategies = {
            "infrastructure": InfrastructureStrategy(),
            "memory": MemoryStrategy(),
            "hybrid": HybridStrategy(),
        }

    async def execute(self, pattern, mode):
        strategy = self.strategies[mode]
        return await strategy.execute(pattern)
```

**Benefits**:
- Each strategy is independently testable
- Easy to add new execution modes
- Reduced cyclomatic complexity

---

## ✅ Phase 3: Verification

### Step 3.1: Code Quality Checks

```bash
# 1. Verify no references to old code
rg "OldClassName" src/ --type py
# Expected: 0 results (or only in comments/docs)

# 2. Ruff compliance
ruff check src/
# Expected: All checks passed!

# 3. Python syntax validation
python -m compileall src/ -q
# Expected: No output (success)

# 4. Import validation
python -c "import src.module_name"
# Expected: No ImportError
```

### Step 3.2: Test Execution

```bash
# Run full test suite
TMWS_DATABASE_URL="sqlite+aiosqlite:///:memory:" \
python -m pytest tests/unit/ -v --tb=short

# Expected:
# - X passed (same as baseline)
# - 0 new failures
# - 0 new errors
```

**Acceptance Criteria**:
- ✅ Same number of passing tests as baseline
- ✅ No new test failures introduced
- ✅ No new test errors introduced

### Step 3.3: Performance Verification (if applicable)

```bash
# For performance-critical changes
pytest tests/unit/test_performance.py -v --benchmark-only

# Compare with baseline metrics
```

### Step 3.4: Manual Smoke Testing

```bash
# Start the application
python -m src.mcp_server

# Test critical paths:
# 1. MCP server initialization
# 2. Memory creation/retrieval
# 3. Agent authentication
# 4. Search functionality
```

---

## 📊 Phase 4: Documentation & Commit

### Step 4.1: Update Documentation

**Files to update**:
1. **CHANGELOG.md**: Document the change
   ```markdown
   ### [Version] - Date

   #### Refactoring
   - **ConfigLoader Removal**: Migrated to Pydantic Settings
     - Impact: -310 LOC
     - Files affected: setup_security.py, config_loader.py
     - Test coverage maintained: 336 passed
   ```

2. **CLAUDE.md**: Update architectural decisions (if applicable)
   ```markdown
   ### Configuration Management

   **Status**: ✅ Pydantic Settings only (as of 2025-10-28)
   **Removed**: ConfigLoader (YAML-based, deprecated)
   **Rationale**: Eliminate duplication, use industry-standard approach
   ```

3. **README.md**: Update setup instructions (if needed)

### Step 4.2: Git Commit

```bash
# Stage changes
git add src/ scripts/ docs/

# Commit with structured message
git commit -m "refactor(config): Remove ConfigLoader duplication

- Delete src/core/config_loader.py (-310 LOC)
- Migrate setup_security.py to Pydantic Settings
- Maintain 100% Ruff compliance
- Test ratio maintained: 336 passed

Rationale: ConfigLoader duplicated Pydantic Settings functionality.
Environment variables are industry standard for configuration.

Risk: LOW
Impact: setup_security.py only
Verification: All 336 unit tests pass"
```

**Commit Message Template**:
```
<type>(<scope>): <subject>

- <change 1>
- <change 2>
- <change 3>

Rationale: <why this change was made>

Risk: <LOW/MEDIUM/HIGH>
Impact: <files affected>
Verification: <test results>
```

**Types**:
- `refactor`: Code restructuring (no functional change)
- `feat`: New feature
- `fix`: Bug fix
- `perf`: Performance improvement
- `docs`: Documentation only

---

## 🚨 Rollback Procedures

### If Tests Fail

**Option 1: Fix Forward** (preferred for LOW risk changes)
```bash
# Analyze failure
pytest tests/unit/test_failing.py -vv

# Fix the issue
# Re-run verification
```

**Option 2: Rollback** (for MEDIUM/HIGH risk changes with unexpected issues)
```bash
# Soft rollback (keep changes for analysis)
git stash

# Hard rollback (discard changes)
git reset --hard HEAD

# Restore from backup (if created)
rm -rf src/
mv src_backup_YYYYMMDD_HHMMSS/ src/
```

### If Production Issues Occur

**Immediate Actions**:
1. **Alert team**: Notify via monitoring/chat
2. **Assess impact**: Check error logs, user reports
3. **Quick decision**:
   - If minor (< 1% users affected): Fix forward
   - If major (> 1% users affected): Rollback immediately

**Rollback Command**:
```bash
# Revert the commit
git revert <commit-hash>

# Deploy immediately
./deploy.sh
```

---

## 📈 Success Metrics

### Code Quality Metrics

| Metric | Target | Phase 4.1 Result |
|--------|--------|------------------|
| **LOC Reduction** | >200 lines | ✅ 310 lines |
| **Ruff Compliance** | 100% | ✅ 100% |
| **Test Coverage** | No regression | ✅ 336 passed |
| **Execution Time** | < 2 hours | ✅ ~30 minutes |
| **Production Incidents** | 0 | ✅ 0 |

### Process Metrics

| Phase | Estimated | Actual (Phase 4.1) |
|-------|-----------|-------------------|
| Investigation | 10-20 min | ~10 min |
| Implementation | 20-40 min | ~15 min |
| Verification | 10-20 min | ~5 min |
| **Total** | **40-80 min** | **✅ ~30 min** |

---

## 🎓 Lessons Learned from Phase 4.1

### ✅ What Worked Well

1. **Serena MCP Server**: Extremely efficient for finding all usage sites
   - Zero false negatives
   - Clear, structured output
   - Faster than manual grep/rg

2. **Systematic Replacement**: One method at a time
   - Easy to verify each step
   - Clear before/after comparison
   - Minimal risk of mistakes

3. **Backward Compatibility**: Deprecation warnings
   - Users have time to migrate
   - No breaking changes
   - Clear migration path

4. **Incremental Verification**: Check after each edit
   - Catch errors early
   - Easy to identify root cause
   - Faster debugging

### ⚠️ What to Improve

1. **Test Suite Baseline**: Establish baseline BEFORE starting
   - Some pre-existing test failures confused verification
   - Recommendation: Fix all tests before refactoring

2. **Documentation**: Update docs DURING implementation
   - Easy to forget what changed
   - Capture decisions while fresh

---

## 📚 Reference Examples

### Example 1: Import Migration (Phase 4.1)

**File**: `scripts/setup_security.py:25`

**Before**:
```python
from core.config_loader import ConfigLoader
```

**After**:
```python
from core.config import Settings, settings
```

**Verification**:
```bash
rg "ConfigLoader" scripts/setup_security.py
# Expected: 0 results
```

### Example 2: Dict → Attribute Access (Phase 4.1)

**File**: `scripts/setup_security.py:103`

**Before**:
```python
if not self.config["security"]["secret_key"] or len(self.config["security"]["secret_key"]) < 32:
    secret_key = secrets.token_urlsafe(64)
```

**After**:
```python
if not self.settings.secret_key or len(self.settings.secret_key) < 32:
    secret_key = secrets.token_urlsafe(64)
    logger.info("Generated new secret key (set TMWS_SECRET_KEY to persist)")
```

**Benefits**:
- ✅ Type-safe (Pydantic validates)
- ✅ Auto-completion in IDEs
- ✅ Clearer intent
- ✅ Better error messages

### Example 3: Backward Compatibility (Phase 4.1)

**File**: `scripts/setup_security.py:49`

**Before**:
```python
def __init__(self, config_path: str = None):
    self.config = ConfigLoader.load_config(config_path)
```

**After**:
```python
def __init__(self, _config_path: str = None):
    # Config path parameter is deprecated but kept for backward compatibility
    if _config_path:
        logger.warning(
            "Config file path is deprecated. Using environment variables instead. "
            "Set TMWS_SECRET_KEY and other TMWS_* variables."
        )

    self.settings = settings
```

**Pattern**:
- Prefix deprecated params with `_`
- Keep in signature for backward compat
- Warn users on usage
- Use new approach internally

---

## 🔮 Future Phases

### Phase 4.2: AsyncSecurityAuditLogger (MEDIUM risk)
- **Strategy**: Facade Pattern
- **LOC Impact**: -618 → +600 (net -18, but better structure)
- **Estimated Time**: 2-3 hours
- **Key Risk**: Alert system integration

### Phase 4.3: Settings Splitting (MEDIUM risk)
- **Strategy**: Composition Pattern
- **LOC Impact**: -728 → +650 (net -78, clearer domains)
- **Estimated Time**: 2-3 hours
- **Key Risk**: Backward compatibility

### Phase 4.4: PatternExecutionEngine (HIGH risk)
- **Strategy**: Strategy + Template Method
- **LOC Impact**: -933 → +750 (net -183, much clearer)
- **Estimated Time**: 4-6 hours (HIGH complexity)
- **Key Risk**: Execution logic correctness

**Total Expected Impact**: **-310 - 18 - 78 - 183 = -589 LOC** (4.7% reduction)

---

## 📞 Support & Questions

**For refactoring questions**:
- Consult: `docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md`
- Review: `.claude/CLAUDE.md` (project knowledge base)
- Ask: Trinitas agents (especially Artemis for technical, Hestia for risk)

**For this manual**:
- Author: Athena (Trinitas Harmonious Conductor)
- Based on: Phase 4.1 ConfigLoader removal (2025-10-28)
- Version: 1.0

---

**End of Manual**

*This manual will evolve as we complete Phase 4.2, 4.3, and 4.4. Each phase will add lessons learned and refine the methodology.*
