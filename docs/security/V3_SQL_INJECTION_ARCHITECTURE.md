# V-3 SQL Injection Mitigation Architecture
## TMWS v2.4.0 Day 2-1: Core Security Hardening (Phase 2-3.1 Joint Deliverable)

**Document Status**: ✅ **APPROVED** (Artemis + Hestia Joint Design)
**Created**: 2025-11-24
**Version**: 1.0
**Phase**: Day 2-1, Phase 2-3.1 (Hour 0-1 Joint Design)
**CVSS Score**: 5.3 MEDIUM (downgraded from initial 7.8 HIGH)

---

## Executive Summary

This document defines the architecture for mitigating **LIKE injection vulnerabilities** (V-3) in TMWS v2.4.0. Based on comprehensive technical analysis (Artemis) and threat modeling (Hestia), we have identified 6 vulnerable LIKE queries and designed a centralized `SecureQueryBuilder` abstraction layer to prevent SQL injection attacks.

### Key Findings:

1. **SQL Injection (UNION attacks)**: ❌ **IMPOSSIBLE** - SQLAlchemy's parameterization provides complete defense
2. **LIKE Pattern Injection (DoS)**: ⚠️ **POSSIBLE** - Wildcard abuse can cause performance degradation (CVSS 5.3)
3. **Information Disclosure**: ⚠️ **LIMITED** - Existing access control prevents cross-namespace attacks
4. **Mitigation Strategy**: ✅ **APPROVED** - `SecureQueryBuilder` with wildcard escaping + ESCAPE clause

### Scope:

- **Files to Create**: 2 (SecureQueryBuilder, test suite)
- **Files to Modify**: 3 (learning_service, agent_service, pattern_execution_service)
- **Vulnerable Queries**: 6 LIKE injections
- **Test Coverage**: 29 test scenarios (exceeding 20+ requirement)
- **Estimated Effort**: 5.5 hours (Design 1h + Implementation 3h + Validation 1.5h)

---

## 1. Vulnerability Analysis (Artemis's Technical Assessment)

### 1.1 Identified Vulnerabilities (6 Total)

#### **File 1: `src/services/learning_service.py`** (2 vulnerabilities)

**Line 339** - Pattern name search:
```python
# BEFORE (❌ VULNERABLE)
pattern_name.ilike(f"%{query_text}%")
```

**Line 343** - Pattern data search:
```python
# BEFORE (❌ VULNERABLE)
pattern_data.like(f"%{query_text.lower()}%")
```

**Attack Vector**:
```python
query_text = "test%' UNION SELECT password FROM users WHERE '1'='1"
# Generated query: WHERE pattern_name ILIKE '%test%' UNION SELECT password FROM users WHERE '1'='1%'
# However: SQLAlchemy parameterization prevents this attack ✅
```

---

#### **File 2: `src/services/agent_service.py`** (3 vulnerabilities)

**Lines 866-868** - Agent search (3 columns):
```python
# BEFORE (❌ VULNERABLE)
display_name.ilike(f"%{query}%")
agent_id.ilike(f"%{query}%")
agent_type.ilike(f"%{query}%")
```

**Attack Vector**: Same as above, but affects 3 separate search paths.

---

#### **File 3: `src/services/pattern_execution_service.py`** (1 vulnerability)

**Line 810** - Pattern content search:
```python
# BEFORE (❌ VULNERABLE)
content.ilike(f"%{query}%")
```

---

### 1.2 Codebase Audit Summary

**Scope**: 84 Python files with database access
**Methodology**: Automated scan + manual analysis

**Results**:
- **Total ORM Usage**: 100% SQLAlchemy (no direct SQL drivers) ✅
- **Raw SQL Usage**: 3 instances of `text()` (all safe):
  1. Health check query (static SQL) ✅
  2. Statistics update (parameterized with `.bindparams()`) ✅
  3. JSON array search (parameterized with `.bindparams()`) ✅
- **LIKE Injection**: 6 instances (identified above)
- **Other Injection Vectors**: ❌ None found (ORDER BY, LIMIT, column names all safe)

**Conclusion**: Attack surface is **limited to LIKE queries** ✅

---

## 2. Threat Modeling (Hestia's Security Assessment)

### 2.1 Threat Classification

#### **Threat 1: SQL Injection (UNION Attacks)** - ❌ **NOT EXPLOITABLE**

**Severity**: N/A (mitigated by SQLAlchemy)
**Probability**: 0%

**Rationale**:
- SQLAlchemy converts all `.ilike()` calls to parameterized queries
- User input is passed as parameter value, not concatenated into SQL string
- UNION attacks require SQL string concatenation, which doesn't occur

**SQLAlchemy Internal Behavior**:
```python
# Code:
.where(Memory.content.ilike(f"%{user_input}%"))

# Generated SQL:
# WHERE content ILIKE :param_1
# Parameters: {":param_1": "%user_input%"}

# Result: user_input is treated as literal string, not SQL code ✅
```

**Verification**: Hestia reviewed SQLAlchemy documentation and confirmed automatic parameterization.

---

#### **Threat 2: LIKE Pattern Injection (DoS Attack)** - ⚠️ **EXPLOITABLE**

**Severity**: CVSS 5.3 MEDIUM
**CVSS Vector**: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L`

**Attack Scenario 1: Wildcard Abuse**
```python
malicious_input = "%%%%%%%%%%%%%%%%"  # 16 consecutive %

# Generated query:
# WHERE pattern_name ILIKE '%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'
# (prefix % + malicious_input + suffix %)

# Impact: Full table scan (10,000 rows → ~500ms latency)
```

**Attack Scenario 2: Coordinated DoS**
```python
# 10 attackers × 100 req/s × 500ms/req = 500 CPU seconds/second
# Result: Database overload → Service degradation/downtime
# CVSS: 7.5 HIGH (if coordinated)
```

**Mitigation**:
1. **Wildcard Escaping** (P0) - Prevents wildcard abuse
2. **Rate Limiting** (P1) - Limits DoS impact to 100 req/min per user
3. **Performance Monitoring** (P1) - Alerts on slow queries (>100ms)

---

#### **Threat 3: Information Disclosure** - ⚠️ **LIMITED IMPACT**

**Severity**: CVSS 2.0 LOW
**CVSS Vector**: `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`

**Attack Scenario**:
```python
malicious_input = "%"  # Match everything

# Result: Retrieve all patterns accessible to attacker
# Accessible data:
# 1. Own namespace (PRIVATE/TEAM) ✅ Legitimate access
# 2. Shared patterns (SHARED with attacker in list) ✅ Legitimate access
# 3. Public/System patterns ✅ Legitimate access

# NOT accessible:
# 1. Other namespaces (PRIVATE) ❌ P0-1 namespace isolation blocks this
# 2. Shared patterns (not in attacker's list) ❌ Access control blocks this
```

**Defense**:
- **P0-1 Namespace Isolation** (completed) ✅
- **Access Control Layer** (verified) ✅
- **Result Pagination** (default 50 items) ✅

**Conclusion**: Cross-namespace attacks **prevented** by existing security layers ✅

---

### 2.2 Attack Surface Summary

| Attack Type | Exploitable? | Severity | Mitigation Status |
|-------------|-------------|----------|-------------------|
| SQL Injection (UNION) | ❌ No | N/A | ✅ SQLAlchemy built-in |
| LIKE Wildcard DoS | ✅ Yes | CVSS 5.3 | ⚠️ P0 implementation needed |
| Information Disclosure | ⚠️ Limited | CVSS 2.0 | ✅ P0-1 namespace isolation |
| Second-order Injection | ⚠️ Limited | CVSS 5.3 | ⚠️ Same as wildcard DoS |
| ORDER BY Injection | ❌ No | N/A | ✅ No vulnerable code found |
| Column Name Injection | ❌ No | N/A | ✅ No vulnerable code found |

**Final Threat Level**: CVSS **5.3 MEDIUM** (DoS via wildcard abuse)

---

## 3. SecureQueryBuilder Architecture (Joint Design)

### 3.1 Design Principles

1. **Centralized Security**: All SQL query construction goes through `SecureQueryBuilder`
2. **Defense in Depth**: Wildcard escaping + parameterization + access control
3. **Backward Compatible**: Drop-in replacement for existing `.ilike()` calls
4. **Performance**: Zero overhead (simple string replacement)
5. **Testability**: Pure functions, easy to unit test

---

### 3.2 Class Design

**File**: `src/security/query_builder.py` (new)

```python
"""Secure query builder for SQL injection prevention.

V-3 Mitigation (CVSS 5.3 MEDIUM): All LIKE queries MUST escape wildcards.

Security Guarantees:
1. SQL Injection (UNION): Prevented by SQLAlchemy parameterization ✅
2. LIKE Wildcard DoS: Prevented by wildcard escaping ✅
3. Information Disclosure: Prevented by access control layer ✅
"""
from typing import Type, Dict, Any, List, Tuple
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase

class SecureQueryBuilder:
    """Centralized parameterized query builder.

    Usage:
        # Basic wildcard escaping
        escaped, escape_char = SecureQueryBuilder.safe_like_pattern(user_input)
        query.where(Memory.content.ilike(f"%{escaped}%", escape=escape_char))

        # Full-text search across multiple columns
        query = SecureQueryBuilder.build_search_query(
            model=Memory,
            search_columns=["content", "tags"],
            search_term=user_input,
            session=session
        )
    """

    @staticmethod
    def safe_like_pattern(
        user_input: str,
        escape_char: str = "\\",
        allow_wildcards: bool = False
    ) -> Tuple[str, str]:
        """Escape LIKE wildcards in user input.

        Escapes: % (match any), _ (match one), \ (escape char)

        Args:
            user_input: User-provided search term
            escape_char: ESCAPE character (default: backslash)
            allow_wildcards: If True, preserve user's % and _ (DANGEROUS)

        Returns:
            (escaped_pattern, escape_char)

        Example:
            >>> safe_like_pattern("50%_off")
            ("50\\%\\_off", "\\")

            # In SQL:
            # WHERE price LIKE '%50\\%\\_off%' ESCAPE '\\'
            # Matches: "Save 50%_off today!" (literal percent and underscore)

        Security:
            - Prevents DoS via wildcard abuse (%%%%%%%%)
            - Prevents second-order injection (stored malicious patterns)
            - Does NOT prevent SQL injection (SQLAlchemy handles that)
        """
        if allow_wildcards:
            # DANGEROUS: User can still cause DoS
            return user_input, escape_char

        # Step 1: Escape the escape character itself (must be first)
        escaped = user_input.replace(escape_char, escape_char + escape_char)

        # Step 2: Escape percent wildcard (matches any characters)
        escaped = escaped.replace("%", escape_char + "%")

        # Step 3: Escape underscore wildcard (matches single character)
        escaped = escaped.replace("_", escape_char + "_")

        return escaped, escape_char

    @staticmethod
    def build_filter_query(
        model: Type[DeclarativeBase],
        filters: Dict[str, Any],
        session: AsyncSession
    ):
        """Build safe SELECT query with exact match filters.

        Security:
            - Column names validated against model schema
            - Values parameterized by SQLAlchemy
            - No user input in SQL string

        Args:
            model: SQLAlchemy model class (e.g., Memory, Agent)
            filters: Column-value pairs (e.g., {"agent_id": "123"})
            session: Async database session

        Returns:
            SQLAlchemy select() query (parameterized)

        Raises:
            ValueError: If filter references invalid column

        Example:
            >>> query = build_filter_query(
            ...     Memory,
            ...     {"agent_id": "agent-123", "access_level": "PRIVATE"},
            ...     session
            ... )
            # Generated SQL:
            # SELECT * FROM memories WHERE agent_id = :agent_id AND access_level = :access_level
            # Parameters: {":agent_id": "agent-123", ":access_level": "PRIVATE"}
        """
        query = select(model)

        for column_name, value in filters.items():
            # Validate column exists (prevent injection via column name)
            if not hasattr(model, column_name):
                raise ValueError(
                    f"Invalid column '{column_name}' for {model.__name__}. "
                    f"Valid columns: {[c.name for c in model.__table__.columns]}"
                )

            column = getattr(model, column_name)
            query = query.where(column == value)  # Parameterized by SQLAlchemy ✅

        return query

    @staticmethod
    def build_search_query(
        model: Type[DeclarativeBase],
        search_columns: List[str],
        search_term: str,
        session: AsyncSession,
        case_insensitive: bool = True
    ):
        """Build safe text search with LIKE across multiple columns.

        Security:
            - Wildcards escaped (prevents DoS)
            - Columns validated (prevents column name injection)
            - Values parameterized (prevents SQL injection)

        Args:
            model: SQLAlchemy model class
            search_columns: Columns to search (e.g., ["content", "tags"])
            search_term: User search term (will be escaped)
            session: Async database session
            case_insensitive: Use ILIKE (default: True)

        Returns:
            SQLAlchemy select() query with OR conditions

        Example:
            >>> query = build_search_query(
            ...     Memory,
            ...     ["content", "tags"],
            ...     "50%_off",  # User input with wildcards
            ...     session
            ... )
            # Generated SQL:
            # SELECT * FROM memories
            # WHERE content ILIKE '%50\\%\\_off%' ESCAPE '\\'
            #    OR tags ILIKE '%50\\%\\_off%' ESCAPE '\\'
        """
        # Validate all columns exist
        for col in search_columns:
            if not hasattr(model, col):
                raise ValueError(
                    f"Invalid column '{col}' for {model.__name__}"
                )

        # Escape wildcards in search term
        escaped_term, escape_char = SecureQueryBuilder.safe_like_pattern(search_term)

        # Add prefix/suffix wildcards for substring search
        pattern = f"%{escaped_term}%"

        # Build OR conditions for each column
        conditions = []
        for col in search_columns:
            column = getattr(model, col)
            if case_insensitive:
                # ILIKE for case-insensitive search
                conditions.append(column.ilike(pattern, escape=escape_char))
            else:
                # LIKE for case-sensitive search
                conditions.append(column.like(pattern, escape=escape_char))

        return select(model).where(or_(*conditions))
```

---

### 3.3 Migration Strategy

#### **Step 1: Replace Vulnerable LIKE Queries** (6 files to modify)

**Pattern**: Replace direct f-string with `safe_like_pattern()` + `escape=` parameter

```python
# BEFORE (❌ VULNERABLE)
.where(Memory.content.ilike(f"%{user_input}%"))

# AFTER (✅ SECURE)
from src.security.query_builder import SecureQueryBuilder

escaped_input, escape_char = SecureQueryBuilder.safe_like_pattern(user_input)
.where(Memory.content.ilike(f"%{escaped_input}%", escape=escape_char))
```

#### **Step 2: Update All 6 Vulnerable Queries**

1. **learning_service.py:339**
   ```python
   # Before:
   pattern_name.ilike(f"%{query_text}%")

   # After:
   escaped_query, escape_char = SecureQueryBuilder.safe_like_pattern(query_text)
   pattern_name.ilike(f"%{escaped_query}%", escape=escape_char)
   ```

2. **learning_service.py:343**
   ```python
   # Before:
   pattern_data.like(f"%{query_text.lower()}%")

   # After:
   escaped_query, escape_char = SecureQueryBuilder.safe_like_pattern(query_text.lower())
   pattern_data.like(f"%{escaped_query}%", escape=escape_char)
   ```

3. **agent_service.py:866-868** (3 instances)
   ```python
   # Before:
   or_(
       Agent.display_name.ilike(f"%{query}%"),
       Agent.agent_id.ilike(f"%{query}%"),
       Agent.agent_type.ilike(f"%{query}%")
   )

   # After:
   escaped_query, escape_char = SecureQueryBuilder.safe_like_pattern(query)
   or_(
       Agent.display_name.ilike(f"%{escaped_query}%", escape=escape_char),
       Agent.agent_id.ilike(f"%{escaped_query}%", escape=escape_char),
       Agent.agent_type.ilike(f"%{escaped_query}%", escape=escape_char)
   )
   ```

4. **pattern_execution_service.py:810**
   ```python
   # Before:
   content.ilike(f"%{query}%")

   # After:
   escaped_query, escape_char = SecureQueryBuilder.safe_like_pattern(query)
   content.ilike(f"%{escaped_query}%", escape=escape_char)
   ```

---

## 4. Test Strategy (Hestia's Recommendations)

### 4.1 Test Coverage (29 Test Scenarios)

**File**: `tests/unit/security/test_sql_injection_prevention.py` (new)

#### **Category A: Basic Escaping (5 tests)**
1. `test_escape_percent` - Single `%` wildcard
2. `test_escape_underscore` - Single `_` wildcard
3. `test_escape_backslash` - Single `\` escape character
4. `test_escape_combined` - Mix of `%`, `_`, `\`
5. `test_escape_empty_string` - Empty input handling

#### **Category B: Attack Patterns (5 tests)**
6. `test_multiple_percent` - DoS attack (16 consecutive `%`)
7. `test_multiple_underscore` - DoS attack (16 consecutive `_`)
8. `test_alternating_wildcards` - Pattern `%_%_%`
9. `test_double_escape_attack` - `\\%` double escaping
10. `test_null_byte_injection` - `\x00` NULL byte

#### **Category C: Edge Cases (5 tests)**
11. `test_unicode_fullwidth` - Full-width `％` and `＿`
12. `test_special_characters` - Non-wildcard special chars
13. `test_very_long_pattern` - 1000 character input
14. `test_utf8_multibyte` - Japanese/Chinese characters
15. `test_escape_clause_generation` - ESCAPE clause correctness

#### **Category D: SQLAlchemy Integration (4 tests)**
16. `test_ilike_with_escape` - `.ilike()` + ESCAPE integration
17. `test_like_with_escape` - `.like()` + ESCAPE integration
18. `test_parameterization_preserved` - Verify parameterization
19. `test_multiple_like_clauses` - Multiple LIKE conditions

#### **Category E: Service Layer Tests (4 tests)**
20. `test_learning_service_search_patterns` - `LearningService.search_patterns()`
21. `test_agent_service_search_agents` - `AgentService.search_agents()`
22. `test_pattern_execution_service` - `PatternExecutionService._execute_memory()`
23. `test_access_control_preserved` - Namespace isolation intact

#### **Category F: Performance Tests (3 tests)**
24. `test_performance_normal_query` - Baseline (<20ms)
25. `test_performance_wildcard_heavy` - 16 `%` wildcards (<100ms target)
26. `test_performance_10000_rows` - Scalability test

#### **Category G: Security Validation (3 tests)**
27. `test_sql_injection_union_attack` - UNION attack prevention
28. `test_timing_attack_resistance` - Side-channel mitigation
29. `test_pattern_pollution_prevention` - Malicious pattern detection

**Total**: 29 tests (exceeds 20+ requirement) ✅

---

### 4.2 Success Criteria

**Phase 2-3.3 Validation** (Hour 4-5.5):
- [ ] All 29 injection tests PASS ✅
- [ ] Zero regression (686 baseline tests PASS) ✅
- [ ] Performance targets met:
  - Normal query: <20ms P95
  - Wildcard-heavy: <100ms P95
  - 10,000 rows: <200ms P95
- [ ] Hestia security sign-off ✅

---

## 5. Implementation Plan (Phase 2-3.2)

### 5.1 Timeline: Hour 1-4 (3 hours)

**Hour 1-2**: `SecureQueryBuilder` implementation
- [ ] Create `src/security/query_builder.py` (150-200 lines)
- [ ] Implement `safe_like_pattern()` method
- [ ] Implement `build_search_query()` method
- [ ] Add comprehensive docstrings with security warnings

**Hour 2-3**: Migrate 6 vulnerable queries
- [ ] Update `learning_service.py` (2 queries)
- [ ] Update `agent_service.py` (3 queries)
- [ ] Update `pattern_execution_service.py` (1 query)
- [ ] Add imports for `SecureQueryBuilder`

**Hour 3-4**: Test suite implementation
- [ ] Create `tests/unit/security/test_sql_injection_prevention.py`
- [ ] Implement 29 test scenarios
- [ ] Run local validation (pytest)
- [ ] Verify zero regression

---

### 5.2 Deliverables

1. **Code** (300-400 LOC total):
   - `src/security/query_builder.py` (150-200 lines)
   - Service file modifications (50-100 lines)
   - Test suite (1,500-2,000 lines)

2. **Documentation**:
   - This architecture document ✅
   - Inline code documentation (docstrings)
   - Security audit trail (commit messages)

3. **Validation**:
   - 29 test scenarios PASS
   - Zero regression (686 baseline tests)
   - Hestia security sign-off

---

## 6. Risk Assessment

### 6.1 Implementation Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Performance regression | LOW | MEDIUM | Performance tests in suite |
| Backward compatibility | LOW | HIGH | Zero API changes |
| Edge case bugs | MEDIUM | LOW | 29 comprehensive tests |
| Developer confusion | LOW | LOW | Clear documentation |

### 6.2 Post-Deployment Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| DoS attack (coordinated) | LOW | HIGH | P1: Rate limiting (100 req/min) |
| Wildcard bypass | VERY LOW | MEDIUM | Escape character validation |
| New LIKE queries added | MEDIUM | MEDIUM | Code review checklist |

---

## 7. Future Enhancements (P2 - Post-GATE 1)

### 7.1 Full-Text Search Migration (Strategic Decision)

**Problem**: LIKE queries are inherently slow for full-text search
**Options**:
1. **SQLite FTS5 Extension** - Built-in full-text search
2. **ChromaDB Text Search** - Leverage existing vector store
3. **Elasticsearch** - Overkill for current scale

**Recommendation**: Defer to Athena + Hera strategic planning (Phase 3+)

### 7.2 Security Audit Logging

**Implementation**: Log suspicious LIKE patterns
```python
if len(user_input) > 50 or user_input.count("%") > 5:
    audit_logger.log_suspicious_query(
        user_input=user_input,
        user_id=current_user.id,
        endpoint=request.url
    )
```

**Priority**: P2 (post-GATE 1)

---

## 8. Sign-Off

### 8.1 Technical Review

- [x] **Artemis (Technical Analysis)**: 6 vulnerabilities identified, mitigation designed ✅
- [x] **Hestia (Threat Modeling)**: CVSS 5.3 assessment complete, SecureQueryBuilder approved ✅

### 8.2 Next Steps

**Proceed to Phase 2-3.2 (Implementation)**: Hour 1-4

**Assigned**: Artemis (Lead Implementation)
**Support**: Hestia (Security Validation)
**Checkpoint**: Hour 5.5-6 (V-3 Complete, V-2 Design Review)

---

**End of Joint Deliverable**

*Prepared by*: Artemis (Technical Perfectionist) + Hestia (Security Guardian)
*Approved for Implementation*: 2025-11-24
*Phase 2-3.1 Complete* ✅
