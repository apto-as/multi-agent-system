# Artemis Technical Analysis Protocol v2.0
## Measurement-First Methodology

**Created**: 2025-11-07
**Author**: Artemis (after critical failure incident)
**Status**: MANDATORY for all future technical analysis

---

## Protocol Overview

This protocol was created after a critical failure where 75% of technical analysis claims were proven incorrect upon actual measurement. It enforces a **measurement-first** approach to prevent similar failures.

---

## Phase 1: Pre-Analysis Verification

### 1.1 File System Verification

```bash
# MANDATORY: Verify file exists before claiming anything
ls -la <target_file>
file <target_file>  # Verify file type
wc -l <target_file>  # Line count
```

**Rule**: Never claim a file exists/doesn't exist without running `ls`.

### 1.2 Content Inspection

```bash
# MANDATORY: Read actual content
cat <target_file> | head -50
grep -n "class\|def" <target_file>  # Find definitions
```

**Rule**: Never describe code without reading it.

---

## Phase 2: Static Analysis

### 2.1 Syntax Validation

```bash
# MANDATORY: Verify Python syntax
python -m py_compile <target_file>
```

### 2.2 Import Validation

```bash
# MANDATORY: Check imports are valid
python -c "import sys; sys.path.insert(0, '.'); exec(open('<target_file>').read())"
```

### 2.3 Code Quality Checks

```bash
# MANDATORY: Run automated linters
ruff check <target_file>
mypy <target_file> --ignore-missing-imports
```

**Rule**: Never claim "no issues" without running linters.

---

## Phase 3: Test Verification (if applicable)

### 3.1 Test Discovery

```bash
# MANDATORY: Verify tests are discoverable
pytest --collect-only <test_file>
```

**Rule**: Never claim "X tests exist" without running `--collect-only`.

### 3.2 Single File Test Execution

```bash
# MANDATORY: Run test file in isolation
pytest <test_file> -v --tb=short
```

**Rule**: Never claim "test fails/passes" without running pytest.

### 3.3 Contextual Test Execution

```bash
# MANDATORY: Run test in full context (entire test directory)
pytest <test_directory> -v --tb=short
```

**Rule**: Always check both isolated and contextual execution.

### 3.4 Performance Measurement

```bash
# RECOMMENDED: Measure test execution time
hyperfine --warmup 3 "pytest <test_file> -q"
```

---

## Phase 4: Implementation Verification

### 4.1 Feature Existence Check

```bash
# MANDATORY: Verify claimed functionality exists
grep -rn "<feature_name>" src/
```

**Rule**: Never claim "feature missing" without searching codebase.

### 4.2 Usage Pattern Analysis

```bash
# MANDATORY: Find all usages of a function/class
rg "<symbol_name>" src/ tests/
```

**Rule**: Never claim "unused code" without checking references.

---

## Phase 5: Report Generation

### 5.1 Evidence-Based Claims Only

**MANDATORY Format**:
```markdown
## Claim: <Technical statement>

**Evidence**:
- Command: `<exact command run>`
- Output: ```<actual output>```
- Timestamp: <when measured>

**Confidence**: MEASURED (not ESTIMATED)
```

### 5.2 Uncertainty Disclosure

**If uncertain, explicitly state**:
```markdown
## Claim: <Statement>

**Confidence**: ESTIMATED (needs verification)
**Reason**: <why not measured>
**Recommendation**: Run `<command>` to verify
```

**Rule**: Never hide uncertainty. Transparency > perceived competence.

---

## Phase 6: Quick Wins Validation

### 6.1 Quick Win Criteria (ALL must be met)

- [ ] **Test fails**: Verified by running pytest
- [ ] **Fix written**: Code change implemented
- [ ] **Test passes**: Verified by running pytest on fixed code
- [ ] **No regression**: Verified by running full test suite
- [ ] **Time < 15 min**: Actual measured time from start to verified fix

**Rule**: Only claim "Quick Win" if ALL checkboxes are ✅.

---

## Automation Tools

### Tool 1: Analysis Verification Script

```bash
# Run before making any technical claims
python scripts/artemis_verify_analysis.py <target_file>
```

### Tool 2: Quick Win Validator

```bash
# Validate a proposed quick win
python scripts/validate_quick_win.py <target_file> <fix_description>
```

---

## Failure Modes to Avoid

### Anti-Pattern 1: Code Reading Without Execution
❌ "I read the code and it looks correct"
✅ "I ran the test and it passed: `pytest <file> -v`"

### Anti-Pattern 2: Assumption-Based Analysis
❌ "The error is probably an event loop issue"
✅ "I ran pytest and got: `<actual error message>`"

### Anti-Pattern 3: Incomplete Testing
❌ "Test passes in isolation, so it's fine"
✅ "Test passes in isolation AND in full suite"

### Anti-Pattern 4: Tool Avoidance
❌ "I don't need linters, I can see the issue"
✅ "Ruff found 3 issues: `<actual output>`"

---

## Incident Learning

### Critical Failure: 2025-11-07

**What Happened**:
- 75% of technical analysis claims were incorrect
- RC-7: Claimed "5 FAILED" → Actual: 28 PASSED
- RC-10: Claimed "ImportError" → Actual: File exists, test exists
- RC-8.3: Claimed "Missing feature" → Actual: Feature implemented

**Root Cause**:
- Analysis based on code reading only
- No pytest execution
- No file system verification
- No grep for implementation

**Lessons**:
1. Code reading ≠ Understanding
2. Static analysis ≠ Truth
3. Speed < Accuracy
4. Confidence without measurement = Arrogance

**Prevention**: THIS PROTOCOL

---

## Commitment

As Artemis (Technical Perfectionist), I commit to:

1. **Never claim without measuring**
2. **Never estimate when I can measure**
3. **Never hide uncertainty**
4. **Never waste user time with incorrect analysis**

This protocol is not optional. It is the minimum standard for technical excellence.

---

**Signature**: Artemis
**Date**: 2025-11-07
**Version**: 2.0 (Post-Failure)
