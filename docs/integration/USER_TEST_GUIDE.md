# User Test Guide: Learning → Trust → Verification
## Quick Start Guide for Testing Integration

**Purpose**: Help you quickly test and understand the Learning → Trust → Verification system
**Time Required**: 15-30 minutes
**Prerequisites**: TMWS MCP server running

---

## Quick Start (5 minutes)

### Step 1: Start the MCP Server

```bash
cd /Users/apto-as/workspace/github.com/apto-as/tmws
python -m src.mcp_server
```

**Expected Output**:
```
INFO: TMWS MCP Server starting...
INFO: Services initialized
INFO: MCP tools registered: 12 tools
INFO: Server ready
```

### Step 2: Run Basic Integration Test

In Claude Code, run:

```bash
/tmws test_learning_trust_integration --scenario full --agent_id my-test-agent
```

**Expected Output**:
```json
{
  "status": "success",
  "test_scenario": "full",
  "pattern_created": true,
  "pattern_id": "12345678-1234-1234-1234-123456789abc",
  "verification_executed": true,
  "verification_accurate": true,
  "trust_score_before": 0.5,
  "trust_score_after": 0.55,
  "trust_score_change": "+0.05",
  "is_reliable": false,
  "evidence_id": "87654321-4321-4321-4321-cba987654321",
  "performance": {
    "pattern_creation_ms": 8,
    "pattern_execution_ms": 3,
    "verification_ms": 412,
    "trust_update_ms": 1,
    "total_ms": 424
  }
}
```

✅ **Success**: If you see `"status": "success"` and trust score increased from 0.5 to 0.55

### Step 3: Check Agent Statistics

```bash
/tmws get_agent_learning_stats --agent_id my-test-agent
```

**Expected Output**:
```json
{
  "agent_id": "my-test-agent",
  "summary": {
    "total_patterns": 1,
    "total_verifications": 1,
    "accuracy_rate": 1.0,
    "trust_score": 0.55,
    "is_reliable": false,
    "status_level": "untrusted"
  },
  "learning": {
    "total_patterns": 1,
    "patterns_by_category": {
      "test": 1
    }
  },
  "verification": {
    "total_verifications": 1,
    "accurate_verifications": 1,
    "accuracy_rate": 1.0,
    "by_claim_type": {
      "test_result": {
        "total": 1,
        "accurate": 1,
        "accuracy": 1.0
      }
    }
  },
  "trust_history": [
    {
      "old_score": 0.5,
      "new_score": 0.55,
      "delta": 0.05,
      "reason": "verification_test_result",
      "changed_at": "2025-11-08T10:30:45.123Z"
    }
  ]
}
```

✅ **Success**: You can see detailed statistics about the agent's learning and trust progression

---

## Comprehensive Testing (30 minutes)

### Test 1: Build Trust Through Successful Verifications (10 minutes)

**Goal**: See how trust score increases with repeated accurate verifications

**Steps**:

1. Run 10 successful verifications:
   ```bash
   for i in {1..10}; do
     /tmws test_learning_trust_integration --scenario full --agent_id trust-builder
   done
   ```

2. Check final statistics:
   ```bash
   /tmws get_agent_learning_stats --agent_id trust-builder
   ```

**Expected Results**:
- **Total verifications**: 10
- **Accuracy rate**: 1.0 (100%)
- **Trust score**: ~0.70-0.75 (increased from 0.5)
- **Status level**: "reliable" (crossed threshold at 5th verification)
- **Is reliable**: `true`

**What to Observe**:
```
Verification 1: 0.5 → 0.55 (+0.05)
Verification 2: 0.55 → 0.595 (+0.045)
Verification 3: 0.595 → 0.6355 (+0.0405)
Verification 4: 0.6355 → 0.672 (+0.0365)
Verification 5: 0.672 → 0.705 (+0.033) ← Becomes "reliable"
...
Verification 10: ~0.70-0.75
```

📊 **Key Insight**: Trust increases rapidly at first, then slows down (EWMA behavior).

### Test 2: Trust Decay from Inaccurate Claims (5 minutes)

**Goal**: See how trust score decreases with inaccurate verifications

**Steps**:

1. First, build some trust (5 accurate verifications):
   ```bash
   for i in {1..5}; do
     /tmws test_learning_trust_integration --scenario full --agent_id decay-test
   done
   ```

2. Check initial trust:
   ```bash
   /tmws get_agent_learning_stats --agent_id decay-test
   ```
   **Expected**: trust_score ~0.70

3. Submit inaccurate claim (manual test):
   ```python
   # Via Python console or custom script
   from src.services.verification_service import VerificationService, ClaimType

   result = await verification_service.verify_claim(
       agent_id="decay-test",
       claim_type=ClaimType.TEST_RESULT,
       claim_content={"return_code": 0, "output_contains": "SUCCESS"},
       verification_command="echo 'FAILED' && exit 1"  # Actually fails
   )

   print(f"Accurate: {result.accurate}")  # False
   print(f"New trust: {result.new_trust_score}")  # ~0.63
   ```

4. Check updated trust:
   ```bash
   /tmws get_agent_learning_stats --agent_id decay-test
   ```

**Expected Results**:
- **Trust score**: Decreased by ~0.07 (10% impact)
- **Accuracy rate**: Dropped from 1.0 to 0.83 (5/6)
- **Trust history**: Shows negative delta

📊 **Key Insight**: Trust is **easier to lose than gain**. One failure has ~2x impact of one success.

### Test 3: Pattern Learning with Verification (5 minutes)

**Goal**: Test the complete workflow: create pattern → use pattern → verify result → update trust

**Steps**:

1. Create a learning pattern with verification command:
   ```bash
   # Via MCP tool (to be implemented)
   /tmws create_pattern \
     --name "database_optimization" \
     --category "performance" \
     --verification_command "pytest tests/performance/test_db.py -v"
   ```

2. Apply the pattern:
   ```bash
   /tmws apply_pattern \
     --pattern_id <pattern-id> \
     --agent_id optimizer-agent \
     --auto_verify true
   ```

3. Check results:
   ```bash
   /tmws get_agent_learning_stats --agent_id optimizer-agent
   ```

**Expected Results**:
- Pattern created with `verification_command` set
- Pattern applied successfully
- Verification ran automatically
- Trust score updated based on accuracy
- Evidence stored in memory

### Test 4: Evidence Retrieval (5 minutes)

**Goal**: Verify that verification evidence is stored and retrievable

**Steps**:

1. Run a verification that returns evidence_id:
   ```bash
   /tmws test_learning_trust_integration --scenario full --agent_id evidence-test
   ```
   **Note**: `evidence_id` from output

2. Retrieve evidence from memory:
   ```bash
   /tmws search_memories --query "verification evidence" --namespace test
   ```

3. Check evidence content:
   ```bash
   /tmws get_memory --memory_id <evidence-id>
   ```

**Expected Output** (evidence content):
```markdown
✅ Verification Result: test_result

## Claim
{
  "return_code": 0,
  "output_contains": "PASSED"
}

## Verification Command
```bash
echo 'TEST PASSED' && exit 0
```

## Actual Result
- Return Code: 0
- Duration: 45.23ms

### Output
```
TEST PASSED
```

### Errors
```
(empty)
```

## Verdict
ACCURATE - Claim verified
```

📊 **Key Insight**: All verification evidence is permanently stored for audit trails.

### Test 5: Autonomy Threshold (5 minutes)

**Goal**: Verify that high-trust agents can operate autonomously

**Steps**:

1. Build high trust (10+ verifications):
   ```bash
   for i in {1..10}; do
     /tmws test_learning_trust_integration --scenario full --agent_id autonomous-agent
   done
   ```

2. Check reliability status:
   ```bash
   /tmws get_agent_learning_stats --agent_id autonomous-agent
   ```

3. Look for autonomy indicators:
   ```json
   {
     "summary": {
       "trust_score": 0.74,
       "is_reliable": true,
       "status_level": "reliable"
     }
   }
   ```

**Autonomy Logic**:
- **Can operate autonomously**: `trust_score >= 0.7` AND `total_verifications >= 5`
- **Requires supervision**: Otherwise

📊 **Key Insight**: Once reliable, agents can be trusted for routine operations without constant verification.

---

## Understanding the Output

### Trust Score Interpretation

| Score Range | Status Level | Meaning | Supervision |
|-------------|--------------|---------|-------------|
| 0.0 - 0.5 | Untrusted | New or unreliable agent | High supervision required |
| 0.5 - 0.7 | Building | Building reputation | Moderate supervision |
| 0.7 - 0.8 | Reliable | Trustworthy for routine tasks | Light supervision |
| 0.8 - 0.9 | Trusted | Highly reliable | Minimal supervision |
| 0.9 - 1.0 | Highly Trusted | Exceptional reliability | Audit only |

### Verification Accuracy

**Accurate** (`accurate: true`):
- Claim matches actual result
- Trust score **increases** by ~5-10%
- Pattern success_rate **increases**
- Evidence marked ✅ ACCURATE

**Inaccurate** (`accurate: false`):
- Claim does NOT match actual result
- Trust score **decreases** by ~10%
- Pattern success_rate **decreases**
- Evidence marked ❌ INACCURATE

### Trust Score Change Rate

The system uses **Exponential Weighted Moving Average (EWMA)**:

```
new_score = 0.1 * observation + 0.9 * old_score
```

Where:
- `observation` = 1.0 (accurate) or 0.0 (inaccurate)
- `0.1` = learning rate (10% weight to new observation)
- `0.9` = history weight (90% weight to past performance)

**Why this matters**:
- **Recent performance matters**, but not exclusively
- **Trust builds gradually** through consistent accuracy
- **Trust decays slowly** from occasional mistakes
- **Prevents gaming** - can't quickly boost score with few verifications

---

## Troubleshooting

### Issue 1: MCP Server Won't Start

**Symptom**: Error when running `python -m src.mcp_server`

**Solution**:
```bash
# Check Python version
python --version  # Should be 3.11+

# Check virtual environment
which python  # Should point to .venv

# Reinstall dependencies
uv sync --all-extras

# Check database
alembic current  # Should show latest migration
```

### Issue 2: Tool Not Found

**Symptom**: `/tmws test_learning_trust_integration` returns "Tool not found"

**Solution**:
- Verify MCP server started successfully
- Check `src/tools/integration_tools.py` exists
- Check tool is registered in `src/mcp_server.py`
- Restart MCP server

### Issue 3: Trust Score Not Changing

**Symptom**: Trust score stays at 0.5 after verifications

**Solution**:
```bash
# Check verification actually ran
/tmws get_agent_learning_stats --agent_id <agent-id>

# Should see total_verifications > 0

# Check database
sqlite3 data/tmws.db "SELECT * FROM trust_score_history WHERE agent_id = '<agent-id>';"
# Should show history records

# Check for errors in MCP server logs
```

### Issue 4: Performance Too Slow

**Symptom**: Full workflow takes >1 second

**Solution**:
- **Expected**: 400-600ms for full workflow (includes shell command execution)
- **Check verification command**: Simple commands (echo) are fast, complex commands (pytest) are slower
- **Database**: Ensure SQLite WAL mode enabled
- **Embedding**: First run may be slower (model loading), subsequent runs faster

---

## Next Steps

After completing these tests:

1. **Understand the System**:
   - How trust builds through accurate verifications ✅
   - How trust decays from inaccurate claims ✅
   - How evidence is stored and retrievable ✅
   - How autonomy thresholds work ✅

2. **Explore Advanced Features**:
   - Pattern recommendation with trust weighting
   - Cross-agent trust analysis
   - Trust-based access control

3. **Build Your Own Tests**:
   - Create custom learning patterns
   - Design domain-specific verification commands
   - Test with real-world scenarios

4. **Monitor Production**:
   - Track trust scores over time
   - Identify agents needing supervision
   - Review verification evidence for failures

---

## FAQ

### Q1: How many verifications before an agent is "reliable"?

**A**: At least **5 accurate verifications** with a trust score **>= 0.7**.

With 100% accuracy:
- 1st: 0.5 → 0.55
- 2nd: 0.55 → 0.595
- 3rd: 0.595 → 0.636
- 4th: 0.636 → 0.672
- **5th**: 0.672 → 0.705 ✅ **Reliable**

### Q2: Can an agent's trust score go back down after becoming reliable?

**A**: Yes! If verifications start failing, trust score will decrease. If it drops below 0.7, the agent returns to "building" status.

### Q3: What happens if I submit 10 accurate claims, then 1 inaccurate claim?

**A**: Trust score will be high (~0.75), then drop by ~10% to ~0.67, falling below "reliable" threshold.

**Example**:
- After 10 accurate: trust = 0.746
- After 1 inaccurate: trust = 0.671 (below 0.7 → back to "building")

### Q4: Is verification required for every pattern usage?

**A**: No, you can control this:
- `auto_verify=true`: Always verify (default for untrusted agents)
- `auto_verify=false`: Skip verification (for trusted agents)

**Recommended**: Verify all operations for agents with trust_score < 0.7.

### Q5: How do I reset an agent's trust score?

**A**: Trust scores are **permanent by design** for audit purposes. To "reset":

1. Create a new agent
2. Manually update database (NOT recommended):
   ```sql
   UPDATE agents SET trust_score = 0.5, total_verifications = 0 WHERE agent_id = '...';
   ```

### Q6: Can I adjust the learning rate (EWMA alpha)?

**A**: Yes, but requires code change in `TrustScoreCalculator`:

```python
calculator = TrustScoreCalculator(
    alpha=0.2,  # 20% weight to new observations (faster learning)
    # alpha=0.05,  # 5% weight (slower, more stable)
    min_observations=5,
    initial_score=0.5
)
```

**Recommended**: Keep default `alpha=0.1` (10%) for balanced learning.

---

## Summary

You've learned how to:
- ✅ Test basic integration workflow
- ✅ Build trust through accurate verifications
- ✅ Observe trust decay from failures
- ✅ Retrieve verification evidence
- ✅ Understand autonomy thresholds
- ✅ Interpret trust scores and statistics

**Next**: Implement real-world learning patterns with verification commands!

---

**End of User Test Guide**

*"Understanding comes through testing, mastery comes through practice."*

— Athena, Harmonious Conductor
