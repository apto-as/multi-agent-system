# Agent Trust & Verification System - Visual Diagrams
## Architecture Visualization

---

## Diagram 1: System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          USER / MCP CLIENT                              │
│                                                                         │
│  Commands:                                                              │
│  • verify_agent_report(agent_id, report, evidence)                     │
│  • get_agent_trust_score(agent_id)                                     │
│  • request_peer_review(agent_id, reviewer)                             │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        MCP TOOLS LAYER                                  │
│                      (src/tools/trust_tools.py)                         │
│                                                                         │
│  - Input validation                                                     │
│  - Permission checks                                                    │
│  - Service orchestration                                                │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    WORKFLOW ORCHESTRATION                               │
│                  (WorkflowService: verification_standard)               │
│                                                                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐     │
│  │  Extract    │→│  Execute    │→│  Compare    │→│   Store     │     │
│  │  Claims     │ │  Measure    │ │  Results    │ │  Evidence   │     │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘     │
│                                          ▼                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                      │
│  │   Learn     │←│  Check PR   │←│   Update    │                      │
│  │  Pattern    │ │  Threshold  │ │   Trust     │                      │
│  └─────────────┘ └─────────────┘ └─────────────┘                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         SERVICE LAYER                                   │
│                                                                         │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐    │
│  │  AgentService    │  │  MemoryService   │  │ LearningService  │    │
│  │                  │  │                  │  │                  │    │
│  │ • get_trust_data │  │ • create_evidence│  │ • create_pattern │    │
│  │ • update_trust   │  │ • search_evidence│  │ • get_best_prac  │    │
│  │ • record_peer_   │  │                  │  │                  │    │
│  │   review         │  │                  │  │                  │    │
│  │                  │  │                  │  │                  │    │
│  │ ⚠️  SECURITY:     │  │ ⚠️  SECURITY:     │  │ READ-ONLY        │    │
│  │ SYSTEM agent     │  │ SYSTEM agent     │  │ PUBLIC access    │    │
│  │ only             │  │ only             │  │                  │    │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         DATA LAYER (SQLite)                             │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │ agents table                                                  │    │
│  │ ────────────────────────────────────────────────────────────  │    │
│  │ • agent_id (PK)                                               │    │
│  │ • display_name                                                │    │
│  │ • namespace                                                   │    │
│  │ • metadata_json: {                                            │    │
│  │     "trust_data": {                                           │    │
│  │       "score": 0.95,          ← TRUST TRACKING HERE          │    │
│  │       "last_updated": "...",                                  │    │
│  │       "verification_count": 42,                               │    │
│  │       "false_report_count": 1,                                │    │
│  │       "peer_review_required": false,                          │    │
│  │       "history": [...]                                        │    │
│  │     }                                                          │    │
│  │   }                                                            │    │
│  └───────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │ memories table                                                │    │
│  │ ────────────────────────────────────────────────────────────  │    │
│  │ • id (PK)                                                     │    │
│  │ • content: "Verification Result: ..."                         │    │
│  │ • tags: ["evidence:verification", "agent:hera", ...]          │    │
│  │ • access_level: SYSTEM       ← IMMUTABLE                      │    │
│  │ • metadata: {                                                 │    │
│  │     "agent_id": "hera",                                       │    │
│  │     "claim": {...},                                           │    │
│  │     "measurement": {...},                                     │    │
│  │     "accuracy": 0.0                                           │    │
│  │   }                                                            │    │
│  └───────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │ learning_patterns table                                       │    │
│  │ ────────────────────────────────────────────────────────────  │    │
│  │ • id (PK)                                                     │    │
│  │ • pattern_name: "hera_false_test_report_..."                  │    │
│  │ • category: "false_report"                                    │    │
│  │ • namespace: "system"                                         │    │
│  │ • access_level: "public"     ← ALL AGENTS CAN LEARN          │    │
│  │ • pattern_data: {                                             │    │
│  │     "agent": "hera",                                          │    │
│  │     "prevention": [...]                                       │    │
│  │   }                                                            │    │
│  └───────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Diagram 2: Trust Score Update Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 1: Agent Submits Report                                           │
│                                                                         │
│  Agent (Hera):                                                          │
│    "Tests passed: 432/432 (100%)"                                      │
│    "Coverage: 100%"                                                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 2: User Calls Verification                                        │
│                                                                         │
│  verify_agent_report(                                                   │
│    agent_id="hera",                                                     │
│    report_content='{"tests_passed": 432, "coverage": 1.0}',            │
│    evidence_path=None  # Will auto-execute                             │
│  )                                                                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 3: Workflow Extracts Claims                                       │
│                                                                         │
│  parsed_claims = {                                                      │
│    "tests_passed": 432,                                                 │
│    "coverage": 1.0                                                      │
│  }                                                                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 4: Execute Measurement                                            │
│                                                                         │
│  $ pytest tests/unit/ -v --json=results.json                           │
│                                                                         │
│  actual_measurements = {                                                │
│    "tests_passed": 370,  ← ACTUAL VALUE                                │
│    "coverage": 0.75       ← ACTUAL VALUE                               │
│  }                                                                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 5: Calculate Accuracy                                             │
│                                                                         │
│  tests_accuracy = 370 / 432 = 0.856                                     │
│  coverage_accuracy = 0.75 / 1.0 = 0.75                                  │
│  overall_accuracy = (0.856 + 0.75) / 2 = 0.803                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 6: Store Evidence (SYSTEM agent)                                  │
│                                                                         │
│  memory_service.create_evidence_memory(                                 │
│    agent_id="hera",                                                     │
│    claim=parsed_claims,                                                 │
│    measurement=actual_measurements,                                     │
│    accuracy=0.803                                                       │
│  )                                                                      │
│                                                                         │
│  → Memory created with:                                                 │
│    • access_level = SYSTEM (immutable)                                 │
│    • tags = ["evidence:verification", "agent:hera", ...]               │
│    • evidence_id = "uuid-abc123"                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 7: Update Trust Score (SYSTEM agent only)                         │
│                                                                         │
│  agent_service.update_trust_score(                                      │
│    agent_id="hera",                                                     │
│    accuracy=0.803,                                                      │
│    evidence_id="uuid-abc123",                                           │
│    reason="Test report verification"                                    │
│  )                                                                      │
│                                                                         │
│  Formula:                                                               │
│    old_trust = 0.95                                                     │
│    penalty = 0.5 * (1 - 0.803) = 0.0985                                │
│    new_trust = 0.95 * (1 - 0.0985) = 0.856                             │
│    new_trust = 0.85 (rounded to 0.05)                                  │
│                                                                         │
│  → Agent.metadata_json["trust_data"]["score"] = 0.85                   │
│  → History entry added                                                  │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 8: Check Peer Review Threshold                                    │
│                                                                         │
│  if new_trust < 0.8:                                                    │
│    # Require peer review                                                │
│    agent.metadata_json["trust_data"]["peer_review_required"] = True    │
│                                                                         │
│  In this case: 0.85 >= 0.8 → No peer review needed                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 9: Learn Pattern (if accuracy < 0.5)                              │
│                                                                         │
│  if accuracy < 0.5:                                                     │
│    learning_service.create_pattern(                                     │
│      pattern_name="hera_false_test_report_2025_10_24",                 │
│      category="false_report",                                           │
│      pattern_data={...}                                                 │
│    )                                                                    │
│                                                                         │
│  In this case: 0.803 >= 0.5 → No pattern creation                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 10: Return Result to User                                         │
│                                                                         │
│  {                                                                      │
│    "verification_id": "uuid-exec456",                                   │
│    "agent_id": "hera",                                                  │
│    "accuracy": 0.803,                                                   │
│    "trust_score": 0.85,                                                 │
│    "peer_review_required": false,                                       │
│    "evidence_id": "uuid-abc123"                                         │
│  }                                                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Diagram 3: Trust Score Degradation & Recovery

```
Trust Score Timeline for Agent "Hera"

1.0 ┤
    │   ┌─ Initial State (new agent)
0.95│   │
    │   │
0.90│   │
    │   │           ┌─ Peer Review
0.85│   │           │  Approved (+0.2)
    │   │           │  ┌───────────────────────────────
0.80│───┼───────────┼──┘ │ Threshold: <0.8 requires peer review
    │   │           │    │
0.75│   │           │    │  ┌─ Perfect reports
    │   │           │    │  │  gradually restore
0.70│   │           │    │  │  trust
    │   │           │    │  │
0.65│   │           │    │  │
    │   │           │    │  │
0.60│   │           │    │  │
    │   │           │    │  │
0.55│   │           │    │  │
    │   │           │    │  │
0.50│   │     ┌─────┘    │  │
    │   │     │ False     │  │
    │   │     │ Report    │  │
0.45│   │     │ (50%      │  │
    │   │     │ penalty)  │  │
0.40│   │     │           │  │
    │   │     │           │  │
0.35│   │     │           │  │
    │   │     │           │  │
0.30│   │     │           │  │
    │   │     │           │  │
0.25│   │     │           │  │
    │   │     │           │  │
0.20│   │     │           │  │
    │   │     │           │  │
0.15│   │     │           │  │
    │   │     │           │  │
0.10│   │     │           │  │
    │   │     │           │  │
0.05│   │     │           │  │
    │   │     │           │  │
0.00└───┴─────┴───────────┴──┴────────────────────────►
    T0   T1   T2         T3  T4  T5  T6  T7  T8  T9   Time

Events:
  T0: Agent created (trust=0.95)
  T1: Verified report (accuracy=1.0) → trust=0.95 (no change)
  T2: FALSE REPORT (accuracy=0.0) → trust=0.48 (50% penalty)
  T3: Peer review approved → trust=0.68 (+0.2)
  T4: Verified report (accuracy=1.0) → trust=0.68 (gradual recovery)
  T5: Verified report (accuracy=1.0) → trust=0.68
  T6: Verified report (accuracy=0.95) → trust=0.70
  T7: Verified report (accuracy=0.98) → trust=0.73
  T8: Verified report (accuracy=1.0) → trust=0.76
  T9: Verified report (accuracy=1.0) → trust=0.79

Note: Recovery is gradual. Takes many perfect reports to restore trust.
```

---

## Diagram 4: Peer Review Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Trigger: Agent trust score drops below 0.8                             │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 1: Flag Agent for Peer Review                                     │
│                                                                         │
│  agent.metadata_json["trust_data"]["peer_review_required"] = True      │
│                                                                         │
│  → Notification sent to system admin                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 2: Create Peer Review Task                                        │
│                                                                         │
│  task_service.create_task(                                              │
│    title="Peer Review: hera",                                           │
│    description="Agent trust dropped to 0.5 after false report",        │
│    assigned_agent_id="artemis-optimizer",  ← Trusted reviewer          │
│    metadata={"type": "peer_review", "subject_agent": "hera"}           │
│  )                                                                      │
│                                                                         │
│  → Task assigned to reviewer                                            │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 3: Reviewer Examines Evidence                                     │
│                                                                         │
│  Reviewer (Artemis) calls:                                              │
│    search_evidence(agent_id="hera", min_accuracy=0.5, limit=10)        │
│                                                                         │
│  Results:                                                               │
│    • Incident 1: 2025-10-24, accuracy=0.0 (test report)                │
│    • Incident 2: 2025-10-20, accuracy=0.4 (coverage report)            │
│                                                                         │
│  Reviewer checks:                                                       │
│    1. Has agent acknowledged the issue?                                 │
│    2. Has agent implemented preventive measures?                        │
│    3. Recent reports show improvement?                                  │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 4: Reviewer Makes Decision                                        │
│                                                                         │
│  Option A: APPROVE                                                      │
│    record_peer_review(                                                  │
│      agent_id="hera",                                                   │
│      reviewer_agent_id="artemis",                                       │
│      approved=True,                                                     │
│      comments="Implemented test-first workflow. Verified 3 reports."   │
│    )                                                                    │
│    → trust_score += 0.2                                                 │
│    → peer_review_required = False                                       │
│                                                                         │
│  Option B: REJECT                                                       │
│    record_peer_review(                                                  │
│      agent_id="hera",                                                   │
│      reviewer_agent_id="artemis",                                       │
│      approved=False,                                                    │
│      comments="Still producing unverified reports. Needs more work."   │
│    )                                                                    │
│    → trust_score unchanged                                              │
│    → peer_review_required = True (still flagged)                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 5: Update Agent Record                                            │
│                                                                         │
│  agent.metadata_json["trust_data"]["peer_reviews"].append({            │
│    "reviewer_agent_id": "artemis",                                      │
│    "timestamp": "2025-10-25T09:00:00Z",                                 │
│    "approved": True,                                                    │
│    "comments": "..."                                                    │
│  })                                                                     │
│                                                                         │
│  → Peer review history recorded                                         │
│  → Agent can resume normal operations                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Diagram 5: Evidence Memory Structure

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Memory Object (Evidence)                                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ id: "uuid-abc123"                                                       │
│ content: "Verification Result: Hera's test report"                      │
│                                                                         │
│ agent_id: "system"         ← Owned by SYSTEM                            │
│ namespace: "system"         ← System namespace                          │
│                                                                         │
│ tags: [                                                                 │
│   "evidence:verification",  ← Type: verification evidence              │
│   "agent:hera",             ← Subject: agent being verified            │
│   "incident:2025-10-24",    ← Date of incident                         │
│   "accuracy:0.0",           ← Measured accuracy                        │
│   "category:false_report"   ← Incident category                        │
│ ]                                                                       │
│                                                                         │
│ access_level: SYSTEM        ← IMMUTABLE (cannot be deleted/modified)   │
│ importance: 1.0             ← High importance for incidents            │
│                                                                         │
│ metadata: {                                                             │
│   "agent_id": "hera-strategist",                                        │
│   "claim": {                                                            │
│     "tests_passed": 432,                                                │
│     "tests_failed": 0,                                                  │
│     "coverage": 1.0                                                     │
│   },                                                                    │
│   "measurement": {                                                      │
│     "tests_passed": 370,                                                │
│     "tests_failed": 62,                                                 │
│     "coverage": 0.75                                                    │
│   },                                                                    │
│   "accuracy": 0.0,                                                      │
│   "timestamp": "2025-10-24T14:23:00Z",                                  │
│   "verifier": "system:verification_workflow"                            │
│ }                                                                       │
│                                                                         │
│ created_at: "2025-10-24T14:23:05Z"                                      │
│ updated_at: "2025-10-24T14:23:05Z"                                      │
└─────────────────────────────────────────────────────────────────────────┘

Key Properties:
  • IMMUTABLE: Cannot be deleted by any agent (SYSTEM access level)
  • SEARCHABLE: Tags enable fast evidence lookup
  • STRUCTURED: Metadata contains full verification details
  • AUDITABLE: Timestamp and verifier recorded
  • NAMESPACE-ISOLATED: System namespace prevents accidental deletion
```

---

## Diagram 6: Security Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SECURITY BOUNDARY DIAGRAM                            │
└─────────────────────────────────────────────────────────────────────────┘

              ┌──────────────────────────────────────────────┐
              │          SYSTEM Agent (Privileged)           │
              │  - Can update trust scores                   │
              │  - Can create evidence memories              │
              │  - Can search all evidence                   │
              │  - Full access to all trust data             │
              └──────────────────────────────────────────────┘
                          ▲           ▲           ▲
                          │           │           │
          ┌───────────────┤           │           └───────────────┐
          │               │           │                           │
          │   update_trust│           │create_evidence            │search_evidence
          │   _score()    │           │_memory()                  │()
          │               │           │                           │
┌─────────┴────────────┐  │  ┌────────┴────────┐  ┌─────────────┴────────┐
│                      │  │  │                 │  │                      │
│  AgentService        │  │  │  MemoryService  │  │  MemoryService       │
│                      │  │  │                 │  │                      │
│  ⚠️ PROTECTED:        │  │  │  ⚠️ PROTECTED:   │  │  ⚠️ PROTECTED:        │
│  Only SYSTEM agent   │  │  │  Only SYSTEM    │  │  Only SYSTEM/admin   │
│  can call            │  │  │  agent can call │  │  can call            │
│                      │  │  │                 │  │                      │
└──────────────────────┘  │  └─────────────────┘  └──────────────────────┘
                          │
                          │
              ┌───────────┴──────────────────────────────────┐
              │                                              │
              │  Other Agents (Unprivileged)                 │
              │  - Can read own trust data (full)            │
              │  - Can read others' trust data (summary)     │
              │  - CANNOT update trust scores                │
              │  - CANNOT create evidence memories           │
              │  - CANNOT delete evidence memories           │
              │  - Can submit reports for verification       │
              └──────────────────────────────────────────────┘
                          ▲           ▲
                          │           │
                          │           │
          ┌───────────────┤           └───────────────┐
          │               │                           │
          │  get_trust_   │                           │verify_agent_
          │  data()       │                           │report()
          │  (summary)    │                           │
          │               │                           │
┌─────────┴────────────┐  │                  ┌────────┴────────┐
│                      │  │                  │                 │
│  AgentService        │  │                  │  WorkflowService│
│                      │  │                  │                 │
│  ✅ ALLOWED:          │  │                  │  ✅ PUBLIC:       │
│  Returns summary     │  │                  │  Any agent can  │
│  for non-owners      │  │                  │  request verify │
│                      │  │                  │                 │
└──────────────────────┘  │                  └─────────────────┘
                          │
                          │
              ┌───────────┴──────────────────────────────────┐
              │                                              │
              │  Malicious Agent (Attacker)                  │
              │  ❌ Cannot manipulate trust scores            │
              │  ❌ Cannot create fake evidence               │
              │  ❌ Cannot delete evidence                    │
              │  ❌ Cannot bypass verification workflow       │
              │  ❌ Cannot read detailed trust data of others │
              └──────────────────────────────────────────────┘

Summary:
  • Trust-modifying operations require SYSTEM agent (highest privilege)
  • Evidence memories are IMMUTABLE (SYSTEM access level)
  • Non-privileged agents have LIMITED READ access
  • Verification workflow is MANDATORY (cannot be bypassed)
  • All operations are LOGGED for audit
```

---

## Diagram 7: Data Flow - False Report Detection

```
┌───────────────────────────────────────────────────────────────────────┐
│ T=0: Agent Hera submits report                                        │
│                                                                       │
│  Report: "All 432 tests passed! 100% coverage achieved!"             │
│  Reality: Tests not yet executed                                     │
└───────────────────────────────────────────────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│ T=1: User suspects false report, calls verification                  │
│                                                                       │
│  verify_agent_report(                                                 │
│    agent_id="hera",                                                   │
│    report_content='{"tests_passed": 432, "coverage": 1.0}',          │
│    evidence_path=None  # System will execute tests                   │
│  )                                                                    │
└───────────────────────────────────────────────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│ T=2: System extracts claims from report                              │
│                                                                       │
│  parsed_claims = {                                                    │
│    "tests_passed": 432,      ← CLAIM                                 │
│    "tests_failed": 0,         ← CLAIM                                │
│    "coverage": 1.0            ← CLAIM                                │
│  }                                                                    │
└───────────────────────────────────────────────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│ T=3: System executes actual measurement                              │
│                                                                       │
│  $ pytest tests/unit/ -v --json=results.json                         │
│                                                                       │
│  ⏱️  Execution time: 15 seconds                                       │
│                                                                       │
│  actual_measurements = {                                              │
│    "tests_passed": 370,      ← REALITY (62 tests FAILED!)            │
│    "tests_failed": 62,        ← REALITY                              │
│    "coverage": 0.75           ← REALITY (25% missing!)               │
│  }                                                                    │
└───────────────────────────────────────────────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│ T=4: System calculates accuracy                                      │
│                                                                       │
│  tests_accuracy = min(370 / 432, 1.0) = 0.856                        │
│  coverage_accuracy = min(0.75 / 1.0, 1.0) = 0.75                     │
│  overall_accuracy = (0.856 + 0.75) / 2 = 0.803                       │
│                                                                       │
│  ❌ FALSE REPORT DETECTED (accuracy < 0.9)                            │
└───────────────────────────────────────────────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│ T=5: System stores evidence (IMMUTABLE)                              │
│                                                                       │
│  memory_service.create_evidence_memory(                               │
│    agent_id="hera",                                                   │
│    claim=parsed_claims,                                               │
│    measurement=actual_measurements,                                   │
│    accuracy=0.803                                                     │
│  )                                                                    │
│                                                                       │
│  → Evidence stored with SYSTEM access level                           │
│  → Cannot be deleted or modified                                      │
│  → Permanently recorded for audit                                     │
└───────────────────────────────────────────────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│ T=6: System updates trust score (PENALTY APPLIED)                    │
│                                                                       │
│  old_trust = 0.95                                                     │
│  penalty = 0.5 * (1 - 0.803) = 0.0985                                │
│  new_trust = 0.95 * (1 - 0.0985) = 0.856                             │
│  new_trust = 0.85 (rounded)                                           │
│                                                                       │
│  → Agent Hera's trust score: 0.95 → 0.85 (⬇️ 10.5% decrease)          │
│  → History entry added to agent.metadata_json                         │
└───────────────────────────────────────────────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│ T=7: System checks peer review threshold                             │
│                                                                       │
│  if new_trust < 0.8:                                                  │
│    require_peer_review = True                                         │
│                                                                       │
│  In this case: 0.85 >= 0.8 → ✅ No peer review needed                 │
│                                                                       │
│  (If trust had dropped below 0.8, peer review would be mandatory)    │
└───────────────────────────────────────────────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│ T=8: System learns pattern (if accuracy < 0.5)                       │
│                                                                       │
│  if accuracy < 0.5:                                                   │
│    # Store false report pattern for future prevention                │
│                                                                       │
│  In this case: 0.803 >= 0.5 → Pattern not created                    │
│                                                                       │
│  (Pattern would contain prevention strategies for other agents)      │
└───────────────────────────────────────────────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│ T=9: User receives verification result                               │
│                                                                       │
│  {                                                                    │
│    "verification_id": "uuid-exec456",                                 │
│    "agent_id": "hera",                                                │
│    "accuracy": 0.803,                                                 │
│    "trust_score": 0.85,      ← Updated score                          │
│    "peer_review_required": false,                                     │
│    "evidence_id": "uuid-abc123"  ← Immutable evidence reference      │
│  }                                                                    │
│                                                                       │
│  ⚠️ User is informed: Agent Hera's trust score decreased              │
└───────────────────────────────────────────────────────────────────────┘
```

---

*For detailed implementation guidance, see [AGENT_TRUST_VERIFICATION_ARCHITECTURE.md](./AGENT_TRUST_VERIFICATION_ARCHITECTURE.md)*
