# Integration Workflows: Visual Guide
## Learning → Trust → Verification System

**Created**: 2025-11-08
**Purpose**: Visual workflow documentation for implementation and testing

---

## Workflow 1: Successful Learning Pattern

```mermaid
graph TB
    Start([Agent wants to apply pattern]) --> A[Get pattern from LearningService]
    A --> B{Has verification<br/>command?}

    B -->|No| C[Execute pattern]
    B -->|Yes| D[Execute pattern + record expected result]

    C --> E[Update usage_count]
    E --> End1([Done - No verification])

    D --> F[VerificationService.verify_claim]
    F --> G[Execute verification command]
    G --> H{Claim<br/>accurate?}

    H -->|Yes| I[accurate = True]
    H -->|No| J[accurate = False]

    I --> K[TrustService.update_trust_score<br/>new_score = 0.1 * 1.0 + 0.9 * old_score]
    J --> L[TrustService.update_trust_score<br/>new_score = 0.1 * 0.0 + 0.9 * old_score]

    K --> M[MemoryService.create_memory<br/>Evidence: ✅ ACCURATE]
    L --> N[MemoryService.create_memory<br/>Evidence: ❌ INACCURATE]

    M --> O[Update pattern success_rate]
    N --> P[Update pattern success_rate]

    O --> Q[Return VerificationResult<br/>trust_score ↑]
    P --> R[Return VerificationResult<br/>trust_score ↓]

    Q --> End2([Done - Verified])
    R --> End2

    style I fill:#90EE90
    style J fill:#FFB6C1
    style K fill:#90EE90
    style L fill:#FFB6C1
    style M fill:#90EE90
    style N fill:#FFB6C1
```

---

## Workflow 2: Trust Score Evolution

```mermaid
graph LR
    Start([New Agent<br/>trust_score = 0.5]) --> V1[Verification 1<br/>accurate = True]
    V1 --> S1[Score: 0.55<br/>+5%]

    S1 --> V2[Verification 2<br/>accurate = True]
    V2 --> S2[Score: 0.595<br/>+4.5%]

    S2 --> V3[Verification 3<br/>accurate = True]
    V3 --> S3[Score: 0.6355<br/>+4.05%]

    S3 --> V4[Verification 4<br/>accurate = True]
    V4 --> S4[Score: 0.67195<br/>+3.645%]

    S4 --> V5[Verification 5<br/>accurate = True]
    V5 --> S5[Score: 0.704755<br/>reliable = True]

    S5 --> Decision{Autonomy<br/>threshold<br/>reached?}
    Decision -->|Yes| Autonomous[Agent can operate<br/>without verification]
    Decision -->|No| Continue[Continue verification]

    style S5 fill:#FFD700
    style Autonomous fill:#90EE90
```

**EWMA Formula**: `new_score = alpha * observation + (1 - alpha) * old_score`
- **alpha = 0.1**: 10% weight to new observation, 90% to history
- **Observation**: 1.0 (accurate) or 0.0 (inaccurate)

---

## Workflow 3: Trust Decay from Inaccurate Claims

```mermaid
graph LR
    Start([Trusted Agent<br/>trust_score = 0.8]) --> V1[Verification 1<br/>accurate = False]
    V1 --> S1[Score: 0.72<br/>-10%]

    S1 --> V2[Verification 2<br/>accurate = False]
    V2 --> S2[Score: 0.648<br/>-10%]

    S2 --> V3[Verification 3<br/>accurate = True]
    V3 --> S3[Score: 0.6832<br/>+5.4%]

    S3 --> Recovery{Recovery<br/>phase}
    Recovery --> SlowRecover[Requires 10+ accurate<br/>verifications to return<br/>to 0.8]

    style S1 fill:#FFB6C1
    style S2 fill:#FFB6C1
    style S3 fill:#FFD700
    style SlowRecover fill:#87CEEB
```

**Key Insight**: Trust is **easy to lose, hard to regain** (by design).
- One inaccurate claim: -10% impact
- One accurate claim: +5-10% impact (diminishing as score increases)

---

## Workflow 4: Full End-to-End Integration

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant MCP as MCP Tool
    participant LS as LearningService
    participant VS as VerificationService
    participant TS as TrustService
    participant MS as MemoryService
    participant DB as Database

    User->>MCP: /tmws test_learning_trust_integration
    activate MCP

    MCP->>LS: create_pattern(...)
    LS->>DB: INSERT learning_patterns
    DB-->>LS: pattern_id
    LS-->>MCP: LearningPattern

    MCP->>LS: use_pattern(pattern_id, agent_id)
    LS->>DB: UPDATE usage_count++
    DB-->>LS: success
    LS-->>MCP: pattern_result

    MCP->>VS: verify_claim(agent_id, claim, command)
    activate VS

    VS->>VS: execute_verification(command)
    Note over VS: Run shell command<br/>Capture stdout/stderr

    VS->>VS: compare_results(claim, actual)
    Note over VS: Check return_code,<br/>output patterns,<br/>metrics

    VS->>MS: create_evidence_memory(...)
    activate MS
    MS->>DB: INSERT memories
    DB-->>MS: memory_id
    MS-->>VS: Evidence
    deactivate MS

    VS->>TS: update_trust_score(agent_id, accurate)
    activate TS
    TS->>DB: SELECT agent FOR UPDATE
    TS->>TS: calculate_new_score (EWMA)
    TS->>DB: UPDATE agent.trust_score
    TS->>DB: INSERT trust_score_history
    DB-->>TS: new_score
    TS-->>VS: new_trust_score
    deactivate TS

    VS->>DB: INSERT verification_records
    VS->>DB: COMMIT
    DB-->>VS: success

    VS-->>MCP: VerificationResult
    deactivate VS

    MCP->>TS: get_trust_score(agent_id)
    TS->>DB: SELECT agent
    DB-->>TS: trust_data
    TS-->>MCP: trust_score, is_reliable

    MCP-->>User: Comprehensive result
    deactivate MCP
```

**Performance Breakdown** (P95 targets):
1. Create pattern: 10ms
2. Use pattern: 5ms
3. Execute verification: 400ms (depends on command)
4. Create evidence: 20ms
5. Update trust score: 1ms
6. Commit: 10ms
7. Get trust score: 2ms

**Total**: ~450ms (well within 600ms target ✅)

---

## Workflow 5: Autonomous Operation for Trusted Agents

```mermaid
flowchart TD
    Start([Agent request]) --> Check{Check trust<br/>score}

    Check -->|score >= 0.7<br/>& verifications >= 5| Skip[Skip verification]
    Check -->|score < 0.7<br/>OR verifications < 5| Verify[Require verification]

    Skip --> Execute1[Execute pattern]
    Execute1 --> Update1[Update usage_count]
    Update1 --> Fast([Fast path: ~15ms])

    Verify --> Execute2[Execute pattern]
    Execute2 --> RunVerify[Run verification]
    RunVerify --> UpdateTrust[Update trust score]
    UpdateTrust --> Slow([Slow path: ~450ms])

    Fast --> Monitor{Periodic<br/>audit?}
    Monitor -->|Every 10th operation| AuditVerify[Audit verification]
    Monitor -->|Otherwise| Done([Done])

    AuditVerify --> AuditResult{Accurate?}
    AuditResult -->|Yes| MaintainTrust[Maintain trust]
    AuditResult -->|No| Demote[Demote to supervised]

    MaintainTrust --> Done
    Demote --> Done
    Slow --> Done

    style Skip fill:#90EE90
    style Verify fill:#FFB6C1
    style Fast fill:#90EE90
    style Slow fill:#FFD700
    style Demote fill:#FF6B6B
```

**Trust Threshold Logic**:
```python
def can_operate_autonomously(trust_score: float, total_verifications: int) -> bool:
    return (
        trust_score >= 0.7 and
        total_verifications >= 5
    )
```

---

## Workflow 6: Pattern Recommendation with Trust Weighting

```mermaid
graph TD
    Start([Agent requests<br/>recommendations]) --> Fetch[Fetch candidate patterns]

    Fetch --> Filter{Filter by<br/>access level}
    Filter --> Candidates[Public + Shared patterns]

    Candidates --> Loop[For each pattern]
    Loop --> CalcBase[Calculate base score<br/>success_rate * 0.4<br/>+ usage_popularity * 0.3<br/>+ confidence * 0.3]

    CalcBase --> GetTrust[Get creator's<br/>trust_score]
    GetTrust --> BoostCheck{trust_score<br/>>= 0.7?}

    BoostCheck -->|Yes| Boost[Apply trust boost<br/>+0-20%]
    BoostCheck -->|No| NoBoost[No boost]

    Boost --> AddToList[Add to recommendations]
    NoBoost --> AddToList

    AddToList --> MorePatterns{More<br/>patterns?}
    MorePatterns -->|Yes| Loop
    MorePatterns -->|No| Sort[Sort by final score]

    Sort --> TopN[Return top N]
    TopN --> End([Recommendations])

    style Boost fill:#90EE90
    style NoBoost fill:#FFB6C1
```

**Trust Boost Formula**:
```python
creator_trust = trust_scores.get(pattern.agent_id, 0.5)
if creator_trust >= 0.7:
    boost = (creator_trust - 0.5) * 0.4  # 0.5→1.0 maps to 0→0.2
    final_score = base_score + boost
```

---

## State Transition Diagram: Agent Trust Levels

```mermaid
stateDiagram-v2
    [*] --> Untrusted: New agent<br/>score=0.5, verifications=0

    Untrusted --> Building: 1st verification
    Building --> Building: 2-4 verifications
    Building --> Reliable: 5th accurate verification<br/>score >= 0.7

    Reliable --> Trusted: 10+ verifications<br/>score >= 0.8
    Trusted --> HighlyTrusted: 50+ verifications<br/>score >= 0.9

    Reliable --> Building: Inaccurate claim<br/>score drops below 0.7
    Trusted --> Reliable: Inaccurate claim<br/>score drops below 0.8
    HighlyTrusted --> Trusted: Inaccurate claim<br/>score drops below 0.9

    Building --> Probation: 3+ consecutive<br/>inaccurate claims
    Probation --> Building: 5 consecutive<br/>accurate claims

    note right of Untrusted
        Requires verification
        for all operations
    end note

    note right of Reliable
        Can skip verification
        for routine tasks
    end note

    note right of Trusted
        Autonomous for most
        operations, periodic audits
    end note

    note right of HighlyTrusted
        Fully autonomous,
        rare audits only
    end note

    note right of Probation
        Intensive supervision,
        all operations verified
    end note
```

---

## Data Flow: Evidence Recording

```mermaid
graph LR
    Verify[Verification<br/>Complete] --> Format[Format Evidence]

    Format --> Content["Content:<br/>✅/❌ Verification Result<br/>## Claim<br/>## Command<br/>## Actual Result<br/>## Verdict"]

    Content --> Tags["Tags:<br/>['verification',<br/>'evidence',<br/>claim_type]"]

    Tags --> Metadata["Metadata:<br/>{<br/>  verification_id,<br/>  claim_type,<br/>  accurate,<br/>  duration_ms<br/>}"]

    Metadata --> Importance{Accurate?}
    Importance -->|Yes| Low[importance = 0.9]
    Importance -->|No| High[importance = 1.0]

    Low --> Create[MemoryService.<br/>create_memory]
    High --> Create

    Create --> Embedding[Generate embedding<br/>1024-dim vector]
    Embedding --> Store1[ChromaDB:<br/>Vector storage]
    Embedding --> Store2[SQLite:<br/>Metadata]

    Store1 --> Link[Link to<br/>VerificationRecord]
    Store2 --> Link

    Link --> Done([Evidence<br/>Retrievable])

    style High fill:#FFB6C1
    style Low fill:#90EE90
```

**Evidence Searchability**:
- **Semantic search**: Find similar verification failures
- **Tag search**: Filter by claim_type
- **Metadata filter**: accuracy, duration, time range
- **Text search**: Search in claim/result details

---

## Performance Optimization: Caching Strategy

```mermaid
graph TD
    Request[Pattern Request] --> CacheCheck{Cache<br/>Hit?}

    CacheCheck -->|Yes| Return[Return cached]
    CacheCheck -->|No| DB[Query Database]

    DB --> Calculate[Calculate scores]
    Calculate --> Store[Store in cache<br/>TTL = 5 min]
    Store --> Return

    Return --> Done([Response])

    Verify[Verification] --> Invalidate{Pattern<br/>affected?}
    Invalidate -->|Yes| Clear[Clear cache<br/>for pattern]
    Invalidate -->|No| Skip[Skip]

    Clear --> Update[Update DB]
    Skip --> Update

    Update --> Done2([Done])

    style Return fill:#90EE90
    style Clear fill:#FFD700
```

**Cache Invalidation Rules**:
1. Pattern used → Clear pattern-specific cache
2. Trust score updated → Clear agent recommendations cache
3. Verification completed → Clear pattern success_rate cache
4. Time-based expiry → 5 minutes for analytics, 1 minute for scores

---

## Error Handling Flow

```mermaid
graph TD
    Start([Operation Start]) --> Try{Try<br/>execution}

    Try -->|Success| Return[Return result]
    Try -->|Error| ErrorType{Error<br/>type?}

    ErrorType -->|AgentNotFound| NotFound[Log + Raise<br/>AgentNotFoundError]
    ErrorType -->|Verification Failed| VerifyErr[Log + Raise<br/>VerificationError]
    ErrorType -->|Authorization| AuthErr[Log + Raise<br/>AuthorizationError]
    ErrorType -->|Database| DBErr[Rollback +<br/>DatabaseError]
    ErrorType -->|Validation| ValErr[ValidationError]
    ErrorType -->|Unknown| UnknownErr[Log + Raise<br/>DatabaseError]

    NotFound --> Logged1[Logged to security_audit_logs]
    VerifyErr --> Logged2[Logged to verification_records]
    AuthErr --> Logged1
    DBErr --> Logged3[Logged to app logs]
    ValErr --> Logged3
    UnknownErr --> Logged3

    Logged1 --> User[Return error<br/>to user]
    Logged2 --> User
    Logged3 --> User

    Return --> Done([Success])
    User --> Done

    style NotFound fill:#FFB6C1
    style VerifyErr fill:#FFB6C1
    style AuthErr fill:#FF6B6B
    style DBErr fill:#FFB6C1
    style ValErr fill:#FFD700
    style UnknownErr fill:#FFB6C1
```

---

**End of Visual Workflows**

*"A picture is worth a thousand words, but a good workflow diagram is worth ten thousand lines of code."*

— Athena, Harmonious Conductor
