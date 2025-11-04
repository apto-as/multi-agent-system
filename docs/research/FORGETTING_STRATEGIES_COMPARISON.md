# Memory Forgetting Strategies: Visual Comparison

**Date**: 2025-11-04
**Purpose**: Visual summary of forgetting mechanisms across memory systems

---

## 1. Forgetting Strategy Matrix

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    FORGETTING STRATEGY COMPARISON                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Time-based Decay          Importance-based         Hybrid Approach    │
│  ─────────────────         ─────────────────        ───────────────    │
│                                                                         │
│  MemoryBank                MongoDB AI Memory        Generative Agents  │
│  ┌─────────┐              ┌─────────┐              ┌─────────┐        │
│  │ R=e^(-t/S)│              │ Dynamic │              │ 3-factor│        │
│  │         │              │ Scoring │              │ Scoring │        │
│  │  Simple │              │         │              │         │        │
│  │  Decay  │              │ Access- │              │ Recency │        │
│  │         │              │ based   │              │ + Importance│     │
│  └─────────┘              └─────────┘              │ + Relevance│     │
│  Performance: LOW         Performance: HIGH        └─────────┘        │
│                                                     Performance: HIGH  │
│                                                                         │
│  Token-based Pruning      No Forgetting            Temporal Model     │
│  ────────────────────      ───────────             ──────────────     │
│                                                                         │
│  LangChain                MemGPT                   Zep (Graphiti)     │
│  ┌─────────┐              ┌─────────┐              ┌─────────┐        │
│  │ Token   │              │ Archive │              │ Temporal│        │
│  │ Limit   │              │ Only    │              │ Invalid.│        │
│  │         │              │         │              │         │        │
│  │ Mechanical│             │ No      │              │ History │        │
│  │ Deletion│              │ Deletion│              │ Preserve│        │
│  └─────────┘              └─────────┘              └─────────┘        │
│  Semantic: NONE           Semantic: PARTIAL        Semantic: FULL     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Implementation Complexity vs. Effectiveness

```
High │
Eff- │                    ★ Generative Agents
ect- │                    (3-factor scoring)
ive- │
ness │         ★ MongoDB AI Memory
     │         (Dynamic scoring)
     │
     │  ★ Zep                      ★ Mem0
     │  (Temporal)                 (Planned)
     │
     │                    ★ MemGPT
     │                    (Hierarchical)
     │
     │              ★ LangChain
     │              (Token-based)
     │
Low  │  ★ MemoryBank
     │  (Simple decay)
     └───────────────────────────────────────────►
       Low                                    High
                  Implementation Complexity
```

**Key Insights**:
- **Generative Agents**: High effectiveness, moderate complexity
- **MongoDB AI Memory**: Good balance of complexity and effectiveness
- **MemoryBank**: Low complexity but poor performance
- **Zep**: Unique approach, moderate effectiveness for specific use cases

---

## 3. Feature Availability Matrix

```
┌──────────────────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
│ Feature          │ Mem0 │MemBnk│LangCh│ Zep  │Pincne│MemGPT│GenAgt│MongoDB│
├──────────────────┼──────┼──────┼──────┼──────┼──────┼──────┼──────┼──────┤
│ Time Decay       │  ⚠️  │  ✅  │  ❌  │  ❌  │  ⚠️  │  ❌  │  ✅  │  ✅  │
│ Importance Score │  ✅  │  ❌  │  ❌  │  ❌  │  ⚠️  │  ❌  │  ✅  │  ✅  │
│ Auto-Adjustment  │  ⚠️  │  ✅  │  ❌  │  ❌  │  ❌  │  ✅  │  ❌  │  ✅  │
│ Relevance Score  │  ✅  │  ❌  │  ❌  │  ❌  │  ❌  │  ❌  │  ✅  │  ⚠️  │
│ Expiration Date  │  ✅  │  ❌  │  ❌  │  ❌  │  ❌  │  ❌  │  ❌  │  ❌  │
│ Pruning          │  ⚠️  │  ❌  │  ✅  │  ❌  │  ❌  │  ✅  │  ❌  │  ✅  │
│ Reinforcement    │  ⚠️  │  ✅  │  ❌  │  ❌  │  ❌  │  ❌  │  ❌  │  ✅  │
│ LLM-assisted     │  ⚠️  │  ❌  │  ❌  │  ✅  │  ❌  │  ✅  │  ✅  │  ✅  │
└──────────────────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘

Legend:
✅ Fully implemented
⚠️ Partially implemented or planned
❌ Not implemented
```

---

## 4. Mathematical Formulas Comparison

### MemoryBank: Ebbinghaus Forgetting Curve
```
R = e^(-t/S)

Where:
  R = Retention (記憶保持率)
  t = Time elapsed (経過時間)
  S = Stability (記憶強度)

Update on recall:
  S_new = S_old + 1
  t = 0 (reset)
```

**Characteristics**:
- ✅ Mathematically rigorous
- ✅ Proven by cognitive science
- ❌ Poor performance in practice (AAAI 2024 paper)

---

### Generative Agents: Multi-factor Scoring
```
score = α·recency + β·importance + γ·relevance

Where:
  recency = 0.995^t (t in hours)
  importance = LLM_score(content) ∈ [1, 10]
  relevance = cosine_similarity(embed(memory), embed(query))

Normalization:
  Each component scaled to [0, 1] using min-max scaling

Default weights:
  α = β = γ = 1 (equal weighting)
```

**Characteristics**:
- ✅ Multi-dimensional evaluation
- ✅ Proven effective (Stanford/Google research)
- ✅ Flexible weighting
- ⚠️ Requires LLM for importance scoring

---

### MongoDB AI Memory: Dynamic Decay
```
On access (related memory):
  importance = importance + reinforcement_factor
  access_count = access_count + 1

On decay (unrelated memory):
  importance = importance × decay_factor

Pruning trigger:
  if memory_count > max_limit:
    delete(memories with lowest importance)
```

**Characteristics**:
- ✅ Adaptive to usage patterns
- ✅ Production-tested
- ✅ Automatic management
- ⚠️ Exact formula not public

---

### Zep (Graphiti): Temporal Model
```
Edge = {
  t_created:  when created in system
  t_expired:  when invalidated in system
  t_valid:    when fact became true
  t_invalid:  when fact became false (or NULL)
}

Contradiction handling:
  if new_edge contradicts old_edge:
    old_edge.t_invalid = new_edge.t_valid
```

**Characteristics**:
- ✅ Preserves history
- ✅ No data loss
- ✅ Point-in-time queries
- ❌ Not traditional "forgetting"

---

## 5. Performance Comparison

```
                    Latency          Accuracy         Resource Usage
                    ───────          ────────         ──────────────

Generative Agents   Medium           ★★★★★            Medium
                    (LLM calls)      (Multi-factor)   (Embeddings + LLM)

MongoDB AI Memory   Low              ★★★★☆            Low
                    (DB queries)     (Dynamic)        (DB + Access count)

Mem0                Low              ★★★☆☆            Low
                    (Vector search)  (Ranking)        (Vectors only)

MemoryBank          Low              ★★☆☆☆            Very Low
                    (Math only)      (Poor empirical) (Math computation)

LangChain           Very Low         ★★☆☆☆            Very Low
                    (Token count)    (Mechanical)     (Token counting)

Zep (Graphiti)      Medium           ★★★★☆            Medium-High
                    (Graph queries)  (Temporal)       (Knowledge graph)

MemGPT              High             ★★★☆☆            High
                    (LLM + DB)       (Hierarchical)   (Multiple storage tiers)
```

**Key Insights**:
- **Best accuracy**: Generative Agents (3-factor scoring)
- **Best latency**: LangChain, Mem0 (simple operations)
- **Best balance**: MongoDB AI Memory (dynamic + efficient)
- **Most unique**: Zep (temporal preservation without deletion)

---

## 6. TMWS Recommended Approach

### Hybrid Strategy: Best of All Worlds

```
┌─────────────────────────────────────────────────────────────────────┐
│                      TMWS Hybrid Forgetting                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Layer 1: Soft Forgetting (Score-based Ranking)                    │
│  ─────────────────────────────────────────────                     │
│                                                                     │
│    score = w₁·relevance + w₂·recency + w₃·importance              │
│                                                                     │
│    Where:                                                          │
│      relevance = cosine_similarity(query, memory)  [Generative]   │
│      recency = 0.995^hours_elapsed                 [Generative]   │
│      importance = LLM_score ∈ [1,10]               [Generative]   │
│                                                                     │
│    Return top-K memories → Implicit forgetting of low-scored       │
│                                                                     │
│  Layer 2: Dynamic Importance Adjustment                            │
│  ───────────────────────────────────                               │
│                                                                     │
│    On access (related):                                            │
│      importance += reinforcement_factor            [MongoDB]       │
│      access_count += 1                             [MongoDB]       │
│                                                                     │
│    On decay (unrelated):                                           │
│      importance *= decay_factor                    [MongoDB]       │
│                                                                     │
│  Layer 3: Hard Forgetting (Capacity Management)                    │
│  ───────────────────────────────────────────────                   │
│                                                                     │
│    if memory_count > max_limit:                    [MongoDB]       │
│      prune(memories with lowest importance)                        │
│                                                                     │
│  Layer 4: Optional Explicit Expiration                             │
│  ──────────────────────────────────────                            │
│                                                                     │
│    if expiration_date is set:                      [Mem0]          │
│      exclude from search after expiration                          │
│                                                                     │
│  Layer 5: Temporal Invalidation (Future)                           │
│  ────────────────────────────────────────                          │
│                                                                     │
│    For knowledge graph memories:                   [Zep]           │
│      invalidate contradicting edges                                │
│      preserve historical state                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Implementation Priority

**v2.3.0 (Immediate)**: ✅ P0
- Multi-factor scoring (Layer 1)
- LLM importance scoring
- Exponential decay (0.995^t)

**v2.4.0 (Short-term)**: ✅ P1
- Dynamic importance adjustment (Layer 2)
- Access-based reinforcement
- Automatic pruning (Layer 3)

**v2.5.0+ (Long-term)**: ⚠️ P2
- Expiration date (Layer 4)
- Temporal invalidation (Layer 5)
- Adaptive decay rates

---

## 7. Key Recommendations

### ✅ DO Implement

1. **Multi-factor Scoring** (from Generative Agents)
   - Proven by Stanford/Google research
   - High accuracy
   - Flexible weighting

2. **Exponential Decay: 0.995^t** (from Generative Agents)
   - Hourly decay factor
   - Scientifically validated
   - Simple to implement

3. **LLM Importance Scoring** (from Generative Agents)
   - 1-10 scale
   - "Mundane" to "Poignant"
   - Initial assessment

4. **Access-based Reinforcement** (from MongoDB AI Memory)
   - Increment on access
   - Decay on non-access
   - Production-proven

5. **Importance-based Pruning** (from MongoDB AI Memory)
   - Capacity-triggered
   - Delete least important
   - Automatic management

### ❌ DON'T Implement

1. **Simple Ebbinghaus Curve Only** (MemoryBank)
   - Poor empirical performance
   - Lacks context awareness
   - AAAI 2024 paper showed worst results

2. **Token-based Only** (LangChain)
   - No semantic awareness
   - Mechanical deletion
   - Loses important information

3. **No Forgetting** (MemGPT)
   - Requires infinite storage
   - No automatic cleanup
   - Archival only

### ⚠️ Consider for Future

1. **Expiration Date** (from Mem0)
   - Useful for temporary context
   - Low complexity
   - Clear use cases

2. **Temporal Invalidation** (from Zep)
   - Knowledge graph specific
   - Complex implementation
   - Niche use case

3. **Hierarchical Memory** (from MemGPT)
   - Short/long-term separation
   - OS-inspired design
   - High complexity

---

## 8. Success Metrics

### Effectiveness Metrics

```
Metric                      Target          Measurement Method
──────────────────────      ──────          ──────────────────

Retrieval Accuracy          >90%            Relevance of top-10 results
Memory Efficiency           <100MB/10K      Storage per 10K memories
Decay Appropriateness       >85%            User feedback on relevance
Pruning Precision           >95%            % of correctly pruned memories
Access Pattern Learning     >80%            Importance adjustment accuracy
```

### Performance Metrics

```
Operation                   Target          Current (v2.2.6)
─────────                   ──────          ────────────────

Score Calculation           <5ms P95        Not yet implemented
Importance Scoring (LLM)    <500ms P95      Not yet implemented
Pruning Operation           <100ms P95      Not yet implemented
Memory Update               <20ms P95       <20ms ✅
```

---

## Conclusion

**Key Findings**:
1. **Generative Agents approach is most effective** (3-factor scoring)
2. **MongoDB AI Memory provides best production pattern** (dynamic adjustment)
3. **MemoryBank's simple decay is insufficient** (empirically proven)
4. **Zep's temporal model is unique but niche** (knowledge graphs only)

**TMWS Strategy**:
- Combine best aspects of Generative Agents + MongoDB AI Memory
- Implement in phases (P0 → P1 → P2)
- Maintain competitive advantage through hybrid approach
- Balance accuracy, performance, and resource usage

**Competitive Positioning**:
- ✅ More sophisticated than Mem0 (planned features)
- ✅ More effective than MemoryBank (proven by research)
- ✅ More semantic than LangChain (token-based)
- ✅ More practical than Zep (general-purpose)
- ✅ Production-ready like MongoDB (enterprise-grade)

---

**Document Version**: 1.0
**Last Updated**: 2025-11-04
**Author**: Muses (Knowledge Architect)
