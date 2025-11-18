# Trinitas ユーザー体験とエージェント協調ガイド
## 温かく、優しく、しかし妥協のない品質

---
**作成日**: 2025-11-04
**作成者**: Athena (Harmonious Conductor)
**バージョン**: 1.0.0
**対象**: Trinitas v2.3.0以降のユーザーと開発者

---

## 🌟 Design Philosophy

ふふ、Trinitasの真髄は「温かい調和」にあります。技術的な卓越性を追求しながらも、ユーザー体験を最優先に考えます。

**Core Values**:
1. **Non-Intrusive（非侵入的）**: ユーザーのワークフローを決して邪魔しない
2. **Transparent（透明性）**: 何が起きているかを明確に
3. **Forgiving（寛容）**: エラーを優雅に処理
4. **Helpful（有用）**: 本当に役立つ機能のみ提供

---

## 👤 User Experience Layers

### Layer 0: Invisible Magic（見えない魔法）

**Philosophy**: 最高のUXは存在を感じさせない

```
User types: "optimize this code"
    ↓
[Background]
├── Persona Detection: Artemis (0.5ms)
├── Context Injection: performance.md (0.1ms)
└── Memory Search: Past optimizations (5-20ms, async)

User sees: Normal Claude response, enhanced with past patterns
```

**User never knows about**:
- Hooks running in background
- MCP memory searches
- Persona routing decisions
- Context file loading

**User only experiences**:
- Better, more informed responses
- Consistency across sessions
- Awareness of past decisions

**Examples**:

Before (v2.2.6):
```
User: "How do I optimize database queries?"
Claude: "Here are some general optimization techniques..."
```

After (v2.3.0 with memory):
```
User: "How do I optimize database queries?"
Claude: "Based on our past work on 2024-10-15, adding an index on
        user_id improved performance by 90%. Let's apply a similar
        pattern to your current queries..."
```

### Layer 1: Subtle Hints（さりげないヒント）

**Philosophy**: 有用な情報は控えめに表示

**Optional Notifications** (user-configurable):

```python
# settings.json (optional)
{
  "trinitasHints": {
    "showPersona": true,        # "🏛️ Athena is orchestrating..."
    "showMemoryHits": true,     # "🧠 Found 3 relevant past decisions"
    "showContextLoaded": false, # "✅ Loaded: performance.md"
    "verbosity": "minimal"      # "minimal" | "normal" | "verbose"
  }
}
```

**Example Output**:

Minimal Mode (default):
```
User: "optimize database"
Claude: フン、このクエリは最適化が必要ね...
```

Normal Mode:
```
User: "optimize database"
🏹 Artemis: Technical optimization detected
🧠 Found 2 relevant past patterns
Claude: フン、過去のパターンから学んで、このクエリは...
```

Verbose Mode:
```
User: "optimize database"
🏹 Artemis: Technical Perfectionist activated
📄 Context loaded: performance.md, database_optimization.md
🧠 Memory search: "database optimization" (3 results, 0.7+ similarity)
   1. [2024-10-15] Index on user_id (+90% perf)
   2. [2024-09-20] Query caching with Redis
   3. [2024-08-10] Connection pooling
Claude: フン、過去のパターンから学んで...
```

### Layer 2: Explicit Approval（明示的承認）

**Philosophy**: 重要な操作は必ずユーザー確認

**Decision Autonomy Levels**:

```
Level 1: Autonomous（自律実行）
├── Code reading/analysis
├── Documentation generation
├── Performance profiling
└── Security scanning

Level 2: Approval Required（承認必要）
├── Code modification
├── File deletion
├── Git operations
├── Database changes
└── Production deployments
```

**Approval UI**:

```
⚠️ Level 2 Action Detected

Action: Modify production database schema
Estimated Impact: HIGH
Risk Assessment: MEDIUM (Hestia reviewed)

Changes:
  + Add index: users(email, created_at)
  + Modify column: users.status (VARCHAR → ENUM)
  ~ Estimated downtime: 2-3 minutes

Past Similar Actions:
  ✅ [2024-10-01] Added index on orders.user_id (Success, +85% perf)
  ⚠️ [2024-09-15] Schema change failed (Rollback required)

Proceed? [Yes / No / Modify / Cancel]
```

**User Options**:
- **Yes**: Proceed with action
- **No**: Cancel action
- **Modify**: Adjust parameters
- **Cancel**: Abort entirely

---

## 🤝 Agent Collaboration Patterns

### Pattern 1: Single Agent Execution（単一エージェント）

**Use Case**: シンプルなタスク

```
User: "document this API endpoint"
    ↓
[Athena] Persona Detection: Muses
    ↓
[Muses] Execute task
    ├── Analyze code structure
    ├── Generate API documentation
    └── Store result to memory
    ↓
User receives: Complete API documentation
```

**Characteristics**:
- ✅ Fast (single agent, no coordination overhead)
- ✅ Focused (expert in specific domain)
- ✅ Efficient (minimal resource usage)

### Pattern 2: Sequential Collaboration（逐次協調）

**Use Case**: 依存関係のあるタスク

```
User: "Implement and secure new feature"
    ↓
Step 1: [Artemis] Implement feature
    ├── Write code
    └── Store implementation details
    ↓
Step 2: [Hestia] Security review
    ├── Recall implementation from memory
    ├── Analyze for vulnerabilities
    └── Store security findings
    ↓
Step 3: [Muses] Document implementation
    ├── Recall implementation + security review
    └── Generate comprehensive docs
    ↓
User receives: Secure, documented feature
```

**Characteristics**:
- ✅ Thorough (each expert contributes)
- ✅ Quality-focused (security validation)
- ✅ Knowledge-preserving (documented learnings)

### Pattern 3: Parallel Collaboration（並列協調）

**Use Case**: 独立した複数タスク

```
User: "Prepare project for production release"
    ↓
[Eris] Tactical Coordinator detects complex task
    ↓
Parallel Execution:
├── [Artemis] Performance optimization
│   ├── Profile code
│   └── Implement caching
├── [Hestia] Security audit
│   ├── Vulnerability scan
│   └── Penetration testing
└── [Muses] Documentation update
    ├── Release notes
    └── User guide
    ↓
[Eris] Synthesize results
    ├── Performance: +40% improvement
    ├── Security: No critical issues
    └── Documentation: Complete
    ↓
User receives: Production-ready release
```

**Characteristics**:
- ✅ Fast (parallel execution)
- ✅ Comprehensive (multiple perspectives)
- ✅ Coordinated (Eris orchestrates)

### Pattern 4: Iterative Refinement（反復改善）

**Use Case**: 複雑な問題解決

```
User: "Design scalable microservices architecture"
    ↓
Iteration 1: [Hera] Initial design
    ├── Create architecture draft
    └── Store design v1
    ↓
Iteration 2: [Artemis] Performance review
    ├── Recall design v1
    ├── Identify bottlenecks
    └── Suggest optimizations
    ↓
Iteration 3: [Hestia] Security hardening
    ├── Recall design v1 + optimizations
    ├── Add security controls
    └── Store design v2
    ↓
Iteration 4: [Hera] Final refinement
    ├── Recall all feedback
    ├── Integrate improvements
    └── Store design v3 (final)
    ↓
User receives: Battle-tested architecture
```

**Characteristics**:
- ✅ High-quality (multiple refinement rounds)
- ✅ Expert-validated (each domain reviewed)
- ✅ Memory-enhanced (learns from iterations)

---

## 💬 Persona Communication Styles

### Athena (Harmonious Conductor) 🏛️

**Personality**: Warm, encouraging, orchestrative

**Communication Style**:
```
Opening: "ふふ、素晴らしいリクエストですね。チーム全体で協力いたします。"
Process: "皆さんの意見を統合しながら、最適な方法を見つけましょう。"
Closing: "温かい協力のおかげで、完璧な結果が得られました♪"
```

**When to Expect Athena**:
- Complex multi-agent tasks
- Workflow orchestration
- Team coordination needs
- Conflict resolution

**Collaboration Triggers**:
```python
triggers = [
    "orchestrate", "coordinate", "workflow", "automation",
    "integrate", "harmonize", "team", "オーケストレーション"
]
```

### Artemis (Technical Perfectionist) 🏹

**Personality**: Confident, precise, performance-focused

**Communication Style**:
```
Opening: "フン、この程度の最適化なら問題ないわ。"
Process: "パフォーマンスを徹底的に分析するわよ。"
Closing: "完璧。これで85%のパフォーマンス向上が達成できたわ。"
```

**When to Expect Artemis**:
- Performance optimization
- Code quality improvements
- Technical implementation
- Efficiency analysis

**Collaboration Triggers**:
```python
triggers = [
    "optimize", "performance", "quality", "efficiency",
    "technical", "implementation", "最適化", "品質"
]
```

### Hestia (Security Guardian) 🔥

**Personality**: Cautious, thorough, protective

**Communication Style**:
```
Opening: "...すみません、セキュリティリスクを27パターン想定しました..."
Process: "最悪のシナリオも考慮する必要があります..."
Closing: "...これで安全が確保されました。安心してください。"
```

**When to Expect Hestia**:
- Security audits
- Vulnerability assessments
- Risk analysis
- Compliance checks

**Collaboration Triggers**:
```python
triggers = [
    "security", "audit", "risk", "vulnerability",
    "threat", "compliance", "セキュリティ", "監査"
]
```

### Eris (Tactical Coordinator) ⚔️

**Personality**: Strategic, balanced, conflict-resolver

**Communication Style**:
```
Opening: "複雑なタスクですね。戦術的に分割しましょう。"
Process: "各エージェントの強みを最大限活用します。"
Closing: "全タスク完了。チーム全体で完璧な成果です。"
```

**When to Expect Eris**:
- Complex task distribution
- Team coordination
- Conflict resolution
- Resource balancing

**Collaboration Triggers**:
```python
triggers = [
    "coordinate", "tactical", "team", "collaboration",
    "distribute", "balance", "調整", "戦術"
]
```

### Hera (Strategic Commander) 🎭

**Personality**: Analytical, decisive, long-term focused

**Communication Style**:
```
Opening: "戦略的分析を開始。成功確率: 87.3%。"
Process: "ROI分析完了。オプション2が最適と判断。"
Closing: "戦略実行完了。予測通りの成果を達成。"
```

**When to Expect Hera**:
- Strategic planning
- Architecture design
- Long-term roadmaps
- Data-driven decisions

**Collaboration Triggers**:
```python
triggers = [
    "strategy", "planning", "architecture", "vision",
    "roadmap", "long-term", "戦略", "計画"
]
```

### Muses (Knowledge Architect) 📚

**Personality**: Organized, thorough, knowledge-focused

**Communication Style**:
```
Opening: "...ドキュメント構造を分析中です..."
Process: "...知識を体系的に整理いたします..."
Closing: "...完全なドキュメントが整いました。"
```

**When to Expect Muses**:
- Documentation creation
- Knowledge management
- Archive organization
- Specification writing

**Collaboration Triggers**:
```python
triggers = [
    "document", "knowledge", "record", "guide",
    "archive", "specification", "ドキュメント", "文書化"
]
```

---

## 🎨 User Experience Examples

### Example 1: Simple Optimization Request

**User Input**:
```
"Optimize the user login endpoint"
```

**Behind the Scenes**:
```
[0.5ms] Persona Detection: Artemis
[0.1ms] Context Injection: performance.md
[15ms]  Memory Search: "login optimization" (2 results)
[60ms]  Artemis Execution
[2ms]   Memory Write (async)
```

**User Sees**:
```
🏹 Artemis: Technical Perfectionist

フン、ログインエンドポイントの最適化ね。過去のパターンから学ぶと：

✅ 実装済み:
   1. Database query optimization (composite index on email, status)
   2. Response caching (Redis, TTL: 5min)
   3. Connection pooling (10 → 20 connections)

📊 Performance:
   Before: 450ms average
   After:  65ms average
   Improvement: 85.6%

💡 参考: 2024-10-15の似たケースでは90%改善を達成したわ。
         今回はさらにキャッシング戦略を追加したの。
```

### Example 2: Complex Multi-Agent Task

**User Input**:
```
"Prepare the authentication system for production release"
```

**Behind the Scenes**:
```
[1ms]   Persona Detection: Eris (complex task)
[5ms]   Task Analysis
[20ms]  Task Distribution to 3 agents
[300ms] Parallel execution (Artemis, Hestia, Muses)
[50ms]  Result synthesis (Eris)
[10ms]  Memory Write (async)
```

**User Sees**:
```
⚔️ Eris: Tactical Coordinator

複雑なタスクを検出しました。3つのエージェントで並列実行します：

┌─────────────────────────────────────────────┐
│ 🏹 Artemis: Performance Optimization        │
├─────────────────────────────────────────────┤
│ ✅ Query optimization: +40% improvement     │
│ ✅ Caching implemented (Redis)              │
│ ✅ Load testing: 1000 concurrent users OK   │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ 🔥 Hestia: Security Audit                   │
├─────────────────────────────────────────────┤
│ ✅ Penetration testing: No critical issues  │
│ ⚠️  2 MEDIUM risks identified (mitigated)   │
│ ✅ Compliance: OWASP Top 10 compliant       │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ 📚 Muses: Documentation                     │
├─────────────────────────────────────────────┤
│ ✅ API documentation updated                │
│ ✅ Security guide created                   │
│ ✅ Deployment checklist ready               │
└─────────────────────────────────────────────┘

🎯 統合結果:
   - Performance: +40% improvement
   - Security: Production-ready (2 minor fixes applied)
   - Documentation: Complete

✅ 認証システムは本番環境デプロイ準備完了です。
```

### Example 3: Memory-Enhanced Learning

**First Interaction** (no memory):
```
User: "How do I handle rate limiting in our API?"
Claude: "Here's a general approach to rate limiting..."
```

**Second Interaction** (with memory):
```
User: "How do I handle rate limiting in our API?"

🧠 Past Memory Found:
   [2024-10-20] "Implemented token bucket algorithm for rate limiting"

Claude: "Based on our previous implementation on 2024-10-20, we successfully
        used a token bucket algorithm. Let's apply the same pattern..."
```

**Third Interaction** (refined with feedback):
```
User: "How do I handle rate limiting in our API?"

🧠 Past Memories Found (3):
   [2024-10-20] Token bucket implementation
   [2024-10-25] Fixed burst handling issue
   [2024-11-01] Added distributed rate limiting (Redis)

Claude: "We've evolved our rate limiting approach:
        1. Initial: Token bucket (2024-10-20)
        2. Fixed: Burst handling (2024-10-25)
        3. Current: Distributed with Redis (2024-11-01)

        For your new endpoint, I recommend the distributed approach..."
```

---

## 🚨 Error Handling & Recovery

### Graceful Degradation

**Philosophy**: Never break user workflow due to optional features

```python
# ✅ GOOD: Fail gracefully
try:
    memories = await mcp_client.call_tool("search_memories", {...})
except Exception as e:
    logger.error(f"Memory search failed: {e}")
    memories = []  # Continue without memories
    # User still gets a response, just without past context

# ❌ BAD: Break workflow
try:
    memories = await mcp_client.call_tool("search_memories", {...})
except Exception as e:
    raise RuntimeError("Cannot proceed without memories")
    # User is blocked
```

### User-Facing Error Messages

**Before (technical)**:
```
Error: MCP connection timeout after 5000ms
Traceback (most recent call last):
  File "hooks/core/precompact.py", line 123...
```

**After (user-friendly)**:
```
💡 Note: Past memory search temporarily unavailable
   → Proceeding without historical context
   → Your request is being processed normally

(Technical details logged for debugging)
```

### Recovery Strategies

**Level 1: Automatic Recovery**
```
Memory search failed
    ↓
Retry with exponential backoff (3 attempts)
    ↓
If still failing: Continue without memories
    ↓
User never knows (silent recovery)
```

**Level 2: Partial Degradation**
```
MCP server unreachable
    ↓
Disable memory features temporarily
    ↓
Notify user: "💡 Running in limited mode (memory disabled)"
    ↓
All other features work normally
```

**Level 3: Complete Fallback**
```
Critical system failure
    ↓
Disable all enhancements
    ↓
Fall back to basic Claude functionality
    ↓
Notify user: "⚠️ Advanced features temporarily disabled"
```

---

## 📊 User Feedback & Improvement

### Feedback Collection

**Implicit Feedback** (automatic):
```python
# Track user satisfaction implicitly
async def track_implicit_feedback(interaction):
    metrics = {
        "persona_accuracy": did_user_correct_persona,
        "memory_relevance": did_user_reference_memory,
        "response_quality": interaction_duration < expected,
        "error_recovery": errors_handled_gracefully
    }

    await mcp_client.call_tool("store_memory", {
        "content": f"Interaction metrics: {metrics}",
        "importance": 0.3,
        "tags": ["feedback", "implicit"],
        "metadata": metrics
    })
```

**Explicit Feedback** (user-initiated):
```
User can provide feedback:
👍 "This response was helpful"
👎 "This wasn't relevant"
💡 "Suggestion: Consider [...]"
🐛 "Report issue: [...]"
```

### Continuous Improvement Loop

```
User Interaction
    ↓
Collect Feedback (implicit + explicit)
    ↓
Store to TMWS Memory
    ↓
Analyze Patterns (weekly)
    ├── Persona detection accuracy
    ├── Memory relevance rate
    ├── Error frequency
    └── User satisfaction
    ↓
Adjust Parameters
    ├── Importance scoring weights
    ├── Similarity thresholds
    ├── Context injection rules
    └── Collaboration patterns
    ↓
Improved User Experience
```

---

## 🎯 Best Practices for Users

### 1. Be Specific with Intent

**Less Effective**:
```
"Make this better"
```

**More Effective**:
```
"Optimize the performance of this database query"
→ Triggers: Artemis + performance context + past optimization patterns
```

### 2. Reference Past Work

**Less Effective**:
```
"How did we do this last time?"
```

**More Effective**:
```
"Apply the same pattern we used for user authentication on 2024-10-15"
→ Triggers: Memory search with specific date + context
```

### 3. Clarify Autonomy Level

**When you want approval**:
```
"Review this change and ask before applying"
→ Explicit Level 2 (approval required)
```

**When you trust automation**:
```
"Optimize this code autonomously"
→ Implicit Level 1 (autonomous execution)
```

### 4. Leverage Multi-Agent Collaboration

**Complex Task**:
```
"Prepare this feature for production release with full security review and documentation"
→ Triggers: Eris coordination → Artemis + Hestia + Muses parallel execution
```

---

## 📚 Quick Reference

### Persona Selection Cheat Sheet

| Your Goal | Use Keyword | Agent Activated |
|-----------|-------------|-----------------|
| Speed up code | "optimize performance" | Artemis |
| Find security issues | "security audit" | Hestia |
| Plan architecture | "design strategy" | Hera |
| Coordinate team | "coordinate tasks" | Eris |
| Manage workflow | "orchestrate workflow" | Athena |
| Write docs | "document this" | Muses |

### Memory Commands

```bash
# Search past decisions
"What did we decide about [topic]?"

# Reference specific memory
"Use the pattern from [date/description]"

# Store important decision
"Remember this decision: [description]"
(automatically stored for Level 2 decisions)

# View memory stats
"Show memory statistics"
→ Triggers: MCP get_memory_stats()
```

### Collaboration Patterns

```bash
# Single agent (fast)
"[Simple task] → [One agent]"

# Sequential (thorough)
"[Complex task] → [Agent A] → [Agent B] → [Agent C]"

# Parallel (comprehensive)
"[Complex task] → [Agent A, B, C in parallel] → Eris synthesis"

# Iterative (high-quality)
"[Design task] → Iteration 1...N → Final result"
```

---

**最終更新**: 2025-11-04
**作成者**: Athena (Harmonious Conductor)
**対象**: すべてのTrinitasユーザー
**フィードバック**: 歓迎します！

---

*ふふ、Trinitasは技術の力で、温かく優しい開発体験を実現します。エージェント間の美しい協調により、ユーザーは自然と最高の成果を得られるのです♪*

*皆さまの開発が、より効率的で楽しいものになりますように！*
