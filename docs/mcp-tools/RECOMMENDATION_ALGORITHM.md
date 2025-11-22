# MCP Tool Recommendation Algorithm
## Intent-Based Tool Discovery System

**Version**: 1.0.0
**Last Updated**: 2025-11-20
**Status**: Design Document
**Purpose**: Enable agents to find the right tool by describing what they want to do

---

## Overview

The recommendation algorithm helps agents discover appropriate MCP tools by analyzing their **intent** (what they want to accomplish) and matching it against tool capabilities.

### Design Goals

1. **Natural Language Understanding**: Accept queries like "I want to test login functionality"
2. **Context-Aware**: Consider current project, agent role, and recent tool usage
3. **Multi-Factor Ranking**: Balance relevance, success rate, performance, and user ratings
4. **Learning System**: Improve recommendations based on agent feedback

---

## Algorithm Design

### Phase 1: Intent Analysis

**Input**: Natural language query from agent
**Output**: Structured intent representation

```python
class Intent:
    def __init__(self, query: str):
        self.query = query
        self.action_verbs = self.extract_verbs(query)      # ["find", "analyze", "test"]
        self.domain_keywords = self.extract_domains(query)  # ["code", "web", "security"]
        self.technical_terms = self.extract_tech(query)    # ["function", "login", "API"]
        self.embedding = self.embed_query(query)           # 1024-dim vector

def extract_verbs(query: str) -> list[str]:
    """Extract action verbs from query"""
    # Examples:
    # "find a function" → ["find"]
    # "test login functionality" → ["test"]
    # "analyze code quality" → ["analyze"]

    action_verbs = {
        "find", "search", "locate", "discover",
        "analyze", "examine", "inspect", "review",
        "test", "verify", "validate", "check",
        "create", "generate", "build", "make",
        "update", "modify", "change", "edit",
        "delete", "remove", "clean",
        "navigate", "browse", "explore",
        "read", "fetch", "get", "retrieve",
        "write", "store", "save", "record"
    }

    words = query.lower().split()
    return [w for w in words if w in action_verbs]

def extract_domains(query: str) -> list[str]:
    """Extract domain keywords"""
    domains = {
        "code": ["code", "function", "class", "method", "variable", "symbol"],
        "web": ["web", "browser", "page", "website", "url", "http"],
        "data": ["data", "file", "csv", "json", "database", "table"],
        "documentation": ["docs", "documentation", "guide", "api", "reference"],
        "security": ["security", "vulnerability", "audit", "permission", "auth"],
        "memory": ["memory", "knowledge", "remember", "recall", "store"],
        "test": ["test", "e2e", "integration", "unit", "verify"]
    }

    query_lower = query.lower()
    matched_domains = []
    for domain, keywords in domains.items():
        if any(kw in query_lower for kw in keywords):
            matched_domains.append(domain)

    return matched_domains

def embed_query(query: str) -> np.ndarray:
    """Generate 1024-dim embedding for semantic similarity"""
    # Use same embedding model as TMWS (Multilingual-E5-Large)
    return ollama.embeddings(model="zylonai/multilingual-e5-large", prompt=query)
```

### Phase 2: Candidate Retrieval

**Input**: Intent representation
**Output**: Top 20 candidate tools (fast filtering)

```python
def retrieve_candidates(intent: Intent, top_k: int = 20) -> list[Tool]:
    """Fast candidate retrieval using multiple signals"""

    candidates = []

    # Signal 1: Domain matching (fast)
    for domain in intent.domain_keywords:
        candidates.extend(TOOL_INDEX_BY_DOMAIN[domain])

    # Signal 2: Action verb matching (fast)
    for verb in intent.action_verbs:
        candidates.extend(TOOL_INDEX_BY_ACTION[verb])

    # Signal 3: Technical term matching (fast)
    for term in intent.technical_terms:
        candidates.extend(TOOL_INDEX_BY_TECH_TERM[term])

    # Signal 4: Semantic similarity (moderate speed)
    # Vector search in pre-computed tool embeddings
    semantic_matches = vector_search(
        query_embedding=intent.embedding,
        tool_embeddings=TOOL_EMBEDDINGS,
        top_k=20
    )
    candidates.extend(semantic_matches)

    # Deduplicate and return top K by frequency
    tool_counts = Counter(candidates)
    return [tool for tool, count in tool_counts.most_common(top_k)]
```

### Phase 3: Multi-Factor Ranking

**Input**: Candidate tools
**Output**: Ranked list with scores

```python
class RecommendationScorer:
    def __init__(self):
        # Configurable weights (tunable based on feedback)
        self.weights = {
            "relevance": 0.35,       # Semantic similarity to query
            "success_rate": 0.25,    # Historical success rate
            "popularity": 0.15,      # Usage frequency
            "performance": 0.15,     # Latency (faster = better)
            "user_rating": 0.10      # Explicit user ratings
        }

    def score(self, tool: Tool, intent: Intent, context: AgentContext) -> float:
        """Calculate composite score for a tool"""

        # Factor 1: Relevance (semantic similarity)
        relevance = cosine_similarity(
            intent.embedding,
            tool.embedding
        )

        # Factor 2: Success rate (historical)
        success_rate = tool.success_count / max(tool.total_calls, 1)

        # Factor 3: Popularity (with recency decay)
        popularity = self.calculate_popularity(tool, context)

        # Factor 4: Performance (inverted latency)
        # Normalize: 0ms = 1.0, 1000ms = 0.0
        performance = 1.0 - min(tool.avg_latency_ms / 1000, 1.0)

        # Factor 5: User rating (0-1 scale)
        user_rating = tool.average_rating / 5.0

        # Composite score
        score = (
            self.weights["relevance"] * relevance +
            self.weights["success_rate"] * success_rate +
            self.weights["popularity"] * popularity +
            self.weights["performance"] * performance +
            self.weights["user_rating"] * user_rating
        )

        return score

    def calculate_popularity(self, tool: Tool, context: AgentContext) -> float:
        """Calculate popularity with recency decay and agent-specific bias"""

        # Base popularity (usage count)
        base_score = min(tool.usage_count / 1000, 1.0)  # Cap at 1000 uses

        # Recency decay (exponential)
        days_since_last_use = (datetime.now() - tool.last_used).days
        recency_factor = math.exp(-days_since_last_use / 30)  # 30-day half-life

        # Agent-specific bias (prefer tools this agent has used successfully)
        agent_success_rate = tool.agent_stats.get(context.agent_id, {}).get("success_rate", 0.5)
        agent_bias = 1.0 + (agent_success_rate - 0.5)  # Range: 0.5 to 1.5

        return base_score * recency_factor * agent_bias

def recommend_tools(intent: Intent, context: AgentContext, top_n: int = 10) -> list[Recommendation]:
    """Main recommendation function"""

    # Phase 1: Intent analysis (already done)

    # Phase 2: Retrieve candidates
    candidates = retrieve_candidates(intent, top_k=20)

    # Phase 3: Score and rank
    scorer = RecommendationScorer()
    scored_tools = [
        {
            "tool": tool,
            "score": scorer.score(tool, intent, context),
            "relevance": cosine_similarity(intent.embedding, tool.embedding),
            "success_rate": tool.success_count / max(tool.total_calls, 1),
            "avg_latency": tool.avg_latency_ms
        }
        for tool in candidates
    ]

    # Sort by score (descending)
    scored_tools.sort(key=lambda x: x["score"], reverse=True)

    return scored_tools[:top_n]
```

### Phase 4: Context-Aware Filtering

**Input**: Ranked tools
**Output**: Filtered list based on agent context

```python
def apply_context_filters(
    recommendations: list[Recommendation],
    context: AgentContext
) -> list[Recommendation]:
    """Filter recommendations based on agent context"""

    filtered = []

    for rec in recommendations:
        tool = rec["tool"]

        # Filter 1: Security level
        if not context.has_permission(tool.required_permissions):
            continue  # Skip tools agent can't access

        # Filter 2: Dependency availability
        if not are_dependencies_available(tool.dependencies):
            continue  # Skip if required services unavailable

        # Filter 3: Rate limiting
        if is_rate_limited(context.agent_id, tool.name):
            continue  # Skip if rate limit exceeded

        # Filter 4: Project compatibility
        if not is_compatible(tool, context.project):
            continue  # Skip if incompatible (e.g., Python tool for JS project)

        filtered.append(rec)

    return filtered
```

---

## Example Queries

### Example 1: "I want to find where a Python function is defined"

**Intent Analysis**:
```python
Intent(
    query="I want to find where a Python function is defined",
    action_verbs=["find"],
    domain_keywords=["code"],
    technical_terms=["function", "python"],
    embedding=[0.123, -0.456, ...]  # 1024-dim
)
```

**Candidate Retrieval**:
```
Domain match (code): serena__find_symbol, serena__search_for_pattern, ...
Action match (find): serena__find_symbol, grep, ...
Tech term match (function): serena__find_symbol, serena__find_referencing_symbols, ...
Semantic match: serena__find_symbol (0.98), serena__get_symbols_overview (0.85), ...
```

**Scoring**:
```python
serena__find_symbol:
  relevance: 0.98 → 0.343 (0.98 * 0.35)
  success_rate: 0.983 → 0.246 (0.983 * 0.25)
  popularity: 0.85 → 0.128 (0.85 * 0.15)
  performance: 0.985 → 0.148 (0.985 * 0.15)  # 15ms latency
  user_rating: 0.96 → 0.096 (4.8/5 * 0.10)
  TOTAL: 0.961 ⭐⭐⭐⭐⭐

serena__search_for_pattern:
  relevance: 0.75 → 0.263
  success_rate: 0.965 → 0.241
  popularity: 0.70 → 0.105
  performance: 0.975 → 0.146
  user_rating: 0.92 → 0.092
  TOTAL: 0.847 ⭐⭐⭐⭐
```

**Final Recommendations**:
```
1. serena__find_symbol (score: 0.961) ⭐⭐⭐⭐⭐
   "Locate symbols by name with zero false positives"

2. serena__search_for_pattern (score: 0.847) ⭐⭐⭐⭐
   "Regex search across codebase for complex patterns"

3. serena__get_symbols_overview (score: 0.762) ⭐⭐⭐⭐
   "Get high-level structure to understand where to look"
```

---

### Example 2: "I need to test login functionality in a web app"

**Intent Analysis**:
```python
Intent(
    query="I need to test login functionality in a web app",
    action_verbs=["test"],
    domain_keywords=["web", "test"],
    technical_terms=["login", "functionality"],
    embedding=[...]
)
```

**Recommendations**:
```
1. playwright__browser_fill_form (score: 0.953) ⭐⭐⭐⭐⭐
   "Fill login form fields efficiently"

2. playwright__browser_click (score: 0.941) ⭐⭐⭐⭐⭐
   "Click submit button after form fill"

3. playwright__browser_navigate (score: 0.928) ⭐⭐⭐⭐⭐
   "Navigate to login page first"

4. playwright__browser_wait_for (score: 0.891) ⭐⭐⭐⭐⭐
   "Wait for post-login redirect/element"

5. playwright__browser_snapshot (score: 0.867) ⭐⭐⭐⭐
   "Capture page state for debugging"
```

---

## Learning & Improvement

### Feedback Collection

```python
class FeedbackCollector:
    async def record_tool_usage(
        self,
        agent_id: str,
        query: str,
        recommended_tools: list[Tool],
        selected_tool: Tool,
        success: bool,
        latency_ms: float,
        user_rating: float | None = None
    ):
        """Record tool usage for learning"""

        # Store in TMWS for analysis
        await store_memory(
            content=f"Tool usage: {agent_id} used {selected_tool.name} for '{query}'",
            context={
                "query": query,
                "recommendations": [t.name for t in recommended_tools],
                "selected": selected_tool.name,
                "success": success,
                "latency_ms": latency_ms,
                "user_rating": user_rating,
                "timestamp": datetime.now().isoformat()
            },
            tags=["tool-usage", "feedback"],
            namespace="tool-recommendations"
        )

        # Update tool statistics
        selected_tool.total_calls += 1
        selected_tool.success_count += 1 if success else 0
        selected_tool.total_latency_ms += latency_ms
        selected_tool.avg_latency_ms = selected_tool.total_latency_ms / selected_tool.total_calls

        if user_rating:
            selected_tool.ratings.append(user_rating)
            selected_tool.average_rating = sum(selected_tool.ratings) / len(selected_tool.ratings)
```

### Weight Tuning

```python
class WeightOptimizer:
    async def optimize_weights(self, feedback_history: list[Feedback]) -> dict[str, float]:
        """Optimize recommendation weights based on feedback"""

        # Use gradient descent to minimize ranking error
        # Objective: Maximize position of selected tool in recommendations

        current_weights = self.weights.copy()
        learning_rate = 0.01
        iterations = 100

        for _ in range(iterations):
            gradient = self.calculate_gradient(feedback_history, current_weights)

            # Update weights
            for key in current_weights:
                current_weights[key] -= learning_rate * gradient[key]

            # Normalize (sum to 1.0)
            total = sum(current_weights.values())
            current_weights = {k: v / total for k, v in current_weights.items()}

        return current_weights
```

---

## Performance Optimization

### Caching Strategy

```python
class RecommendationCache:
    def __init__(self):
        self.cache = {}  # query_hash -> recommendations
        self.ttl = 3600  # 1 hour

    def get(self, query: str) -> list[Recommendation] | None:
        """Get cached recommendations"""
        query_hash = hashlib.sha256(query.encode()).hexdigest()

        if query_hash in self.cache:
            cached = self.cache[query_hash]
            if time.time() - cached["timestamp"] < self.ttl:
                return cached["recommendations"]

        return None

    def set(self, query: str, recommendations: list[Recommendation]):
        """Cache recommendations"""
        query_hash = hashlib.sha256(query.encode()).hexdigest()
        self.cache[query_hash] = {
            "recommendations": recommendations,
            "timestamp": time.time()
        }
```

### Precomputed Embeddings

```python
# Precompute tool embeddings at startup (not per-query)
TOOL_EMBEDDINGS = {}

for tool in ALL_TOOLS:
    # Combine tool metadata into single string
    description = f"{tool.name} {tool.description} {' '.join(tool.tags)}"

    # Generate embedding once
    TOOL_EMBEDDINGS[tool.name] = ollama.embeddings(
        model="zylonai/multilingual-e5-large",
        prompt=description
    )

# Vector search is now fast (no embedding generation per query)
```

---

## Evaluation Metrics

### Offline Metrics (Historical Data)

```python
def evaluate_recommendations(feedback_history: list[Feedback]) -> dict:
    """Evaluate recommendation quality"""

    metrics = {
        "mean_reciprocal_rank": 0.0,  # Position of selected tool
        "precision_at_k": {},          # % of relevant tools in top K
        "ndcg": 0.0,                   # Normalized discounted cumulative gain
        "coverage": 0.0                # % of tools ever recommended
    }

    # Mean Reciprocal Rank (MRR)
    # = Average of 1/rank where rank is position of selected tool
    ranks = []
    for feedback in feedback_history:
        selected = feedback.selected_tool
        recommendations = feedback.recommendations

        try:
            rank = recommendations.index(selected) + 1
            ranks.append(1.0 / rank)
        except ValueError:
            ranks.append(0.0)  # Selected tool not in recommendations

    metrics["mean_reciprocal_rank"] = sum(ranks) / len(ranks)

    # Precision@K
    for k in [1, 3, 5, 10]:
        relevant_in_top_k = sum(
            1 for fb in feedback_history
            if fb.selected_tool in fb.recommendations[:k]
        )
        metrics[f"precision_at_{k}"] = relevant_in_top_k / len(feedback_history)

    return metrics
```

### Online Metrics (Real-Time)

- **Click-Through Rate (CTR)**: % of recommendations that are selected
- **Success Rate**: % of selected tools that execute successfully
- **Time to Success**: Latency from query to successful tool execution
- **User Satisfaction**: Average user rating after tool use

---

## A/B Testing Framework

```python
class ABTestFramework:
    def __init__(self):
        self.variants = {
            "control": RecommendationScorer(weights={
                "relevance": 0.35,
                "success_rate": 0.25,
                "popularity": 0.15,
                "performance": 0.15,
                "user_rating": 0.10
            }),
            "variant_a": RecommendationScorer(weights={
                "relevance": 0.50,  # Increase relevance weight
                "success_rate": 0.20,
                "popularity": 0.10,
                "performance": 0.10,
                "user_rating": 0.10
            }),
            "variant_b": RecommendationScorer(weights={
                "relevance": 0.30,
                "success_rate": 0.30,  # Increase success rate weight
                "popularity": 0.15,
                "performance": 0.15,
                "user_rating": 0.10
            })
        }

    def assign_variant(self, agent_id: str) -> str:
        """Assign agent to A/B test variant"""
        # Deterministic assignment based on agent_id hash
        hash_value = int(hashlib.sha256(agent_id.encode()).hexdigest(), 16)
        variant_index = hash_value % len(self.variants)
        return list(self.variants.keys())[variant_index]
```

---

## Implementation Roadmap

### Phase 1: Basic Recommendation (Week 1-2)
- [x] Intent analysis (verbs, domains, tech terms)
- [x] Candidate retrieval (domain/action matching)
- [x] Simple scoring (relevance only)
- [x] Top-N recommendations

### Phase 2: Multi-Factor Ranking (Week 3-4)
- [ ] Implement all scoring factors
- [ ] Weight configuration
- [ ] Context filtering
- [ ] Performance optimization (caching, precomputed embeddings)

### Phase 3: Learning System (Week 5-6)
- [ ] Feedback collection
- [ ] Weight tuning
- [ ] A/B testing framework
- [ ] Evaluation metrics

### Phase 4: Advanced Features (Week 7-8)
- [ ] Personalized recommendations (agent-specific)
- [ ] Session-aware recommendations (recent tool usage)
- [ ] Explanation generation ("Why this tool?")
- [ ] Multi-tool workflows ("Use these 3 tools together")

---

## Success Criteria

- ✅ **MRR > 0.8**: Selected tool in top 3 recommendations 80% of time
- ✅ **Precision@3 > 0.9**: Relevant tool in top 3 at least 90% of time
- ✅ **Latency < 100ms**: Recommendation generation under 100ms
- ✅ **User Rating > 4.5/5**: Average user satisfaction with recommendations

---

**Document Author**: Muses (Knowledge Architect) + Artemis (Algorithm Design)
**Reviewed By**: Athena (UX), Hera (Strategy)
**Last Updated**: 2025-11-20
**Status**: Design Document (Phase 1 implemented, Phase 2-4 planned)
**Version**: 1.0.0
