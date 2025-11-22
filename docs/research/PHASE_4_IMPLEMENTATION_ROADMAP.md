# TMWS Phase 4 Implementation Roadmap
## Context Optimization & Configuration Simplification

**Status**: Planning Document
**Created**: 2025-11-20
**Author**: Muses (Knowledge Architect)
**Based On**:
- [Anthropic: Agent Skills Pattern](ANTHROPIC_AGENT_SKILLS_ANALYSIS.md)
- [Anthropic: Context Engineering Reference](ANTHROPIC_CONTEXT_ENGINEERING_REFERENCE.md)

---

## Executive Summary

This roadmap synthesizes insights from Anthropic's Agent Skills and Context Engineering articles into a phased implementation plan for TMWS Phase 4. The goal: **80% context reduction** while maintaining ≥95% task success rate.

**Target Metrics**:
- Baseline context: 11,000 tokens → 1,300 tokens (88% reduction)
- Average total context: 17,500 tokens → 4,000 tokens (77% reduction)
- Cost efficiency: +340% (0.99 → 3.39 success/M tokens)
- Task success rate: ≥95% (no regression)

---

## Core Strategy

### Two-Pillar Approach

**Pillar 1: Progressive Disclosure (Agent Skills)**
- Structural pattern for modular context loading
- Three-level hierarchy (metadata → core → supplementary)
- Expected impact: 87% baseline reduction

**Pillar 2: Context Engineering Optimization**
- Right altitude instructions (flexible heuristics)
- Tool result clearing (10-30% reduction)
- Semantic deduplication (20-40% reduction)
- Effectiveness metrics (data-driven optimization)

### Guiding Principles

1. **Measurement-First**: Track metrics before, during, and after each phase
2. **Incremental Deployment**: Ship quick wins first, build infrastructure second
3. **Quality Preservation**: TSR ≥95% (no regression from optimization)
4. **Security-First**: Hestia validation for all skill implementations

---

## Phase 1: Quick Wins (Week 1-2, ~16 hours)

**Goal**: 20-40% immediate context reduction with minimal infrastructure changes

### 1.1: Tool Result Clearing
**Effort**: 4 hours | **Impact**: 10-30% reduction | **Priority**: P0

**Implementation**:
```python
# src/services/context_optimization_service.py
class ToolResultClearer:
    def __init__(self, keep_recent: int = 5):
        self.keep_recent = keep_recent

    async def clear_old_results(self, messages: List[Message]) -> List[Message]:
        """Clear tool results beyond recent window"""
        tool_results = [
            (i, msg) for i, msg in enumerate(messages)
            if msg.type == "tool_result"
        ]

        if len(tool_results) <= self.keep_recent:
            return messages

        recent_indices = {i for i, _ in tool_results[-self.keep_recent:]}

        return [
            msg if i not in {idx for idx, _ in tool_results} or i in recent_indices
            else Message(
                type="tool_result",
                content="[Cleared - result no longer needed]",
                metadata={"original_size": len(msg.content)}
            )
            for i, msg in enumerate(messages)
        ]
```

**Testing**:
```python
# tests/unit/services/test_context_optimization.py
async def test_tool_result_clearing_preserves_recent():
    clearer = ToolResultClearer(keep_recent=3)
    messages = [
        Message(type="user", content="Query"),
        Message(type="tool_result", content="Result 1"),  # Should clear
        Message(type="tool_result", content="Result 2"),  # Should clear
        Message(type="tool_result", content="Result 3"),  # Keep (recent)
        Message(type="tool_result", content="Result 4"),  # Keep (recent)
        Message(type="tool_result", content="Result 5"),  # Keep (recent)
    ]

    cleared = await clearer.clear_old_results(messages)

    assert cleared[1].content == "[Cleared - result no longer needed]"
    assert cleared[2].content == "[Cleared - result no longer needed]"
    assert cleared[3].content == "Result 3"
    assert cleared[4].content == "Result 4"
    assert cleared[5].content == "Result 5"
```

**Metrics**:
- Token reduction: Measure before/after (target: 10-30%)
- Quality: TSR comparison (target: no regression)

**Rollout**:
- Deploy to development environment
- Monitor for 48 hours
- If TSR ≥95%, deploy to production

---

### 1.2: Prompt Caching (Anthropic Feature)
**Effort**: 6 hours | **Impact**: 50-70% cost reduction | **Priority**: P0

**Implementation**:
```python
# src/core/prompt_builder.py
class PromptBuilder:
    def build_system_prompt(
        self,
        static_components: List[str],
        dynamic_context: dict
    ) -> str:
        """
        Build system prompt with cacheable prefix and dynamic suffix

        Anthropic caches static prefix, reducing cost and latency
        """
        # Cacheable prefix (static)
        cacheable = "\n\n".join([
            "<background_information>",
            "You are the TMWS Memory & Workflow System...",
            "</background_information>",
            "",
            "<core_instructions>",
            "1. Enforce namespace isolation",
            "2. Use async/await for all I/O",
            "3. Validate access control",
            "</core_instructions>",
            "",
            # Skill metadata (static, rarely changes)
            self._build_skill_metadata_section(),
        ])

        # Dynamic suffix (not cached)
        dynamic = "\n\n".join([
            "<current_context>",
            f"Current namespace: {dynamic_context['namespace']}",
            f"Current agent: {dynamic_context['agent_id']}",
            f"Task: {dynamic_context['task_description']}",
            "</current_context>"
        ])

        return f"{cacheable}\n\n{dynamic}"
```

**Measurement**:
```python
# Track cache performance
class CacheMetrics:
    cache_hits: int = 0
    cache_misses: int = 0
    tokens_cached: int = 0
    cost_savings: float = 0.0

    def record_hit(self, tokens: int):
        self.cache_hits += 1
        self.tokens_cached += tokens
        self.cost_savings += tokens * 0.003 / 1000  # $3/M tokens

# After 1 week, expect:
# - Cache hit rate: 80-90%
# - Cost reduction: 50-70%
# - Latency reduction: 30-40%
```

---

### 1.3: Semantic Deduplication
**Effort**: 6 hours | **Impact**: 20-40% reduction | **Priority**: P0

**Implementation**:
```python
# src/services/semantic_cache_service.py
class SemanticCache:
    def __init__(
        self,
        embedding_service: EmbeddingService,
        similarity_threshold: float = 0.92,
        ttl: int = 3600
    ):
        self.embedding_service = embedding_service
        self.threshold = similarity_threshold
        self.cache = []  # [(query_emb, response, timestamp)]
        self.ttl = ttl

    async def get_or_execute(
        self,
        query: str,
        execute_fn: Callable,
        force_refresh: bool = False
    ) -> str:
        if force_refresh:
            return await self._execute_and_cache(query, execute_fn)

        query_emb = await self.embedding_service.embed(query)

        now = datetime.now()
        for cached_emb, cached_response, timestamp in self.cache:
            if now - timestamp > timedelta(seconds=self.ttl):
                continue

            similarity = self._cosine_similarity(query_emb, cached_emb)
            if similarity >= self.threshold:
                logger.info(
                    f"Semantic cache HIT (similarity: {similarity:.3f})",
                    extra={"query": query}
                )
                return cached_response

        return await self._execute_and_cache(query, execute_fn)

    async def _execute_and_cache(self, query: str, execute_fn: Callable) -> str:
        response = await execute_fn()
        query_emb = await self.embedding_service.embed(query)
        self.cache.append((query_emb, response, datetime.now()))
        self._evict_expired()
        return response

    def _cosine_similarity(self, emb1: List[float], emb2: List[float]) -> float:
        return np.dot(emb1, emb2) / (np.linalg.norm(emb1) * np.linalg.norm(emb2))

    def _evict_expired(self):
        now = datetime.now()
        self.cache = [
            (emb, resp, ts) for emb, resp, ts in self.cache
            if now - ts <= timedelta(seconds=self.ttl)
        ]
```

**Testing**:
```python
async def test_semantic_cache_detects_similar_queries():
    cache = SemanticCache(
        embedding_service=ollama_service,
        similarity_threshold=0.92
    )

    # First query
    result1 = await cache.get_or_execute(
        "How do I optimize database queries?",
        lambda: "Use indexes and query optimization..."
    )

    # Similar query (should hit cache)
    result2 = await cache.get_or_execute(
        "What's the best way to speed up database operations?",
        lambda: "This should NOT execute"
    )

    assert result1 == result2  # Cache hit
    assert cache.cache_hits == 1
```

**Metrics**:
- Cache hit rate (target: 30-50%)
- Token savings per hit (average: 1,500 tokens)
- Total savings (target: 20-40% reduction)

---

### Phase 1 Deliverables

**Code**:
- [ ] `src/services/context_optimization_service.py` (ToolResultClearer)
- [ ] `src/services/semantic_cache_service.py` (SemanticCache)
- [ ] `src/core/prompt_builder.py` (Cacheable prompt structure)
- [ ] `tests/unit/services/test_context_optimization.py` (15 tests)
- [ ] `tests/unit/services/test_semantic_cache.py` (12 tests)

**Documentation**:
- [ ] `docs/guides/CONTEXT_OPTIMIZATION_GUIDE.md`
- [ ] `docs/api/SEMANTIC_CACHE_API.md`

**Metrics Baseline**:
- [ ] Measure current token usage (7-day average)
- [ ] Measure current TSR (7-day average)
- [ ] Measure current cost (7-day total)

**Success Criteria**:
- ✅ 20-40% token reduction (measured)
- ✅ TSR ≥95% (no regression)
- ✅ All tests passing (27 tests)
- ✅ Documentation complete

---

## Phase 2: Core Infrastructure (Week 3-5, ~40 hours)

**Goal**: 80% baseline context reduction via progressive disclosure (Agent Skills)

### 2.1: Agent Skills Implementation
**Effort**: 24 hours | **Impact**: 87% baseline reduction | **Priority**: P0

**Step 1: Directory Structure Design** (2 hours)
```
.claude/skills/
  ├─ trinitas/
  │   ├─ athena/
  │   │   ├─ SKILL.md
  │   │   └─ coordination_patterns.md
  │   ├─ artemis/
  │   │   ├─ SKILL.md
  │   │   └─ optimization_techniques.md
  │   ├─ hestia/
  │   │   ├─ SKILL.md
  │   │   └─ security_playbooks.md
  │   ├─ eris/
  │   │   ├─ SKILL.md
  │   │   └─ tactical_coordination.md
  │   ├─ hera/
  │   │   ├─ SKILL.md
  │   │   └─ strategic_frameworks.md
  │   └─ muses/
  │       ├─ SKILL.md
  │       └─ documentation_templates.md
  ├─ security/
  │   ├─ SKILL.md
  │   ├─ incident_response.md
  │   └─ vulnerability_patterns.md
  ├─ tools/
  │   ├─ SKILL.md
  │   ├─ serena_guide.md
  │   ├─ playwright_guide.md
  │   └─ context7_guide.md
  └─ tmws/
      ├─ SKILL.md
      ├─ architecture.md
      ├─ migrations.md
      └─ performance_targets.md
```

**Step 2: CLAUDE.md Extraction** (8 hours)

**Current CLAUDE.md Structure** (11,000 tokens):
```markdown
# TMWS Project Knowledge Base (800 lines)
## Project Overview (200 lines)
## Core Technologies (100 lines)
## Critical Design Decisions (400 lines)
...

# Trinitas Integration (600 lines)
## Available AI Personas (500 lines)
- Athena (100 lines)
- Artemis (100 lines)
- Hestia (100 lines)
...

# Rules 1-11 (1,200 lines)
## Rule 1: 実測優先の原則 (150 lines)
## Rule 2: ベースライン測定の義務 (150 lines)
...
```

**Extraction Plan**:

1. **Trinitas Personas → skills/trinitas/***
   - Extract each persona to separate skill
   - Metadata: name, triggers, role
   - Core: communication style, decision patterns
   - Supplementary: specialized knowledge

2. **Security Rules → skills/security/SKILL.md**
   - Rule 11 (Project-specific security)
   - Extract incident playbooks to supplementary
   - Create reusable security patterns

3. **Tool Guidelines → skills/tools/SKILL.md**
   - Extract MCP tool usage patterns
   - Create tool-specific guides (serena, playwright, context7)

4. **TMWS Specifics → skills/tmws/SKILL.md**
   - Architecture summary (metadata)
   - Detailed architecture (supplementary)
   - Performance targets (supplementary)

**Step 3: Skill Metadata Schema** (2 hours)
```yaml
# skills/trinitas/athena/SKILL.md
---
name: "Athena - Harmonious Conductor"
category: "trinitas"
version: "2.4.0"
description: "Strategic coordination, workflow automation, parallel execution management"
triggers:
  - orchestration
  - workflow
  - coordination
  - parallel
  - harmony
  - "チーム調整"
access_level: "SYSTEM"
estimated_tokens:
  metadata: 80
  core: 1500
  supplementary: 2000
---

# Athena - Core Capabilities

## Communication Style
Athena communicates with warmth and encouragement...

## Decision Patterns
...

## Coordination Protocols
...
```

**Step 4: Skill Loader Service** (6 hours)
```python
# src/services/skill_loader_service.py
class SkillLoaderService:
    def __init__(
        self,
        embedding_service: EmbeddingService,
        cache_ttl: int = 900  # 15 min
    ):
        self.embedding_service = embedding_service
        self.cache = TTLCache(maxsize=100, ttl=cache_ttl)
        self.skill_catalog = {}  # skill_id → SkillMetadata

    async def initialize(self):
        """Load all skill metadata on startup"""
        skills_dir = Path(".claude/skills")
        for skill_path in skills_dir.rglob("SKILL.md"):
            metadata = await self._parse_skill_metadata(skill_path)
            self.skill_catalog[metadata.id] = metadata

            # Index for semantic search
            await self._index_skill(metadata)

        logger.info(f"Loaded {len(self.skill_catalog)} skills")

    async def discover_skills(
        self,
        task_description: str,
        top_k: int = 3
    ) -> List[SkillMetadata]:
        """Semantic search for relevant skills"""
        task_emb = await self.embedding_service.embed(task_description)

        # Semantic search in ChromaDB
        results = await vector_search_service.search(
            query_embedding=task_emb,
            collection="agent_skills",
            top_k=top_k
        )

        return [self.skill_catalog[r.id] for r in results]

    async def load_skill_core(self, skill_id: str) -> str:
        """Load Level 2 core documentation"""
        cache_key = f"skill_core:{skill_id}"

        if cache_key in self.cache:
            return self.cache[cache_key]

        skill_path = self._get_skill_path(skill_id)
        content = await self._read_skill_file(skill_path)

        # Cache for TTL period
        self.cache[cache_key] = content
        return content

    async def load_skill_resource(
        self,
        skill_id: str,
        resource_name: str
    ) -> str:
        """Load Level 3 supplementary resource"""
        cache_key = f"skill_resource:{skill_id}:{resource_name}"

        if cache_key in self.cache:
            return self.cache[cache_key]

        resource_path = self._get_resource_path(skill_id, resource_name)
        content = await self._read_skill_file(resource_path)

        self.cache[cache_key] = content
        return content
```

**Step 5: Integration with Prompt Builder** (4 hours)
```python
# src/core/prompt_builder.py
class PromptBuilder:
    def __init__(self, skill_loader: SkillLoaderService):
        self.skill_loader = skill_loader

    async def build_system_prompt(
        self,
        task_description: str,
        namespace: str,
        agent_id: str
    ) -> str:
        """Build optimized system prompt with progressive disclosure"""

        # Level 1: Metadata (preloaded, cacheable)
        skill_metadata = await self._build_skill_metadata_section()

        # Level 2: Discover and load relevant skills
        relevant_skills = await self.skill_loader.discover_skills(
            task_description,
            top_k=3
        )

        skill_cores = []
        for skill in relevant_skills:
            core = await self.skill_loader.load_skill_core(skill.id)
            skill_cores.append(core)

        # Build prompt
        return "\n\n".join([
            "<background_information>",
            "You are the TMWS Memory & Workflow System...",
            "</background_information>",
            "",
            "<agent_skills>",
            skill_metadata,  # All skill metadata (~1,050 tokens)
            "</agent_skills>",
            "",
            "<loaded_skills>",
            "\n\n".join(skill_cores),  # Relevant skills (~1,500-4,500 tokens)
            "</loaded_skills>",
            "",
            "<current_context>",
            f"Namespace: {namespace}",
            f"Agent: {agent_id}",
            f"Task: {task_description}",
            "</current_context>"
        ])

    async def _build_skill_metadata_section(self) -> str:
        """Build Level 1 metadata section (cacheable)"""
        metadata_lines = []

        for skill in self.skill_loader.skill_catalog.values():
            metadata_lines.append(
                f"- **{skill.name}** ({skill.category}): {skill.description}"
            )

        return "\n".join(metadata_lines)
```

**Step 6: Testing** (2 hours)
```python
# tests/unit/services/test_skill_loader.py
async def test_skill_loader_discovers_relevant_skills():
    loader = SkillLoaderService(ollama_embedding_service)
    await loader.initialize()

    # Task: Security audit
    skills = await loader.discover_skills(
        "Perform comprehensive security audit of authentication system",
        top_k=3
    )

    # Expect: Hestia persona + security skill
    skill_names = {s.name for s in skills}
    assert "Hestia - Security Guardian" in skill_names
    assert "Security" in skill_names

async def test_skill_loader_caches_loaded_content():
    loader = SkillLoaderService(ollama_embedding_service, cache_ttl=300)

    # First load (cache miss)
    start = time.perf_counter()
    content1 = await loader.load_skill_core("athena")
    duration1 = time.perf_counter() - start

    # Second load (cache hit)
    start = time.perf_counter()
    content2 = await loader.load_skill_core("athena")
    duration2 = time.perf_counter() - start

    assert content1 == content2
    assert duration2 < duration1 * 0.1  # Cache hit 10x faster
```

---

### 2.2: Lazy Loading Infrastructure
**Effort**: 8 hours | **Impact**: Enable on-demand skill loading | **Priority**: P0

**Database Schema**:
```sql
-- skills/trinitas/athena/SKILL.md → agent_skills table
CREATE TABLE agent_skills (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    category TEXT NOT NULL,  -- "trinitas", "security", "tools", "tmws"
    description TEXT NOT NULL,
    triggers TEXT[],  -- ["orchestration", "workflow", ...]
    version TEXT NOT NULL,
    access_level TEXT NOT NULL,  -- "PRIVATE", "TEAM", "SHARED", "PUBLIC", "SYSTEM"

    -- Paths
    skill_path TEXT NOT NULL,  -- ".claude/skills/trinitas/athena/SKILL.md"
    supplementary_resources TEXT[],  -- ["coordination_patterns.md"]

    -- Metadata
    estimated_tokens JSONB,  -- {"metadata": 80, "core": 1500, "supplementary": 2000}
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    -- Indexes
    INDEX idx_agent_skills_category (category),
    INDEX idx_agent_skills_access_level (access_level)
);

-- Skill usage tracking
CREATE TABLE skill_usage_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    skill_id UUID NOT NULL REFERENCES agent_skills(id),
    agent_id TEXT NOT NULL,
    task_type TEXT,

    loaded_at TIMESTAMP NOT NULL DEFAULT NOW(),
    resources_loaded TEXT[],  -- ["SKILL.md", "coordination_patterns.md"]

    execution_time_ms INT,
    success BOOLEAN,
    unexpected_trajectory BOOLEAN DEFAULT FALSE,  -- Red flag

    -- Indexes
    INDEX idx_skill_usage_skill_id (skill_id),
    INDEX idx_skill_usage_agent_id (agent_id),
    INDEX idx_skill_usage_loaded_at (loaded_at)
);
```

**MCP Resource URIs**:
```python
# MCP resource pattern for skills
class SkillMCPResource:
    @staticmethod
    def build_uri(skill_id: str, level: int, resource_name: str = None) -> str:
        """
        Build MCP resource URI for skill

        Examples:
        - Level 1: tmws://skills/athena/metadata
        - Level 2: tmws://skills/athena/core
        - Level 3: tmws://skills/athena/resource/coordination_patterns
        """
        base = f"tmws://skills/{skill_id}"

        if level == 1:
            return f"{base}/metadata"
        elif level == 2:
            return f"{base}/core"
        elif level == 3:
            return f"{base}/resource/{resource_name}"
        else:
            raise ValueError(f"Invalid level: {level}")

# MCP tool: list_skills
@mcp_server.tool()
async def list_skills(category: str = None) -> List[dict]:
    """List available agent skills"""
    query = db.query(AgentSkill)

    if category:
        query = query.filter(AgentSkill.category == category)

    skills = await query.all()

    return [
        {
            "id": str(skill.id),
            "name": skill.name,
            "category": skill.category,
            "description": skill.description,
            "triggers": skill.triggers,
            "uri": SkillMCPResource.build_uri(skill.id, level=1)
        }
        for skill in skills
    ]

# MCP tool: load_skill
@mcp_server.tool()
async def load_skill(
    skill_id: str,
    level: int,
    resource_name: str = None
) -> dict:
    """Load skill content at specified level"""
    if level == 1:
        # Return metadata only
        skill = await db.get(AgentSkill, skill_id)
        return {
            "name": skill.name,
            "description": skill.description,
            "triggers": skill.triggers,
            "estimated_tokens": skill.estimated_tokens
        }

    elif level == 2:
        # Load core documentation
        content = await skill_loader_service.load_skill_core(skill_id)
        return {"content": content}

    elif level == 3:
        # Load supplementary resource
        content = await skill_loader_service.load_skill_resource(
            skill_id,
            resource_name
        )
        return {"content": content}
```

---

### 2.3: Context Compaction Service
**Effort**: 8 hours | **Impact**: Handle long-running workflows | **Priority**: P1

**Implementation**:
```python
# src/services/context_compaction_service.py
class ContextCompactionService:
    def __init__(self, threshold_tokens: int = 150000):
        self.threshold = threshold_tokens

    async def should_compact(self, messages: List[Message]) -> bool:
        """Check if context window needs compaction"""
        total_tokens = sum(count_tokens(m.content) for m in messages)
        return total_tokens >= self.threshold

    async def compact(
        self,
        messages: List[Message],
        preserve: List[str] = None
    ) -> List[Message]:
        """
        Compact context window by summarizing old messages

        Preserves:
        - System prompt (messages[0])
        - Recent messages (last 10)
        - Critical information (architectural decisions, unresolved bugs, etc.)
        """
        if preserve is None:
            preserve = [
                "architectural_decisions",
                "unresolved_bugs",
                "implementation_details",
                "security_incidents"
            ]

        # Phase 1: Identify compactable messages
        system_prompt = messages[0]
        recent_messages = messages[-10:]
        compactable = messages[1:-10]

        # Phase 2: Extract critical info
        critical_info = await self._extract_critical_info(compactable, preserve)

        # Phase 3: Generate summary
        summary = await self._generate_summary(compactable, critical_info)

        # Phase 4: Rebuild context
        return [
            system_prompt,
            Message(
                role="assistant",
                content=f"[Context Compaction Summary]\n\n{summary}",
                metadata={"compacted_message_count": len(compactable)}
            ),
            *recent_messages
        ]

    async def _extract_critical_info(
        self,
        messages: List[Message],
        preserve: List[str]
    ) -> dict:
        """Extract information to preserve during compaction"""
        critical = {category: [] for category in preserve}

        for message in messages:
            # Pattern matching for critical information
            if "architectural decision" in message.content.lower():
                critical["architectural_decisions"].append(message.content)

            if any(term in message.content.lower() for term in ["bug", "error", "issue"]):
                if "fixed" not in message.content.lower():
                    critical["unresolved_bugs"].append(message.content)

            # ... more pattern matching

        return critical

    async def _generate_summary(
        self,
        messages: List[Message],
        critical_info: dict
    ) -> str:
        """Generate compact summary preserving critical information"""
        summary_parts = []

        # Critical information (verbatim)
        for category, items in critical_info.items():
            if items:
                summary_parts.append(f"## {category.replace('_', ' ').title()}")
                summary_parts.extend(f"- {item}" for item in items)
                summary_parts.append("")

        # General summary (condensed)
        message_content = "\n\n".join(m.content for m in messages)
        condensed = await self._condense_text(message_content, max_tokens=2000)
        summary_parts.append("## General Context")
        summary_parts.append(condensed)

        return "\n".join(summary_parts)

    async def _condense_text(self, text: str, max_tokens: int) -> str:
        """Use LLM to condense text while preserving meaning"""
        # Use Claude to summarize
        prompt = f"""
        Condense the following text to approximately {max_tokens} tokens
        while preserving all critical information:

        {text}
        """

        # ... LLM call for summarization
```

**Testing**:
```python
async def test_context_compaction_preserves_critical_info():
    compactor = ContextCompactionService(threshold_tokens=150000)

    messages = [
        Message(role="system", content="System prompt"),
        Message(role="user", content="Implement feature X"),
        Message(role="assistant", content="Architectural decision: Using microservices"),
        Message(role="tool", content="[Large tool result: 10,000 tokens]"),
        Message(role="assistant", content="Bug detected: Memory leak in service Y"),
        # ... 100 more messages
        Message(role="user", content="Recent message 1"),
        Message(role="user", content="Recent message 2"),
    ]

    compacted = await compactor.compact(messages)

    # Verify preservation
    summary_content = compacted[1].content
    assert "microservices" in summary_content.lower()  # Architectural decision
    assert "memory leak" in summary_content.lower()  # Unresolved bug

    # Verify recent messages preserved
    assert compacted[-2].content == "Recent message 1"
    assert compacted[-1].content == "Recent message 2"

    # Verify token reduction
    original_tokens = sum(count_tokens(m.content) for m in messages)
    compacted_tokens = sum(count_tokens(m.content) for m in compacted)
    reduction = (original_tokens - compacted_tokens) / original_tokens

    assert reduction >= 0.40  # At least 40% reduction
```

---

### Phase 2 Deliverables

**Code**:
- [ ] `.claude/skills/` directory structure (10 skills, 30+ files)
- [ ] `src/services/skill_loader_service.py` (400+ lines)
- [ ] `src/services/context_compaction_service.py` (300+ lines)
- [ ] `src/core/prompt_builder.py` (updated, 200+ lines)
- [ ] `migrations/versions/YYYYMMDD_add_agent_skills_tables.py`
- [ ] `tests/unit/services/test_skill_loader.py` (20 tests)
- [ ] `tests/unit/services/test_context_compaction.py` (15 tests)

**Documentation**:
- [ ] `docs/guides/AGENT_SKILLS_GUIDE.md`
- [ ] `docs/api/SKILL_LOADER_API.md`
- [ ] `docs/architecture/PROGRESSIVE_DISCLOSURE_ARCHITECTURE.md`

**Metrics**:
- [ ] Baseline context: 11,000 → 1,300 tokens (88% reduction)
- [ ] Average total context: 17,500 → 4,000 tokens (77% reduction)
- [ ] Skill discovery latency: <10ms P95
- [ ] Skill load latency: <50ms P95
- [ ] TSR: ≥95% (maintained)

**Success Criteria**:
- ✅ 80% baseline context reduction (measured)
- ✅ TSR ≥95% (no regression)
- ✅ All tests passing (35 tests)
- ✅ Documentation complete
- ✅ Hestia security approval (skill validation workflow)

---

## Phase 3: Advanced Optimization (Week 6-8, ~32 hours)

**Goal**: Refine instructions and tools for maximum effectiveness

### 3.1: Right Altitude Instruction Refactoring
**Effort**: 16 hours | **Impact**: Improved flexibility | **Priority**: P1

### 3.2: Tool Result Optimization
**Effort**: 8 hours | **Impact**: 60-90% tool result reduction | **Priority**: P1

### 3.3: Effectiveness Metrics Dashboard
**Effort**: 8 hours | **Impact**: Data-driven optimization | **Priority**: P1

*(Detailed plans in individual analysis documents)*

---

## Success Metrics & Monitoring

### Key Performance Indicators (KPIs)

| Metric | Baseline | Phase 1 Target | Phase 2 Target | Phase 3 Target |
|--------|----------|----------------|----------------|----------------|
| **Baseline Context** | 11,000 tokens | 9,000 tokens | 1,300 tokens | 1,000 tokens |
| **Average Total Context** | 17,500 tokens | 13,000 tokens | 4,000 tokens | 3,000 tokens |
| **Task Success Rate (TSR)** | 94% | ≥95% | ≥95% | ≥95% |
| **Token Efficiency Ratio (TER)** | 0.15 | 0.20 | 0.40 | 0.50 |
| **Context Utilization (CUR)** | 25% | 35% | 50% | 55% |
| **Cost Efficiency (CE)** | 0.99 | 1.50 | 3.00 | 3.50 |
| **Skill Discovery Latency** | N/A | N/A | <10ms | <8ms |
| **Skill Load Latency** | N/A | N/A | <50ms | <40ms |

### Monitoring Dashboard

```sql
-- Daily metrics snapshot
SELECT
    DATE(recorded_at) as date,
    context_config,
    AVG(total_context_tokens) as avg_context_tokens,
    AVG(ter) as avg_ter,
    AVG(cur) as avg_cur,
    SUM(CASE WHEN task_success THEN 1 ELSE 0 END)::FLOAT / COUNT(*) as tsr,
    COUNT(*) as request_count
FROM context_metrics
WHERE recorded_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(recorded_at), context_config
ORDER BY date DESC, context_config;
```

**Alerting**:
- TSR drops below 95% → HIGH alert (rollback consideration)
- CUR drops below 30% → MEDIUM alert (context bloat)
- Skill load latency >100ms → LOW alert (caching issue)

---

## Risk Management

### Identified Risks

1. **TSR Regression** (HIGH)
   - **Risk**: Context optimization degrades task success rate
   - **Mitigation**: Incremental deployment, A/B testing, rollback plan
   - **Monitoring**: Real-time TSR tracking, alert at <95%

2. **Skill Discovery Latency** (MEDIUM)
   - **Risk**: Semantic search adds unacceptable latency
   - **Mitigation**: Caching, index optimization, hybrid approach
   - **Monitoring**: P95 latency tracking, alert at >50ms

3. **Implementation Complexity** (MEDIUM)
   - **Risk**: Phase 2 infrastructure is complex, high bug risk
   - **Mitigation**: Comprehensive testing (35+ tests), code review
   - **Monitoring**: Test coverage ≥90%, Hestia security approval

4. **Skill Catalog Maintenance** (LOW)
   - **Risk**: Skills become stale, require ongoing updates
   - **Mitigation**: Quarterly skill review, usage analytics
   - **Monitoring**: Skill usage heatmap, identify underused skills

### Rollback Plan

**Phase 1 Rollback**:
```python
# Feature flag: disable optimizations
ENABLE_TOOL_RESULT_CLEARING = False
ENABLE_SEMANTIC_CACHE = False
ENABLE_PROMPT_CACHING = True  # Safe to keep

# Immediate rollback (< 5 min)
# No data migration needed
```

**Phase 2 Rollback**:
```python
# Feature flag: revert to monolithic CLAUDE.md
ENABLE_PROGRESSIVE_DISCLOSURE = False

# Fallback to Phase 1 optimizations
# Database rollback: DROP TABLE agent_skills, skill_usage_metrics
# Restore .claude/CLAUDE.md from backup
```

**Phase 3 Rollback**:
```python
# Feature flag: disable advanced optimizations
ENABLE_RIGHT_ALTITUDE_INSTRUCTIONS = False
ENABLE_TOOL_RESULT_OPTIMIZATION = False

# Fallback to Phase 2 infrastructure
# No database changes needed
```

---

## Team Coordination

### Trinitas Agent Responsibilities

**Athena (Harmonious Conductor)**:
- Overall phase coordination
- Cross-team communication
- User reporting and updates

**Hera (Strategic Commander)**:
- Phase planning and prioritization
- Risk assessment and mitigation
- Resource allocation decisions

**Artemis (Technical Perfectionist)**:
- Implementation (all phases)
- Performance optimization
- Code review and quality assurance

**Hestia (Security Guardian)**:
- Skill validation workflow (Phase 2)
- Security impact assessment
- Final approval for Phase 2 deployment

**Eris (Tactical Coordinator)**:
- Sprint planning (week-by-week)
- Bottleneck identification
- Team workload balancing

**Muses (Knowledge Architect)**:
- Documentation (all phases)
- Skill content extraction (Phase 2)
- Metrics dashboard design (Phase 3)

---

## Timeline Summary

**Week 1-2**: Phase 1 (Quick Wins)
- Tool result clearing
- Prompt caching
- Semantic deduplication
- **Expected**: 20-40% context reduction

**Week 3-5**: Phase 2 (Core Infrastructure)
- Agent Skills implementation
- Lazy loading infrastructure
- Context compaction service
- **Expected**: 80% baseline reduction

**Week 6-8**: Phase 3 (Advanced Optimization)
- Right altitude instruction refactoring
- Tool result optimization
- Effectiveness metrics dashboard
- **Expected**: 85% total reduction, 3.5x cost efficiency

**Total Duration**: 8 weeks (56 hours of implementation)

---

## Conclusion

This roadmap synthesizes Anthropic's Agent Skills pattern and Context Engineering techniques into a concrete, phased implementation plan for TMWS Phase 4. By following this plan, we expect:

- **88% baseline context reduction** (11,000 → 1,300 tokens)
- **77% average total context reduction** (17,500 → 4,000 tokens)
- **340% cost efficiency improvement** (0.99 → 3.39 success/M tokens)
- **Maintained quality** (TSR ≥95%, no regression)

The three-phase approach balances quick wins (Phase 1), structural transformation (Phase 2), and continuous refinement (Phase 3), ensuring measurable progress every 2 weeks while minimizing risk through incremental deployment.

---

**Document Status**: Planning v1.0
**Next Steps**:
1. **Strategic Review** (Athena, Hera): Validate phase priorities and timeline
2. **Security Assessment** (Hestia): Review skill validation workflow (Phase 2)
3. **Technical Feasibility** (Artemis): Validate implementation estimates
4. **Documentation Planning** (Muses): Create documentation templates

---

*"Through progressive disclosure and relentless optimization, we transform context scarcity into precision. Every token serves a purpose, every skill loads with intention."*

— Muses, Knowledge Architect
