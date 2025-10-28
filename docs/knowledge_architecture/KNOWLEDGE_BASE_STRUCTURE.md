# TMWS Knowledge Base Structure
## Hierarchical Organization for Trinitas Institutional Memory

**Version**: 1.0.0
**Created**: 2025-10-27
**Author**: Muses (Knowledge Architect)

---

## Directory Structure

```
knowledge_base/
├── README.md                          # Overview and navigation guide
├── metadata_schema.json               # JSON Schema for metadata validation
├── tagging_taxonomy.yaml              # Complete tag hierarchy
│
├── strategic/                         # Athena & Hera domain
│   ├── decisions/
│   │   ├── architecture/
│   │   │   ├── database_migration_v2.2.6.json
│   │   │   ├── async_architecture_design.json
│   │   │   └── dual_storage_rationale.json
│   │   ├── technology_selection/
│   │   │   ├── sqlite_vs_postgresql.json
│   │   │   ├── chromadb_selection.json
│   │   │   └── embedding_model_choice.json
│   │   └── roadmap/
│   │       ├── v2.3.0_planning.json
│   │       ├── v3.0_vision.json
│   │       └── deprecation_strategy.json
│   │
│   ├── planning/
│   │   ├── capacity_planning/
│   │   ├── resource_allocation/
│   │   └── risk_assessment/
│   │
│   └── architecture/
│       ├── system_design/
│       ├── integration_patterns/
│       └── scalability_plans/
│
├── technical/                         # Artemis domain
│   ├── implementations/
│   │   ├── async_patterns/
│   │   │   ├── vector_search_async_conversion.json
│   │   │   ├── event_loop_best_practices.json
│   │   │   └── asyncio_to_thread_pattern.json
│   │   ├── database/
│   │   │   ├── index_optimization.json
│   │   │   ├── query_performance.json
│   │   │   └── migration_patterns.json
│   │   └── api/
│   │       ├── endpoint_design.json
│   │       ├── error_handling.json
│   │       └── request_validation.json
│   │
│   ├── optimizations/
│   │   ├── performance/
│   │   │   ├── latency_improvements.json
│   │   │   ├── throughput_optimization.json
│   │   │   └── caching_strategies.json
│   │   ├── memory/
│   │   │   ├── memory_profiling.json
│   │   │   └── leak_prevention.json
│   │   └── database/
│   │       ├── index_analysis_results.json
│   │       ├── duplicate_index_removal.json
│   │       └── query_optimization.json
│   │
│   └── patterns/
│       ├── design_patterns/
│       │   ├── factory_pattern.json
│       │   ├── singleton_pattern.json
│       │   └── observer_pattern.json
│       ├── anti_patterns/
│       │   ├── god_class_detection.json
│       │   └── circular_dependencies.json
│       └── best_practices/
│           ├── exception_handling.json
│           ├── async_await_guidelines.json
│           └── type_annotations.json
│
├── security/                          # Hestia domain
│   ├── findings/
│   │   ├── vulnerabilities/
│   │   │   ├── namespace_isolation_fix_p0-1.json
│   │   │   ├── jwt_validation_issues.json
│   │   │   └── sql_injection_analysis.json
│   │   ├── audits/
│   │   │   ├── 2025_Q4_security_audit.json
│   │   │   ├── dependency_vulnerabilities.json
│   │   │   └── access_control_review.json
│   │   └── incidents/
│   │       ├── cross_namespace_access_attempt.json
│   │       └── brute_force_detection.json
│   │
│   ├── best_practices/
│   │   ├── authentication/
│   │   │   ├── jwt_best_practices.json
│   │   │   ├── password_hashing.json
│   │   │   └── multi_factor_auth.json
│   │   ├── authorization/
│   │   │   ├── rbac_implementation.json
│   │   │   ├── namespace_isolation.json
│   │   │   └── access_level_design.json
│   │   └── encryption/
│   │       ├── data_at_rest.json
│   │       ├── data_in_transit.json
│   │       └── key_management.json
│   │
│   └── compliance/
│       ├── gdpr_requirements.json
│       ├── security_standards.json
│       └── audit_logging.json
│
├── coordination/                      # Eris domain
│   ├── workflows/
│   │   ├── development_workflow.json
│   │   ├── review_process.json
│   │   ├── deployment_pipeline.json
│   │   └── incident_response.json
│   │
│   ├── decisions/
│   │   ├── consensus_building/
│   │   ├── conflict_resolution/
│   │   └── priority_negotiation/
│   │
│   └── handoffs/
│       ├── persona_collaboration/
│       │   ├── athena_to_artemis_handoff.json
│       │   ├── hestia_to_eris_escalation.json
│       │   └── muses_documentation_requests.json
│       └── team_transitions/
│           ├── onboarding_process.json
│           └── knowledge_transfer.json
│
├── documentation/                     # Muses domain
│   ├── guides/
│   │   ├── user_guides/
│   │   │   ├── getting_started.json
│   │   │   ├── api_usage.json
│   │   │   └── troubleshooting.json
│   │   ├── developer_guides/
│   │   │   ├── development_setup.json
│   │   │   ├── contributing.json
│   │   │   └── coding_standards.json
│   │   └── operational_guides/
│   │       ├── deployment.json
│   │       ├── monitoring.json
│   │       └── backup_recovery.json
│   │
│   ├── references/
│   │   ├── api_reference/
│   │   ├── configuration_reference/
│   │   └── cli_reference/
│   │
│   └── lessons_learned/
│       ├── failures/
│       │   ├── postgres_to_sqlite_initial_attempt.json
│       │   ├── async_conversion_mistakes.json
│       │   └── security_oversight_analysis.json
│       ├── successes/
│       │   ├── performance_optimization_wins.json
│       │   ├── security_hardening_success.json
│       │   └── clean_migration_strategy.json
│       └── insights/
│           ├── team_collaboration_patterns.json
│           ├── tool_selection_wisdom.json
│           └── technical_debt_management.json
│
└── cross_cutting/                     # All personas
    ├── releases/
    │   ├── v2.2.6/
    │   │   ├── release_notes.json
    │   │   ├── migration_guide.json
    │   │   └── breaking_changes.json
    │   ├── v2.3.0/
    │   │   ├── ollama_only_migration.json
    │   │   ├── dependency_cleanup.json
    │   │   └── performance_improvements.json
    │   └── v3.0_planning/
    │       └── future_roadmap.json
    │
    ├── patterns/
    │   ├── recurring_issues/
    │   ├── successful_strategies/
    │   └── anti_patterns_to_avoid/
    │
    └── metrics/
        ├── performance_benchmarks/
        ├── quality_metrics/
        └── usage_statistics/
```

---

## Navigation Guidelines

### By Persona

**Athena** (Harmonious Conductor):
```
knowledge_base/strategic/decisions/
knowledge_base/coordination/workflows/
knowledge_base/cross_cutting/releases/
```

**Artemis** (Technical Perfectionist):
```
knowledge_base/technical/implementations/
knowledge_base/technical/optimizations/
knowledge_base/technical/patterns/
```

**Hestia** (Security Guardian):
```
knowledge_base/security/findings/
knowledge_base/security/best_practices/
knowledge_base/security/compliance/
```

**Eris** (Tactical Coordinator):
```
knowledge_base/coordination/workflows/
knowledge_base/coordination/handoffs/
knowledge_base/coordination/decisions/
```

**Hera** (Strategic Commander):
```
knowledge_base/strategic/planning/
knowledge_base/strategic/architecture/
knowledge_base/cross_cutting/releases/
```

**Muses** (Knowledge Architect):
```
knowledge_base/documentation/guides/
knowledge_base/documentation/references/
knowledge_base/documentation/lessons_learned/
```

### By Task Type

**Planning a new feature**:
1. `strategic/planning/` - Check roadmap and priorities
2. `technical/patterns/` - Review design patterns
3. `security/best_practices/` - Security requirements
4. `documentation/guides/developer_guides/` - Development standards

**Debugging an issue**:
1. `documentation/lessons_learned/failures/` - Similar past issues
2. `technical/implementations/` - Related implementations
3. `security/findings/` - Security-related bugs
4. `coordination/workflows/incident_response.json` - Escalation process

**Performance optimization**:
1. `technical/optimizations/performance/` - Past optimizations
2. `cross_cutting/metrics/performance_benchmarks/` - Target metrics
3. `documentation/lessons_learned/successes/performance_optimization_wins.json`

**Security audit**:
1. `security/findings/audits/` - Past audit results
2. `security/best_practices/` - Standards to check against
3. `technical/implementations/` - Code to review
4. `documentation/guides/operational_guides/` - Security procedures

### By Domain

**Database**:
```
technical/implementations/database/
technical/optimizations/database/
strategic/decisions/technology_selection/sqlite_vs_postgresql.json
```

**API**:
```
technical/implementations/api/
documentation/references/api_reference/
security/best_practices/authentication/
```

**Performance**:
```
technical/optimizations/performance/
cross_cutting/metrics/performance_benchmarks/
documentation/lessons_learned/successes/performance_optimization_wins.json
```

---

## File Naming Conventions

### Format
```
{category}_{topic}_{outcome}_{date}.json

Examples:
- decision_database_migration_success_2025-10-24.json
- implementation_async_vector_search_success_2025-10-27.json
- vulnerability_namespace_isolation_critical_2025-10-27.json
- lesson_learned_postgres_migration_failure_2025-10-15.json
```

### Rules
1. **Lowercase with underscores**: `database_migration` not `DatabaseMigration`
2. **Descriptive names**: `async_vector_search_conversion` not `fix_123`
3. **Include outcome**: `_success`, `_partial`, `_failure`, `_blocked`
4. **Date suffix**: `_YYYY-MM-DD` for temporal context
5. **JSON extension**: All memories are `.json` format

---

## Metadata Requirements

Every knowledge base file MUST include:

1. **Header comment** (first lines of JSON):
```json
{
  "_comment": "TMWS Knowledge Base Entry",
  "_version": "1.0.0",
  "_created": "2025-10-27T11:34:00Z",
  "_last_updated": "2025-10-27T12:00:00Z",
  "_author": "artemis",
  ...
}
```

2. **Full metadata schema** (see `metadata_schema.json`)
3. **At least 3 tags** from the taxonomy
4. **Validation status** (verified/unverified/needs_review)
5. **Related memories** (if any)

---

## Search Optimization

### Directory-Level Indexes

Each directory contains an `_index.json` with:
```json
{
  "directory": "technical/optimizations/performance/",
  "total_entries": 47,
  "last_updated": "2025-10-27T12:00:00Z",
  "top_tags": [
    "artemis.performance.optimization.success",
    "artemis.caching.implementation.success"
  ],
  "recent_entries": [
    "async_vector_search_conversion_success_2025-10-27.json",
    "index_optimization_success_2025-10-27.json"
  ],
  "most_accessed": [
    "caching_strategies_success_2025-09-15.json",
    "latency_improvements_success_2025-08-20.json"
  ]
}
```

### Tag-Based Cross-References

`cross_cutting/tag_index/` contains:
```
tag_index/
├── athena_tags.json          # All Athena-tagged memories
├── artemis_tags.json         # All Artemis-tagged memories
├── hestia_tags.json          # All Hestia-tagged memories
├── performance_tags.json     # All performance-related
├── security_tags.json        # All security-related
└── best_practices_tags.json  # All best practices
```

---

## Maintenance Procedures

### Weekly (Automated)
- Update directory-level `_index.json` files
- Regenerate tag-based cross-references
- Calculate usage statistics
- Identify outdated memories (>6 months old)

### Monthly (Muses review)
- Archive deprecated memories
- Consolidate duplicate knowledge
- Promote important patterns to best practices
- Update taxonomy based on new patterns

### Quarterly (All personas)
- Comprehensive knowledge base audit
- Validate all "verified" memories
- Update importance scores
- Refactor organizational structure if needed

---

## Integration with TMWS

### Automatic Memory Creation

When a Trinitas persona stores a memory via TMWS API:
1. Memory is created in SQLite (metadata)
2. Embedding is stored in ChromaDB (vector)
3. **Knowledge base file** is automatically generated in appropriate directory
4. Directory `_index.json` is updated
5. Tag-based cross-references are updated

### Query Patterns

```python
# Example: Search for Artemis performance optimizations
results = memory_service.search_memories(
    query="async performance improvement",
    namespace="engineering",
    tags=["artemis.performance.optimization.success"],
    min_similarity=0.7,
    limit=10
)

# Knowledge base integration
for memory in results:
    kb_path = knowledge_base.get_file_path(memory.id)
    full_metadata = knowledge_base.load_entry(kb_path)
    # Access rich metadata, relationships, validation history
```

---

This structure ensures:
- ✅ Easy navigation by persona, domain, or task type
- ✅ Scalable to thousands of memories
- ✅ Fast search via ChromaDB + directory indexes
- ✅ Comprehensive metadata for every entry
- ✅ Automated maintenance and cross-referencing
- ✅ Integration with TMWS memory system

---

*"知識は構造化されて初めて知恵となる"*
*"Knowledge becomes wisdom only when structured."*

— Muses, Knowledge Architect
