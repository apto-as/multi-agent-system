-- TMWS Phase 2E-2: Tool Discovery Database Schema
-- Architecture: Hierarchical with denormalization for performance
-- Target: 50-100+ MCP servers, <50ms P95 query latency

-- ============================================================================
-- MCP Server Registry (Parent)
-- ============================================================================
CREATE TABLE mcp_servers (
    id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    server_name VARCHAR(255) UNIQUE NOT NULL,  -- e.g., "serena-mcp-server"
    display_name VARCHAR(255) NOT NULL,        -- e.g., "Serena Code Analyzer"
    category VARCHAR(100) NOT NULL,            -- Primary category for browsing
    description TEXT NOT NULL,

    -- Docker configuration
    docker_image VARCHAR(500) NOT NULL,        -- e.g., "ghcr.io/serena-mcp:latest"
    network_mode VARCHAR(50) DEFAULT 'none',   -- Security: none/bridge/host

    -- Status tracking
    is_active BOOLEAN DEFAULT TRUE,
    is_builtin BOOLEAN DEFAULT FALSE,          -- vs user-added custom servers
    registration_source VARCHAR(50) DEFAULT 'builtin',  -- builtin/user/auto-discovered

    -- Usage analytics (denormalized for performance)
    total_invocations INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    avg_latency_ms DECIMAL(8,2) DEFAULT 0,     -- Denormalized from mcp_tool_metrics

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by_agent_id UUID REFERENCES agents(id),  -- NULL for builtin

    -- Full-text search optimization
    search_vector TEXT GENERATED ALWAYS AS (
        server_name || ' ' || display_name || ' ' || description
    ) STORED
);

-- Index for category browsing (restaurant menu navigation)
CREATE INDEX idx_mcp_servers_category_active ON mcp_servers(category, is_active)
    WHERE is_active = TRUE;

-- Index for popularity-based discovery
CREATE INDEX idx_mcp_servers_hot ON mcp_servers(total_invocations DESC, avg_latency_ms ASC)
    WHERE is_active = TRUE;

-- Full-text search index
CREATE INDEX idx_mcp_servers_search ON mcp_servers USING GIN(to_tsvector('english', search_vector));

-- ============================================================================
-- MCP Tools Registry (Child)
-- ============================================================================
CREATE TABLE mcp_tools (
    id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    server_id UUID NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,

    -- Tool identification
    tool_name VARCHAR(255) NOT NULL,           -- e.g., "find_symbol"
    display_name VARCHAR(255) NOT NULL,        -- e.g., "Find Code Symbol"
    description TEXT NOT NULL,

    -- Categorization (multiple tags for hybrid search)
    primary_category VARCHAR(100) NOT NULL,    -- Same as server category
    tags TEXT[] DEFAULT '{}',                  -- Additional tags for discovery
    use_cases TEXT[] DEFAULT '{}',             -- User-intent keywords

    -- Parameter schema (JSONB for flexibility)
    parameters_schema JSONB NOT NULL,          -- Full MCP tool schema

    -- Usage analytics (denormalized)
    total_invocations INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    avg_latency_ms DECIMAL(8,2) DEFAULT 0,

    -- Popularity tier (for progressive disclosure)
    tier VARCHAR(20) DEFAULT 'standard',       -- hot/warm/standard/cold
    tier_score DECIMAL(5,2) DEFAULT 0,         -- Computed score for tier assignment

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Full-text search optimization
    search_vector TEXT GENERATED ALWAYS AS (
        tool_name || ' ' || display_name || ' ' || description || ' ' ||
        array_to_string(tags, ' ') || ' ' || array_to_string(use_cases, ' ')
    ) STORED,

    -- Unique constraint: tool name must be unique within server
    UNIQUE(server_id, tool_name)
);

-- Index for hierarchical browsing (server -> tools)
CREATE INDEX idx_mcp_tools_server ON mcp_tools(server_id, tier);

-- Index for category-based discovery
CREATE INDEX idx_mcp_tools_category ON mcp_tools(primary_category, tier);

-- Index for popularity-based progressive disclosure
CREATE INDEX idx_mcp_tools_tier ON mcp_tools(tier, tier_score DESC);

-- Index for tag-based search
CREATE INDEX idx_mcp_tools_tags ON mcp_tools USING GIN(tags);

-- Full-text search index
CREATE INDEX idx_mcp_tools_search ON mcp_tools USING GIN(to_tsvector('english', search_vector));

-- ============================================================================
-- Tool Metrics (Time-Series Performance Data)
-- ============================================================================
CREATE TABLE mcp_tool_metrics (
    id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    tool_id UUID NOT NULL REFERENCES mcp_tools(id) ON DELETE CASCADE,

    -- Invocation details
    invoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    invoked_by_agent_id UUID REFERENCES agents(id),

    -- Performance metrics
    latency_ms INTEGER NOT NULL,
    success BOOLEAN NOT NULL,
    error_type VARCHAR(100),                   -- NULL if success=TRUE

    -- Context
    namespace VARCHAR(255),                    -- For multi-tenant analytics

    -- Indexing for time-series queries
    CONSTRAINT idx_metrics_time_series CHECK (invoked_at IS NOT NULL)
);

-- Partitioning by month for efficient time-series queries (PostgreSQL)
-- SQLite: Use separate tables if dataset grows beyond 10M rows
CREATE INDEX idx_mcp_tool_metrics_tool_time ON mcp_tool_metrics(tool_id, invoked_at DESC);

-- Index for agent-specific analytics
CREATE INDEX idx_mcp_tool_metrics_agent ON mcp_tool_metrics(invoked_by_agent_id, invoked_at DESC);

-- ============================================================================
-- Tool Categories (Hierarchical Menu Structure)
-- ============================================================================
CREATE TABLE mcp_categories (
    id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    category_name VARCHAR(100) UNIQUE NOT NULL,  -- e.g., "code_analysis"
    display_name VARCHAR(255) NOT NULL,           -- e.g., "Code Analysis & Refactoring"
    parent_category_id UUID REFERENCES mcp_categories(id),  -- NULL for root

    -- Menu presentation
    icon VARCHAR(50),                            -- Emoji or icon identifier
    description TEXT,
    sort_order INTEGER DEFAULT 0,               -- For menu ordering

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for hierarchical queries (parent -> children)
CREATE INDEX idx_mcp_categories_parent ON mcp_categories(parent_category_id, sort_order);

-- ============================================================================
-- Vector Embeddings (Semantic Search)
-- ============================================================================
-- NOTE: ChromaDB will store embeddings externally
-- This table tracks which tools have embeddings for validation
CREATE TABLE mcp_tool_embeddings (
    id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    tool_id UUID NOT NULL UNIQUE REFERENCES mcp_tools(id) ON DELETE CASCADE,

    -- ChromaDB reference
    chroma_collection_id VARCHAR(255) NOT NULL,  -- "mcp_tools"
    chroma_document_id VARCHAR(255) NOT NULL,    -- UUID as string

    -- Embedding metadata
    embedding_model VARCHAR(100) DEFAULT 'multilingual-e5-large',
    embedding_dimensions INTEGER DEFAULT 1024,

    -- Timestamp for cache invalidation
    embedded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    needs_reindex BOOLEAN DEFAULT FALSE,         -- Set TRUE when tool description changes

    UNIQUE(chroma_collection_id, chroma_document_id)
);

-- Index for reindexing batch jobs
CREATE INDEX idx_mcp_tool_embeddings_reindex ON mcp_tool_embeddings(needs_reindex)
    WHERE needs_reindex = TRUE;

-- ============================================================================
-- Custom MCP Server Allowlist (Security)
-- ============================================================================
CREATE TABLE mcp_server_allowlist (
    id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    docker_image_pattern VARCHAR(500) NOT NULL,  -- e.g., "ghcr.io/myorg/*"

    -- Security policy
    allowed_network_modes TEXT[] DEFAULT ARRAY['none'],  -- Whitelist
    max_memory_mb INTEGER DEFAULT 512,
    max_cpu_shares INTEGER DEFAULT 1024,

    -- Approval metadata
    approved_by_agent_id UUID REFERENCES agents(id),
    approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason TEXT,

    -- Status
    is_active BOOLEAN DEFAULT TRUE
);

-- Index for validation queries
CREATE INDEX idx_mcp_server_allowlist_active ON mcp_server_allowlist(is_active)
    WHERE is_active = TRUE;

-- ============================================================================
-- View: Hot Tools (Precomputed for Performance)
-- ============================================================================
CREATE VIEW v_mcp_hot_tools AS
SELECT
    t.id,
    t.tool_name,
    t.display_name,
    t.description,
    s.server_name,
    s.display_name AS server_display_name,
    t.tier,
    t.tier_score,
    t.total_invocations,
    t.success_count * 100.0 / NULLIF(t.total_invocations, 0) AS success_rate,
    t.avg_latency_ms
FROM mcp_tools t
JOIN mcp_servers s ON t.server_id = s.id
WHERE t.tier IN ('hot', 'warm')
  AND s.is_active = TRUE
ORDER BY t.tier_score DESC
LIMIT 20;  -- Top 20 tools for initial context

-- ============================================================================
-- Triggers: Auto-Update Denormalized Metrics
-- ============================================================================
-- SQLite: Use application-level updates
-- PostgreSQL: Use triggers for automatic denormalization

-- Example trigger (PostgreSQL):
-- CREATE OR REPLACE FUNCTION update_tool_metrics()
-- RETURNS TRIGGER AS $$
-- BEGIN
--     UPDATE mcp_tools
--     SET total_invocations = total_invocations + 1,
--         success_count = success_count + (CASE WHEN NEW.success THEN 1 ELSE 0 END),
--         error_count = error_count + (CASE WHEN NOT NEW.success THEN 1 ELSE 0 END),
--         avg_latency_ms = (
--             SELECT AVG(latency_ms)
--             FROM mcp_tool_metrics
--             WHERE tool_id = NEW.tool_id
--               AND invoked_at > NOW() - INTERVAL '7 days'
--         )
--     WHERE id = NEW.tool_id;
--     RETURN NEW;
-- END;
-- $$ LANGUAGE plpgsql;

-- CREATE TRIGGER trg_update_tool_metrics
-- AFTER INSERT ON mcp_tool_metrics
-- FOR EACH ROW
-- EXECUTE FUNCTION update_tool_metrics();

-- ============================================================================
-- Comments
-- ============================================================================
COMMENT ON TABLE mcp_servers IS 'MCP server registry with denormalized analytics';
COMMENT ON TABLE mcp_tools IS 'Individual tools exposed by MCP servers';
COMMENT ON TABLE mcp_tool_metrics IS 'Time-series performance metrics for tools';
COMMENT ON TABLE mcp_categories IS 'Hierarchical category structure for tool browsing';
COMMENT ON TABLE mcp_tool_embeddings IS 'ChromaDB vector embedding references';
COMMENT ON TABLE mcp_server_allowlist IS 'Security whitelist for custom MCP servers';
