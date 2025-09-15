-- ============================================
-- TMWS Database Initialization Script v2.2.0
--
-- Run this script as postgres superuser:
-- psql -U postgres -f init_database.sql
-- ============================================

-- Configuration variables
\set db_name 'tmws'
\set db_user 'tmws_user'
\set db_password 'tmws_password'
\set db_encoding 'UTF8'

-- Terminate existing connections
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = :'db_name'
  AND pid <> pg_backend_pid();

-- Drop database if exists (be careful!)
DROP DATABASE IF EXISTS :db_name;

-- Drop user if exists
DROP USER IF EXISTS :db_user;

-- Create user
CREATE USER :db_user WITH
    PASSWORD :'db_password'
    CREATEDB
    NOSUPERUSER
    NOCREATEROLE
    NOINHERIT
    LOGIN
    NOREPLICATION
    NOBYPASSRLS
    CONNECTION LIMIT 100;

-- Create database
CREATE DATABASE :db_name
    WITH
    OWNER = :db_user
    ENCODING = :'db_encoding'
    LC_COLLATE = 'C'
    LC_CTYPE = 'C'
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE :db_name TO :db_user;

-- Connect to the new database
\c :db_name

-- Create extensions (as superuser)
CREATE EXTENSION IF NOT EXISTS vector SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pgcrypto SCHEMA public;
CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA public;

-- For production: pg_stat_statements for monitoring
CREATE EXTENSION IF NOT EXISTS pg_stat_statements SCHEMA public;

-- Grant extension usage to user
GRANT USAGE ON SCHEMA public TO :db_user;
GRANT CREATE ON SCHEMA public TO :db_user;
GRANT ALL ON ALL TABLES IN SCHEMA public TO :db_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO :db_user;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO :db_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON TABLES TO :db_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON SEQUENCES TO :db_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON FUNCTIONS TO :db_user;

-- Create custom types if needed
DO $$
BEGIN
    -- Task status enum
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'task_status') THEN
        CREATE TYPE task_status AS ENUM (
            'pending',
            'in_progress',
            'completed',
            'failed',
            'cancelled'
        );
    END IF;

    -- Task priority enum
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'task_priority') THEN
        CREATE TYPE task_priority AS ENUM (
            'low',
            'medium',
            'high',
            'urgent'
        );
    END IF;

    -- Workflow status enum
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'workflow_status') THEN
        CREATE TYPE workflow_status AS ENUM (
            'pending',
            'running',
            'completed',
            'failed',
            'cancelled'
        );
    END IF;

    -- User role enum
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        CREATE TYPE user_role AS ENUM (
            'user',
            'admin',
            'service'
        );
    END IF;

    -- User status enum
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_status') THEN
        CREATE TYPE user_status AS ENUM (
            'active',
            'inactive',
            'locked',
            'deleted'
        );
    END IF;
END$$;

-- Optimize database settings for vector operations
ALTER DATABASE :db_name SET max_parallel_workers_per_gather = 4;
ALTER DATABASE :db_name SET max_parallel_workers = 8;
ALTER DATABASE :db_name SET max_parallel_maintenance_workers = 4;

-- Memory settings (adjust based on available RAM)
ALTER DATABASE :db_name SET shared_buffers = '256MB';
ALTER DATABASE :db_name SET effective_cache_size = '1GB';
ALTER DATABASE :db_name SET maintenance_work_mem = '128MB';
ALTER DATABASE :db_name SET work_mem = '4MB';

-- SSD optimizations
ALTER DATABASE :db_name SET random_page_cost = 1.1;
ALTER DATABASE :db_name SET effective_io_concurrency = 200;

-- Disable JIT for better connection times
ALTER DATABASE :db_name SET jit = off;

-- Enable partitioning optimizations
ALTER DATABASE :db_name SET enable_partitionwise_aggregate = on;
ALTER DATABASE :db_name SET enable_partitionwise_join = on;

-- Set statement timeout for production (30 seconds)
ALTER DATABASE :db_name SET statement_timeout = '30s';

-- Set lock timeout (5 seconds)
ALTER DATABASE :db_name SET lock_timeout = '5s';

-- Set idle in transaction timeout (5 minutes)
ALTER DATABASE :db_name SET idle_in_transaction_session_timeout = '5min';

-- Log slow queries (> 1 second)
ALTER DATABASE :db_name SET log_min_duration_statement = '1000';

-- Create performance monitoring views
CREATE OR REPLACE VIEW database_stats AS
SELECT
    datname AS database_name,
    numbackends AS active_connections,
    xact_commit AS transactions_committed,
    xact_rollback AS transactions_rolled_back,
    blks_read AS blocks_read,
    blks_hit AS blocks_hit,
    tup_returned AS rows_returned,
    tup_fetched AS rows_fetched,
    tup_inserted AS rows_inserted,
    tup_updated AS rows_updated,
    tup_deleted AS rows_deleted,
    CASE
        WHEN blks_read + blks_hit > 0
        THEN ROUND(100.0 * blks_hit / (blks_read + blks_hit), 2)
        ELSE 0
    END AS cache_hit_ratio
FROM pg_stat_database
WHERE datname = current_database();

-- Create index usage statistics view
CREATE OR REPLACE VIEW index_usage_stats AS
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan AS index_scans,
    idx_tup_read AS index_rows_read,
    idx_tup_fetch AS index_rows_fetched,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;

-- Create table size view
CREATE OR REPLACE VIEW table_sizes AS
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) AS table_size,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) AS indexes_size
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Create function to analyze query performance
CREATE OR REPLACE FUNCTION analyze_query_performance(query_text TEXT)
RETURNS TABLE(
    plan_line TEXT
) AS $$
BEGIN
    RETURN QUERY
    EXECUTE 'EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) ' || query_text;
END;
$$ LANGUAGE plpgsql;

-- Grant execute permission to user
GRANT EXECUTE ON FUNCTION analyze_query_performance(TEXT) TO :db_user;

-- Output setup confirmation
\echo ''
\echo '======================================'
\echo '   TMWS Database Initialized!'
\echo '======================================'
\echo ''
\echo 'Database: ':db_name
\echo 'User: ':db_user
\echo ''
\echo 'Enabled Extensions:'
\echo '  - vector (for embeddings)'
\echo '  - pgcrypto (for encryption)'
\echo '  - pg_trgm (for text search)'
\echo '  - uuid-ossp (for UUIDs)'
\echo '  - pg_stat_statements (for monitoring)'
\echo ''
\echo 'Performance Views Created:'
\echo '  - database_stats'
\echo '  - index_usage_stats'
\echo '  - table_sizes'
\echo ''
\echo 'Next Steps:'
\echo '  1. Run Alembic migrations'
\echo '  2. Create initial data'
\echo '  3. Set up regular backups'
\echo ''