-- ==============================================
-- TMWS Database Initialization Script
-- PostgreSQL with pgvector extension setup
-- ==============================================

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Create additional extensions for advanced functionality
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create database user with appropriate permissions (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'tmws_user') THEN
        CREATE ROLE tmws_user WITH LOGIN PASSWORD 'tmws_dev_password';
    END IF;
END
$$;

-- Grant necessary permissions
GRANT CONNECT ON DATABASE tmws_dev TO tmws_user;
GRANT USAGE ON SCHEMA public TO tmws_user;
GRANT CREATE ON SCHEMA public TO tmws_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tmws_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO tmws_user;

-- Configure PostgreSQL for optimal performance
-- These settings are for development; adjust for production
ALTER SYSTEM SET shared_preload_libraries = 'vector';
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;

-- Reload configuration
SELECT pg_reload_conf();