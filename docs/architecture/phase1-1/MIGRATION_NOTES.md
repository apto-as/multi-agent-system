# Phase 1-1 Database Migration Notes

**Created**: 2025-11-12
**Migration**: Phase 1-1 (MCP Connections Table)
**Database**: SQLite (TMWS v2.3.0+)
**Status**: ✅ Tested and Verified

---

## Table of Contents

1. [Migration Overview](#migration-overview)
2. [Schema Changes](#schema-changes)
3. [Migration File](#migration-file)
4. [Applying Migration](#applying-migration)
5. [Rollback Procedure](#rollback-procedure)
6. [Verification](#verification)
7. [Troubleshooting](#troubleshooting)

---

## Migration Overview

**Migration ID**: `ff4b1a18d2f0`
**Migration File**: `migrations/versions/20251112_1330-ff4b1a18d2f0_phase_1_1_add_mcp_connections_table.py`
**Parent Revision**: Previous migration (check `alembic current`)

### Purpose

Add `mcp_connections` table to support MCP (Model Context Protocol) Integration Layer. This table stores connection metadata and discovered tools for MCP servers.

### Impact

- **Database Size**: +1 table, minimal size increase
- **Performance**: No impact on existing tables
- **Downtime**: None required (new table only)
- **Data Loss Risk**: None (additive change)

---

## Schema Changes

### New Table: `mcp_connections`

**Purpose**: Store MCPConnection aggregate data

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | String(36) | PRIMARY KEY | UUID of connection |
| `server_name` | String(255) | NOT NULL | MCP server identifier |
| `namespace` | String(255) | NOT NULL, INDEX | Namespace for multi-tenant isolation |
| `agent_id` | String(255) | NOT NULL | Agent owner ID |
| `status` | String(50) | NOT NULL, DEFAULT 'disconnected' | Connection status enum |
| `config_json` | JSONB | NOT NULL | ConnectionConfig as JSON |
| `tools_json` | JSONB | NOT NULL, DEFAULT '[]' | List of Tool entities as JSON |
| `error_message` | Text | NULL | Error description if status=ERROR |
| `error_at` | DateTime | NULL | Timestamp of error occurrence |
| `created_at` | DateTime | NOT NULL | Creation timestamp (UTC) |
| `connected_at` | DateTime | NULL | Timestamp when became ACTIVE |
| `disconnected_at` | DateTime | NULL | Timestamp when disconnected |
| `updated_at` | DateTime | NULL | Last update timestamp (auto-update) |

### Indexes

1. **`ix_mcp_connections_namespace`** (Single-column)
   - Column: `namespace`
   - Purpose: Fast filtering by namespace
   - Query: `SELECT * FROM mcp_connections WHERE namespace = ?`

2. **`ix_mcp_connections_namespace_agent`** (Composite)
   - Columns: `namespace`, `agent_id`
   - Purpose: Security queries (namespace + ownership verification)
   - Query: `SELECT * FROM mcp_connections WHERE namespace = ? AND agent_id = ?`

### JSON Column Schemas

#### config_json Format

```json
{
  "server_name": "tmws_mcp",
  "url": "http://localhost:8080/mcp",
  "timeout": 30,
  "retry_attempts": 3,
  "auth_required": false,
  "api_key": null
}
```

#### tools_json Format

```json
[
  {
    "name": "store_memory",
    "description": "Store semantic memory",
    "input_schema": {
      "type": "object",
      "properties": {
        "content": {"type": "string"},
        "importance": {"type": "number"}
      }
    },
    "category": "memory"
  },
  {
    "name": "search_memories",
    "description": "Search semantic memories",
    "input_schema": {...},
    "category": "memory"
  }
]
```

---

## Migration File

**Location**: `migrations/versions/20251112_1330-ff4b1a18d2f0_phase_1_1_add_mcp_connections_table.py`

### Key Operations

#### Upgrade (Apply Migration)

```python
def upgrade():
    """Add mcp_connections table."""
    op.create_table(
        'mcp_connections',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('server_name', sa.String(length=255), nullable=False),
        sa.Column('namespace', sa.String(length=255), nullable=False),
        sa.Column('agent_id', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='disconnected'),
        sa.Column('config_json', sa.JSON(), nullable=False),
        sa.Column('tools_json', sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('error_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('connected_at', sa.DateTime(), nullable=True),
        sa.Column('disconnected_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True, onupdate=sa.func.now()),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes
    op.create_index('ix_mcp_connections_namespace', 'mcp_connections', ['namespace'])
    op.create_index('ix_mcp_connections_namespace_agent', 'mcp_connections', ['namespace', 'agent_id'])
```

#### Downgrade (Rollback Migration)

```python
def downgrade():
    """Remove mcp_connections table."""
    op.drop_index('ix_mcp_connections_namespace_agent', table_name='mcp_connections')
    op.drop_index('ix_mcp_connections_namespace', table_name='mcp_connections')
    op.drop_table('mcp_connections')
```

---

## Applying Migration

### Prerequisites

1. **Alembic Installed**
   ```bash
   pip install alembic
   # Or with uv:
   uv sync --all-extras
   ```

2. **Database Connection String Configured**
   ```bash
   # .env file
   TMWS_DATABASE_URL="sqlite+aiosqlite:///./data/tmws.db"
   ```

3. **Backup Current Database** (Recommended)
   ```bash
   cp data/tmws.db data/tmws.db.backup-$(date +%Y%m%d_%H%M%S)
   ```

### Step-by-Step Procedure

#### 1. Check Current Migration Status

```bash
cd /Users/apto-as/workspace/github.com/apto-as/tmws

# Check current version
alembic current

# Example output:
# INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
# INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
# (head) -> <previous_migration_id>
```

#### 2. Review Pending Migrations

```bash
# Show migration history
alembic history

# Show pending migrations
alembic heads
```

#### 3. Apply Migration

```bash
# Upgrade to latest version
alembic upgrade head

# Expected output:
# INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
# INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
# INFO  [alembic.runtime.migration] Running upgrade <previous_id> -> ff4b1a18d2f0, phase_1_1_add_mcp_connections_table
```

#### 4. Verify Migration Applied

```bash
# Check current version (should show ff4b1a18d2f0)
alembic current

# Verify table exists
sqlite3 data/tmws.db "SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_connections';"

# Expected output:
# mcp_connections
```

#### 5. Verify Indexes Created

```bash
# Check indexes
sqlite3 data/tmws.db "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='mcp_connections';"

# Expected output:
# ix_mcp_connections_namespace|CREATE INDEX ix_mcp_connections_namespace ON mcp_connections (namespace)
# ix_mcp_connections_namespace_agent|CREATE INDEX ix_mcp_connections_namespace_agent ON mcp_connections (namespace, agent_id)
```

---

## Rollback Procedure

### When to Rollback

- Migration failed partially
- Unexpected errors after migration
- Need to revert for testing

### Rollback Steps

#### 1. Backup Current Database

```bash
cp data/tmws.db data/tmws.db.backup-before-rollback-$(date +%Y%m%d_%H%M%S)
```

#### 2. Rollback One Version

```bash
# Downgrade to previous version
alembic downgrade -1

# Expected output:
# INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
# INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
# INFO  [alembic.runtime.migration] Running downgrade ff4b1a18d2f0 -> <previous_id>, phase_1_1_add_mcp_connections_table
```

#### 3. Verify Rollback

```bash
# Check current version (should NOT show ff4b1a18d2f0)
alembic current

# Verify table removed
sqlite3 data/tmws.db "SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_connections';"

# Expected output: (empty - no results)
```

#### 4. Re-apply if Needed

```bash
# If rollback was for testing, re-apply:
alembic upgrade head
```

---

## Verification

### Automated Test

```bash
# Run repository tests
pytest tests/unit/infrastructure/test_mcp_connection_repository_impl.py -v

# Expected: 14/14 tests PASSED
```

### Manual Verification

#### 1. Insert Test Record

```python
from sqlalchemy import create_engine, text
from datetime import datetime

# Connect to database
engine = create_engine("sqlite:///./data/tmws.db")

# Insert test connection
with engine.connect() as conn:
    conn.execute(text("""
        INSERT INTO mcp_connections (
            id, server_name, namespace, agent_id, status,
            config_json, tools_json, created_at
        ) VALUES (
            'test-uuid-123',
            'test_server',
            'test-namespace',
            'test-agent',
            'disconnected',
            '{"server_name": "test_server", "url": "http://localhost:8080", "timeout": 30, "retry_attempts": 3, "auth_required": false, "api_key": null}',
            '[]',
            :created_at
        )
    """), {"created_at": datetime.utcnow()})
    conn.commit()

print("Test record inserted successfully")
```

#### 2. Query Test Record

```python
# Query test connection
with engine.connect() as conn:
    result = conn.execute(text("""
        SELECT * FROM mcp_connections WHERE id = 'test-uuid-123'
    """))

    row = result.fetchone()
    print(f"Server Name: {row[1]}")  # test_server
    print(f"Namespace: {row[2]}")    # test-namespace
    print(f"Agent ID: {row[3]}")     # test-agent
    print(f"Status: {row[4]}")       # disconnected
```

#### 3. Test Indexes

```python
# Test namespace index
with engine.connect() as conn:
    result = conn.execute(text("""
        EXPLAIN QUERY PLAN
        SELECT * FROM mcp_connections WHERE namespace = 'test-namespace'
    """))

    for row in result:
        print(row)
        # Should show: SEARCH mcp_connections USING INDEX ix_mcp_connections_namespace

# Test composite index
with engine.connect() as conn:
    result = conn.execute(text("""
        EXPLAIN QUERY PLAN
        SELECT * FROM mcp_connections WHERE namespace = 'test-namespace' AND agent_id = 'test-agent'
    """))

    for row in result:
        print(row)
        # Should show: SEARCH mcp_connections USING INDEX ix_mcp_connections_namespace_agent
```

#### 4. Clean Up Test Data

```python
# Delete test record
with engine.connect() as conn:
    conn.execute(text("DELETE FROM mcp_connections WHERE id = 'test-uuid-123'"))
    conn.commit()

print("Test record deleted")
```

---

## Troubleshooting

### Issue 1: Migration Already Applied

**Error**:
```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) table mcp_connections already exists
```

**Solution**:
```bash
# Check current version
alembic current

# If migration already applied, you're done
# If version is wrong, stamp the correct version:
alembic stamp ff4b1a18d2f0
```

---

### Issue 2: Database Locked

**Error**:
```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) database is locked
```

**Solution**:
```bash
# Close all connections to database
# Kill any running Python processes:
pkill -f "python.*tmws"

# Wait a moment, then retry:
alembic upgrade head
```

---

### Issue 3: JSON Column Not Supported (Old SQLite)

**Error**:
```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) no such column type: JSON
```

**Solution**:

SQLite 3.9.0+ supports JSON. Check version:

```bash
sqlite3 --version

# If < 3.9.0, upgrade SQLite:
# macOS:
brew upgrade sqlite3

# Ubuntu/Debian:
sudo apt-get update && sudo apt-get upgrade sqlite3
```

---

### Issue 4: Permission Denied

**Error**:
```
PermissionError: [Errno 13] Permission denied: './data/tmws.db'
```

**Solution**:
```bash
# Create data directory if missing:
mkdir -p data

# Fix permissions:
chmod 755 data
chmod 644 data/tmws.db  # If file exists
```

---

### Issue 5: Downgrade Fails

**Error**:
```
alembic.util.exc.CommandError: Can't locate revision identified by 'ff4b1a18d2f0'
```

**Solution**:

Check migration history:

```bash
# Show all migrations
alembic history

# Manually specify target:
alembic downgrade <previous_migration_id>

# If corrupted, re-stamp:
alembic stamp head
```

---

## Best Practices

### Before Migration

1. ✅ **Backup Database**
   ```bash
   cp data/tmws.db data/tmws.db.backup-$(date +%Y%m%d_%H%M%S)
   ```

2. ✅ **Review Migration File**
   ```bash
   cat migrations/versions/20251112_1330-ff4b1a18d2f0_phase_1_1_add_mcp_connections_table.py
   ```

3. ✅ **Test in Development First**
   ```bash
   # Copy production DB to dev:
   cp data/tmws.db data/tmws-dev.db

   # Test migration:
   TMWS_DATABASE_URL="sqlite:///./data/tmws-dev.db" alembic upgrade head
   ```

### After Migration

1. ✅ **Run Tests**
   ```bash
   pytest tests/unit/infrastructure/test_mcp_connection_repository_impl.py -v
   ```

2. ✅ **Verify Indexes**
   ```bash
   sqlite3 data/tmws.db "PRAGMA index_list('mcp_connections');"
   ```

3. ✅ **Check Performance**
   ```python
   # Test index usage:
   from sqlalchemy import create_engine, text
   engine = create_engine("sqlite:///./data/tmws.db")

   with engine.connect() as conn:
       result = conn.execute(text("EXPLAIN QUERY PLAN SELECT * FROM mcp_connections WHERE namespace = ?"), ("test",))
       print(result.fetchall())
       # Should show index usage
   ```

---

## Migration Checklist

### Pre-Migration

- [ ] Database backed up
- [ ] Migration file reviewed
- [ ] Current version checked (`alembic current`)
- [ ] Test environment prepared

### Migration Execution

- [ ] Migration applied (`alembic upgrade head`)
- [ ] Current version verified (`alembic current`)
- [ ] Table created verified (SQLite query)
- [ ] Indexes created verified (SQLite query)

### Post-Migration

- [ ] Automated tests passed
- [ ] Manual verification completed
- [ ] Performance verified (index usage)
- [ ] Documentation updated

### Rollback Plan

- [ ] Rollback procedure tested in dev
- [ ] Backup strategy confirmed
- [ ] Downgrade command known (`alembic downgrade -1`)

---

## Related Documentation

- **Implementation Guide**: `docs/architecture/phase1-1/IMPLEMENTATION_GUIDE.md`
- **Security Compliance**: `docs/architecture/phase1-1/SECURITY_COMPLIANCE.md`
- **API Specification**: `docs/architecture/phase1-1/API_SPECIFICATION.md`
- **Alembic Documentation**: https://alembic.sqlalchemy.org/

---

## Migration History

| Version | Date | Description | Author |
|---------|------|-------------|--------|
| `ff4b1a18d2f0` | 2025-11-12 | Add mcp_connections table (Phase 1-1) | Artemis |

---

**End of Migration Notes**

*Last Updated: 2025-11-12*
*Status: Production-Ready*
*Next Migration: Phase 1-2 (Application Service Layer)*
