# Phase 4: Tool Discovery Schema Design
## Database Architecture for Tool Management System

**Document Version**: 1.0.0
**Date**: 2025-11-22
**Author**: Hera (Strategic Commander)
**Status**: Strategic Planning - Day 1
**Review Required**: Artemis (Performance), Hestia (Security)

---

## 1. Executive Summary

### 1.1 Strategic Rationale

The Tool Discovery Schema is the **persistent knowledge layer** for TMWS's dynamic tool ecosystem. This SQLite-based schema stores discovered tools, their metadata, verification history, and dependency graphs.

**Strategic Objectives**:
1. **Fast Queries**: <20ms P95 for tool lookups by ID, category, source
2. **Integrity**: Foreign key constraints ensure referential integrity
3. **Auditability**: Complete history of tool discovery and verification
4. **Scalability**: Support 50-100 tools initially, designed for 500+ tools
5. **Integration**: Seamless integration with Phase 2A/2B (Verification-Trust system)

**Design Principles**:
- **Normalization**: 3NF (Third Normal Form) to minimize redundancy
- **Indexing Strategy**: Covering indexes for hot paths
- **Soft Deletes**: is_active flag for historical tracking
- **JSON Metadata**: Flexible extension without schema changes

### 1.2 Success Criteria

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| Tool Lookup (by ID) | < 5ms P95 | < 10ms P95 |
| Tool Search (by category) | < 15ms P95 | < 30ms P95 |
| Discovery Insert | < 10ms P95 | < 20ms P95 |
| Migration Time | < 5s | < 10s |
| Database Size (100 tools) | < 10MB | < 50MB |

---

## 2. Architecture Overview

### 2.1 Entity-Relationship Diagram (ERD)

```
┌─────────────────────────────────────────────────────────────────┐
│                    discovered_tools                             │
├─────────────────────────────────────────────────────────────────┤
│ PK │ id                UUID                                     │
│    │ tool_id           VARCHAR(255) UNIQUE NOT NULL             │
│    │ name              VARCHAR(255) NOT NULL                    │
│    │ category          VARCHAR(50) NOT NULL                     │
│    │ source_path       TEXT NOT NULL                            │
│    │ version           VARCHAR(50)                              │
│    │ metadata          JSON                                     │
│    │ checksum          VARCHAR(64) NOT NULL (SHA256)            │
│    │ discovered_at     TIMESTAMP NOT NULL DEFAULT CURRENT       │
│    │ last_verified_at  TIMESTAMP                                │
│    │ is_active         BOOLEAN NOT NULL DEFAULT TRUE            │
│    │ created_at        TIMESTAMP NOT NULL DEFAULT CURRENT       │
│    │ updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT       │
└────┬────────────────────────────────────────────────────────────┘
     │
     │ 1:N
     │
┌────▼────────────────────────────────────────────────────────────┐
│                    tool_dependencies                            │
├─────────────────────────────────────────────────────────────────┤
│ PK │ id                UUID                                     │
│ FK │ tool_id           UUID NOT NULL → discovered_tools.id     │
│ FK │ dependency_id     UUID NOT NULL → discovered_tools.id     │
│    │ dependency_type   VARCHAR(50) NOT NULL (requires/optional)│
│    │ version_constraint VARCHAR(100) (e.g., ">=1.0.0")         │
│    │ created_at        TIMESTAMP NOT NULL DEFAULT CURRENT       │
└────┬────────────────────────────────────────────────────────────┘
     │
     │
┌────▼────────────────────────────────────────────────────────────┐
│                    tool_instances                               │
├─────────────────────────────────────────────────────────────────┤
│ PK │ id                UUID                                     │
│ FK │ tool_id           UUID NOT NULL → discovered_tools.id     │
│    │ container_id      VARCHAR(255) (Docker container ID)      │
│    │ status            VARCHAR(50) NOT NULL (running/stopped)  │
│    │ started_at        TIMESTAMP                                │
│    │ stopped_at        TIMESTAMP                                │
│    │ exit_code         INTEGER                                  │
│    │ resource_usage    JSON (CPU, memory, etc.)                │
│    │ created_at        TIMESTAMP NOT NULL DEFAULT CURRENT       │
│    │ updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT       │
└────┬────────────────────────────────────────────────────────────┘
     │
     │
┌────▼────────────────────────────────────────────────────────────┐
│                    tool_verification_history                    │
├─────────────────────────────────────────────────────────────────┤
│ PK │ id                UUID                                     │
│ FK │ tool_id           UUID NOT NULL → discovered_tools.id     │
│ FK │ verification_id   UUID → verifications.id (Phase 2A)      │
│    │ verified_by       VARCHAR(255) (agent_id)                 │
│    │ verification_result VARCHAR(50) (passed/failed/error)     │
│    │ checksum_verified VARCHAR(64) (SHA256 at verification)    │
│    │ notes             TEXT                                     │
│    │ verified_at       TIMESTAMP NOT NULL DEFAULT CURRENT       │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Design Patterns

**Pattern 1: Soft Deletes**
- `is_active` flag instead of DELETE operations
- Historical data preserved for auditing
- Queries default to `WHERE is_active = TRUE`

**Pattern 2: JSON Metadata**
- Flexible schema for tool-specific data
- Examples: {"image": "playwright:1.0", "ports": [9222], "capabilities": ["browser"]}
- SQLite JSON functions for querying (json_extract)

**Pattern 3: Timestamp Tracking**
- `created_at`: Record creation time (immutable)
- `updated_at`: Last modification time (auto-updated)
- `discovered_at`: Tool first discovered (business logic)
- `last_verified_at`: Last successful verification

**Pattern 4: Foreign Key Cascades**
- `ON DELETE CASCADE`: Deleting tool deletes dependencies/instances
- `ON UPDATE CASCADE`: Tool ID changes propagate

---

## 3. Detailed Schema Design

### 3.1 `discovered_tools` Table

**Purpose**: Core table storing all discovered tools

```sql
CREATE TABLE discovered_tools (
    -- Primary Key
    id UUID PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),

    -- Business Identifiers
    tool_id VARCHAR(255) UNIQUE NOT NULL,  -- e.g., "playwright-mcp"
    name VARCHAR(255) NOT NULL,            -- e.g., "Playwright MCP Server"
    category VARCHAR(50) NOT NULL,         -- e.g., "mcp", "cli", "docker"

    -- Source Information
    source_path TEXT NOT NULL,             -- Filesystem path to tool
    version VARCHAR(50),                   -- e.g., "1.0.0"

    -- Metadata
    metadata JSON,                         -- Flexible tool-specific data
    checksum VARCHAR(64) NOT NULL,         -- SHA256 hash of tool file

    -- Discovery Tracking
    discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_verified_at TIMESTAMP,            -- Last whitelist verification

    -- Lifecycle
    is_active BOOLEAN NOT NULL DEFAULT TRUE,  -- Soft delete flag

    -- Audit Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_discovered_tools_tool_id ON discovered_tools(tool_id);
CREATE INDEX idx_discovered_tools_category_active ON discovered_tools(category, is_active);
CREATE INDEX idx_discovered_tools_checksum ON discovered_tools(checksum);
CREATE INDEX idx_discovered_tools_source_path ON discovered_tools(source_path);
CREATE INDEX idx_discovered_tools_discovered_at ON discovered_tools(discovered_at DESC);

-- Trigger: Auto-update updated_at
CREATE TRIGGER update_discovered_tools_updated_at
    AFTER UPDATE ON discovered_tools
    FOR EACH ROW
BEGIN
    UPDATE discovered_tools SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
```

**Index Strategy Justification**:

| Index | Use Case | Cardinality | Selectivity |
|-------|----------|-------------|-------------|
| `idx_discovered_tools_tool_id` | Lookup by tool_id (primary access) | High (1:1) | Excellent |
| `idx_discovered_tools_category_active` | Filter by category + active status | Medium (10-20 per category) | Good |
| `idx_discovered_tools_checksum` | Verify tool integrity | High (1:1) | Excellent |
| `idx_discovered_tools_source_path` | Rescan detection | High (1:1) | Excellent |
| `idx_discovered_tools_discovered_at` | Chronological queries (DESC) | High | Good |

**Estimated Row Size**: ~500 bytes (including JSON metadata)
**Estimated Size (100 tools)**: 100 × 500 bytes = 50KB

### 3.2 `tool_dependencies` Table

**Purpose**: Track dependencies between tools

```sql
CREATE TABLE tool_dependencies (
    -- Primary Key
    id UUID PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),

    -- Foreign Keys
    tool_id UUID NOT NULL,
    dependency_id UUID NOT NULL,

    -- Dependency Details
    dependency_type VARCHAR(50) NOT NULL,  -- "requires", "optional", "conflicts"
    version_constraint VARCHAR(100),       -- e.g., ">=1.0.0,<2.0.0"

    -- Audit
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Foreign Key Constraints
    FOREIGN KEY (tool_id) REFERENCES discovered_tools(id) ON DELETE CASCADE,
    FOREIGN KEY (dependency_id) REFERENCES discovered_tools(id) ON DELETE CASCADE,

    -- Unique Constraint: One dependency relationship per tool pair
    UNIQUE(tool_id, dependency_id)
);

-- Indexes
CREATE INDEX idx_tool_dependencies_tool_id ON tool_dependencies(tool_id);
CREATE INDEX idx_tool_dependencies_dependency_id ON tool_dependencies(dependency_id);
```

**Example Data**:
```json
{
    "tool_id": "tool-a-uuid",
    "dependency_id": "tool-b-uuid",
    "dependency_type": "requires",
    "version_constraint": ">=2.0.0"
}
```

**Query Example** (Get all dependencies of a tool):
```sql
SELECT dt2.tool_id, dt2.name, td.dependency_type, td.version_constraint
FROM tool_dependencies td
JOIN discovered_tools dt2 ON td.dependency_id = dt2.id
WHERE td.tool_id = 'tool-a-uuid' AND dt2.is_active = TRUE;
```

**Estimated Row Size**: ~200 bytes
**Estimated Size (100 tools, avg 2 deps each)**: 200 × 200 = 40KB

### 3.3 `tool_instances` Table

**Purpose**: Track running tool containers

```sql
CREATE TABLE tool_instances (
    -- Primary Key
    id UUID PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),

    -- Foreign Key
    tool_id UUID NOT NULL,

    -- Container Information
    container_id VARCHAR(255),             -- Docker container ID
    status VARCHAR(50) NOT NULL,           -- "starting", "running", "stopping", "stopped", "failed"

    -- Lifecycle
    started_at TIMESTAMP,
    stopped_at TIMESTAMP,
    exit_code INTEGER,

    -- Resource Tracking
    resource_usage JSON,                   -- {"cpu_percent": 5.2, "memory_mb": 128, ...}

    -- Audit
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Foreign Key Constraint
    FOREIGN KEY (tool_id) REFERENCES discovered_tools(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_tool_instances_tool_id ON tool_instances(tool_id);
CREATE INDEX idx_tool_instances_container_id ON tool_instances(container_id);
CREATE INDEX idx_tool_instances_status ON tool_instances(status);
CREATE INDEX idx_tool_instances_started_at ON tool_instances(started_at DESC);

-- Trigger: Auto-update updated_at
CREATE TRIGGER update_tool_instances_updated_at
    AFTER UPDATE ON tool_instances
    FOR EACH ROW
BEGIN
    UPDATE tool_instances SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
```

**Status Lifecycle**:
```
starting → running → stopping → stopped
         ↘ failed
```

**Example resource_usage JSON**:
```json
{
    "cpu_percent": 5.2,
    "memory_mb": 128,
    "network_rx_bytes": 1024000,
    "network_tx_bytes": 512000,
    "block_read_bytes": 2048000,
    "block_write_bytes": 1024000,
    "pids_count": 12
}
```

**Query Example** (Get all running instances):
```sql
SELECT ti.id, ti.container_id, dt.name, ti.started_at,
       json_extract(ti.resource_usage, '$.memory_mb') as memory_mb
FROM tool_instances ti
JOIN discovered_tools dt ON ti.tool_id = dt.id
WHERE ti.status = 'running'
ORDER BY ti.started_at DESC;
```

**Estimated Row Size**: ~400 bytes (including JSON)
**Estimated Size (20 concurrent instances)**: 400 × 20 = 8KB

### 3.4 `tool_verification_history` Table

**Purpose**: Audit trail of tool verification events (integrates with Phase 2A)

```sql
CREATE TABLE tool_verification_history (
    -- Primary Key
    id UUID PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),

    -- Foreign Keys
    tool_id UUID NOT NULL,
    verification_id UUID,                  -- Links to verifications table (Phase 2A)

    -- Verification Details
    verified_by VARCHAR(255),              -- agent_id who performed verification
    verification_result VARCHAR(50) NOT NULL,  -- "passed", "failed", "error"
    checksum_verified VARCHAR(64),         -- SHA256 at time of verification
    notes TEXT,                            -- Verification notes/errors

    -- Timestamp
    verified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Foreign Key Constraint
    FOREIGN KEY (tool_id) REFERENCES discovered_tools(id) ON DELETE CASCADE,
    FOREIGN KEY (verification_id) REFERENCES verifications(id) ON DELETE SET NULL
);

-- Indexes
CREATE INDEX idx_tool_verification_history_tool_id ON tool_verification_history(tool_id);
CREATE INDEX idx_tool_verification_history_verified_at ON tool_verification_history(verified_at DESC);
CREATE INDEX idx_tool_verification_history_result ON tool_verification_history(verification_result);
```

**Example Data**:
```json
{
    "tool_id": "tool-a-uuid",
    "verification_id": "verif-123-uuid",
    "verified_by": "hestia-auditor",
    "verification_result": "passed",
    "checksum_verified": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "notes": "Whitelist verification successful. Checksum matches approved version 1.0.0.",
    "verified_at": "2025-11-22T10:30:00Z"
}
```

**Query Example** (Get verification history for a tool):
```sql
SELECT tvh.verified_at, tvh.verified_by, tvh.verification_result, tvh.notes
FROM tool_verification_history tvh
WHERE tvh.tool_id = 'tool-a-uuid'
ORDER BY tvh.verified_at DESC
LIMIT 10;
```

**Estimated Row Size**: ~300 bytes
**Estimated Size (100 tools, 5 verifications each)**: 300 × 500 = 150KB

---

## 4. SQLAlchemy Model Definitions

### 4.1 `DiscoveredTool` Model

```python
# src/models/discovered_tool.py
from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID, uuid4
from sqlalchemy import (
    Boolean, Column, DateTime, String, Text,
    Index, text
)
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship
from src.core.database import Base

class DiscoveredTool(Base):
    """
    Represents a tool discovered by the Orchestrator Service.

    This model stores metadata about external tools (MCP servers, CLI tools, etc.)
    that have been discovered and validated for use in TMWS.
    """
    __tablename__ = "discovered_tools"

    # Primary Key
    id: UUID = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
        comment="Unique tool record ID"
    )

    # Business Identifiers
    tool_id: str = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique tool identifier (e.g., 'playwright-mcp')"
    )
    name: str = Column(
        String(255),
        nullable=False,
        comment="Human-readable tool name"
    )
    category: str = Column(
        String(50),
        nullable=False,
        index=True,
        comment="Tool category: 'mcp', 'cli', 'docker'"
    )

    # Source Information
    source_path: str = Column(
        Text,
        nullable=False,
        index=True,
        comment="Filesystem path to tool definition"
    )
    version: Optional[str] = Column(
        String(50),
        nullable=True,
        comment="Tool version (semver)"
    )

    # Metadata
    metadata: Dict[str, Any] = Column(
        JSON,
        nullable=True,
        comment="Tool-specific metadata (JSON)"
    )
    checksum: str = Column(
        String(64),
        nullable=False,
        index=True,
        comment="SHA256 checksum of tool file"
    )

    # Discovery Tracking
    discovered_at: datetime = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        index=True,
        comment="When tool was first discovered"
    )
    last_verified_at: Optional[datetime] = Column(
        DateTime,
        nullable=True,
        comment="Last whitelist verification timestamp"
    )

    # Lifecycle
    is_active: bool = Column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Soft delete flag"
    )

    # Audit Timestamps
    created_at: datetime = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        comment="Record creation timestamp"
    )
    updated_at: datetime = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=datetime.utcnow,
        comment="Record last update timestamp"
    )

    # Relationships
    dependencies = relationship(
        "ToolDependency",
        foreign_keys="ToolDependency.tool_id",
        back_populates="tool",
        cascade="all, delete-orphan"
    )
    dependents = relationship(
        "ToolDependency",
        foreign_keys="ToolDependency.dependency_id",
        back_populates="dependency"
    )
    instances = relationship(
        "ToolInstance",
        back_populates="tool",
        cascade="all, delete-orphan"
    )
    verification_history = relationship(
        "ToolVerificationHistory",
        back_populates="tool",
        cascade="all, delete-orphan"
    )

    # Indexes (composite)
    __table_args__ = (
        Index("idx_discovered_tools_category_active", "category", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<DiscoveredTool(id={self.id}, tool_id='{self.tool_id}', "
            f"name='{self.name}', category='{self.category}', "
            f"version='{self.version}', is_active={self.is_active})>"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "id": str(self.id),
            "tool_id": self.tool_id,
            "name": self.name,
            "category": self.category,
            "source_path": self.source_path,
            "version": self.version,
            "metadata": self.metadata,
            "checksum": self.checksum,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "last_verified_at": self.last_verified_at.isoformat() if self.last_verified_at else None,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
```

### 4.2 `ToolDependency` Model

```python
# src/models/tool_dependency.py
from datetime import datetime
from uuid import UUID, uuid4
from sqlalchemy import (
    Column, DateTime, ForeignKey, String,
    UniqueConstraint, text
)
from sqlalchemy.orm import relationship
from src.core.database import Base

class ToolDependency(Base):
    """
    Represents a dependency relationship between tools.

    Examples:
    - tool-a requires tool-b (version >=1.0.0)
    - tool-x optionally uses tool-y
    - tool-p conflicts with tool-q
    """
    __tablename__ = "tool_dependencies"

    # Primary Key
    id: UUID = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
        comment="Unique dependency record ID"
    )

    # Foreign Keys
    tool_id: UUID = Column(
        String(36),
        ForeignKey("discovered_tools.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Tool that has the dependency"
    )
    dependency_id: UUID = Column(
        String(36),
        ForeignKey("discovered_tools.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Tool that is depended upon"
    )

    # Dependency Details
    dependency_type: str = Column(
        String(50),
        nullable=False,
        comment="Type: 'requires', 'optional', 'conflicts'"
    )
    version_constraint: str = Column(
        String(100),
        nullable=True,
        comment="Version constraint (e.g., '>=1.0.0,<2.0.0')"
    )

    # Audit
    created_at: datetime = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        comment="Record creation timestamp"
    )

    # Relationships
    tool = relationship(
        "DiscoveredTool",
        foreign_keys=[tool_id],
        back_populates="dependencies"
    )
    dependency = relationship(
        "DiscoveredTool",
        foreign_keys=[dependency_id],
        back_populates="dependents"
    )

    # Unique Constraint
    __table_args__ = (
        UniqueConstraint("tool_id", "dependency_id", name="uq_tool_dependency"),
    )

    def __repr__(self) -> str:
        return (
            f"<ToolDependency(id={self.id}, "
            f"tool_id={self.tool_id}, dependency_id={self.dependency_id}, "
            f"type='{self.dependency_type}')>"
        )
```

### 4.3 `ToolInstance` Model

```python
# src/models/tool_instance.py
from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID, uuid4
from sqlalchemy import (
    Column, DateTime, ForeignKey, Integer,
    String, text
)
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship
from src.core.database import Base

class ToolInstance(Base):
    """
    Represents a running instance of a tool (Docker container).

    Tracks lifecycle, status, and resource usage of tool containers.
    """
    __tablename__ = "tool_instances"

    # Primary Key
    id: UUID = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
        comment="Unique instance ID"
    )

    # Foreign Key
    tool_id: UUID = Column(
        String(36),
        ForeignKey("discovered_tools.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Tool being run"
    )

    # Container Information
    container_id: Optional[str] = Column(
        String(255),
        nullable=True,
        index=True,
        comment="Docker container ID"
    )
    status: str = Column(
        String(50),
        nullable=False,
        index=True,
        comment="Status: 'starting', 'running', 'stopping', 'stopped', 'failed'"
    )

    # Lifecycle
    started_at: Optional[datetime] = Column(
        DateTime,
        nullable=True,
        index=True,
        comment="Container start timestamp"
    )
    stopped_at: Optional[datetime] = Column(
        DateTime,
        nullable=True,
        comment="Container stop timestamp"
    )
    exit_code: Optional[int] = Column(
        Integer,
        nullable=True,
        comment="Container exit code"
    )

    # Resource Tracking
    resource_usage: Optional[Dict[str, Any]] = Column(
        JSON,
        nullable=True,
        comment="Resource usage snapshot (JSON)"
    )

    # Audit
    created_at: datetime = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        comment="Record creation timestamp"
    )
    updated_at: datetime = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=datetime.utcnow,
        comment="Record last update timestamp"
    )

    # Relationships
    tool = relationship("DiscoveredTool", back_populates="instances")

    def __repr__(self) -> str:
        return (
            f"<ToolInstance(id={self.id}, tool_id={self.tool_id}, "
            f"container_id='{self.container_id}', status='{self.status}')>"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "id": str(self.id),
            "tool_id": str(self.tool_id),
            "container_id": self.container_id,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "stopped_at": self.stopped_at.isoformat() if self.stopped_at else None,
            "exit_code": self.exit_code,
            "resource_usage": self.resource_usage,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
```

### 4.4 `ToolVerificationHistory` Model

```python
# src/models/tool_verification_history.py
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4
from sqlalchemy import (
    Column, DateTime, ForeignKey, String, Text, text
)
from sqlalchemy.orm import relationship
from src.core.database import Base

class ToolVerificationHistory(Base):
    """
    Audit trail of tool verification events.

    Integrates with Phase 2A Verification-Trust system to track
    whitelist validations and security checks.
    """
    __tablename__ = "tool_verification_history"

    # Primary Key
    id: UUID = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
        comment="Unique verification record ID"
    )

    # Foreign Keys
    tool_id: UUID = Column(
        String(36),
        ForeignKey("discovered_tools.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Tool being verified"
    )
    verification_id: Optional[UUID] = Column(
        String(36),
        ForeignKey("verifications.id", ondelete="SET NULL"),
        nullable=True,
        comment="Links to Phase 2A verification record"
    )

    # Verification Details
    verified_by: Optional[str] = Column(
        String(255),
        nullable=True,
        comment="Agent ID who performed verification"
    )
    verification_result: str = Column(
        String(50),
        nullable=False,
        index=True,
        comment="Result: 'passed', 'failed', 'error'"
    )
    checksum_verified: Optional[str] = Column(
        String(64),
        nullable=True,
        comment="SHA256 checksum at time of verification"
    )
    notes: Optional[str] = Column(
        Text,
        nullable=True,
        comment="Verification notes or error messages"
    )

    # Timestamp
    verified_at: datetime = Column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        index=True,
        comment="Verification timestamp"
    )

    # Relationships
    tool = relationship("DiscoveredTool", back_populates="verification_history")
    verification = relationship("Verification")  # Phase 2A integration

    def __repr__(self) -> str:
        return (
            f"<ToolVerificationHistory(id={self.id}, tool_id={self.tool_id}, "
            f"result='{self.verification_result}', verified_at={self.verified_at})>"
        )
```

---

## 5. Alembic Migration Strategy

### 5.1 Migration Naming Convention

```
YYYYMMDD_HHMM-<revision>_<description>.py

Examples:
- 20251122_1400-a1b2c3d4e5f6_create_discovered_tools.py
- 20251122_1405-f6e5d4c3b2a1_add_tool_verification_history.py
```

### 5.2 Initial Migration (Phase 4 Day 1)

```python
# migrations/versions/20251122_1400_create_tool_discovery_schema.py
"""Create tool discovery schema

Revision ID: a1b2c3d4e5f6
Revises: d42bfef42946  # Previous migration (Phase 2D-1)
Create Date: 2025-11-22 14:00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = 'd42bfef42946'
branch_labels = None
depends_on = None

def upgrade():
    # Create discovered_tools table
    op.create_table(
        'discovered_tools',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tool_id', sa.String(255), nullable=False, unique=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('category', sa.String(50), nullable=False),
        sa.Column('source_path', sa.Text(), nullable=False),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('metadata', sqlite.JSON(), nullable=True),
        sa.Column('checksum', sa.String(64), nullable=False),
        sa.Column('discovered_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('last_verified_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    )

    # Indexes for discovered_tools
    op.create_index('idx_discovered_tools_tool_id', 'discovered_tools', ['tool_id'])
    op.create_index('idx_discovered_tools_category_active', 'discovered_tools', ['category', 'is_active'])
    op.create_index('idx_discovered_tools_checksum', 'discovered_tools', ['checksum'])
    op.create_index('idx_discovered_tools_source_path', 'discovered_tools', ['source_path'])
    op.create_index('idx_discovered_tools_discovered_at', 'discovered_tools', [sa.text('discovered_at DESC')])

    # Create tool_dependencies table
    op.create_table(
        'tool_dependencies',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tool_id', sa.String(36), sa.ForeignKey('discovered_tools.id', ondelete='CASCADE'), nullable=False),
        sa.Column('dependency_id', sa.String(36), sa.ForeignKey('discovered_tools.id', ondelete='CASCADE'), nullable=False),
        sa.Column('dependency_type', sa.String(50), nullable=False),
        sa.Column('version_constraint', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.UniqueConstraint('tool_id', 'dependency_id', name='uq_tool_dependency')
    )

    # Indexes for tool_dependencies
    op.create_index('idx_tool_dependencies_tool_id', 'tool_dependencies', ['tool_id'])
    op.create_index('idx_tool_dependencies_dependency_id', 'tool_dependencies', ['dependency_id'])

    # Create tool_instances table
    op.create_table(
        'tool_instances',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tool_id', sa.String(36), sa.ForeignKey('discovered_tools.id', ondelete='CASCADE'), nullable=False),
        sa.Column('container_id', sa.String(255), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('stopped_at', sa.DateTime(), nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('resource_usage', sqlite.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    )

    # Indexes for tool_instances
    op.create_index('idx_tool_instances_tool_id', 'tool_instances', ['tool_id'])
    op.create_index('idx_tool_instances_container_id', 'tool_instances', ['container_id'])
    op.create_index('idx_tool_instances_status', 'tool_instances', ['status'])
    op.create_index('idx_tool_instances_started_at', 'tool_instances', [sa.text('started_at DESC')])

    # Create tool_verification_history table
    op.create_table(
        'tool_verification_history',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tool_id', sa.String(36), sa.ForeignKey('discovered_tools.id', ondelete='CASCADE'), nullable=False),
        sa.Column('verification_id', sa.String(36), sa.ForeignKey('verifications.id', ondelete='SET NULL'), nullable=True),
        sa.Column('verified_by', sa.String(255), nullable=True),
        sa.Column('verification_result', sa.String(50), nullable=False),
        sa.Column('checksum_verified', sa.String(64), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('verified_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    )

    # Indexes for tool_verification_history
    op.create_index('idx_tool_verification_history_tool_id', 'tool_verification_history', ['tool_id'])
    op.create_index('idx_tool_verification_history_verified_at', 'tool_verification_history', [sa.text('verified_at DESC')])
    op.create_index('idx_tool_verification_history_result', 'tool_verification_history', ['verification_result'])

    # Triggers for updated_at (SQLite)
    op.execute("""
        CREATE TRIGGER update_discovered_tools_updated_at
        AFTER UPDATE ON discovered_tools
        FOR EACH ROW
        BEGIN
            UPDATE discovered_tools SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
        END;
    """)

    op.execute("""
        CREATE TRIGGER update_tool_instances_updated_at
        AFTER UPDATE ON tool_instances
        FOR EACH ROW
        BEGIN
            UPDATE tool_instances SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
        END;
    """)

def downgrade():
    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS update_tool_instances_updated_at")
    op.execute("DROP TRIGGER IF EXISTS update_discovered_tools_updated_at")

    # Drop tables (reverse order due to foreign keys)
    op.drop_table('tool_verification_history')
    op.drop_table('tool_instances')
    op.drop_table('tool_dependencies')
    op.drop_table('discovered_tools')
```

### 5.3 Migration Testing

```bash
# Test upgrade
alembic upgrade a1b2c3d4e5f6
alembic current  # Should show: a1b2c3d4e5f6

# Test downgrade
alembic downgrade d42bfef42946
alembic current  # Should show: d42bfef42946

# Re-upgrade
alembic upgrade head
```

---

## 6. Performance Analysis

### 6.1 Query Performance Estimates

| Query Type | Expected Latency (P95) | Index Used | Rows Scanned |
|-----------|----------------------|-----------|--------------|
| **Lookup by tool_id** | < 5ms | idx_discovered_tools_tool_id | 1 |
| **List by category** | < 15ms | idx_discovered_tools_category_active | 10-20 |
| **Check by checksum** | < 5ms | idx_discovered_tools_checksum | 1 |
| **Insert new tool** | < 10ms | N/A | N/A |
| **Get dependencies** | < 10ms | idx_tool_dependencies_tool_id | 2-5 |
| **List running instances** | < 15ms | idx_tool_instances_status | 5-20 |

### 6.2 Database Size Projections

| # Tools | discovered_tools | tool_dependencies | tool_instances | tool_verification_history | **Total** |
|---------|-----------------|-------------------|----------------|--------------------------|-----------|
| 50 | 25 KB | 10 KB | 4 KB | 38 KB | **77 KB** |
| 100 | 50 KB | 20 KB | 8 KB | 75 KB | **153 KB** |
| 500 | 250 KB | 100 KB | 40 KB | 375 KB | **765 KB** |

**Estimated Total (100 tools)**: ~153 KB (well under 10MB target) ✅

### 6.3 Index Selectivity Analysis

**Covering Index Example** (category + active status):
```sql
-- Query:
SELECT id, tool_id, name, version
FROM discovered_tools
WHERE category = 'mcp' AND is_active = TRUE;

-- Index: idx_discovered_tools_category_active (category, is_active)
-- Selectivity: ~10-20% (assuming 5-10 categories)
-- Rows scanned: 10-20 out of 100 (excellent selectivity)
```

**Non-Covering Index Example** (checksum lookup):
```sql
-- Query:
SELECT *
FROM discovered_tools
WHERE checksum = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

-- Index: idx_discovered_tools_checksum
-- Selectivity: 100% (1:1 unique)
-- Rows scanned: 1 (perfect selectivity)
```

---

## 7. Security Considerations

### 7.1 Access Control Integration

**Namespace Isolation** (inherited from TMWS security model):
- Tools are NOT namespace-isolated (single namespace for all tools)
- Tool instances inherit agent namespace from creator

**Authorization Check Pattern**:
```python
# src/services/tool_discovery_service.py
async def get_tool(tool_id: str, agent_id: str, namespace: str) -> DiscoveredTool:
    """
    Get tool by ID (no namespace isolation).

    Tools are globally visible but instances are namespace-isolated.
    """
    # Verify agent namespace from DB (P0-1 security pattern)
    agent = await db.get(Agent, agent_id)
    verified_namespace = agent.namespace  # NEVER trust user input

    # Fetch tool (no namespace check)
    tool = await db.query(DiscoveredTool).filter_by(
        tool_id=tool_id,
        is_active=True
    ).first()

    if not tool:
        raise ToolNotFoundError(f"Tool {tool_id} not found")

    return tool
```

### 7.2 SQL Injection Prevention

**ORM Protection**:
- All queries use SQLAlchemy ORM (parameterized queries)
- No raw SQL except for triggers (safe, static SQL)

**Example Safe Query**:
```python
# Safe (parameterized)
tool = await session.execute(
    select(DiscoveredTool).where(DiscoveredTool.tool_id == user_input)
)

# NEVER do this (vulnerable to SQL injection)
# query = f"SELECT * FROM discovered_tools WHERE tool_id = '{user_input}'"  # ❌
```

### 7.3 Checksum Integrity

**SHA256 Verification**:
- All tools have SHA256 checksum
- Recalculated on every discovery scan
- Compared against whitelist approved checksums

**Checksum Mismatch Handling**:
```python
# src/services/tool_discovery_service.py
async def verify_tool_checksum(tool: DiscoveredTool, whitelist: Whitelist) -> bool:
    """Verify tool checksum against whitelist"""
    approved_checksums = whitelist.get_checksums(tool.tool_id)

    if tool.checksum not in approved_checksums:
        # Log security event
        await audit_logger.log_security_event(
            event_type="checksum_mismatch",
            severity="HIGH",
            details={
                "tool_id": tool.tool_id,
                "expected": approved_checksums,
                "actual": tool.checksum
            }
        )
        return False

    return True
```

---

## 8. Integration with Phase 2A/2B

### 8.1 Verification-Trust Integration

**Scenario**: Verify a tool using Phase 2A Verification Service

```python
# src/services/tool_discovery_service.py
from src.services.verification_service import VerificationService

async def verify_tool_with_trust(
    tool: DiscoveredTool,
    agent_id: str
) -> ToolVerificationHistory:
    """
    Verify tool using Phase 2A Verification-Trust system.

    This integrates tool discovery with TMWS's verification framework.
    """
    verification_service = VerificationService()

    # Claim: Tool checksum matches whitelist
    claim_content = {
        "tool_id": tool.tool_id,
        "checksum": tool.checksum,
        "category": tool.category,
        "version": tool.version
    }

    # Verification command (run whitelist check)
    verification_command = f"orchestrator verify-tool {tool.tool_id} {tool.checksum}"

    # Execute verification
    verification_result = await verification_service.verify_and_record(
        agent_id=agent_id,
        claim_type="tool_whitelist_check",
        claim_content=claim_content,
        verification_command=verification_command
    )

    # Create verification history record
    history = ToolVerificationHistory(
        tool_id=tool.id,
        verification_id=verification_result["verification_id"],
        verified_by=agent_id,
        verification_result="passed" if verification_result["accurate"] else "failed",
        checksum_verified=tool.checksum,
        notes=f"Whitelist verification via Phase 2A. Accurate: {verification_result['accurate']}"
    )

    # Update tool last_verified_at
    tool.last_verified_at = datetime.utcnow()

    await db_session.add(history)
    await db_session.commit()

    return history
```

### 8.2 Foreign Key to Verifications Table

```python
# tool_verification_history.verification_id links to verifications.id
verification_id: Optional[UUID] = Column(
    String(36),
    ForeignKey("verifications.id", ondelete="SET NULL"),
    nullable=True,
    comment="Links to Phase 2A verification record"
)
```

**Query Example** (Get full verification details):
```sql
SELECT
    tvh.verified_at,
    tvh.verification_result,
    v.claim_type,
    v.claim_content,
    v.accurate
FROM tool_verification_history tvh
LEFT JOIN verifications v ON tvh.verification_id = v.id
WHERE tvh.tool_id = 'tool-a-uuid'
ORDER BY tvh.verified_at DESC;
```

---

## 9. Migration Path & Rollback Strategy

### 9.1 Rollback Plan

**Scenario**: Migration fails or needs to be reverted

```bash
# Check current revision
alembic current

# Rollback one step
alembic downgrade -1

# Rollback to specific revision
alembic downgrade d42bfef42946  # Before Phase 4 migration

# Verify rollback success
alembic current
sqlite3 data/tmws.db ".schema discovered_tools"  # Should error (table doesn't exist)
```

### 9.2 Data Loss Prevention

**Before Migration**:
```bash
# Backup database
cp data/tmws.db data/tmws.db.backup-$(date +%Y%m%d-%H%M%S)

# Verify backup
sqlite3 data/tmws.db.backup-* ".schema" | head -20
```

**After Migration**:
```bash
# Verify tables created
sqlite3 data/tmws.db ".tables" | grep discovered_tools

# Check row counts (should be 0)
sqlite3 data/tmws.db "SELECT COUNT(*) FROM discovered_tools;"
```

---

## 10. Success Metrics

### 10.1 Performance Benchmarks (Post-Migration)

```python
# tests/performance/test_tool_discovery_performance.py
import pytest
import time
from src.models.discovered_tool import DiscoveredTool

@pytest.mark.asyncio
async def test_tool_lookup_performance(db_session):
    """Test tool lookup by tool_id < 5ms P95"""
    # Create 100 test tools
    for i in range(100):
        tool = DiscoveredTool(
            tool_id=f"test-tool-{i}",
            name=f"Test Tool {i}",
            category="mcp",
            source_path=f"/tools/test-{i}.json",
            checksum="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        db_session.add(tool)
    await db_session.commit()

    # Benchmark lookup (100 iterations)
    latencies = []
    for i in range(100):
        start = time.perf_counter()
        result = await db_session.query(DiscoveredTool).filter_by(
            tool_id=f"test-tool-{i % 100}"
        ).first()
        latency = (time.perf_counter() - start) * 1000  # Convert to ms
        latencies.append(latency)

    # Calculate P95
    p95 = sorted(latencies)[94]  # 95th percentile

    assert p95 < 5.0, f"P95 latency {p95:.2f}ms exceeds target 5ms"
```

### 10.2 Data Integrity Validation

```sql
-- Post-migration integrity checks
-- 1. All tools have checksums
SELECT COUNT(*) FROM discovered_tools WHERE checksum IS NULL OR checksum = '';
-- Expected: 0

-- 2. No orphaned dependencies
SELECT COUNT(*)
FROM tool_dependencies td
WHERE NOT EXISTS (SELECT 1 FROM discovered_tools dt WHERE dt.id = td.tool_id);
-- Expected: 0

-- 3. No orphaned instances
SELECT COUNT(*)
FROM tool_instances ti
WHERE NOT EXISTS (SELECT 1 FROM discovered_tools dt WHERE dt.id = ti.tool_id);
-- Expected: 0

-- 4. All active tools have valid tool_id
SELECT COUNT(*) FROM discovered_tools WHERE is_active = TRUE AND (tool_id IS NULL OR tool_id = '');
-- Expected: 0
```

---

## 11. Conclusion

This schema design provides a **robust, performant, and secure** foundation for TMWS's tool discovery system. Key strengths:

1. **Performance**: <20ms P95 query latency with strategic indexing
2. **Integrity**: Foreign keys, unique constraints, and soft deletes
3. **Auditability**: Complete verification history with Phase 2A integration
4. **Scalability**: Designed for 500+ tools with <1MB database size
5. **Security**: Checksum verification, no SQL injection risks

**Database Size Estimate**: 153 KB for 100 tools (98.5% under 10MB target) ✅

**Next Steps**:
1. **Artemis Performance Review**: Validate latency estimates
2. **Hestia Security Review**: SQL injection, checksum integrity
3. **Orchestrator Implementation**: Begin Go service development

---

**Document Status**: ✅ **COMPLETE - READY FOR REVIEW**

**Review Checklist**:
- [ ] Performance review (Artemis) - validate latency targets
- [ ] Security review (Hestia) - SQL injection, checksum verification
- [ ] Integration review (Athena) - Phase 2A compatibility

**Approval**: _Pending multi-agent review_

---

*"データの完全性と戦略的設計を通じて、完璧なツール管理を実現する。"*

*Through data integrity and strategic design, we achieve perfect tool management.*

**Hera, Strategic Commander - TMWS Phase 4 Day 1**
