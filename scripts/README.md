# TMWS Scripts Directory

## Active Scripts (Production Use)

### Core Operations
| Script | Description |
|--------|-------------|
| `start-tmws.sh` / `.bat` | Start TMWS server |
| `stop-tmws.sh` / `.bat` | Stop TMWS server |
| `start_production.sh` | Production server startup |
| `stop_production.sh` | Production server shutdown |
| `deploy.sh` | Deployment automation |

### Build & Testing
| Script | Description |
|--------|-------------|
| `build.sh` | Build TMWS package |
| `build_bytecode_wheel.sh` | Build bytecode-compiled wheel |
| `run_tests.sh` | Run test suite |
| `run_integration_tests.sh` | Run integration tests |
| `test-quick.sh` | Quick test run |
| `test-security.sh` | Security tests |
| `test-multi-client.sh` | Multi-client testing |

### Security & Setup
| Script | Description |
|--------|-------------|
| `setup_security.py` | Security configuration |
| `security_hardening.sh` | Production hardening |
| `ssl-automation.sh` | SSL certificate automation |
| `init_db_encryption.py` | Database encryption setup |
| `setup_database.py` / `.sh` | Database setup |
| `setup_multi_instance.sh` | Multi-instance configuration |
| `scan_base_images.sh` | Container image scanning |

### MCP Server
| Script | Description |
|--------|-------------|
| `run_mcp.py` | Run MCP server |
| `start_mcp_server.py` | Start MCP server |
| `generate_mcp_config.sh` | Generate MCP configuration |
| `mcp/` | MCP Docker scripts |

### License Management
| Script | Description |
|--------|-------------|
| `generate_license.py` | Generate license files |
| `manage_licenses.py` | License management CLI |
| `license/` | License signing tools |

### Database
| Script | Description |
|--------|-------------|
| `schema.sql` | Database schema (canonical) |

### Installation
| Script | Description |
|--------|-------------|
| `install/` | Current installation scripts |
| `windows/` | Windows-specific setup |

---

## Archive Directory

Archived scripts are organized by category:

### `archive/deprecated/`
Scripts replaced by newer implementations or no longer needed.

### `archive/migration/`
One-time migration scripts (already executed in production).

### `archive/validation/`
Performance validation and analysis scripts.

### `archive/verification/`
Benchmark and verification scripts.

### `archive/one-time/`
One-time setup scripts.

---

## Notes

- **Do not use archived scripts** - they are preserved for historical reference only
- All active scripts have been tested with TMWS v2.4.x
- For new installations, use `install/install.sh`
- For development, use `run_tests.sh` and `test-quick.sh`

---

*Last updated: 2025-12-06*
*Archived: 26 scripts*
*Active: ~25 scripts*
