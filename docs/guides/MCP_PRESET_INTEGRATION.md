# MCP Preset Integration Guide

**Version**: v2.4.3+
**Status**: Production Ready
**Created**: 2025-11-27

## Overview

TMWS supports pre-configured MCP server connections through `.mcp.json` configuration files. This feature allows you to:

- Define MCP servers to auto-connect on startup
- Support both STDIO (subprocess) and HTTP transport types
- Use environment variable expansion for secrets
- Maintain compatibility with Claude Code's configuration format

## Quick Start

### 1. Create Configuration File

Create `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "context7": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@context7/mcp-server"],
      "env": {
        "CONTEXT7_API_KEY": "${CONTEXT7_API_KEY}"
      },
      "autoConnect": true
    }
  }
}
```

### 2. Set Environment Variables

```bash
export CONTEXT7_API_KEY="your-api-key-here"
```

### 3. Start TMWS

```bash
# TMWS will auto-connect to configured servers on startup
uvx tmws
```

## Configuration Locations

Configuration files are loaded in the following priority order:

| Priority | Location | Description |
|----------|----------|-------------|
| 1 | `$TMWS_MCP_SERVERS_PATH` | Environment variable override |
| 2 | `./.mcp.json` | Project-level (version controlled) |
| 3 | `~/.tmws/mcp.json` | User-level (personal presets) |

When both project and user configs exist, they are **merged** with project taking precedence for duplicate server names.

### Default Configuration

On first run, TMWS automatically creates `~/.tmws/mcp.json` with these default servers:

- **context7**: Documentation lookup (auto-connect)
- **playwright**: Browser automation (auto-connect)
- **serena**: Code analysis (auto-connect)
- **chrome-devtools**: Chrome DevTools (manual connect, requires `chrome --remote-debugging-port=9222`)

You can edit this file to add, remove, or modify MCP server configurations.

## Configuration Schema

### Server Types

#### STDIO Transport (subprocess-based)

For MCP servers that run as subprocesses and communicate via stdin/stdout:

```json
{
  "mcpServers": {
    "server-name": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@package/mcp-server"],
      "env": {
        "API_KEY": "${MY_API_KEY}"
      },
      "cwd": "/path/to/working/directory",
      "autoConnect": true
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"stdio"` |
| `command` | string | Yes | Executable command (e.g., `npx`, `uvx`, `python`) |
| `args` | array | No | Command line arguments |
| `env` | object | No | Environment variables for subprocess |
| `cwd` | string | No | Working directory for subprocess |
| `autoConnect` | boolean | No | Auto-connect on startup (default: `false`) |

#### HTTP Transport (HTTP API-based)

For MCP servers that expose HTTP endpoints:

```json
{
  "mcpServers": {
    "http-server": {
      "type": "http",
      "url": "http://localhost:8080/mcp",
      "timeout": 30,
      "retryAttempts": 3,
      "authRequired": true,
      "apiKeyEnv": "CUSTOM_SERVER_API_KEY",
      "autoConnect": false
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"http"` or `"sse"` |
| `url` | string | Yes | HTTP endpoint URL |
| `timeout` | integer | No | Connection timeout in seconds (default: 30) |
| `retryAttempts` | integer | No | Number of retry attempts (default: 3) |
| `authRequired` | boolean | No | Whether authentication is required |
| `apiKeyEnv` | string | No | Environment variable name for API key |
| `autoConnect` | boolean | No | Auto-connect on startup (default: `false`) |

### Environment Variable Expansion

Use `${VAR_NAME}` syntax to reference environment variables:

```json
{
  "mcpServers": {
    "example": {
      "type": "stdio",
      "command": "node",
      "args": ["server.js"],
      "env": {
        "API_KEY": "${MY_API_KEY}",
        "DATA_PATH": "${HOME}/data"
      }
    }
  }
}
```

**Security Note**: Never commit actual secrets to `.mcp.json`. Always use environment variable references.

## Example Configurations

### Context7 (Documentation Lookup)

```json
{
  "mcpServers": {
    "context7": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@context7/mcp-server"],
      "env": {
        "CONTEXT7_API_KEY": "${CONTEXT7_API_KEY}"
      },
      "autoConnect": true
    }
  }
}
```

### Playwright (Browser Automation)

```json
{
  "mcpServers": {
    "playwright": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@anthropic/mcp-playwright"],
      "autoConnect": true
    }
  }
}
```

### Serena (Code Analysis)

```json
{
  "mcpServers": {
    "serena": {
      "type": "stdio",
      "command": "uvx",
      "args": ["serena-mcp-server"],
      "env": {
        "SERENA_PROJECT_PATH": "${PWD}"
      },
      "autoConnect": false
    }
  }
}
```

### Custom HTTP Server

```json
{
  "mcpServers": {
    "custom": {
      "type": "http",
      "url": "http://localhost:8080/mcp",
      "timeout": 60,
      "retryAttempts": 5,
      "authRequired": true,
      "apiKeyEnv": "CUSTOM_MCP_API_KEY",
      "autoConnect": false
    }
  }
}
```

## Complete Example

```json
{
  "$schema": "https://tmws.dev/schemas/mcp-servers.json",
  "mcpServers": {
    "context7": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@context7/mcp-server"],
      "env": {
        "CONTEXT7_API_KEY": "${CONTEXT7_API_KEY}"
      },
      "autoConnect": true
    },
    "playwright": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@anthropic/mcp-playwright"],
      "autoConnect": true
    },
    "serena": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "serena-mcp-server", "serena"],
      "autoConnect": true
    },
    "chrome-devtools": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@anthropic/mcp-chrome-devtools@latest"],
      "autoConnect": false
    },
    "custom-http": {
      "type": "http",
      "url": "http://localhost:8080/mcp",
      "timeout": 30,
      "authRequired": true,
      "apiKeyEnv": "CUSTOM_SERVER_API_KEY",
      "autoConnect": false
    }
  }
}
```

## Compatibility with Claude Code

This configuration format is designed to be compatible with Claude Code's `.mcp.json` format. You can use the same configuration file for both TMWS and Claude Code.

**Shared Fields**:
- `mcpServers` container
- `type` (stdio/http)
- `command`, `args`, `env` for STDIO
- `url` for HTTP
- `autoConnect` flag

## Startup Behavior

When TMWS starts:

1. Configuration files are loaded in priority order
2. Servers with `autoConnect: true` are connected in parallel
3. Available tools are discovered from each server
4. Connection status is logged

Example startup log:

```
INFO  🔖 Default namespace detected: github-com-myorg-myproject
INFO  Chroma vector service initialized
INFO  Auto-connecting to 2 MCP servers
INFO  Starting MCP server: npx -y @context7/mcp-server
INFO  Starting MCP server: npx -y @anthropic/mcp-playwright
INFO  Connected to context7: 5 tools available
INFO  Connected to playwright: 12 tools available
INFO  ✅ External MCP servers connected: 2
      Servers: context7, playwright
      Total external tools available: 17
```

## Troubleshooting

### Server Fails to Start

Check that:
1. The command is installed (`npx`, `uvx`, `python`, etc.)
2. Required environment variables are set
3. Working directory exists (if `cwd` is specified)

### Environment Variable Not Resolved

Ensure:
1. Variable is exported in your shell
2. Variable name matches exactly (case-sensitive)
3. Syntax is `${VAR_NAME}` (not `$VAR_NAME`)

### Connection Timeout

For slow-starting servers:
1. Increase `timeout` value for HTTP servers
2. Check server logs for startup issues
3. Verify network connectivity

## Security Best Practices

1. **Never commit secrets**: Use environment variable references (`${VAR}`)
2. **Version control `.mcp.json.example`**: Include example with placeholders
3. **Use `.gitignore`**: Exclude actual `.mcp.json` if it contains sensitive paths
4. **Audit `autoConnect`**: Only auto-connect servers you trust

## Dynamic Server Management (v2.4.3+)

TMWS provides MCP tools that allow agents to dynamically connect to and disconnect from preset MCP servers at runtime. This is useful for servers configured with `autoConnect: false`.

### Available Tools

#### `list_mcp_servers`

Lists all MCP servers defined in presets with their current connection status.

**Usage Example (Agent conversation)**:
```
User: "What MCP servers are available?"
Agent: [calls list_mcp_servers]
```

**Response**:
```json
{
  "status": "success",
  "server_count": 4,
  "servers": [
    {
      "name": "context7",
      "transport_type": "stdio",
      "auto_connect": true,
      "is_connected": true,
      "tool_count": 5
    },
    {
      "name": "chrome-devtools",
      "transport_type": "stdio",
      "auto_connect": false,
      "is_connected": false,
      "tool_count": 0
    }
  ]
}
```

#### `connect_mcp_server`

Connects to a preset MCP server by name.

**Parameters**:
- `server_name` (string, required): Name of the server as defined in presets

**Usage Example**:
```
User: "chrome-devtoolsを使えるようにして"
Agent: [calls connect_mcp_server with server_name="chrome-devtools"]
```

**Response (success)**:
```json
{
  "status": "connected",
  "server": "chrome-devtools",
  "transport_type": "stdio",
  "tool_count": 12,
  "tools": ["browser_navigate", "browser_click", ...]
}
```

**Response (already connected)**:
```json
{
  "status": "already_connected",
  "server": "chrome-devtools",
  "tool_count": 12
}
```

**Response (not found)**:
```json
{
  "status": "error",
  "error": "Server 'unknown' not found in presets",
  "available_servers": ["context7", "playwright", "serena", "chrome-devtools"]
}
```

#### `disconnect_mcp_server`

Disconnects from an MCP server.

**Parameters**:
- `server_name` (string, required): Name of the server to disconnect

**Usage Example**:
```
User: "chrome-devtoolsを切断して"
Agent: [calls disconnect_mcp_server with server_name="chrome-devtools"]
```

**Response**:
```json
{
  "status": "disconnected",
  "server": "chrome-devtools"
}
```

#### `get_mcp_status`

Gets the current status of all MCP server connections.

**Response**:
```json
{
  "status": "success",
  "connected_count": 3,
  "connections": [
    {
      "name": "context7",
      "is_connected": true,
      "tool_count": 5
    }
  ],
  "total_tools": 17
}
```

### Security Considerations

1. **Preset-Only Connections**: Only servers defined in `~/.tmws/mcp.json` or `.mcp.json` can be connected. This prevents arbitrary command execution.

2. **Connection Limit**: Maximum 10 concurrent connections to prevent resource exhaustion.

3. **No Direct Command Execution**: Agents cannot specify arbitrary commands - they can only reference predefined presets.

### Example Workflow

```
# 1. User asks to enable chrome-devtools
User: "Chrome DevToolsを有効にして"

# 2. Agent lists available servers
Agent: [list_mcp_servers]
→ Sees chrome-devtools is available but not connected

# 3. Agent connects to the server
Agent: [connect_mcp_server server_name="chrome-devtools"]
→ Server connected, 12 tools now available

# 4. Agent confirms to user
Agent: "Chrome DevToolsに接続しました。12個のツールが利用可能になりました。"

# 5. User finishes using chrome-devtools
User: "Chrome DevToolsの使用を終了"

# 6. Agent disconnects
Agent: [disconnect_mcp_server server_name="chrome-devtools"]
→ Server disconnected
```

## API Reference

### Python API

```python
from src.infrastructure.mcp import (
    MCPManager,
    MCPPresetConfig,
    MCPServerPreset,
    load_mcp_presets,
)

# Load presets
config = load_mcp_presets()

# Create manager
manager = MCPManager()

# Auto-connect
connected = await manager.auto_connect(config)

# List tools from all servers
tools = await manager.list_all_tools()

# Call a tool
result = await manager.call_tool("context7", "search", {"query": "fastapi"})

# Disconnect
await manager.disconnect_all()
```

## Related Documentation

- [MCP Protocol Specification](https://modelcontextprotocol.io/docs)
- [TMWS Architecture](../architecture/TMWS_v2.2.0_ARCHITECTURE.md)
- [Security Guidelines](../security/SECURITY_GUIDELINES.md)
