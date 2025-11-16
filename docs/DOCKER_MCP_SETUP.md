# Docker MCP Setup Guide

## Overview

This guide explains how to connect Claude Desktop to your Dockerized TMWS instance using MCP (Model Context Protocol).

## Architecture

```
Claude Desktop
    ↓ (stdio MCP protocol)
tmws-mcp-docker.sh/bat
    ↓ (docker exec -i)
Docker Container (tmws-app)
    ↓
MCP Server (src/mcp_server)
    ↓
TMWS Services
```

## Prerequisites

1. **Docker Desktop** running
2. **TMWS container** running (`docker-compose up -d`)
3. **Claude Desktop** installed

## Setup Instructions

### Step 1: Start TMWS Container

**Mac/Linux**:
```bash
./scripts/start-tmws.sh
```

**Windows**:
```batch
scripts\start-tmws.bat
```

Or manually:
```bash
docker-compose up -d
```

### Step 2: Configure Claude Desktop

Edit Claude Desktop's MCP settings:

**Mac**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

**Linux**: `~/.config/Claude/claude_desktop_config.json`

**Configuration (Mac/Linux)**:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "/absolute/path/to/tmws/scripts/mcp/tmws-mcp-docker.sh"
    }
  }
}
```

**Configuration (Windows)**:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "C:\\absolute\\path\\to\\tmws\\scripts\\mcp\\tmws-mcp-docker.bat"
    }
  }
}
```

**Important**: Use **absolute paths** (not relative like `./scripts/...`)

### Step 3: Restart Claude Desktop

Close and reopen Claude Desktop to load the new configuration.

### Step 4: Verify Connection

In Claude Desktop, type:
```
/tmws get_agent_status
```

You should see TMWS agent information.

## Troubleshooting

### Error: "Docker is not running"

**Solution**: Start Docker Desktop

### Error: "Container does not exist"

**Solution**:
```bash
docker-compose up -d
```

### Error: "Container is not running"

**Solution**:
```bash
docker-compose start
```

Or:
```bash
./scripts/start-tmws.sh
```

### Error: "Permission denied" (Mac/Linux)

**Solution**: Ensure script is executable:
```bash
chmod +x scripts/mcp/tmws-mcp-docker.sh
```

### Claude Desktop doesn't connect

1. **Check config path**: Must be absolute path
2. **Check logs**:
   - Mac: `~/Library/Logs/Claude/mcp*.log`
   - Windows: `%APPDATA%\Claude\logs\mcp*.log`
3. **Verify container**: `docker ps | grep tmws-app`
4. **Test wrapper manually**:
   ```bash
   echo '{"jsonrpc":"2.0","id":1,"method":"ping"}' | ./scripts/mcp/tmws-mcp-docker.sh
   ```

## How It Works

1. **Claude Desktop** sends MCP protocol messages via stdin
2. **Wrapper script** (`tmws-mcp-docker.sh/bat`) validates Docker container is running
3. **`docker exec -i`** passes stdin to the container
4. **MCP Server** inside container processes requests
5. **Responses** flow back through stdout

## Security Notes

- MCP wrapper scripts do **not** expose environment variables
- All secrets remain inside Docker container
- No network ports exposed (pure stdio communication)
- Container isolation protects TMWS data

## CI/CD Integration

Docker images are automatically built and published on git tags:

```bash
git tag v2.3.1
git push origin v2.3.1
```

GitHub Actions workflow:
- Builds for **amd64** (Intel/AMD) and **arm64** (Apple Silicon)
- Publishes to **ghcr.io/apto-as/tmws**
- Runs **Trivy security scan**
- Creates **SARIF report** in GitHub Security tab

Pull published image:
```bash
docker pull ghcr.io/apto-as/tmws:v2.3.1
```

## Advanced Configuration

### Custom Container Name

If your container isn't named `tmws-app`, edit the wrapper script:

**Mac/Linux** (`tmws-mcp-docker.sh`):
```bash
CONTAINER_NAME="your-custom-name"
```

**Windows** (`tmws-mcp-docker.bat`):
```batch
set CONTAINER_NAME=your-custom-name
```

### Multiple TMWS Instances

Create separate wrapper scripts for each instance:
- `tmws-mcp-docker-dev.sh` → `tmws-app-dev`
- `tmws-mcp-docker-prod.sh` → `tmws-app-prod`

Configure multiple MCP servers in Claude Desktop:
```json
{
  "mcpServers": {
    "tmws-dev": {
      "command": "/path/to/tmws-mcp-docker-dev.sh"
    },
    "tmws-prod": {
      "command": "/path/to/tmws-mcp-docker-prod.sh"
    }
  }
}
```

## Support

For issues:
1. Check Docker container logs: `docker logs tmws-app`
2. Check MCP wrapper output: Run script manually and inspect stderr
3. Review Claude Desktop MCP logs
4. File GitHub issue with logs attached
