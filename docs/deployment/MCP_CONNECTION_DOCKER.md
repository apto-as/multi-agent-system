# Claude Desktop MCP Connection - Docker Mode
## Connecting Claude Desktop to Dockerized TMWS MCP Server

**Last Updated**: 2025-11-16
**Version**: v2.3.1
**Prerequisite**: TMWS Docker deployment complete (see [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md))
**Target Audience**: End users, AI researchers, developers

---

## 📋 Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Setup Instructions](#3-setup-instructions)
4. [Platform-Specific Guides](#4-platform-specific-guides)
5. [Verification](#5-verification)
6. [Advanced Configuration](#6-advanced-configuration)
7. [Troubleshooting](#7-troubleshooting)
8. [Multi-Agent Setup](#8-multi-agent-setup)

---

## 1. Overview

### 1.1 What This Guide Covers

**Purpose**: Configure Claude Desktop to communicate with TMWS running in a Docker container via MCP (Model Context Protocol).

**What You'll Learn**:
- Creating MCP wrapper scripts for Docker
- Configuring Claude Desktop for Docker-based MCP servers
- Platform-specific setup (Mac, Windows, Linux)
- Troubleshooting connection issues

**What You WON'T Learn** (see other guides):
- TMWS Docker installation → [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)
- Native (non-Docker) MCP setup → [../MCP_INTEGRATION.md](../MCP_INTEGRATION.md)
- Claude Desktop installation → [../CLAUDE_DESKTOP_MCP_SETUP.md](../CLAUDE_DESKTOP_MCP_SETUP.md)

---

### 1.2 Why Wrapper Scripts?

**The Challenge**:
- Claude Desktop expects **stdio** (standard input/output) communication
- Docker containers run **isolated processes**
- Direct stdio connection to container processes is not possible

**The Solution**:
```
Claude Desktop (Host OS)
    ↓ stdio
MCP Wrapper Script (.sh or .bat)
    ↓ docker exec -i
TMWS Container (tmws-app)
    ↓ stdio inside container
FastMCP Server
```

**Benefits of Wrapper Scripts**:
- ✅ No network port exposure (secure stdio-only communication)
- ✅ Automatic container health check before connection
- ✅ Platform-specific optimizations (Metal GPU on Mac, CUDA on Linux)
- ✅ Simple Claude Desktop configuration (just one `command` field)

---

## 2. Architecture

### 2.1 Communication Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Claude Desktop (Host OS)                                    │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ MCP Client (built into Claude Desktop)              │  │
│  │                                                       │  │
│  │  - Reads claude_desktop_config.json                  │  │
│  │  - Spawns wrapper script as subprocess               │  │
│  │  - Communicates via stdin/stdout                     │  │
│  └─────────────────────┬────────────────────────────────┘  │
│                        │ stdio                              │
└────────────────────────┼────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ Wrapper Script (tmws-mcp-docker.sh / .bat)                  │
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │ 1. Check container running (docker ps)            │    │
│  │ 2. Execute: docker exec -i tmws-app tmws          │    │
│  │ 3. Forward stdin → container stdin                │    │
│  │ 4. Forward container stdout → stdout              │    │
│  │ 5. Forward container stderr → stderr              │    │
│  └────────────────────────────────────────────────────┘    │
│                        │ docker exec -i                     │
└────────────────────────┼────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ TMWS Docker Container (tmws-app)                            │
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │ FastMCP Server (Python)                           │    │
│  │                                                    │    │
│  │  - Reads stdin (MCP protocol messages)            │    │
│  │  - Executes MCP tools (store_memory, search, etc)│    │
│  │  - Writes stdout (MCP protocol responses)         │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │ SQLite Database (./data/tmws.db)                  │    │
│  │ ChromaDB (./data/chromadb)                        │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

### 2.2 Security Considerations

**Why This Is Secure**:
1. **No network exposure**: Communication is stdio-only (no TCP/HTTP ports)
2. **Container isolation**: TMWS runs in isolated Docker environment
3. **Host OS permissions**: Wrapper script validates container before exec
4. **No credential storage**: Claude Desktop never sees database credentials

**Security Checklist**:
- [ ] Wrapper script validates container is running before exec
- [ ] Container started with `docker-compose up -d` (not manually with `--privileged`)
- [ ] .env file contains SECRET_KEY (never in wrapper script)
- [ ] Claude Desktop config file has correct permissions (0600 recommended)

---

## 3. Setup Instructions

### 3.1 Overview of Steps

**5-Minute Setup Process**:
1. Create wrapper script (platform-specific)
2. Make wrapper script executable
3. Configure Claude Desktop (edit JSON config)
4. Restart Claude Desktop
5. Verify connection

**Prerequisites Checklist**:
- [ ] TMWS Docker container running (`docker ps | grep tmws-app`)
- [ ] Claude Desktop installed (version 1.0+)
- [ ] Text editor (nano, vim, VSCode, Notepad)
- [ ] Terminal/PowerShell access

---

### 3.2 Step 1: Create Wrapper Script Directory

**Mac/Linux**:
```bash
# Create directory for wrapper scripts
mkdir -p ~/.local/bin

# Add to PATH (if not already)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc  # Mac (zsh)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc  # Linux (bash)
source ~/.zshrc  # Or: source ~/.bashrc
```

**Windows**:
```powershell
# Create directory
New-Item -Path "$env:USERPROFILE\.local\bin" -ItemType Directory -Force

# Add to PATH (requires Admin PowerShell)
[Environment]::SetEnvironmentVariable(
    "Path",
    "$env:Path;$env:USERPROFILE\.local\bin",
    [EnvironmentVariableTarget]::User
)

# Restart PowerShell to apply changes
```

---

### 3.3 Step 2: Create Wrapper Script

**Mac/Linux**: Create `~/.local/bin/tmws-mcp-docker.sh`
```bash
#!/bin/bash
# TMWS MCP Docker Wrapper Script for Claude Desktop
# Version: 2.3.1
# Platform: Mac/Linux

set -e  # Exit on error

CONTAINER_NAME="tmws-app"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: TMWS container '${CONTAINER_NAME}' is not running" >&2
    echo "Please start the container with: docker-compose up -d" >&2
    exit 1
fi

# Execute tmws in container with interactive stdin
exec docker exec -i "${CONTAINER_NAME}" tmws
```

**Windows**: Create `%USERPROFILE%\.local\bin\tmws-mcp-docker.bat`
```batch
@echo off
REM TMWS MCP Docker Wrapper Script for Claude Desktop
REM Version: 2.3.1
REM Platform: Windows

setlocal

set CONTAINER_NAME=tmws-app

REM Check if container is running
docker ps --format "{{.Names}}" | findstr /R "^%CONTAINER_NAME%$" >nul 2>&1
if errorlevel 1 (
    echo ERROR: TMWS container '%CONTAINER_NAME%' is not running >&2
    echo Please start the container with: docker-compose up -d >&2
    exit /b 1
)

REM Execute tmws in container with interactive stdin
docker exec -i %CONTAINER_NAME% tmws
```

---

### 3.4 Step 3: Make Script Executable

**Mac/Linux**:
```bash
chmod +x ~/.local/bin/tmws-mcp-docker.sh

# Verify permissions
ls -la ~/.local/bin/tmws-mcp-docker.sh
# Expected: -rwxr-xr-x (755)
```

**Windows**:
```powershell
# No explicit chmod needed - .bat files are executable by default
# Verify file exists
Get-ChildItem "$env:USERPROFILE\.local\bin\tmws-mcp-docker.bat"
```

---

### 3.5 Step 4: Configure Claude Desktop

**Config File Location**:
- **Mac**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

**Open Config File**:
```bash
# Mac
open ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Linux
nano ~/.config/Claude/claude_desktop_config.json

# Windows (PowerShell)
notepad "$env:APPDATA\Claude\claude_desktop_config.json"
```

**Add TMWS MCP Server Configuration**:

**Mac Configuration**:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/<your-username>/.local/bin/tmws-mcp-docker.sh"
    }
  }
}
```

**Linux Configuration**:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "/home/<your-username>/.local/bin/tmws-mcp-docker.sh"
    }
  }
}
```

**Windows Configuration**:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "C:\\Users\\<YourUsername>\\.local\\bin\\tmws-mcp-docker.bat"
    }
  }
}
```

**Important Notes**:
- Replace `<your-username>` / `<YourUsername>` with your actual username
- Use absolute paths (not ~/ or %USERPROFILE%)
- Windows: Use double backslashes (`\\`) in JSON strings
- Ensure valid JSON syntax (use https://jsonlint.com/ to validate)

---

### 3.6 Step 5: Restart Claude Desktop

**Mac**:
```bash
# Quit Claude Desktop
osascript -e 'quit app "Claude"'

# Wait 2 seconds
sleep 2

# Restart Claude Desktop
open -a "Claude"
```

**Windows**:
```powershell
# Close Claude Desktop (manually or via Task Manager)
Stop-Process -Name "Claude" -Force

# Wait 2 seconds
Start-Sleep -Seconds 2

# Restart (adjust path if installed elsewhere)
Start-Process "$env:LOCALAPPDATA\Programs\Claude\Claude.exe"
```

**Linux**:
```bash
# Close Claude Desktop
pkill -f claude

# Wait 2 seconds
sleep 2

# Restart (adjust path if needed)
claude &
```

---

## 4. Platform-Specific Guides

### 4.1 Mac (macOS 11+)

**Complete Setup Example**:

```bash
# 1. Create wrapper script
mkdir -p ~/.local/bin
cat > ~/.local/bin/tmws-mcp-docker.sh << 'EOF'
#!/bin/bash
set -e
CONTAINER_NAME="tmws-app"
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: TMWS container '${CONTAINER_NAME}' is not running" >&2
    exit 1
fi
exec docker exec -i "${CONTAINER_NAME}" tmws
EOF

# 2. Make executable
chmod +x ~/.local/bin/tmws-mcp-docker.sh

# 3. Test wrapper script manually
~/.local/bin/tmws-mcp-docker.sh
# Should NOT exit immediately (it's waiting for stdin)
# Press Ctrl+C to exit

# 4. Configure Claude Desktop
# Replace YOUR_USERNAME with actual username
cat > ~/Library/Application\ Support/Claude/claude_desktop_config.json << EOF
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/YOUR_USERNAME/.local/bin/tmws-mcp-docker.sh"
    }
  }
}
EOF

# 5. Set secure permissions
chmod 600 ~/Library/Application\ Support/Claude/claude_desktop_config.json

# 6. Restart Claude Desktop
osascript -e 'quit app "Claude"'
sleep 2
open -a "Claude"
```

**Mac-Specific Notes**:
- **Metal GPU**: Automatically utilized if Ollama running natively
- **Path**: Always use `/Users/<username>` (NOT `~/`)
- **Permissions**: Claude Desktop may require Full Disk Access in System Settings
  - Go to: System Settings → Privacy & Security → Full Disk Access
  - Add Claude Desktop app

---

### 4.2 Windows (10/11)

**Complete Setup Example** (PowerShell):

```powershell
# 1. Create wrapper script directory
New-Item -Path "$env:USERPROFILE\.local\bin" -ItemType Directory -Force

# 2. Create wrapper script
$scriptContent = @'
@echo off
setlocal
set CONTAINER_NAME=tmws-app
docker ps --format "{{.Names}}" | findstr /R "^%CONTAINER_NAME%$" >nul 2>&1
if errorlevel 1 (
    echo ERROR: TMWS container is not running >&2
    exit /b 1
)
docker exec -i %CONTAINER_NAME% tmws
'@

$scriptContent | Out-File -FilePath "$env:USERPROFILE\.local\bin\tmws-mcp-docker.bat" -Encoding ASCII

# 3. Test wrapper script
& "$env:USERPROFILE\.local\bin\tmws-mcp-docker.bat"
# Press Ctrl+C to exit

# 4. Configure Claude Desktop
$configPath = "$env:APPDATA\Claude\claude_desktop_config.json"
New-Item -Path (Split-Path $configPath) -ItemType Directory -Force

$config = @{
    mcpServers = @{
        tmws = @{
            command = "$env:USERPROFILE\.local\bin\tmws-mcp-docker.bat" -replace '\\', '\\'
        }
    }
} | ConvertTo-Json -Depth 3

$config | Out-File -FilePath $configPath -Encoding UTF8

# 5. Restart Claude Desktop
Stop-Process -Name "Claude" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process "$env:LOCALAPPDATA\Programs\Claude\Claude.exe"
```

**Windows-Specific Notes**:
- **WSL2**: Ensure Docker Desktop is using WSL2 backend (Settings → General)
- **Paths**: Use `C:\Users\<Username>` format (not `~`)
- **Backslashes**: JSON requires `\\` (double backslash)
- **Firewall**: Windows Defender may prompt - allow Docker Desktop

---

### 4.3 Linux (Ubuntu 20.04+)

**Complete Setup Example** (Bash):

```bash
# 1. Create wrapper script
mkdir -p ~/.local/bin
cat > ~/.local/bin/tmws-mcp-docker.sh << 'EOF'
#!/bin/bash
set -e
CONTAINER_NAME="tmws-app"
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: TMWS container is not running" >&2
    exit 1
fi
exec docker exec -i "${CONTAINER_NAME}" tmws
EOF

# 2. Make executable
chmod +x ~/.local/bin/tmws-mcp-docker.sh

# 3. Add to PATH (if not already)
if ! grep -q ".local/bin" ~/.bashrc; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    source ~/.bashrc
fi

# 4. Test wrapper script
~/.local/bin/tmws-mcp-docker.sh
# Press Ctrl+C to exit

# 5. Configure Claude Desktop
mkdir -p ~/.config/Claude
cat > ~/.config/Claude/claude_desktop_config.json << EOF
{
  "mcpServers": {
    "tmws": {
      "command": "$HOME/.local/bin/tmws-mcp-docker.sh"
    }
  }
}
EOF

# 6. Set secure permissions
chmod 600 ~/.config/Claude/claude_desktop_config.json

# 7. Restart Claude Desktop
pkill -f claude
sleep 2
claude &
```

**Linux-Specific Notes**:
- **Docker Group**: Ensure user is in `docker` group (avoid sudo)
  ```bash
  sudo usermod -aG docker $USER
  newgrp docker
  ```
- **SELinux**: If enabled, may need to set context for wrapper script
  ```bash
  chcon -t bin_t ~/.local/bin/tmws-mcp-docker.sh
  ```
- **AppArmor**: Typically no issues, but check logs if connection fails
  ```bash
  sudo journalctl -u apparmor -f
  ```

---

## 5. Verification

### 5.1 Pre-Connection Checks

**Step 1: Container Running**
```bash
# Check container status
docker ps | grep tmws-app

# Expected output:
# abc123...   tmws:v2.3.1   "tmws"   Up 5 minutes   0.0.0.0:8000->8000/tcp   tmws-app
```

**Step 2: Wrapper Script Works**
```bash
# Mac/Linux
~/.local/bin/tmws-mcp-docker.sh

# Windows
%USERPROFILE%\.local\bin\tmws-mcp-docker.bat

# Expected: Script starts and waits for input (doesn't exit immediately)
# Press Ctrl+C to exit
```

**Step 3: Config File Syntax Valid**
```bash
# Mac
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | jq .

# Linux
cat ~/.config/Claude/claude_desktop_config.json | jq .

# Windows (PowerShell)
Get-Content "$env:APPDATA\Claude\claude_desktop_config.json" | ConvertFrom-Json

# Expected: Valid JSON parsed successfully
```

---

### 5.2 Connection Test

**Step 1: Open Claude Desktop**
- Look for MCP server icon in sidebar (usually bottom-left)
- Should show "tmws" in list of available MCP servers
- Green indicator = connected, Red = connection failed

**Step 2: Test MCP Tool Availability**

In Claude Desktop chat:
```
List available TMWS MCP tools
```

**Expected Response**:
```
The following TMWS MCP tools are available:

Memory Management:
- store_memory
- search_memories
- get_memory_stats
- prune_expired_memories
- set_memory_ttl

Task Management:
- create_task
- get_agent_status

[... additional tools ...]
```

**Step 3: Test Basic Functionality**

In Claude Desktop:
```
Store a test memory in TMWS: "Docker MCP connection successful on 2025-11-16"
```

**Expected Response**:
```
Memory stored successfully:
- Memory ID: <uuid>
- Content: Docker MCP connection successful on 2025-11-16
- Agent: claude-desktop-xxxxx
- Namespace: default
```

**Step 4: Search Test**

```
Search TMWS memories for "Docker MCP"
```

**Expected Response**:
```
Found 1 memory:
1. Content: Docker MCP connection successful on 2025-11-16
   Created: 2025-11-16 12:34:56
   Similarity: 0.95
```

---

### 5.3 Diagnostic Commands

**Check Claude Desktop Logs**:

**Mac**:
```bash
# Claude Desktop logs
tail -f ~/Library/Logs/Claude/mcp*.log

# Look for TMWS connection messages
grep -i tmws ~/Library/Logs/Claude/mcp*.log
```

**Linux**:
```bash
# Claude Desktop logs
tail -f ~/.config/Claude/logs/mcp*.log

# Look for errors
grep -i error ~/.config/Claude/logs/mcp*.log
```

**Windows (PowerShell)**:
```powershell
# Claude Desktop logs
Get-Content "$env:APPDATA\Claude\logs\mcp*.log" -Tail 20 -Wait

# Search for errors
Select-String -Path "$env:APPDATA\Claude\logs\mcp*.log" -Pattern "error" -CaseSensitive:$false
```

**Check TMWS Container Logs**:
```bash
# Real-time logs
docker-compose logs -f tmws-app

# Last 100 lines
docker-compose logs --tail=100 tmws-app

# Search for MCP-related entries
docker-compose logs tmws-app | grep -i "mcp\|fastmcp"
```

---

## 6. Advanced Configuration

### 6.1 Custom Environment Variables

**Passing Environment Variables to Container**:

Edit `docker-compose.yml`:
```yaml
services:
  tmws-app:
    environment:
      - TMWS_AGENT_ID=claude-desktop-custom
      - TMWS_AGENT_NAMESPACE=my-namespace
      - TMWS_LOG_LEVEL=DEBUG
```

Restart container:
```bash
docker-compose down
docker-compose up -d
```

**Verify Environment Variables**:
```bash
docker-compose exec tmws-app env | grep TMWS_
```

---

### 6.2 Custom Container Name

**If using different container name** (e.g., `tmws-prod`):

**Update wrapper script**:
```bash
# Mac/Linux
CONTAINER_NAME="tmws-prod"  # Changed from tmws-app

# Windows
set CONTAINER_NAME=tmws-prod
```

**Update docker-compose.yml**:
```yaml
services:
  tmws-app:
    container_name: tmws-prod  # Changed from tmws-app
```

---

### 6.3 Multiple TMWS Instances

**Running multiple TMWS containers** (e.g., for different namespaces):

**docker-compose.yml**:
```yaml
services:
  tmws-dev:
    image: tmws:v2.3.1
    container_name: tmws-dev
    environment:
      - TMWS_AGENT_NAMESPACE=development
    ports:
      - "8001:8000"

  tmws-prod:
    image: tmws:v2.3.1
    container_name: tmws-prod
    environment:
      - TMWS_AGENT_NAMESPACE=production
    ports:
      - "8002:8000"
```

**Create separate wrapper scripts**:
```bash
# tmws-mcp-dev.sh
CONTAINER_NAME="tmws-dev"

# tmws-mcp-prod.sh
CONTAINER_NAME="tmws-prod"
```

**Claude Desktop config**:
```json
{
  "mcpServers": {
    "tmws-dev": {
      "command": "/path/to/tmws-mcp-dev.sh"
    },
    "tmws-prod": {
      "command": "/path/to/tmws-mcp-prod.sh"
    }
  }
}
```

---

## 7. Troubleshooting

### 7.1 Connection Refused / Timeout

**Symptom**: Claude Desktop shows "MCP server connection failed" for TMWS

**Diagnostic Steps**:
```bash
# 1. Check container running
docker ps | grep tmws

# 2. Test wrapper script manually
~/.local/bin/tmws-mcp-docker.sh
# Should NOT exit immediately

# 3. Check wrapper script permissions
ls -la ~/.local/bin/tmws-mcp-docker.sh
# Expected: -rwxr-xr-x (executable)

# 4. Check Claude Desktop logs
tail -f ~/Library/Logs/Claude/mcp*.log  # Mac
```

**Common Causes**:

**Issue 1: Container Not Running**
```bash
# Check status
docker ps -a | grep tmws

# If status shows "Exited":
docker-compose up -d
```

**Issue 2: Wrapper Script Not Executable**
```bash
# Fix permissions
chmod +x ~/.local/bin/tmws-mcp-docker.sh

# Verify
ls -la ~/.local/bin/tmws-mcp-docker.sh
```

**Issue 3: Absolute Path Not Used in Config**
```json
{
  "mcpServers": {
    "tmws": {
      "command": "tmws-mcp-docker.sh"  // ❌ WRONG - relative path
    }
  }
}

// ✅ CORRECT:
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/yourname/.local/bin/tmws-mcp-docker.sh"
    }
  }
}
```

---

### 7.2 MCP Tools Not Showing

**Symptom**: Claude Desktop connects, but TMWS tools don't appear

**Diagnostic Steps**:
```bash
# 1. Verify container health
docker-compose exec tmws-app curl -sf http://localhost:8000/health

# 2. Check MCP server initialization
docker-compose logs tmws-app | grep -i "mcp.*ready"

# 3. Test MCP server directly
docker-compose exec tmws-app tmws --help
```

**Common Causes**:

**Issue 1: TMWS Not in Container PATH**
```bash
# Verify tmws executable exists
docker-compose exec tmws-app which tmws

# If not found, rebuild container:
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

**Issue 2: Database Not Initialized**
```bash
# Check database file exists
docker-compose exec tmws-app ls -la /app/data/tmws.db

# If missing, initialize:
docker-compose exec tmws-app alembic upgrade head
```

---

### 7.3 Performance Issues

**Symptom**: Slow response times (>1 second per MCP call)

**Diagnostic Steps**:
```bash
# 1. Check container resources
docker stats tmws-app

# 2. Check Ollama connection
docker-compose exec tmws-app curl -s http://ollama:11434/api/tags

# 3. Monitor logs for slow queries
docker-compose logs -f tmws-app | grep -i "slow\|timeout"
```

**Solutions**:

**Solution 1: Increase Container Resources**
```yaml
# docker-compose.yml
services:
  tmws-app:
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 8G
        reservations:
          cpus: '2.0'
          memory: 4G
```

**Solution 2: Enable Caching** (if Redis available)
```yaml
services:
  tmws-app:
    environment:
      - TMWS_REDIS_URL=redis://redis:6379/0
```

---

### 7.4 Windows-Specific Issues

**Issue: "tmws-mcp-docker.bat is not recognized"**

**Cause**: Path not set correctly

**Solution**:
```powershell
# Add to PATH (Admin PowerShell)
[Environment]::SetEnvironmentVariable(
    "Path",
    "$env:Path;$env:USERPROFILE\.local\bin",
    [EnvironmentVariableTarget]::User
)

# Restart PowerShell
```

**Issue: "Access Denied" when running wrapper**

**Cause**: PowerShell execution policy

**Solution**:
```powershell
# Check current policy
Get-ExecutionPolicy

# Set to RemoteSigned (allows local scripts)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

### 7.5 Mac-Specific Issues

**Issue: "Operation not permitted" when running wrapper**

**Cause**: Full Disk Access required

**Solution**:
1. Open System Settings
2. Privacy & Security → Full Disk Access
3. Click "+" and add Claude Desktop app
4. Restart Claude Desktop

**Issue: "docker: command not found" in wrapper script**

**Cause**: Docker Desktop not in PATH for GUI apps

**Solution**:
```bash
# Add to wrapper script (before docker commands)
export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
```

---

## 8. Multi-Agent Setup

### 8.1 Multiple Claude Desktop Instances

**Scenario**: Running different AI agents (Athena, Artemis, Hestia) with separate TMWS namespaces

**Architecture**:
```
┌──────────────────────────────────────────────────────┐
│ Host OS                                              │
│                                                      │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│ │ Claude      │  │ Claude      │  │ Claude      │  │
│ │ (Athena)    │  │ (Artemis)   │  │ (Hestia)    │  │
│ │             │  │             │  │             │  │
│ │ Namespace:  │  │ Namespace:  │  │ Namespace:  │  │
│ │ "arch"      │  │ "optimize"  │  │ "security"  │  │
│ └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │
│        │                │                │          │
│        └────────────────┴────────────────┘          │
│                         │                           │
└─────────────────────────┼───────────────────────────┘
                          │
                          ▼
                  ┌───────────────┐
                  │ TMWS Container│
                  │ (Shared)      │
                  │               │
                  │ - SQLite DB   │
                  │ - ChromaDB    │
                  └───────────────┘
```

**Setup Steps**:

**1. Create namespace-specific wrapper scripts**:

`tmws-mcp-athena.sh`:
```bash
#!/bin/bash
set -e
export TMWS_AGENT_ID="athena-conductor"
export TMWS_AGENT_NAMESPACE="architecture"
exec docker exec -i -e TMWS_AGENT_ID -e TMWS_AGENT_NAMESPACE tmws-app tmws
```

`tmws-mcp-artemis.sh`:
```bash
#!/bin/bash
set -e
export TMWS_AGENT_ID="artemis-optimizer"
export TMWS_AGENT_NAMESPACE="optimization"
exec docker exec -i -e TMWS_AGENT_ID -e TMWS_AGENT_NAMESPACE tmws-app tmws
```

**2. Configure each Claude Desktop instance**:

**Athena's config**:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/athena/.local/bin/tmws-mcp-athena.sh"
    }
  }
}
```

**Artemis's config**:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/artemis/.local/bin/tmws-mcp-artemis.sh"
    }
  }
}
```

**3. Verify namespace isolation**:
```bash
# In Athena's Claude Desktop:
Store memory: "Athena's architectural decision"

# In Artemis's Claude Desktop:
Search memories for "architectural"
# Expected: No results (different namespace)
```

---

### 8.2 Shared Namespace for Collaboration

**Scenario**: Multiple agents sharing memories in same namespace

**Configuration**:

All wrapper scripts use same namespace:
```bash
export TMWS_AGENT_NAMESPACE="shared-workspace"
```

**Access Control**:
```yaml
# docker-compose.yml
services:
  tmws-app:
    environment:
      - TMWS_DEFAULT_ACCESS_LEVEL=TEAM  # Allow namespace sharing
```

---

## Related Documentation

- **Docker Deployment**: [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)
- **General MCP Guide**: [../MCP_INTEGRATION.md](../MCP_INTEGRATION.md)
- **Claude Desktop Setup**: [../CLAUDE_DESKTOP_MCP_SETUP.md](../CLAUDE_DESKTOP_MCP_SETUP.md)
- **RBAC Configuration**: [RBAC_ROLLBACK_PROCEDURE.md](RBAC_ROLLBACK_PROCEDURE.md)

---

## Support

**Issues**: https://github.com/apto-as/tmws/issues
**Discussions**: https://github.com/apto-as/tmws/discussions
**MCP Protocol**: https://modelcontextprotocol.io

---

**Last Reviewed**: 2025-11-16
**Next Review**: 2025-12-16
**Version**: v2.3.1
**Status**: Production-Ready ✅
