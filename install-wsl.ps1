# =============================================================================
# Trinitas Multi-Agent System Installer v2.4.15
# For Windows (WSL2 Required)
# =============================================================================
#
# This installer sets up:
#   1. WSL2 environment with Docker
#   2. TMWS (Trinitas Memory & Workflow System) via Docker
#   3. Trinitas agents and configuration for Claude Code
#   4. Pre-activated ENTERPRISE license
#
# Features:
#   - Automatic backup of existing installations
#   - WSL2 detection and setup guidance
#   - Docker Desktop integration
#
# Requirements:
#   - Windows 10 version 2004+ or Windows 11
#   - WSL2 enabled
#   - Docker Desktop with WSL2 backend
#
# Usage (Run as Administrator):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\install-wsl.ps1
#
# =============================================================================

param(
    [switch]$Force,
    [switch]$SkipBackup,
    [string]$TargetIDE = "claude"  # "claude" or "opencode"
)

# Version
$INSTALLER_VERSION = "2.4.15"
$TMWS_VERSION = "2.4.15"

# Configuration
$TMWS_IMAGE = "ghcr.io/apto-as/tmws:$TMWS_VERSION"
$DEFAULT_LICENSE_KEY = "TMWS-ENTERPRISE-020d8e77-de36-48a1-b585-7f66aef78c06-20260303-Tp9UYRt6ucUB21hPF9lqZoH.FjSslvfr~if1ThD75L.ro~Kx5glyVyGPm0n4xuziJ~Qmc87PZipJWCefj2HEAA"

# Colors
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Log-Info { Write-Host "[INFO] " -ForegroundColor Blue -NoNewline; Write-Host $args }
function Log-Success { Write-Host "[OK] " -ForegroundColor Green -NoNewline; Write-Host $args }
function Log-Warn { Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline; Write-Host $args }
function Log-Error { Write-Host "[ERROR] " -ForegroundColor Red -NoNewline; Write-Host $args }
function Log-Step { Write-Host "[STEP] " -ForegroundColor Magenta -NoNewline; Write-Host $args }

# Banner
function Show-Banner {
    Write-Host ""
    Write-Host "=======================================================================" -ForegroundColor Cyan
    Write-Host "                                                                       " -ForegroundColor Cyan
    Write-Host "   TRINITAS Multi-Agent System Installer v$INSTALLER_VERSION           " -ForegroundColor Cyan
    Write-Host "   For Windows (WSL2)                                                   " -ForegroundColor Cyan
    Write-Host "                                                                       " -ForegroundColor Cyan
    Write-Host "=======================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Check WSL2
function Test-WSL2 {
    Log-Step "Checking WSL2 installation..."

    try {
        $wslVersion = wsl --status 2>&1
        if ($wslVersion -match "Default Version: 2" -or $wslVersion -match "WSL 2") {
            Log-Success "WSL2 is installed and configured"
            return $true
        }
    } catch {}

    Log-Error "WSL2 is not properly configured"
    Write-Host ""
    Write-Host "To install WSL2:" -ForegroundColor Yellow
    Write-Host "  1. Open PowerShell as Administrator"
    Write-Host "  2. Run: wsl --install"
    Write-Host "  3. Restart your computer"
    Write-Host "  4. Run: wsl --set-default-version 2"
    Write-Host ""
    return $false
}

# Check Docker Desktop
function Test-DockerDesktop {
    Log-Step "Checking Docker Desktop..."

    try {
        $dockerVersion = docker version 2>&1
        if ($dockerVersion -match "Server:") {
            Log-Success "Docker Desktop is running"

            # Check WSL2 backend
            $dockerInfo = docker info 2>&1
            if ($dockerInfo -match "WSL") {
                Log-Success "Docker is using WSL2 backend"
                return $true
            } else {
                Log-Warn "Docker may not be using WSL2 backend"
                Write-Host "  Enable WSL2 backend in Docker Desktop settings" -ForegroundColor Yellow
            }
            return $true
        }
    } catch {}

    Log-Error "Docker Desktop is not running"
    Write-Host ""
    Write-Host "Please install and start Docker Desktop:" -ForegroundColor Yellow
    Write-Host "  1. Download from: https://www.docker.com/products/docker-desktop"
    Write-Host "  2. Install with WSL2 backend enabled"
    Write-Host "  3. Start Docker Desktop"
    Write-Host ""
    return $false
}

# Get WSL distro
function Get-WSLDistro {
    $distros = wsl -l -q 2>&1 | Where-Object { $_ -ne "" }
    if ($distros.Count -gt 0) {
        # Return first distro (default)
        return ($distros | Select-Object -First 1).Trim()
    }
    return $null
}

# Check existing installation in WSL
function Test-ExistingInstallation {
    Log-Step "Checking for existing installation in WSL..."

    $distro = Get-WSLDistro
    if (-not $distro) {
        Log-Info "No WSL distribution found"
        return $false
    }

    $existingItems = @()

    # Check ~/.trinitas
    $result = wsl -d $distro -- test -d ~/.trinitas 2>&1
    if ($LASTEXITCODE -eq 0) {
        $existingItems += "~/.trinitas/"
    }

    # Check ~/.claude or ~/.config/opencode
    if ($TargetIDE -eq "claude") {
        $result = wsl -d $distro -- test -f ~/.claude/CLAUDE.md 2>&1
        if ($LASTEXITCODE -eq 0) {
            $existingItems += "~/.claude/ (Trinitas config)"
        }
    } else {
        $result = wsl -d $distro -- test -f ~/.config/opencode/opencode.md 2>&1
        if ($LASTEXITCODE -eq 0) {
            $existingItems += "~/.config/opencode/ (Trinitas config)"
        }
    }

    # Check ~/.tmws
    $result = wsl -d $distro -- test -d ~/.tmws 2>&1
    if ($LASTEXITCODE -eq 0) {
        $existingItems += "~/.tmws/ (data)"
    }

    # Check Docker container
    $containers = docker ps -a --format "{{.Names}}" 2>&1
    if ($containers -match "tmws") {
        $existingItems += "tmws Docker container"
    }

    if ($existingItems.Count -gt 0) {
        Log-Warn "Existing Trinitas/TMWS installation detected:"
        foreach ($item in $existingItems) {
            Write-Host "  - $item"
        }
        Write-Host ""
        return $true
    }

    Log-Info "No existing installation found (fresh install)"
    return $false
}

# Create backup in WSL
function New-Backup {
    Log-Step "Creating backup of existing installation..."

    $distro = Get-WSLDistro
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    # Run backup script in WSL
    $backupScript = @"
#!/bin/bash
BACKUP_DIR=~/.trinitas-backup/$timestamp
mkdir -p \$BACKUP_DIR

# Backup directories
[ -d ~/.trinitas ] && cp -r ~/.trinitas \$BACKUP_DIR/trinitas
[ -d ~/.claude ] && cp -r ~/.claude \$BACKUP_DIR/claude
[ -d ~/.config/opencode ] && cp -r ~/.config/opencode \$BACKUP_DIR/opencode
[ -d ~/.tmws ] && mkdir -p \$BACKUP_DIR/tmws && find ~/.tmws -maxdepth 2 -type f \( -name "*.json" -o -name "*.yaml" -o -name "*.env" \) -exec cp {} \$BACKUP_DIR/tmws/ \; 2>/dev/null

echo "Backup created at: \$BACKUP_DIR"
"@

    $backupScript | wsl -d $distro -- bash

    Log-Success "Backup created"
}

# Stop existing TMWS container
function Stop-ExistingTMWS {
    Log-Step "Stopping existing TMWS container..."

    $containers = @("tmws-app", "tmws", "tmws-server", "trinitas-tmws")

    foreach ($container in $containers) {
        $running = docker ps --format "{{.Names}}" 2>&1 | Where-Object { $_ -eq $container }
        if ($running) {
            docker stop $container 2>&1 | Out-Null
            Log-Success "Stopped $container"
        }

        $exists = docker ps -a --format "{{.Names}}" 2>&1 | Where-Object { $_ -eq $container }
        if ($exists) {
            docker rm $container 2>&1 | Out-Null
            Log-Info "Removed $container"
        }
    }
}

# Pull TMWS image
function Get-TMWSImage {
    Log-Step "Pulling TMWS Docker image ($TMWS_IMAGE)..."

    docker pull $TMWS_IMAGE

    if ($LASTEXITCODE -eq 0) {
        Log-Success "TMWS image pulled successfully"
    } else {
        Log-Error "Failed to pull TMWS image"
        exit 1
    }
}

# Setup TMWS in WSL
function Install-TMWSInWSL {
    Log-Step "Setting up TMWS in WSL..."

    $distro = Get-WSLDistro

    # Determine which installer to use
    $installerUrl = if ($TargetIDE -eq "opencode") {
        "https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install-opencode.sh"
    } else {
        "https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh"
    }

    # Run installer in WSL (non-interactive mode)
    $installScript = @"
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

# Download and run installer with auto-yes for upgrade
curl -fsSL "$installerUrl" -o /tmp/trinitas-install.sh
chmod +x /tmp/trinitas-install.sh

# Run with force flag (skip confirmation)
echo "y" | /tmp/trinitas-install.sh

rm /tmp/trinitas-install.sh
"@

    Log-Info "Running installer in WSL (this may take a few minutes)..."
    $installScript | wsl -d $distro -- bash

    if ($LASTEXITCODE -eq 0) {
        Log-Success "TMWS installed in WSL"
    } else {
        Log-Warn "Installation completed with warnings"
    }
}

# Verify installation
function Test-Installation {
    Log-Step "Verifying installation..."

    # Check Docker container
    Start-Sleep -Seconds 5
    $container = docker ps --format "{{.Names}}" 2>&1 | Where-Object { $_ -eq "tmws-app" }

    if ($container) {
        Log-Success "TMWS container is running"

        # Check health endpoint
        try {
            $health = Invoke-RestMethod -Uri "http://localhost:8000/health" -TimeoutSec 10 -ErrorAction SilentlyContinue
            if ($health) {
                Log-Success "TMWS health check passed"
            }
        } catch {
            Log-Warn "TMWS may still be starting..."
        }
    } else {
        Log-Warn "TMWS container not found - may need manual start"
    }
}

# Show completion
function Show-Completion {
    $distro = Get-WSLDistro

    Write-Host ""
    Write-Host "=======================================================================" -ForegroundColor Green
    Write-Host "           Installation Complete! (Windows/WSL2)                       " -ForegroundColor Green
    Write-Host "=======================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "What was installed:" -ForegroundColor Cyan
    Write-Host "  - TMWS Docker container (ghcr.io/apto-as/tmws:$TMWS_VERSION)"
    Write-Host "  - Trinitas 9-agent configuration for $TargetIDE"
    Write-Host "  - Pre-activated ENTERPRISE license"
    Write-Host ""
    Write-Host "WSL Distribution: $distro" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Services:" -ForegroundColor Cyan
    Write-Host "  - MCP Server:      localhost:8892"
    Write-Host "  - REST API:        localhost:8000"
    Write-Host "  - Health check:    http://localhost:8000/health"
    Write-Host ""
    Write-Host "Quick start:" -ForegroundColor Cyan
    Write-Host "  1. Open WSL: wsl -d $distro"
    Write-Host "  2. Ensure Ollama is running: ollama serve"
    Write-Host "  3. Start Claude Code in your project"
    Write-Host ""
    Write-Host "Useful commands:" -ForegroundColor Cyan
    Write-Host "  - View logs:       docker logs -f tmws-app"
    Write-Host "  - Restart TMWS:    docker restart tmws-app"
    Write-Host "  - WSL shell:       wsl -d $distro"
    Write-Host ""
    Write-Host "License: ENTERPRISE" -ForegroundColor Green
    Write-Host ""
    Write-Host "Enjoy Trinitas Multi-Agent System!" -ForegroundColor Green
    Write-Host ""
}

# Main
function Main {
    Show-Banner

    # Check prerequisites
    if (-not (Test-WSL2)) {
        exit 1
    }

    if (-not (Test-DockerDesktop)) {
        exit 1
    }

    $distro = Get-WSLDistro
    if (-not $distro) {
        Log-Error "No WSL distribution found"
        Write-Host "Install Ubuntu: wsl --install -d Ubuntu" -ForegroundColor Yellow
        exit 1
    }
    Log-Info "Using WSL distribution: $distro"

    # Check existing installation
    $existing = Test-ExistingInstallation

    if ($existing -and -not $Force) {
        Write-Host ""
        $confirm = Read-Host "Do you want to upgrade? (existing data will be backed up) [Y/n]"
        if ($confirm -eq "n" -or $confirm -eq "N") {
            Log-Info "Installation cancelled"
            exit 0
        }

        if (-not $SkipBackup) {
            New-Backup
        }
        Stop-ExistingTMWS
    }

    # Install
    Get-TMWSImage
    Install-TMWSInWSL
    Test-Installation

    Show-Completion
}

# Run
Main
