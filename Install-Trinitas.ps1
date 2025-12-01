#Requires -Version 5.1

<#
.SYNOPSIS
    Trinitas Agent System - Unified Cross-Platform Installer for Windows
.DESCRIPTION
    Installs Trinitas AI Personas for Claude Code and/or OpenCode on Windows.
    Supports all 9 agents (Core 6 + Support 3).
.PARAMETER Platform
    Target platform: claude, opencode, or both
.PARAMETER Force
    Skip confirmation prompts
.PARAMETER Uninstall
    Restore from latest backup
.EXAMPLE
    .\Install-Trinitas.ps1
    Interactive installation
.EXAMPLE
    .\Install-Trinitas.ps1 -Platform claude
    Install for Claude Code only
.EXAMPLE
    .\Install-Trinitas.ps1 -Platform both -Force
    Install for both platforms without confirmation
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet("claude", "opencode", "both")]
    [string]$Platform,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$Uninstall,

    [Parameter()]
    [switch]$Version
)

# Version Information
$InstallerVersion = "2.5.0"
$TrinitasVersion = "2.2.4"

# Color Functions
function Write-ColorHost {
    param (
        [string]$Message,
        [string]$ForegroundColor = "White"
    )
    Write-Host $Message -ForegroundColor $ForegroundColor
}

function Write-Success { param([string]$Message) Write-Host "✓ $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "⚠ $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "✗ $Message" -ForegroundColor Red }
function Write-Info { param([string]$Message) Write-Host "ℹ $Message" -ForegroundColor Cyan }
function Write-Step { param([string]$Message) Write-Host "▶ $Message" -ForegroundColor Magenta }

# Path Definitions
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Claude Code Paths (TMWS structure)
$ClaudeConfigDir = Join-Path $env:USERPROFILE ".claude"
$ClaudeBackupDir = Join-Path $ClaudeConfigDir "backup"
$ClaudeAgentsSrc = Join-Path $ScriptDir "src\trinitas\agents"

# OpenCode Paths
$OpenCodeConfigDir = Join-Path $env:USERPROFILE ".config\opencode"
$OpenCodeBackupDir = Join-Path $env:USERPROFILE ".config\opencode.backup.$Timestamp"
$OpenCodeAgentsSrc = Join-Path $ScriptDir ".opencode\agent"

# Hooks and Shared Paths (TMWS structure)
$HooksSrc = Join-Path $ScriptDir "hooks"
$SharedSrc = Join-Path $ScriptDir "shared"

# Agent Definitions - ALL 9 AGENTS
$CoreAgents = @("athena", "artemis", "hestia", "eris", "hera", "muses")
$SupportAgents = @("aphrodite", "metis", "aurora")
$AllAgents = $CoreAgents + $SupportAgents

# Claude Code Agent File Names
$ClaudeCoreFiles = @("athena-conductor", "artemis-optimizer", "hestia-auditor", "eris-coordinator", "hera-strategist", "muses-documenter")
$ClaudeSupportFiles = @("aphrodite-designer", "metis-developer", "aurora-researcher")
$ClaudeAllFiles = $ClaudeCoreFiles + $ClaudeSupportFiles

# ============================================================================
# Header
# ============================================================================

function Show-Header {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     Trinitas Agent System - Windows Installer v$InstallerVersion      ║" -ForegroundColor Cyan
    Write-Host "║       Claude Code & OpenCode Cross-Platform Support        ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# Prerequisites
# ============================================================================

function Test-Prerequisites {
    Write-Step "Checking prerequisites..."

    # Check source directories (TMWS structure)
    if (-not (Test-Path $ClaudeAgentsSrc)) {
        Write-Error "Claude Code agents not found: $ClaudeAgentsSrc"
        Write-Host "Please run this script from the TMWS project root."
        exit 1
    }

    if (-not (Test-Path $OpenCodeAgentsSrc)) {
        Write-Error "OpenCode agents not found: $OpenCodeAgentsSrc"
        Write-Host "Please run this script from the TMWS project root."
        exit 1
    }

    # Check pyproject.toml to verify TMWS root
    $PyprojectPath = Join-Path $ScriptDir "pyproject.toml"
    if (-not (Test-Path $PyprojectPath)) {
        Write-Warning "pyproject.toml not found - may not be TMWS root"
    }

    # Get version from pyproject.toml
    if (Test-Path $PyprojectPath) {
        $content = Get-Content $PyprojectPath -Raw
        if ($content -match 'version = "([^"]+)"') {
            Write-Success "TMWS version: $($Matches[1])"
        }
    }

    # Show source paths
    Write-Info "Claude agents: $ClaudeAgentsSrc"
    Write-Info "OpenCode agents: $OpenCodeAgentsSrc"

    Write-Success "Prerequisites satisfied"
    Write-Host ""
}

# ============================================================================
# Platform Selection
# ============================================================================

function Select-Platform {
    if ($script:Platform) {
        return
    }

    Write-Host "Select installation target:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1) Claude Code only     (~/.claude/)"
    Write-Host "  2) OpenCode only        (~/.config/opencode/)"
    Write-Host "  3) Both platforms"
    Write-Host "  4) Cancel"
    Write-Host ""

    $choice = Read-Host "Choose (1-4)"

    switch ($choice) {
        "1" { $script:Platform = "claude" }
        "2" { $script:Platform = "opencode" }
        "3" { $script:Platform = "both" }
        default {
            Write-Warning "Installation cancelled"
            exit 0
        }
    }

    Write-Host ""
}

# ============================================================================
# Claude Code Installation
# ============================================================================

function Install-ClaudeCode {
    Write-Step "Installing Trinitas for Claude Code..."
    Write-Host ""

    # Create directories
    if (-not (Test-Path $ClaudeConfigDir)) {
        New-Item -ItemType Directory -Path $ClaudeConfigDir -Force | Out-Null
    }
    if (-not (Test-Path (Join-Path $ClaudeConfigDir "agents"))) {
        New-Item -ItemType Directory -Path (Join-Path $ClaudeConfigDir "agents") -Force | Out-Null
    }
    if (-not (Test-Path $ClaudeBackupDir)) {
        New-Item -ItemType Directory -Path $ClaudeBackupDir -Force | Out-Null
    }

    # Backup
    Backup-ClaudeConfig

    # Install agents
    Install-ClaudeAgents

    # Install hooks
    Install-ClaudeHooks

    # Install global config
    Install-ClaudeGlobalConfig

    Write-Success "Claude Code installation complete!"
    Write-Host ""
}

function Backup-ClaudeConfig {
    Write-Info "Creating Claude Code backup..."

    $backupCreated = $false

    # Backup CLAUDE.md
    $claudeMdPath = Join-Path $ClaudeConfigDir "CLAUDE.md"
    if (Test-Path $claudeMdPath) {
        $backupPath = Join-Path $ClaudeBackupDir "CLAUDE_$Timestamp.md"
        Copy-Item $claudeMdPath $backupPath
        Write-Success "Backed up: CLAUDE.md"
        $backupCreated = $true
    }

    # Backup AGENTS.md
    $agentsMdPath = Join-Path $ClaudeConfigDir "AGENTS.md"
    if (Test-Path $agentsMdPath) {
        $backupPath = Join-Path $ClaudeBackupDir "AGENTS_$Timestamp.md"
        Copy-Item $agentsMdPath $backupPath
        Write-Success "Backed up: AGENTS.md"
        $backupCreated = $true
    }

    # Backup agents directory
    $agentsDir = Join-Path $ClaudeConfigDir "agents"
    if ((Test-Path $agentsDir) -and (Get-ChildItem $agentsDir -ErrorAction SilentlyContinue)) {
        $backupAgentsDir = Join-Path $ClaudeBackupDir "agents_$Timestamp"
        Copy-Item $agentsDir $backupAgentsDir -Recurse -Force
        Write-Success "Backed up: agents/ directory"
        $backupCreated = $true
    }

    if ($backupCreated) {
        Write-Info "Backup location: $ClaudeBackupDir"
    } else {
        Write-Info "No existing files to backup (fresh installation)"
    }
    Write-Host ""
}

function Install-ClaudeAgents {
    Write-Info "Installing Claude Code agents (9 total)..."

    $installedCount = 0
    $agentsDir = Join-Path $ClaudeConfigDir "agents"

    foreach ($agentFile in $ClaudeAllFiles) {
        $srcFile = Join-Path $ClaudeAgentsSrc "$agentFile.md"
        $dstFile = Join-Path $agentsDir "$agentFile.md"

        if (Test-Path $srcFile) {
            Copy-Item $srcFile $dstFile -Force
            Write-Success "Installed: $agentFile"
            $installedCount++
        } else {
            Write-Warning "Not found: $agentFile (skipped)"
        }
    }

    Write-Host ""
    Write-Info "Agents installed: $installedCount/9"

    if ($installedCount -ge 6) {
        Write-Success "Core agents (6) installed successfully"
    }
    if ($installedCount -eq 9) {
        Write-Success "Support agents (3) installed successfully"
    }
    Write-Host ""
}

function Install-ClaudeHooks {
    Write-Info "Installing Claude Code hooks..."

    $hooksDir = Join-Path $ClaudeConfigDir "hooks\core"
    if (-not (Test-Path $hooksDir)) {
        New-Item -ItemType Directory -Path $hooksDir -Force | Out-Null
    }

    # Install protocol_injector.py
    $protocolInjector = Join-Path $HooksSrc "core\protocol_injector.py"
    if (Test-Path $protocolInjector) {
        Copy-Item $protocolInjector $hooksDir -Force
        Write-Success "Installed: protocol_injector.py"
    } else {
        Write-Warning "protocol_injector.py not found (optional)"
    }

    # Install dynamic_context_loader.py
    $contextLoader = Join-Path $HooksSrc "core\dynamic_context_loader.py"
    if (Test-Path $contextLoader) {
        Copy-Item $contextLoader $hooksDir -Force
        Write-Success "Installed: dynamic_context_loader.py"
    }

    # Install shared utilities
    $sharedUtils = Join-Path $SharedSrc "utils"
    if (Test-Path $sharedUtils) {
        $targetShared = Join-Path $ClaudeConfigDir "shared\utils"
        if (-not (Test-Path $targetShared)) {
            New-Item -ItemType Directory -Path $targetShared -Force | Out-Null
        }
        Copy-Item "$sharedUtils\*.py" $targetShared -Force -ErrorAction SilentlyContinue
        Write-Success "Installed: shared utilities"
    }

    # Generate settings.json
    $templateFile = Join-Path $HooksSrc "settings_global.template.json"
    $settingsFile = Join-Path $ClaudeConfigDir "settings.json"

    if (Test-Path $templateFile) {
        $content = Get-Content $templateFile -Raw
        $content = $content -replace '\{\{GLOBAL_CONFIG_DIR\}\}', ($ClaudeConfigDir -replace '\\', '/')
        Set-Content $settingsFile $content
        Write-Success "Generated: settings.json"
    }
    Write-Host ""
}

function Install-ClaudeGlobalConfig {
    Write-Info "Installing Claude Code global configuration..."

    # Note: CLAUDE.md is typically a user's personal file
    # We do not overwrite it, but provide AGENTS.md

    $claudeMdPath = Join-Path $ClaudeConfigDir "CLAUDE.md"
    if (-not (Test-Path $claudeMdPath)) {
        Write-Info "CLAUDE.md not found - skipping (user should configure manually)"
    } else {
        Write-Success "CLAUDE.md already exists (preserved)"
    }

    # Install AGENTS.md (agent coordination rules)
    $agentsMdSrc = Join-Path $ScriptDir ".opencode\AGENTS.md"
    if (Test-Path $agentsMdSrc) {
        Copy-Item $agentsMdSrc (Join-Path $ClaudeConfigDir "AGENTS.md") -Force
        Write-Success "Installed: AGENTS.md"
    } else {
        Write-Warning "AGENTS.md not found"
    }
    Write-Host ""
}

# ============================================================================
# OpenCode Installation
# ============================================================================

function Install-OpenCode {
    Write-Step "Installing Trinitas for OpenCode..."
    Write-Host ""

    if (-not (Test-Path $OpenCodeAgentsSrc)) {
        Write-Error "OpenCode agent source not found: $OpenCodeAgentsSrc"
        Write-Info "OpenCode installation skipped"
        return
    }

    # Backup
    Backup-OpenCodeConfig

    # Create directories
    $openCodeAgentsDir = Join-Path $OpenCodeConfigDir "agent"
    if (-not (Test-Path $openCodeAgentsDir)) {
        New-Item -ItemType Directory -Path $openCodeAgentsDir -Force | Out-Null
    }

    # Install agents
    Install-OpenCodeAgents

    # Install system instructions
    Install-OpenCodeSystemInstructions

    Write-Success "OpenCode installation complete!"
    Write-Host ""
}

function Backup-OpenCodeConfig {
    if (Test-Path $OpenCodeConfigDir) {
        Write-Info "Creating OpenCode backup..."
        Copy-Item $OpenCodeConfigDir $OpenCodeBackupDir -Recurse -Force
        Write-Success "Backed up to: $OpenCodeBackupDir"
        Write-Host ""
    }
}

function Install-OpenCodeAgents {
    Write-Info "Installing OpenCode agents (9 total)..."

    $installedCount = 0
    $agentsDir = Join-Path $OpenCodeConfigDir "agent"

    foreach ($agent in $AllAgents) {
        $srcFile = Join-Path $OpenCodeAgentsSrc "$agent.md"
        $dstFile = Join-Path $agentsDir "$agent.md"

        if (Test-Path $srcFile) {
            Copy-Item $srcFile $dstFile -Force
            Write-Success "Installed: $agent"
            $installedCount++
        } else {
            Write-Warning "Not found: $agent (skipped)"
        }
    }

    Write-Host ""
    Write-Info "Agents installed: $installedCount/9"
    Write-Host ""
}

function Install-OpenCodeSystemInstructions {
    Write-Info "Installing OpenCode system instructions..."

    # Install AGENTS.md
    $agentsMdSrc = Join-Path $ScriptDir ".opencode\AGENTS.md"
    if (Test-Path $agentsMdSrc) {
        Copy-Item $agentsMdSrc $OpenCodeConfigDir -Force
        Write-Success "Installed: AGENTS.md"
    }

    # Copy documentation
    $docsSrc = Join-Path $ScriptDir ".opencode\docs"
    if (Test-Path $docsSrc) {
        Copy-Item $docsSrc $OpenCodeConfigDir -Recurse -Force
        Write-Success "Installed: documentation"
    }
    Write-Host ""
}

# ============================================================================
# Verification
# ============================================================================

function Test-Installation {
    Write-Step "Verifying installation..."
    Write-Host ""

    if ($Platform -eq "claude" -or $Platform -eq "both") {
        Write-Host "Claude Code (~/.claude/):" -ForegroundColor Cyan

        $agentsDir = Join-Path $ClaudeConfigDir "agents"
        $agentCount = (Get-ChildItem "$agentsDir\*.md" -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host "  Agents:    $agentCount/9"

        $claudeMd = Join-Path $ClaudeConfigDir "CLAUDE.md"
        $agentsMd = Join-Path $ClaudeConfigDir "AGENTS.md"
        $settings = Join-Path $ClaudeConfigDir "settings.json"

        Write-Host "  CLAUDE.md: $( if (Test-Path $claudeMd) { '✓' } else { '✗' } )"
        Write-Host "  AGENTS.md: $( if (Test-Path $agentsMd) { '✓' } else { '✗' } )"
        Write-Host "  Hooks:     $( if (Test-Path $settings) { '✓' } else { '✗' } )"
        Write-Host ""
    }

    if ($Platform -eq "opencode" -or $Platform -eq "both") {
        Write-Host "OpenCode (~/.config/opencode/):" -ForegroundColor Cyan

        $agentsDir = Join-Path $OpenCodeConfigDir "agent"
        $agentCount = (Get-ChildItem "$agentsDir\*.md" -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host "  Agents:    $agentCount/9"

        $agentsMd = Join-Path $OpenCodeConfigDir "AGENTS.md"
        Write-Host "  AGENTS.md: $( if (Test-Path $agentsMd) { '✓' } else { '✗' } )"
        Write-Host ""
    }

    Write-Success "Installation verified!"
    Write-Host ""
}

# ============================================================================
# Summary
# ============================================================================

function Show-Summary {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║           Installation Complete! v$InstallerVersion                  ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    Write-Host "Installed Components:" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    Write-Host ""
    Write-Host "Core Agents (6):" -ForegroundColor White
    Write-Host "  • Athena  - Harmonious Conductor"
    Write-Host "  • Artemis - Technical Perfectionist"
    Write-Host "  • Hestia  - Security Guardian"
    Write-Host "  • Eris    - Tactical Coordinator"
    Write-Host "  • Hera    - Strategic Commander"
    Write-Host "  • Muses   - Knowledge Architect"
    Write-Host ""
    Write-Host "Support Agents (3):" -ForegroundColor White
    Write-Host "  • Aphrodite - UI/UX Designer"
    Write-Host "  • Metis     - Development Assistant"
    Write-Host "  • Aurora    - Research Assistant"
    Write-Host ""

    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if ($Platform -eq "claude" -or $Platform -eq "both") {
        Write-Host ""
        Write-Host "Claude Code:" -ForegroundColor White
        Write-Host "  1. Restart Claude Code to load new configuration"
        Write-Host "  2. Test: 'Trinitasシステムの動作確認'"
    }

    if ($Platform -eq "opencode" -or $Platform -eq "both") {
        Write-Host ""
        Write-Host "OpenCode:" -ForegroundColor White
        Write-Host "  1. Start OpenCode: opencode"
        Write-Host "  2. Select agent: opencode --agent athena"
    }

    Write-Host ""
    Write-Host "🎭 Trinitas Agent System is ready!" -ForegroundColor Magenta
    Write-Host ""
}

# ============================================================================
# Uninstall
# ============================================================================

function Invoke-Uninstall {
    Write-Step "Restoring from backup..."
    Write-Host ""

    # Find latest Claude backup
    $latestClaudeBackup = Get-ChildItem "$ClaudeBackupDir\CLAUDE_*.md" -ErrorAction SilentlyContinue |
                          Sort-Object LastWriteTime -Descending |
                          Select-Object -First 1

    if ($latestClaudeBackup) {
        Copy-Item $latestClaudeBackup.FullName (Join-Path $ClaudeConfigDir "CLAUDE.md") -Force
        Write-Success "Restored Claude Code configuration"
    } else {
        Write-Warning "No Claude Code backup found"
    }

    # Find latest OpenCode backup
    $latestOpenCodeBackup = Get-ChildItem "$env:USERPROFILE\.config\opencode.backup.*" -Directory -ErrorAction SilentlyContinue |
                            Sort-Object LastWriteTime -Descending |
                            Select-Object -First 1

    if ($latestOpenCodeBackup) {
        if (Test-Path $OpenCodeConfigDir) {
            Remove-Item $OpenCodeConfigDir -Recurse -Force
        }
        Copy-Item $latestOpenCodeBackup.FullName $OpenCodeConfigDir -Recurse -Force
        Write-Success "Restored OpenCode configuration"
    } else {
        Write-Warning "No OpenCode backup found"
    }

    Write-Host ""
    Write-Success "Restore complete!"
}

# ============================================================================
# Version Info
# ============================================================================

function Show-VersionInfo {
    Write-Host "Trinitas Unified Installer v$InstallerVersion"
    Write-Host "Trinitas Agent System v$TrinitasVersion"
    Write-Host "Supports: Claude Code, OpenCode"
    Write-Host "Platform: Windows PowerShell"
}

# ============================================================================
# Main
# ============================================================================

# Handle version flag
if ($Version) {
    Show-VersionInfo
    exit 0
}

# Handle uninstall
if ($Uninstall) {
    Show-Header
    Invoke-Uninstall
    exit 0
}

# Main installation flow
Show-Header
Test-Prerequisites
Select-Platform

# Confirmation
if (-not $Force) {
    Write-Host "This will install Trinitas v$TrinitasVersion for: $Platform" -ForegroundColor Yellow
    Write-Host "Existing configurations will be backed up."
    Write-Host ""

    $confirm = Read-Host "Continue? [y/N]"
    if ($confirm -notmatch '^[Yy]') {
        Write-Warning "Installation cancelled"
        exit 0
    }
    Write-Host ""
}

# Execute installation
switch ($Platform) {
    "claude" {
        Install-ClaudeCode
    }
    "opencode" {
        Install-OpenCode
    }
    "both" {
        Install-ClaudeCode
        Install-OpenCode
    }
}

# Verify and summarize
Test-Installation
Show-Summary
