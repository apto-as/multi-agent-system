# Trinitas System Windows Installer v2.2.4 (PowerShell)
# Run with: powershell -ExecutionPolicy Bypass -File install.ps1
# This installer copies Trinitas agents, hooks, and configuration to ~/.claude/

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Trinitas System Installer v2.2.4" -ForegroundColor Cyan
Write-Host "Windows (PowerShell)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ターゲットディレクトリの設定
if ($env:CLAUDE_HOME) {
    $targetDir = $env:CLAUDE_HOME
} else {
    $targetDir = Join-Path $env:USERPROFILE ".claude"
}

Write-Host "Target directory: $targetDir" -ForegroundColor Yellow
Write-Host ""

# .claudeディレクトリの作成
if (-not (Test-Path $targetDir)) {
    Write-Host "Creating .claude directory..." -ForegroundColor Gray
    try {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        Write-Host "Directory created successfully." -ForegroundColor Green
    } catch {
        Write-Host "Error: Failed to create .claude directory" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host ".claude directory already exists." -ForegroundColor Gray
}

Write-Host ""
Write-Host "Copying files..." -ForegroundColor Yellow
Write-Host ""

# コピー対象のファイルリスト
$files = @(
    "CLAUDE.md",
    "AGENTS.md",
    "TRINITAS-CORE-PROTOCOL.md",
    "settings.json"
)

# ファイルのコピー
foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "Copying $file..." -NoNewline
        try {
            Copy-Item -Path $file -Destination $targetDir -Force
            Write-Host " [OK]" -ForegroundColor Green
        } catch {
            Write-Host " [ERROR]" -ForegroundColor Red
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "$file" -NoNewline
        Write-Host " [SKIP] (not found)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Copying directories..." -ForegroundColor Yellow
Write-Host ""

# コピー対象のディレクトリリスト
$directories = @(
    "agents",
    "commands",
    "hooks",
    "config",
    "contexts",
    "shared"
)

# ディレクトリのコピー
foreach ($dir in $directories) {
    if (Test-Path $dir) {
        Write-Host "Copying $dir directory..." -NoNewline
        $targetSubDir = Join-Path $targetDir $dir
        try {
            # ターゲットディレクトリが存在する場合は削除
            if (Test-Path $targetSubDir) {
                Remove-Item -Path $targetSubDir -Recurse -Force
            }
            # ディレクトリをコピー
            Copy-Item -Path $dir -Destination $targetSubDir -Recurse -Force
            Write-Host " [OK]" -ForegroundColor Green
        } catch {
            Write-Host " [ERROR]" -ForegroundColor Red
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "$dir/" -NoNewline
        Write-Host " [SKIP] (not found)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files have been copied to:" -ForegroundColor Yellow
Write-Host "  $targetDir" -ForegroundColor White
Write-Host ""
Write-Host "To verify the installation, run:" -ForegroundColor Gray
Write-Host "  Get-ChildItem `"$targetDir`"" -ForegroundColor White
Write-Host ""

# 実行ポリシーの確認と推奨事項
$executionPolicy = Get-ExecutionPolicy
if ($executionPolicy -eq "Restricted") {
    Write-Host "Note: PowerShell execution policy is currently set to 'Restricted'." -ForegroundColor Yellow
    Write-Host "To run this script in the future, use:" -ForegroundColor Yellow
    Write-Host "  powershell -ExecutionPolicy Bypass -File install.ps1" -ForegroundColor White
    Write-Host ""
}

# Python installation check
Write-Host "Checking Python installation..." -ForegroundColor Yellow
$pythonFound = $false
$pythonCmd = ""

# Try python3 first (Windows Store version)
try {
    $null = python3 --version 2>&1
    $pythonCmd = "python3"
    $pythonFound = $true
} catch {
    # Try python
    try {
        $null = python --version 2>&1
        $pythonCmd = "python"
        $pythonFound = $true
    } catch {
        # Try py launcher
        try {
            $null = py --version 2>&1
            $pythonCmd = "py"
            $pythonFound = $true
        } catch {
            $pythonFound = $false
        }
    }
}

if ($pythonFound) {
    Write-Host "  Python found: $pythonCmd" -ForegroundColor Green
    Write-Host "  Note: Trinitas hooks require Python 3.8 or higher" -ForegroundColor White
} else {
    Write-Host "  Warning: Python not found in PATH" -ForegroundColor Yellow
    Write-Host "  Trinitas hooks require Python 3.8 or higher" -ForegroundColor Yellow
    Write-Host "  Please install Python from https://python.org" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")