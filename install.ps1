# Trinitas System Windows Installer (PowerShell)
# Run with: powershell -ExecutionPolicy Bypass -File install.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Trinitas System Windows Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ターゲットディレクトリの設定
$targetDir = Join-Path $env:USERPROFILE ".claude"

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
    "hooks"
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

Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")