# ========================================
# TMWS Windows Secure Environment Setup
# Hestia Security Audit: 2025-11-29
# ========================================
# 🔥 このスクリプトは管理者権限で実行してください
# 🔥 秘密情報を安全に生成・保存します
# ========================================

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🔥 TMWS Security-Hardened Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ========================================
# 1. 作業ディレクトリの確認
# ========================================
$ProjectRoot = $PSScriptRoot | Split-Path | Split-Path
Write-Host "[1/6] Project root: $ProjectRoot" -ForegroundColor Yellow

if (-not (Test-Path "$ProjectRoot\pyproject.toml")) {
    Write-Host "❌ ERROR: Not in TMWS project directory" -ForegroundColor Red
    exit 1
}

# ========================================
# 2. .gitignoreの確認と更新
# ========================================
Write-Host "[2/6] Checking .gitignore..." -ForegroundColor Yellow

$gitignorePath = Join-Path $ProjectRoot ".gitignore"
$requiredPatterns = @(
    ".env",
    ".env.local",
    ".env.production",
    ".env.test",
    "*.key",
    "secrets/",
    ".tmws/secrets/"
)

$gitignoreContent = ""
if (Test-Path $gitignorePath) {
    $gitignoreContent = Get-Content $gitignorePath -Raw
}

$updated = $false
foreach ($pattern in $requiredPatterns) {
    if ($gitignoreContent -notmatch [regex]::Escape($pattern)) {
        Write-Host "  ➕ Adding pattern: $pattern" -ForegroundColor Green
        Add-Content -Path $gitignorePath -Value $pattern
        $updated = $true
    }
}

if ($updated) {
    Write-Host "  ✅ .gitignore updated" -ForegroundColor Green
} else {
    Write-Host "  ✅ .gitignore already complete" -ForegroundColor Green
}

# ========================================
# 3. 秘密鍵の生成
# ========================================
Write-Host "[3/6] Generating secret keys..." -ForegroundColor Yellow

# OpenSSLの確認（WSL経由またはGit Bashのopenssl.exeを使用）
$opensslPath = $null
$possiblePaths = @(
    "C:\Program Files\Git\usr\bin\openssl.exe",
    "C:\Program Files (x86)\Git\usr\bin\openssl.exe"
)

foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $opensslPath = $path
        break
    }
}

if (-not $opensslPath) {
    # WSL経由でopenssl実行
    try {
        $testResult = wsl openssl version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $opensslPath = "wsl openssl"
            Write-Host "  ℹ️ Using WSL openssl" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "❌ ERROR: OpenSSL not found. Please install Git for Windows or WSL." -ForegroundColor Red
        exit 1
    }
}

# TMWS_SECRET_KEY生成
Write-Host "  🔐 Generating TMWS_SECRET_KEY..." -ForegroundColor Cyan
if ($opensslPath -like "wsl*") {
    $secretKey = (wsl openssl rand -hex 32) -replace "`r", "" -replace "`n", ""
} else {
    $secretKey = (& $opensslPath rand -hex 32) -replace "`r", "" -replace "`n", ""
}

if ($secretKey.Length -ne 64) {
    Write-Host "❌ ERROR: Invalid secret key length: $($secretKey.Length)" -ForegroundColor Red
    exit 1
}

Write-Host "  ✅ TMWS_SECRET_KEY: $($secretKey.Substring(0, 16))... (64 chars)" -ForegroundColor Green

# ========================================
# 4. .env.productionファイルの作成
# ========================================
Write-Host "[4/6] Creating .env.production..." -ForegroundColor Yellow

$envPath = Join-Path $ProjectRoot ".env.production"

# 既存ファイルのバックアップ
if (Test-Path $envPath) {
    $backupPath = "$envPath.backup.$(Get-Date -Format 'yyyyMMddHHmmss')"
    Copy-Item $envPath $backupPath
    Write-Host "  ℹ️ Existing .env.production backed up to: $backupPath" -ForegroundColor Cyan
}

# .env.productionテンプレート
$envContent = @"
# ========================================
# TMWS Production Environment
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# ========================================
# 🔥 DO NOT COMMIT THIS FILE TO GIT
# ========================================

# Database (SQLite with WAL mode)
TMWS_DATABASE_URL=sqlite+aiosqlite:///app/.tmws/db/tmws.db

# Secret Key (JWT signing)
TMWS_SECRET_KEY=$secretKey

# License Key (TODO: Obtain from Trinitas licensing service)
TMWS_LICENSE_KEY=YOUR_LICENSE_KEY_HERE

# Ollama Configuration
TMWS_OLLAMA_BASE_URL=http://host.docker.internal:11434
TMWS_OLLAMA_TIMEOUT=30

# Environment
TMWS_ENVIRONMENT=production
TMWS_LOG_LEVEL=INFO

# Security Settings
TMWS_SECURITY_HEADERS_ENABLED=true
TMWS_SESSION_TIMEOUT=3600
TMWS_MAX_REQUEST_SIZE=10485760

# CORS (adjust for your domain)
TMWS_CORS_ORIGINS=["http://localhost:3000"]

# API Key Expiration (days)
TMWS_API_KEY_EXPIRE_DAYS=90

# ========================================
# Security Notes:
# - TMWS_SECRET_KEY: MUST be kept secret
# - Rotate every 90 days (next: $(Get-Date).AddDays(90).ToString('yyyy-MM-dd'))
# - Never commit to version control
# ========================================
"@

Set-Content -Path $envPath -Value $envContent -NoNewline
Write-Host "  ✅ Created: $envPath" -ForegroundColor Green

# ========================================
# 5. ファイルパーミッションの設定
# ========================================
Write-Host "[5/6] Setting file permissions..." -ForegroundColor Yellow

# .env.productionのACL設定
$acl = Get-Acl $envPath
$acl.SetAccessRuleProtection($true, $false)  # 継承を無効化

# 現在のユーザーのみアクセス許可
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $env:USERNAME,
    "FullControl",
    "Allow"
)
$acl.SetAccessRule($accessRule)
Set-Acl $envPath $acl

Write-Host "  ✅ Permissions set: $env:USERNAME (FullControl only)" -ForegroundColor Green

# データディレクトリの作成とパーミッション設定
$dataDirs = @(
    "data\db",
    "data\vector_store",
    "data\logs"
)

foreach ($dir in $dataDirs) {
    $dirPath = Join-Path $ProjectRoot $dir
    if (-not (Test-Path $dirPath)) {
        New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
        Write-Host "  ➕ Created: $dirPath" -ForegroundColor Green
    }

    # ACL設定
    $dirAcl = Get-Acl $dirPath
    $dirAcl.SetAccessRuleProtection($true, $false)
    $dirAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $env:USERNAME,
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $dirAcl.SetAccessRule($dirAccessRule)
    Set-Acl $dirPath $dirAcl
}

Write-Host "  ✅ Data directories secured" -ForegroundColor Green

# ========================================
# 6. システム環境変数の設定（オプション）
# ========================================
Write-Host "[6/6] Setting system environment variables..." -ForegroundColor Yellow

$setEnvVar = Read-Host "  Set TMWS_SECRET_KEY as user environment variable? (y/N)"
if ($setEnvVar -eq 'y' -or $setEnvVar -eq 'Y') {
    [System.Environment]::SetEnvironmentVariable(
        "TMWS_SECRET_KEY",
        $secretKey,
        [System.EnvironmentVariableTarget]::User
    )
    Write-Host "  ✅ TMWS_SECRET_KEY set in user environment" -ForegroundColor Green
    Write-Host "  ℹ️ Restart your terminal to apply changes" -ForegroundColor Cyan
} else {
    Write-Host "  ⏭️ Skipped (will use .env.production)" -ForegroundColor Yellow
}

# ========================================
# 完了メッセージ
# ========================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ Security setup completed!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review and edit .env.production (set TMWS_LICENSE_KEY)" -ForegroundColor White
Write-Host "  2. Build Docker image: docker-compose build" -ForegroundColor White
Write-Host "  3. Start TMWS: docker-compose --env-file .env.production up -d" -ForegroundColor White
Write-Host ""
Write-Host "Security reminders:" -ForegroundColor Yellow
Write-Host "  🔥 Rotate TMWS_SECRET_KEY every 90 days" -ForegroundColor Red
Write-Host "  🔥 Never commit .env.production to Git" -ForegroundColor Red
Write-Host "  🔥 Backup .env.production securely (encrypted storage)" -ForegroundColor Red
Write-Host ""
Write-Host "Key rotation schedule:" -ForegroundColor Cyan
Write-Host "  Next rotation: $((Get-Date).AddDays(90).ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host ""
