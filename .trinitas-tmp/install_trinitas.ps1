# Trinitas v2.2.0 Windows PowerShell Installer
# This script delegates the installation to the cross-platform Python script
# to ensure consistent behavior across all operating systems.
# Usage: .\install_trinitas.ps1

[CmdletBinding()]
param (
    [Switch]$Force,
    [ValidateSet("default", "minimal", "optimize")]
    [string]$Mode = "default"
)

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  Trinitas v2.2.0 Windows Installer (Delegated)  " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# --- 1. Check for Python ---
Write-Host "Step 1: Checking for Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
}
catch {
    Write-Host "✗ Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "  Please install Python 3.8+ from https://python.org and ensure it's in your PATH."
    exit 1
}

# --- 2. Check for Python Installer Script ---
$pythonInstaller = "install_trinitas.py"
Write-Host "Step 2: Verifying Python installer script..." -ForegroundColor Yellow
if (-not (Test-Path $pythonInstaller)) {
    Write-Host "✗ Critical: '$pythonInstaller' not found in the current directory." -ForegroundColor Red
    Write-Host "  Please run this script from the root of the trinitas-agents repository."
    exit 1
}
Write-Host "✓ Python installer found." -ForegroundColor Green

# --- 3. Delegate to Python Installer ---
Write-Host "Step 3: Delegating installation to '$pythonInstaller'..." -ForegroundColor Yellow
Write-Host "This ensures a consistent installation experience."

$pythonArgs = @("--mode", $Mode)
if ($Force) {
    $pythonArgs += "--yes"
}

Write-Host "Executing: python $pythonInstaller $($pythonArgs -join ' ')" -ForegroundColor Gray

# Execute the Python script
python $pythonInstaller $pythonArgs

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  PowerShell wrapper script finished.       " -ForegroundColor Green
    Write-Host "  Installation managed by Python script.    " -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "✗ An error occurred during the Python installation script." -ForegroundColor Red
    Write-Host "  Please review the output above for details."
    exit 1
}

# The Python script now handles all installation, backup, and summary logic.