@echo off
REM TMWS Shutdown Script - Windows
REM Purpose: One-command graceful shutdown with data preservation

setlocal enabledelayedexpansion

echo [92m========================================[0m
echo [92mTMWS Shutdown - Graceful Stop[0m
echo [92m========================================[0m
echo.

REM Step 1: Check if Docker is available
where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo [91mX Docker not found[0m
    exit /b 1
)

REM Step 2: Determine docker-compose command
docker compose version >nul 2>&1
if %errorlevel% equ 0 (
    set DOCKER_COMPOSE=docker compose
) else (
    docker-compose --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [91mX docker-compose not found[0m
        exit /b 1
    )
    set DOCKER_COMPOSE=docker-compose
)

REM Step 3: Check if TMWS is running
%DOCKER_COMPOSE% -f docker-compose.yml ps | findstr tmws >nul 2>&1
if %errorlevel% neq 0 (
    echo [93m! TMWS is not running[0m
    echo    No action needed.
    exit /b 0
)

REM Step 4: Stop containers (preserve volumes by default)
echo [96mStopping TMWS containers...[0m
%DOCKER_COMPOSE% -f docker-compose.yml down

if %errorlevel% equ 0 (
    echo.
    echo [92m========================================[0m
    echo [92m✓ TMWS stopped successfully[0m
    echo [92m========================================[0m
    echo.
    echo [96mData preserved in .\data\[0m
    echo.
    echo [93mNext steps:[0m
    echo    • Restart: scripts\start-tmws.bat
    echo    • Remove all data: %DOCKER_COMPOSE% -f docker-compose.yml down -v
    echo    • View stopped containers: docker ps -a
    echo.
) else (
    echo [91mX Failed to stop TMWS[0m
    echo    Check running containers: docker ps
    exit /b 1
)

endlocal
