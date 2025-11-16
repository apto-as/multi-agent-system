@echo off
REM TMWS Startup Script - Windows
REM Purpose: One-command startup for Windows with automatic configuration

setlocal enabledelayedexpansion

echo [92m========================================[0m
echo [92mTMWS Startup - Windows Environment[0m
echo [92m========================================[0m
echo.

REM Step 1: Check Docker Desktop
where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo [91mX Docker not found[0m
    echo    Install Docker Desktop from: https://www.docker.com/get-started
    exit /b 1
)

docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [91mX Docker is not running[0m
    echo    Please start Docker Desktop and try again.
    exit /b 1
)

echo [92m✓ Docker is running[0m

REM Step 2: Check docker-compose
docker compose version >nul 2>&1
if %errorlevel% equ 0 (
    set DOCKER_COMPOSE=docker compose
) else (
    docker-compose --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [91mX docker-compose not found[0m
        echo    Please ensure Docker Desktop is up to date.
        exit /b 1
    )
    set DOCKER_COMPOSE=docker-compose
)

echo [92m✓ docker-compose available[0m

REM Step 3: Check .env file
if not exist .env (
    echo [93m! .env not found, creating from .env.example[0m
    if exist .env.example (
        copy .env.example .env >nul
        echo [92m✓ Created .env from template[0m
        echo [93m! Please review .env and set TMWS_SECRET_KEY if needed[0m
    ) else (
        echo [91mX .env.example not found[0m
        exit /b 1
    )
)

REM Step 4: Start TMWS (Windows uses full Docker mode)
echo.
echo [96mStarting TMWS with docker-compose.yml...[0m
%DOCKER_COMPOSE% -f docker-compose.yml up -d

if %errorlevel% neq 0 (
    echo [91mX Failed to start TMWS[0m
    echo    Check logs with: %DOCKER_COMPOSE% -f docker-compose.yml logs
    exit /b 1
)

REM Step 5: Wait for health check
echo [96mWaiting for TMWS health check...[0m
set /a attempts=0
set /a max_attempts=30

:health_check_loop
if %attempts% geq %max_attempts% (
    echo [91mX Health check timeout[0m
    echo    Check logs: %DOCKER_COMPOSE% -f docker-compose.yml logs tmws
    exit /b 1
)

curl -s http://localhost:8000/health >nul 2>&1
if %errorlevel% equ 0 (
    goto health_check_passed
)

set /a attempts+=1
timeout /t 1 /nobreak >nul
goto health_check_loop

:health_check_passed
echo [92m✓ Health check passed![0m
echo.
echo [92m========================================[0m
echo [92m✓ TMWS started successfully![0m
echo [92m========================================[0m
echo.
echo [96mTMWS API:[0m http://localhost:8000
echo [96mAPI Docs:[0m http://localhost:8000/docs
echo [96mHealth:[0m http://localhost:8000/health
echo.
echo [93mNext steps:[0m
echo    1. Configure Claude Desktop MCP:
echo       Update MCP settings with: scripts\mcp\tmws-mcp-docker.bat
echo    2. View logs: %DOCKER_COMPOSE% -f docker-compose.yml logs -f
echo    3. Stop TMWS: scripts\stop-tmws.bat
echo.

REM Optional: Tail logs if --logs flag provided
if "%1"=="--logs" (
    echo [96mTailing logs (Ctrl+C to exit)...[0m
    %DOCKER_COMPOSE% -f docker-compose.yml logs -f
)

endlocal
