@echo off
REM TMWS MCP Docker Wrapper for Claude Desktop (Windows)
REM Purpose: Bridge Claude Desktop <-> Docker container for MCP protocol
REM Architecture: Claude Desktop -> this script -> docker exec -> MCP Server

setlocal enabledelayedexpansion

REM Configuration
set CONTAINER_NAME=tmws-app
set MCP_COMMAND=python -m src.mcp_server

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker is not running.
    echo --^> Please start Docker Desktop and try again.
    exit /b 1
)

REM Check if container exists
docker ps -a --format "{{.Names}}" | findstr /x "%CONTAINER_NAME%" >nul 2>&1
if errorlevel 1 (
    echo ERROR: TMWS container '%CONTAINER_NAME%' does not exist.
    echo --^> Run: scripts\start-tmws.bat
    echo --^> Or: docker-compose up -d
    exit /b 1
)

REM Check if container is running
docker ps --format "{{.Names}}" | findstr /x "%CONTAINER_NAME%" >nul 2>&1
if errorlevel 1 (
    echo ERROR: TMWS container '%CONTAINER_NAME%' is not running.
    echo --^> Start the container: docker-compose up -d
    echo --^> Or run: scripts\start-tmws.bat
    exit /b 1
)

REM Execute MCP server inside container
REM -i: Keep STDIN open (required for MCP stdio protocol)
REM The MCP protocol communicates via stdin/stdout
docker exec -i %CONTAINER_NAME% %MCP_COMMAND%

REM Exit with the same code as the docker exec command
exit /b %errorlevel%
