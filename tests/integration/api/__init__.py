"""Integration tests for TMWS API endpoints.

This package contains integration tests that verify the full stack:
- FastAPI Router → Application Use Case → Infrastructure Repository → Real Database

Tests use real SQLite :memory: database but mock external services (MCP adapter).
"""
