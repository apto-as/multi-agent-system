# FastAPI Legacy Tests (v2.x)

## Status: ARCHIVED

These tests were written for TMWS v2.x which used FastAPI for REST API endpoints.

## Architecture Change

**Date**: 2025-10-13  
**Version**: v3.0  
**Change**: Migrated from FastAPI to MCP-only architecture

## Files

- `test_api_router_functions.py` - Direct API router function tests
- `test_api_key_management.py` - API key management integration tests

## Why Archived

TMWS v3.0 removed FastAPI completely and migrated to Model Context Protocol (MCP) only.
The `src/api/` directory no longer exists.

## Future

These tests may be:
1. Converted to MCP tool tests
2. Kept as historical reference
3. Deleted if no longer relevant

## Reference

- Migration commit: 81df488
- Architecture docs: See v3.0 migration planning documents
