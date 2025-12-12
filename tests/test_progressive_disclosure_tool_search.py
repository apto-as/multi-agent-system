"""Tests for Progressive Disclosure in Tool Search (Issue #66).

Tests 3-tier progressive disclosure:
- Level 1: Metadata only (~64 tokens, 85% reduction)
- Level 2: Core info (~128 tokens, schema summary)
- Level 3: Full schema (complete tool definition)

Author: Artemis (Implementation)
Created: 2025-12-12
Issue: #66
"""

import pytest

from src.services.tool_search_service import ToolSearchService, ToolSearchConfig
from src.models.tool_search import ToolMetadata, ToolSourceType


@pytest.fixture
def tool_search_service():
    """Create a ToolSearchService for testing."""
    config = ToolSearchConfig(
        collection_name="test_tools_progressive_disclosure",
        enable_adaptive_ranking=False,  # Disable for simpler testing
    )
    return ToolSearchService(
        config=config,
        persist_directory="./data/test_chromadb",
        embedding_service=None,  # Use ChromaDB default
    )


@pytest.fixture
async def populated_service(tool_search_service):
    """Populate service with test tools."""
    # Ensure service is initialized
    await tool_search_service.initialize()

    # Create tools with various schema complexities
    tools = [
        ToolMetadata(
            name="simple_tool",
            description="A simple tool with minimal schema",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
            tags=["search", "simple"],
        ),
        ToolMetadata(
            name="complex_tool",
            description="A complex tool with extensive schema and nested properties",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Main search query parameter with detailed explanation",
                    },
                    "filters": {
                        "type": "object",
                        "description": "Complex filter object",
                        "properties": {
                            "date_range": {
                                "type": "object",
                                "properties": {
                                    "start": {"type": "string"},
                                    "end": {"type": "string"},
                                },
                            },
                            "tags": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 10,
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["semantic", "regex", "hybrid"],
                        "description": "Search mode selection",
                    },
                },
                "required": ["query"],
            },
            tags=["search", "complex", "advanced"],
        ),
    ]

    await tool_search_service.register_internal_tools(tools)
    return tool_search_service


@pytest.mark.asyncio
async def test_detail_level_1_metadata_only(populated_service):
    """Test detail_level=1 returns only metadata (~64 tokens)."""
    results = await populated_service.search_tools(
        query="search",
        detail_level=1,
        limit=5,
    )

    assert len(results) > 0
    result = results[0]

    # Level 1 must have these fields
    assert "tool_name" in result
    assert "server_id" in result
    assert "description" in result
    assert "relevance_score" in result
    assert "weighted_score" in result
    assert "source_type" in result
    assert "tags" in result
    assert "detail_level" in result
    assert result["detail_level"] == 1

    # Level 1 must NOT have schema
    assert "input_schema" not in result
    assert "input_schema_summary" not in result

    # Description should be truncated at 200 chars
    if len(result["description"]) > 200:
        assert result["description"].endswith("...")


@pytest.mark.asyncio
async def test_detail_level_2_core_with_summary(populated_service):
    """Test detail_level=2 returns metadata + schema summary (~128 tokens)."""
    results = await populated_service.search_tools(
        query="complex",
        detail_level=2,
        limit=5,
    )

    assert len(results) > 0
    result = results[0]

    # Level 2 must have metadata
    assert "tool_name" in result
    assert "description" in result
    assert "detail_level" in result
    assert result["detail_level"] == 2

    # Level 2 must have schema SUMMARY (not full)
    assert "input_schema_summary" in result
    assert "input_schema" not in result

    # Verify summary structure
    summary = result["input_schema_summary"]
    assert "type" in summary
    assert "required" in summary
    assert "properties" in summary

    # Verify properties only have type (no descriptions)
    for prop_name, prop_data in summary["properties"].items():
        assert "type" in prop_data
        # Should NOT have descriptions (token reduction)
        assert "description" not in prop_data


@pytest.mark.asyncio
async def test_detail_level_3_full_schema(populated_service):
    """Test detail_level=3 returns complete tool definition."""
    results = await populated_service.search_tools(
        query="complex",
        detail_level=3,
        limit=5,
    )

    assert len(results) > 0
    result = results[0]

    # Level 3 must have metadata
    assert "tool_name" in result
    assert "description" in result
    assert "detail_level" in result
    assert result["detail_level"] == 3

    # Level 3 must have FULL schema
    assert "input_schema" in result
    # Summary is redundant at level 3
    assert "input_schema_summary" not in result

    # Verify full schema has descriptions
    schema = result["input_schema"]
    assert "properties" in schema
    for prop_name, prop_data in schema["properties"].items():
        # Complex tool should have descriptions
        if prop_name == "query":
            assert "description" in prop_data


@pytest.mark.asyncio
async def test_backward_compatibility_defer_loading(populated_service):
    """Test defer_loading=True maps to detail_level=1 (backward compat)."""
    results = await populated_service.search_tools(
        query="search",
        defer_loading=True,
        limit=5,
    )

    assert len(results) > 0
    result = results[0]

    # Should behave like detail_level=1
    assert result["detail_level"] == 1
    assert "input_schema" not in result
    assert "input_schema_summary" not in result


@pytest.mark.asyncio
async def test_default_is_level_3(populated_service):
    """Test default behavior is detail_level=3 (full schema, backward compat)."""
    results = await populated_service.search_tools(
        query="search",
        limit=5,
    )

    assert len(results) > 0
    result = results[0]

    # Default should be level 3
    assert result["detail_level"] == 3
    assert "input_schema" in result


@pytest.mark.asyncio
async def test_token_reduction_estimation():
    """Estimate token reduction from Level 1 vs Level 3."""
    # This is a qualitative test to verify ~85% reduction
    service = ToolSearchService(
        config=ToolSearchConfig(collection_name="test_token_reduction"),
        persist_directory="./data/test_chromadb",
    )
    await service.initialize()

    # Create a tool with large schema (realistic MCP tool)
    large_tool = ToolMetadata(
        name="large_schema_tool",
        description="Tool with extensive schema representing a typical MCP tool",
        input_schema={
            "type": "object",
            "properties": {
                f"param_{i}": {
                    "type": "string",
                    "description": f"Parameter {i} with detailed description explaining its purpose and usage",
                }
                for i in range(20)  # 20 parameters with descriptions
            },
            "required": [f"param_{i}" for i in range(5)],
        },
        tags=["large", "test"],
    )

    await service.register_internal_tools([large_tool])

    # Get Level 1 (metadata only)
    results_l1 = await service.search_tools("large", detail_level=1, limit=1)
    # Get Level 3 (full schema)
    results_l3 = await service.search_tools("large", detail_level=3, limit=1)

    assert len(results_l1) == 1
    assert len(results_l3) == 1

    # Convert to strings to estimate size
    import json
    l1_size = len(json.dumps(results_l1[0]))
    l3_size = len(json.dumps(results_l3[0]))

    # Level 1 should be significantly smaller
    reduction_percentage = (1 - l1_size / l3_size) * 100
    print(f"\nToken reduction: {reduction_percentage:.1f}%")
    print(f"Level 1 size: {l1_size} chars")
    print(f"Level 3 size: {l3_size} chars")

    # Should achieve >70% reduction (target is 85%)
    assert reduction_percentage > 70, f"Only {reduction_percentage:.1f}% reduction"


@pytest.mark.asyncio
async def test_schema_summary_preserves_enums(populated_service):
    """Test that schema summary preserves enum values (compact and useful)."""
    results = await populated_service.search_tools(
        query="complex",
        detail_level=2,
        limit=5,
    )

    result = next((r for r in results if r["tool_name"] == "complex_tool"), None)
    assert result is not None

    summary = result["input_schema_summary"]
    mode_prop = summary["properties"]["mode"]

    # Enums should be preserved in summary (compact and useful)
    assert "enum" in mode_prop
    assert mode_prop["enum"] == ["semantic", "regex", "hybrid"]


@pytest.mark.asyncio
async def test_description_truncation_only_at_level_1(populated_service):
    """Test description is only truncated at level 1."""
    # Create tool with long description
    long_desc_tool = ToolMetadata(
        name="long_description_tool",
        description="A" * 300,  # 300 char description
        input_schema={"type": "object", "properties": {}},
    )
    await populated_service.register_internal_tools([long_desc_tool])

    # Level 1: Should truncate
    results_l1 = await populated_service.search_tools(
        "long_description", detail_level=1, limit=1
    )
    assert len(results_l1) == 1
    assert results_l1[0]["description"].endswith("...")
    assert len(results_l1[0]["description"]) <= 203  # 200 + "..."

    # Level 2: Should NOT truncate
    results_l2 = await populated_service.search_tools(
        "long_description", detail_level=2, limit=1
    )
    assert len(results_l2) == 1
    assert not results_l2[0]["description"].endswith("...")
    assert len(results_l2[0]["description"]) == 300


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
