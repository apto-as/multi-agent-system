"""Tool entity for MCP Integration.

Tool is an entity that represents a tool discovered from an MCP server.
Unlike value objects, entities have identity and lifecycle.

Two tools are considered the same if they have the same name,
even if their other properties differ (e.g., description updated).

Author: Athena (TDD) + Hera (DDD)
Created: 2025-11-12 (Phase 1-1: Day 1)
"""

from dataclasses import dataclass, field

from src.domain.value_objects.tool_category import ToolCategory


@dataclass
class Tool:
    """Entity representing a tool from an MCP server.

    Tools are entities with identity based on their name.
    Two tools with the same name are considered the same entity,
    even if their other properties differ.

    Attributes:
        name: Unique identifier for the tool (within a connection)
        description: Human-readable description of what the tool does
        input_schema: JSON Schema defining the tool's input parameters
        category: Functional category of the tool (auto-inferred if not provided)

    Example:
        >>> tool = Tool(
        ...     name="store_memory",
        ...     description="Store a new memory",
        ...     input_schema={"type": "object", "properties": {"content": {"type": "string"}}}
        ... )
        >>> tool.name
        'store_memory'
        >>> tool.category
        ToolCategory.MEMORY
    """

    name: str
    description: str
    input_schema: dict = field(default_factory=dict)
    category: ToolCategory = field(default=ToolCategory.GENERAL)

    def __post_init__(self):
        """Initialize entity after dataclass construction.

        - Auto-infer category if not explicitly set
        - Validate required fields
        """
        # Validate required fields
        if not self.name or not self.name.strip():
            raise ValueError("Tool name cannot be empty")

        if not self.description or not self.description.strip():
            raise ValueError("Tool description cannot be empty")

        # Auto-infer category if it's still GENERAL
        if self.category == ToolCategory.GENERAL:
            self.category = ToolCategory.infer_from_name(self.name, self.description)

    def __eq__(self, other: object) -> bool:
        """Entity equality based on identity (name).

        Two tools are equal if they have the same name,
        regardless of other properties.

        Args:
            other: Object to compare with

        Returns:
            True if both tools have the same name

        Example:
            >>> tool1 = Tool(name="test", description="Original")
            >>> tool2 = Tool(name="test", description="Updated")
            >>> tool1 == tool2
            True
        """
        if not isinstance(other, Tool):
            return False
        return self.name == other.name

    def __hash__(self) -> int:
        """Hash based on identity (name).

        This allows Tool entities to be used in sets and as dict keys.

        Returns:
            Hash of the tool name

        Example:
            >>> tool = Tool(name="test", description="Test tool")
            >>> tool_set = {tool}
            >>> tool in tool_set
            True
        """
        return hash(self.name)

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"Tool("
            f"name='{self.name}', "
            f"category={self.category.value}, "
            f"description='{self.description[:50]}...'"
            f")"
        )

    def __str__(self) -> str:
        """User-friendly representation."""
        return f"{self.name} ({self.category.value}): {self.description}"

    def matches_schema_requirements(self) -> bool:
        """Check if input schema is valid JSON Schema.

        Returns:
            True if schema is valid (has 'type' field)

        Example:
            >>> tool = Tool(
            ...     name="test",
            ...     description="Test",
            ...     input_schema={"type": "object", "properties": {}}
            ... )
            >>> tool.matches_schema_requirements()
            True
        """
        if not self.input_schema:
            return True  # Empty schema is valid (no input)

        # Basic validation: must have 'type' field
        return "type" in self.input_schema
