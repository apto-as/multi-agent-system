# TMWS Command Usage Guide

## Important Note
Claude Code uses MCP (Model Context Protocol) tools directly. Python scripts cannot be installed as custom commands. Instead, TMWS functionality is accessed through MCP tools when the TMWS server is configured in Claude Desktop.

## Setup

1. **Configure Claude Desktop** with TMWS MCP server:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws", "tmws"],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://tmws_user:tmws_password@localhost:5432/tmws",
        "TMWS_SECRET_KEY": "your-secret-key",
        "TMWS_ENVIRONMENT": "development"
      }
    }
  }
}
```

2. **Restart Claude Desktop** to load the MCP server

## Available MCP Tools

Once configured, the following MCP tools become available:

### Memory Operations
- `store_memory` - Store new memories
- `recall_memories` - Retrieve memories
- `semantic_search` - Semantic similarity search

### Workflow Management
- `create_workflow` - Create workflow definitions
- `execute_workflow` - Execute workflows
- `list_workflows` - List all workflows

### Task Management
- `create_task` - Create new tasks
- `complete_task` - Mark tasks as complete
- `list_tasks` - List tasks with filters

### Persona Operations
- `execute_persona` - Execute with specific persona
- `multi_persona_analysis` - Parallel persona analysis

## Usage Examples

When TMWS MCP server is configured, you can ask Claude to:

```
"Store this optimization pattern in TMWS memory with high importance"
"Recall all memories about database optimization"
"Create a security audit workflow"
"Execute the deployment workflow with production parameters"
"Analyze this architecture with Athena, Artemis, and Hestia personas"
```

Claude will automatically use the appropriate MCP tools to execute these requests.

## Hooks Integration (Optional)

If you need to trigger Python scripts, use Claude Code's hooks feature:

### Example Hook Configuration
Create `.claude/hooks/tmws-hook.py`:

```python
#!/usr/bin/env python3
import json
import sys

def on_command(command_data):
    """Hook that triggers on specific commands"""
    if "tmws" in command_data.get("message", "").lower():
        # Process TMWS-related commands
        return {"status": "processed", "action": "continue"}
    return {"status": "ignored"}

if __name__ == "__main__":
    input_data = json.loads(sys.stdin.read())
    result = on_command(input_data)
    print(json.dumps(result))
```

Configure in `.claude/config.json`:
```json
{
  "hooks": {
    "pre-command": ".claude/hooks/tmws-hook.py"
  }
}
```

## Direct MCP Tool Usage

Claude can directly call TMWS MCP tools:

```python
# This happens internally when you ask Claude to use TMWS
await mcp_tools.store_memory(
    content="Important information",
    tags=["optimization", "database"],
    importance=0.9
)

results = await mcp_tools.recall_memories(
    query="optimization patterns",
    limit=10,
    semantic=True
)
```

## Summary

- **No Python scripts as commands**: Claude Code doesn't support custom Python command installation
- **Use MCP tools directly**: TMWS functionality is accessed through MCP server configuration
- **Hooks for automation**: Use hooks if you need to trigger Python scripts
- **Natural language interface**: Simply ask Claude to use TMWS features

The TMWS MCP server provides all functionality without needing custom command scripts.