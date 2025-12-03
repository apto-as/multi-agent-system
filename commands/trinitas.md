---
name: trinitas
description: Execute Trinitas TMWS commands for unified intelligence operations
icon: 🎯
---

# Trinitas TMWS Command Interface

Execute Trinitas operations via TMWS (Trinitas Memory & Workflow System) with proper MCP tool integration.

## Usage

```
/trinitas <operation> [options]
```

## Available Operations

### 1. Execute with Persona
```
/trinitas execute <persona> <task>
/trinitas exec <persona> <task>
```
Execute task with specified persona using TMWS task management.

**Personas**: 
- `athena` - Strategic Architect (戦略的設計)
- `artemis` - Technical Perfectionist (技術的完璧性)
- `hestia` - Security Guardian (セキュリティ監査)
- `eris` - Tactical Coordinator (戦術的調整)
- `hera` - System Conductor (システム指揮)
- `muses` - Knowledge Architect (知識管理)

**Examples**:
```
/trinitas execute athena "Design microservice architecture"
/trinitas exec artemis "Optimize database queries"
```

### 2. Memory Operations
```
/trinitas remember <key> <value> [--persona NAME] [--importance 0.0-1.0]
/trinitas recall <query> [--semantic] [--limit N]
```

Store and retrieve memories using TMWS PostgreSQL backend with vector search.

**Examples**:
```
/trinitas remember project_architecture "Microservices with PostgreSQL" --persona athena --importance 0.9
/trinitas recall architecture --semantic --limit 5
```

### 3. Pattern Learning
```
/trinitas learn <pattern_name> <description>
/trinitas apply <pattern_name> <task>
```

Learn and apply patterns using TMWS learning system.

**Examples**:
```
/trinitas learn optimization_pattern "Add index on user_id column"
/trinitas apply optimization_pattern "Optimize product queries"
```

### 4. Status and Reports
```
/trinitas status [component]
/trinitas report <type>
```

Check system status and generate reports.

**Components**: all, memory, personas, workflow, vector
**Report Types**: usage, optimization, security, learning

**Examples**:
```
/trinitas status memory
/trinitas report optimization
```

### 5. Parallel Analysis (Multiple Personas)
```
/trinitas analyze <task> [--personas p1,p2,p3] [--mode MODE]
```

Execute parallel analysis with multiple personas.

**Modes**: parallel (同時実行), sequential (順次実行), wave (段階的実行)

**Examples**:
```
/trinitas analyze "Review security vulnerabilities" --personas hestia,artemis,athena
/trinitas analyze "System architecture review" --personas all --mode wave
```

### 6. Workflow Operations
```
/trinitas workflow create <name> <description>
/trinitas workflow execute <workflow_id>
/trinitas workflow list
```

Manage and execute complex workflows.

**Examples**:
```
/trinitas workflow create deployment_check "Pre-deployment verification"
/trinitas workflow execute workflow_001
/trinitas workflow list
```

## Implementation

```python
import asyncio
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
import httpx

# Configuration
TMWS_API_URL = "http://localhost:8000/api/v1"

# NOTE: This implementation uses actual TMWS MCP tools and REST API
# MCP tools: semantic_search, store_memory, manage_task, execute_workflow

async def handle_trinitas_command(args: str) -> str:
    """
    Handle /trinitas command execution via TMWS MCP tools and REST API
    """
    parts = args.strip().split(maxsplit=2)
    if not parts:
        return show_help()
    
    operation = parts[0].lower()
    
    # Route to appropriate handler
    handlers = {
        'execute': handle_execute,
        'exec': handle_execute,
        'remember': handle_remember,
        'recall': handle_recall,
        'learn': handle_learn,
        'apply': handle_apply,
        'status': handle_status,
        'report': handle_report,
        'analyze': handle_analyze,
        'workflow': handle_workflow
    }
    
    if operation in handlers:
        return await handlers[operation](parts[1:] if len(parts) > 1 else [])
    else:
        return f"Unknown operation: {operation}\n\n{show_help()}"

async def handle_execute(args: List[str]) -> str:
    """Execute with specific persona via TMWS task management"""
    if len(args) < 2:
        return "Usage: /trinitas execute <persona> <task>"
    
    persona = args[0].lower()
    task_description = args[1]
    
    valid_personas = ['athena', 'artemis', 'hestia', 'eris', 'hera', 'muses']
    if persona not in valid_personas:
        return f"Invalid persona. Choose from: {', '.join(valid_personas)}"
    
    # Create task via MCP tool or REST API
    try:
        # Using MCP tool: manage_task
        result = await manage_task(
            operation='create',
            task_data={
                'title': f"{persona.capitalize()} Task: {task_description[:50]}",
                'description': task_description,
                'assigned_persona': persona,
                'priority': 'high' if persona in ['hestia', 'athena'] else 'medium',
                'metadata': {
                    'source': 'trinitas_command',
                    'persona': persona
                }
            }
        )
        
        if result.get('task_id'):
            return f"""✅ Task created for {persona.capitalize()}
Task ID: {result['task_id']}
Status: {result.get('status', 'PENDING')}
Description: {task_description}"""
        else:
            return f"✅ Task assigned to {persona.capitalize()}"
            
    except Exception as e:
        return f"❌ Execution failed: {str(e)}"

async def handle_remember(args: List[str]) -> str:
    """Store in TMWS memory via MCP tools"""
    if len(args) < 2:
        return "Usage: /trinitas remember <key> <value> [--persona NAME] [--importance N]"
    
    key = args[0]
    remaining = ' '.join(args[1:])
    
    # Parse options
    persona_id = None
    importance = 0.5
    value = remaining
    
    if '--persona' in remaining:
        parts = remaining.split('--persona')
        value = parts[0].strip()
        persona_part = parts[1].strip().split()[0]
        persona_id = persona_part
    
    if '--importance' in remaining:
        import_parts = remaining.split('--importance')
        if not persona_id:
            value = import_parts[0].strip()
        importance = float(import_parts[1].strip().split()[0])
    
    # Use actual MCP tool: store_memory
    try:
        result = await store_memory(
            content=f"{key}: {value}",
            importance=importance,
            metadata={
                'key': key,
                'persona_id': persona_id,
                'source': 'trinitas_command'
            }
        )
        
        if result.get('memory_id'):
            return f"✅ Stored '{key}' with importance {importance} (ID: {result['memory_id']})"
        else:
            return f"✅ Stored '{key}' with importance {importance}"
            
    except Exception as e:
        return f"❌ Failed to store: {str(e)}"

async def handle_recall(args: List[str]) -> str:
    """Recall from TMWS memory via MCP tools"""
    if not args:
        return "Usage: /trinitas recall <query> [--semantic] [--limit N]"
    
    query = args[0]
    use_semantic = '--semantic' in ' '.join(args)
    
    # Extract limit
    limit = 10
    if '--limit' in ' '.join(args):
        for i, arg in enumerate(args):
            if arg == '--limit' and i + 1 < len(args):
                limit = int(args[i + 1])
    
    # Use actual MCP tool: semantic_search
    try:
        result = await semantic_search(
            query=query,
            limit=limit,
            threshold=0.7 if use_semantic else 0.5
        )
        
        if result.get('results'):
            output = [f"🔍 Found {len(result['results'])} memories:"]
            for mem in result['results']:
                content = mem.get('content', '')
                score = mem.get('score', 0.0)
                metadata = mem.get('metadata', {})
                
                output.append(f"\n• {content[:100]}...")
                output.append(f"  Score: {score:.2f}")
                if metadata.get('key'):
                    output.append(f"  Key: {metadata['key']}")
                if metadata.get('persona_id'):
                    output.append(f"  Persona: {metadata['persona_id']}")
                    
            return '\n'.join(output)
        else:
            return f"No memories found for '{query}'"
            
    except Exception as e:
        return f"❌ Recall failed: {str(e)}"

async def handle_analyze(args: List[str]) -> str:
    """Parallel analysis with multiple personas via task creation"""
    if not args:
        return "Usage: /trinitas analyze <task> [--personas p1,p2,p3] [--mode MODE]"
    
    task = args[0]
    personas = ['athena', 'artemis', 'hestia']  # Default
    mode = 'parallel'
    
    # Parse options
    if '--personas' in ' '.join(args):
        for i, arg in enumerate(args):
            if arg == '--personas' and i + 1 < len(args):
                personas_str = args[i + 1]
                if personas_str == 'all':
                    personas = ['athena', 'artemis', 'hestia', 'eris', 'hera', 'muses']
                else:
                    personas = personas_str.split(',')
    
    if '--mode' in ' '.join(args):
        for i, arg in enumerate(args):
            if arg == '--mode' and i + 1 < len(args):
                mode = args[i + 1]
    
    # Create tasks for each persona
    results = []
    try:
        for persona in personas:
            result = await manage_task(
                operation='create',
                task_data={
                    'title': f"Analysis by {persona.capitalize()}",
                    'description': f"{task} (Mode: {mode})",
                    'assigned_persona': persona,
                    'priority': 'high',
                    'metadata': {
                        'analysis_mode': mode,
                        'task': task,
                        'source': 'trinitas_analyze'
                    }
                }
            )
            results.append((persona, result))
        
        # Format results
        output = [f"📊 Analysis initiated with {len(personas)} personas:"]
        for persona, result in results:
            task_id = result.get('task_id', 'N/A')
            output.append(f"  • {persona.capitalize()}: Task {task_id}")
        
        output.append(f"\nMode: {mode}")
        output.append(f"Task: {task}")
        
        return '\n'.join(output)
        
    except Exception as e:
        return f"❌ Analysis failed: {str(e)}"

async def handle_workflow(args: List[str]) -> str:
    """Handle workflow operations via MCP tools"""
    if not args:
        return "Usage: /trinitas workflow <create|execute|list|status> [args]"
    
    action = args[0].lower()
    
    try:
        if action == 'create' and len(args) >= 3:
            name = args[1]
            description = ' '.join(args[2:])
            
            # Create workflow via REST API
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{TMWS_API_URL}/workflows",
                    params={
                        'name': name,
                        'workflow_type': 'trinitas_workflow',
                        'description': description,
                        'priority': 'MEDIUM'
                    }
                )
                
                if response.status_code == 201:
                    data = response.json()
                    workflow_id = data['workflow']['id']
                    return f"✅ Workflow created: {name} (ID: {workflow_id})"
                else:
                    return f"❌ Failed to create workflow: {response.text}"
        
        elif action == 'execute' and len(args) >= 2:
            workflow_id = args[1]
            
            # Use MCP tool: execute_workflow
            result = await execute_workflow(
                workflow_id=workflow_id,
                parameters={}
            )
            
            if result.get('status') == 'RUNNING':
                return f"✅ Workflow {workflow_id} started"
            else:
                return f"Workflow status: {result.get('status', 'Unknown')}"
        
        elif action == 'list':
            # List workflows via REST API
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{TMWS_API_URL}/workflows")
                
                if response.status_code == 200:
                    data = response.json()
                    workflows = data.get('workflows', [])
                    
                    if workflows:
                        output = ["📋 Workflows:"]
                        for wf in workflows[:10]:
                            output.append(f"  • {wf['name']} ({wf['id']})")
                            output.append(f"    Status: {wf['status']}")
                        return '\n'.join(output)
                    else:
                        return "No workflows found"
                else:
                    return f"❌ Failed to list workflows: {response.text}"
        
        elif action == 'status' and len(args) >= 2:
            workflow_id = args[1]
            
            # Get workflow status via REST API
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{TMWS_API_URL}/workflows/{workflow_id}/status")
                
                if response.status_code == 200:
                    data = response.json()
                    return f"""📊 Workflow Status
ID: {workflow_id}
Status: {data.get('status', 'Unknown')}
Started: {data.get('started_at', 'N/A')}
Completed: {data.get('completed_at', 'N/A')}"""
                else:
                    return f"❌ Failed to get status: {response.text}"
        
        else:
            return "Invalid workflow command. Use: create, execute, list, or status"
            
    except Exception as e:
        return f"❌ Workflow operation failed: {str(e)}"

async def handle_status(args: List[str]) -> str:
    """Handle status checks via REST API"""
    component = args[0] if args else 'all'
    
    try:
        async with httpx.AsyncClient() as client:
            # Get health status
            response = await client.get(f"{TMWS_API_URL}/../health")
            
            if response.status_code == 200:
                data = response.json()
                
                output = ["🔧 TMWS Status"]
                output.append(f"Overall: {data.get('status', 'Unknown')}")
                
                if data.get('components'):
                    output.append("\nComponents:")
                    for comp, status in data['components'].items():
                        if component == 'all' or comp == component:
                            output.append(f"  • {comp}: {status}")
                
                return '\n'.join(output)
            else:
                return f"❌ Failed to get status: {response.text}"
                
    except Exception as e:
        return f"❌ Status check failed: {str(e)}"

async def handle_report(args: List[str]) -> str:
    """Generate reports via REST API"""
    report_type = args[0] if args else 'usage'
    
    try:
        endpoints = {
            'usage': '/tasks/stats/summary',
            'optimization': '/workflows/stats/summary',
            'security': '/health',
            'learning': '/memory/stats'
        }
        
        endpoint = endpoints.get(report_type, '/tasks/stats/summary')
        
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{TMWS_API_URL}{endpoint}")
            
            if response.status_code == 200:
                data = response.json()
                
                output = [f"📊 {report_type.capitalize()} Report"]
                output.append("=" * 30)
                
                # Format based on report type
                if report_type == 'usage':
                    output.append(f"Total Tasks: {data.get('total_tasks', 0)}")
                    if data.get('by_status'):
                        output.append("\nBy Status:")
                        for status, count in data['by_status'].items():
                            output.append(f"  • {status}: {count}")
                
                elif report_type == 'optimization':
                    output.append(f"Total Workflows: {data.get('total_workflows', 0)}")
                    if data.get('by_status'):
                        output.append("\nBy Status:")
                        for status, count in data['by_status'].items():
                            output.append(f"  • {status}: {count}")
                
                else:
                    # Generic formatting
                    for key, value in data.items():
                        if isinstance(value, dict):
                            output.append(f"\n{key.replace('_', ' ').title()}:")
                            for k, v in value.items():
                                output.append(f"  • {k}: {v}")
                        else:
                            output.append(f"{key.replace('_', ' ').title()}: {value}")
                
                return '\n'.join(output)
            else:
                return f"❌ Failed to generate report: {response.text}"
                
    except Exception as e:
        return f"❌ Report generation failed: {str(e)}"

async def handle_learn(args: List[str]) -> str:
    """Learn patterns - store in memory with pattern metadata"""
    if len(args) < 2:
        return "Usage: /trinitas learn <pattern_name> <description>"
    
    pattern_name = args[0]
    description = ' '.join(args[1:])
    
    try:
        # Store pattern as memory with high importance
        result = await store_memory(
            content=f"Pattern: {pattern_name} - {description}",
            importance=0.9,
            metadata={
                'type': 'pattern',
                'pattern_name': pattern_name,
                'description': description,
                'source': 'trinitas_learn'
            }
        )
        
        if result.get('memory_id'):
            return f"✅ Learned pattern: {pattern_name} (ID: {result['memory_id']})"
        else:
            return f"✅ Learned pattern: {pattern_name}"
            
    except Exception as e:
        return f"❌ Failed to learn pattern: {str(e)}"

async def handle_apply(args: List[str]) -> str:
    """Apply learned patterns to tasks"""
    if len(args) < 2:
        return "Usage: /trinitas apply <pattern_name> <task>"
    
    pattern_name = args[0]
    task = ' '.join(args[1:])
    
    try:
        # First, search for the pattern
        search_result = await semantic_search(
            query=f"Pattern: {pattern_name}",
            limit=1,
            threshold=0.8
        )
        
        if not search_result.get('results'):
            return f"❌ Pattern '{pattern_name}' not found"
        
        pattern_info = search_result['results'][0]
        pattern_desc = pattern_info.get('content', '')
        
        # Create task to apply pattern
        result = await manage_task(
            operation='create',
            task_data={
                'title': f"Apply {pattern_name} to: {task[:50]}",
                'description': f"Task: {task}\nPattern: {pattern_desc}",
                'priority': 'medium',
                'metadata': {
                    'pattern': pattern_name,
                    'source': 'trinitas_apply'
                }
            }
        )
        
        if result.get('task_id'):
            return f"""✅ Pattern application initiated
Pattern: {pattern_name}
Task: {task}
Task ID: {result['task_id']}"""
        else:
            return f"✅ Pattern '{pattern_name}' applied to task"
            
    except Exception as e:
        return f"❌ Failed to apply pattern: {str(e)}"

def show_help() -> str:
    """Show command help"""
    return """
🎯 Trinitas TMWS Command Interface

Usage: /trinitas <operation> [options]

Operations:
  Execute:
    execute <persona> <task>    - Execute with persona
  
  Memory:
    remember <key> <value>      - Store memory
    recall <query>              - Retrieve memory
  
  Learning:
    learn <pattern> <desc>      - Learn pattern
    apply <pattern> <task>      - Apply pattern
  
  Analysis:
    analyze <task>              - Multi-persona analysis
  
  Workflow:
    workflow create <name>      - Create workflow
    workflow execute <id>       - Execute workflow
    workflow list               - List workflows
    workflow status <id>        - Check status
  
  System:
    status [component]          - System status
    report <type>               - Generate report

Examples:
  /trinitas execute athena "Design API structure"
  /trinitas remember architecture "Microservices" --importance 0.9
  /trinitas recall architecture --semantic
  /trinitas analyze "Security review" --personas all
  /trinitas workflow create deployment_pipeline "CI/CD automation"

For low-level operations, use /tmws command.
"""

# Register command handler
if __name__ == "__main__":
    import sys
    args = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else ""
    result = asyncio.run(handle_trinitas_command(args))
    print(result)
```