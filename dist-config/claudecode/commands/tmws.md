---
name: tmws
description: Direct TMWS (Trinitas Memory & Workflow System) operations
icon: 🧠
---

# TMWS Direct Interface

Direct access to TMWS database and service operations.

## Usage

```
/tmws <operation> [options]
```

## Operations

### Database Operations
```
/tmws db status              - Check database connection
/tmws db stats               - Show database statistics
/tmws db migrate             - Run database migrations
/tmws db backup              - Create database backup
```

### Memory Operations
```
/tmws memory count           - Count total memories
/tmws memory search <query>  - Search memories
/tmws memory cleanup         - Clean old memories
/tmws memory export          - Export memories to JSON
```

### Vector Operations
```
/tmws vector status          - Check pgvector status
/tmws vector reindex         - Rebuild vector indexes
/tmws vector stats           - Show vector statistics
```

### Service Operations
```
/tmws service start          - Start TMWS services
/tmws service stop           - Stop TMWS services
/tmws service restart        - Restart TMWS services
/tmws service logs           - Show service logs
```

### Health Checks
```
/tmws health                 - Overall health status
/tmws health api             - API health check
/tmws health db              - Database health check
/tmws health redis           - Redis health check
```

## Implementation

```python
import asyncio
import json
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# NOTE: This implementation uses TMWS MCP tools for system operations
# The TMWS MCP server must be registered in Claude Desktop

async def handle_tmws_command(args: str) -> str:
    """Handle /tmws command execution"""
    parts = args.strip().split()
    if not parts:
        return show_help()
    
    operation = parts[0].lower()
    
    handlers = {
        'db': handle_database,
        'memory': handle_memory,
        'vector': handle_vector,
        'service': handle_service,
        'health': handle_health
    }
    
    if operation in handlers:
        return await handlers[operation](parts[1:] if len(parts) > 1 else [])
    else:
        return f"Unknown operation: {operation}\n\n{show_help()}"

async def handle_database(args: List[str]) -> str:
    """Handle database operations via MCP tools"""
    if not args:
        return "Usage: /tmws db <status|stats|migrate|backup>"
    
    action = args[0].lower()
    
    try:
        if action == 'status':
            # Get database status via system status tool
            result = await mcp__tmws__get_system_status(component='database')
            
            if result.get('database'):
                db = result['database']
                return f"""
✅ Database Status
Status: {db.get('status', 'Unknown')}
Version: {db.get('version', 'Unknown')}
Database: {db.get('name', 'Unknown')}
Connections: {db.get('active_connections', 0)}/{db.get('max_connections', 0)}
"""
            else:
                return "❌ Failed to get database status"
        
        elif action == 'stats':
            # Get database statistics
            result = await mcp__tmws__database_stats()
            
            output = ["📊 Database Statistics", "="*30]
            
            if result.get('tables'):
                output.append("\nTop Tables by Size:")
                for table in result['tables'][:10]:
                    output.append(f"  • {table['name']}: {table['size']} ({table['rows']} rows)")
            
            if result.get('memory_usage'):
                output.append(f"\nMemory Usage: {result['memory_usage']}")
            
            if result.get('vector_count'):
                output.append(f"Vector Count: {result['vector_count']}")
            
            return '\n'.join(output)
        
        elif action == 'migrate':
            # Run database migrations
            result = await mcp__tmws__run_migration(
                direction='upgrade',
                target='head'
            )
            
            if result.get('success'):
                return f"✅ Migrations completed: {result.get('message', 'Success')}"
            else:
                return f"❌ Migration failed: {result.get('error', 'Unknown error')}"
        
        elif action == 'backup':
            # Create database backup
            backup_name = f"tmws_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            result = await mcp__tmws__backup_database(
                backup_name=backup_name
            )
            
            if result.get('success'):
                return f"✅ Backup created: {result.get('filename', backup_name)}"
            else:
                return f"❌ Backup failed: {result.get('error', 'Unknown error')}"
        
        else:
            return f"Invalid database action: {action}"
            
    except Exception as e:
        return f"❌ Database operation failed: {str(e)}"

async def handle_memory(args: List[str]) -> str:
    """Handle memory operations via MCP tools"""
    if not args:
        return "Usage: /tmws memory <count|search|cleanup|export>"
    
    action = args[0].lower()
    
    try:
        if action == 'count':
            # Get memory count statistics
            result = await mcp__tmws__memory_stats()
            
            output = [f"📊 Total Memories: {result.get('total', 0)}"]
            
            if result.get('by_persona'):
                output.append("\nBy Persona:")
                for persona, count in result['by_persona'].items():
                    output.append(f"  • {persona}: {count}")
            
            if result.get('by_tag'):
                output.append("\nTop Tags:")
                for tag, count in list(result['by_tag'].items())[:5]:
                    output.append(f"  • {tag}: {count}")
            
            return '\n'.join(output)
        
        elif action == 'search' and len(args) > 1:
            query = ' '.join(args[1:])
            
            # Search memories
            result = await mcp__tmws__search_memories(
                query=query,
                limit=10,
                threshold=0.5
            )
            
            if result.get('memories'):
                output = [f"🔍 Found {len(result['memories'])} memories:"]
                for mem in result['memories']:
                    output.append(f"\n• {mem.get('key', 'Unknown')}")
                    output.append(f"  Value: {str(mem.get('value', ''))[:100]}...")
                    output.append(f"  Score: {mem.get('score', 0):.2f}")
                    output.append(f"  Created: {mem.get('created_at', 'Unknown')}")
                return '\n'.join(output)
            else:
                return f"No memories found for '{query}'"
        
        elif action == 'cleanup':
            # Clean up old memories
            result = await mcp__tmws__cleanup_memories(
                days_old=30,
                importance_threshold=0.3
            )
            
            deleted = result.get('deleted', 0)
            return f"✅ Cleaned up {deleted} old memories"
        
        elif action == 'export':
            # Export memories
            result = await mcp__tmws__export_memories(
                format='json',
                include_vectors=False
            )
            
            if result.get('success'):
                filename = result.get('filename', f"memories_export_{datetime.now().strftime('%Y%m%d')}.json")
                count = result.get('count', 0)
                return f"✅ Exported {count} memories to {filename}"
            else:
                return f"❌ Export failed: {result.get('error', 'Unknown error')}"
        
        else:
            return f"Invalid memory action: {action}"
            
    except Exception as e:
        return f"❌ Memory operation failed: {str(e)}"

async def handle_vector(args: List[str]) -> str:
    """Handle vector operations via MCP tools"""
    if not args:
        return "Usage: /tmws vector <status|reindex|stats>"
    
    action = args[0].lower()
    
    try:
        if action == 'status':
            # Get vector system status
            result = await mcp__tmws__vector_status()
            
            return f"""
✅ pgvector Status
Version: {result.get('version', 'Unknown')}
Vectors: {result.get('vector_count', 0)}
Status: {result.get('status', 'Unknown')}
Index Health: {result.get('index_health', 'Unknown')}
"""
        
        elif action == 'reindex':
            # Rebuild vector indexes
            result = await mcp__tmws__reindex_vectors()
            
            if result.get('success'):
                return f"✅ Vector indexes rebuilt successfully. Time: {result.get('time_ms', 0)}ms"
            else:
                return f"❌ Reindex failed: {result.get('error', 'Unknown error')}"
        
        elif action == 'stats':
            # Get vector statistics
            result = await mcp__tmws__vector_stats()
            
            return f"""
📊 Vector Statistics
Index Size: {result.get('index_size', 'N/A')}
Total Vectors: {result.get('total_vectors', 0)}
Avg Dimensions: {result.get('avg_dimensions', 0)}
Search Performance: {result.get('avg_search_ms', 0)}ms
Similarity Threshold: {result.get('default_threshold', 0.7)}
"""
        
        else:
            return f"Invalid vector action: {action}"
            
    except Exception as e:
        return f"❌ Vector operation failed: {str(e)}"

async def handle_service(args: List[str]) -> str:
    """Handle service operations via MCP tools"""
    if not args:
        return "Usage: /tmws service <start|stop|restart|logs|status>"
    
    action = args[0].lower()
    
    try:
        if action == 'start':
            # Start TMWS services
            result = await mcp__tmws__service_control(
                action='start',
                service='all'
            )
            
            if result.get('success'):
                return "✅ TMWS services started"
            else:
                return f"❌ Start failed: {result.get('error', 'Unknown error')}"
        
        elif action == 'stop':
            # Stop TMWS services
            result = await mcp__tmws__service_control(
                action='stop',
                service='all'
            )
            
            if result.get('success'):
                return "✅ TMWS services stopped"
            else:
                return f"❌ Stop failed: {result.get('error', 'Unknown error')}"
        
        elif action == 'restart':
            # Restart services
            result = await mcp__tmws__service_control(
                action='restart',
                service='all'
            )
            
            if result.get('success'):
                return "✅ TMWS services restarted"
            else:
                return f"❌ Restart failed: {result.get('error', 'Unknown error')}"
        
        elif action == 'logs':
            # Get recent logs
            result = await mcp__tmws__get_logs(
                lines=50,
                service=None  # All services
            )
            
            if result.get('logs'):
                return f"📋 Recent Logs:\n{result['logs']}"
            else:
                return "No logs available"
        
        elif action == 'status':
            # Get service status
            result = await mcp__tmws__service_status()
            
            output = ["🔧 Service Status"]
            for service, status in result.get('services', {}).items():
                icon = '✅' if status == 'running' else '❌'
                output.append(f"{icon} {service}: {status}")
            
            return '\n'.join(output)
        
        else:
            return f"Invalid service action: {action}"
            
    except Exception as e:
        return f"❌ Service operation failed: {str(e)}"

async def handle_health(args: List[str]) -> str:
    """Handle health checks via MCP tools"""
    component = args[0] if args else 'all'
    
    try:
        # Get system health status
        result = await mcp__tmws__health_check(
            component=component
        )
        
        health_status = ["🏥 Health Status"]
        
        # Overall status
        overall = result.get('overall', 'unknown')
        icon = '✅' if overall == 'healthy' else '⚠️' if overall == 'degraded' else '❌'
        health_status.append(f"{icon} Overall: {overall.title()}")
        health_status.append("")
        
        # Component statuses
        if result.get('components'):
            for comp, status in result['components'].items():
                icon = '✅' if status['healthy'] else '❌'
                health_status.append(f"{icon} {comp.title()}: {status.get('status', 'Unknown')}")
                if status.get('message'):
                    health_status.append(f"    {status['message']}")
        
        # Performance metrics
        if result.get('metrics'):
            health_status.append("\n📊 Metrics:")
            metrics = result['metrics']
            if metrics.get('response_time_ms'):
                health_status.append(f"  Response Time: {metrics['response_time_ms']}ms")
            if metrics.get('memory_usage_mb'):
                health_status.append(f"  Memory Usage: {metrics['memory_usage_mb']}MB")
            if metrics.get('cpu_percent'):
                health_status.append(f"  CPU Usage: {metrics['cpu_percent']}%")
        
        return '\n'.join(health_status)
        
    except Exception as e:
        return f"❌ Health check failed: {str(e)}"

def show_help() -> str:
    """Show command help"""
    return """
🧠 TMWS Direct Interface

Usage: /tmws <operation> [options]

Operations:
  Database:
    db status     - Check connection
    db stats      - Show statistics
    db migrate    - Run migrations
    db backup     - Create backup
  
  Memory:
    memory count    - Count memories
    memory search   - Search memories
    memory cleanup  - Clean old data
    memory export   - Export to JSON
  
  Vector:
    vector status   - Check pgvector
    vector reindex  - Rebuild indexes
    vector stats    - Show statistics
  
  Service:
    service start   - Start services
    service stop    - Stop services
    service restart - Restart services
    service logs    - Show logs
  
  Health:
    health [component] - Health check

Examples:
  /tmws db status
  /tmws memory search "architecture"
  /tmws service restart
  /tmws health

For high-level operations, use /trinitas command.
"""

# NOTE: MCP tool functions are prefixed with mcp__tmws__
# These are called when TMWS MCP server is registered in Claude Desktop

# Register command handler
if __name__ == "__main__":
    import sys
    args = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else ""
    result = asyncio.run(handle_tmws_command(args))
    print(result)
```