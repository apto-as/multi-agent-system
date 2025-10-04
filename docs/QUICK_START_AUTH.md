# Quick Start: TMWS Authentication

Get up and running with TMWS authentication in 5 minutes.

---

## Prerequisites

- TMWS v2.2.0 installed and running
- `curl` or similar HTTP client
- (Optional) Python 3.11+ for code examples

---

## 1. Choose Your Authentication Method

### Option A: Development Mode (No Auth)

**Best for**: Local development, testing, learning TMWS

```bash
# Set environment variables
export TMWS_ENVIRONMENT=development
export TMWS_AUTH_ENABLED=false

# Start TMWS
python -m src.main
```

**Try it**:
```bash
# No authentication needed!
curl http://localhost:8000/api/v1/tasks
```

✅ **You're ready!** Skip to [Testing Your Setup](#testing-your-setup)

---

### Option B: Production Mode (With Auth)

**Best for**: Production deployments, multi-user environments

```bash
# Set environment variables
export TMWS_ENVIRONMENT=production
export TMWS_AUTH_ENABLED=true
export TMWS_SECRET_KEY=$(openssl rand -hex 32)

# Start TMWS
python -m src.main
```

Continue to step 2 ↓

---

## 2. Create Your First User

### Using the Setup Script

```bash
# Run the security setup script
python scripts/security_setup.py
```

Follow the prompts to create an admin user.

### Manual User Creation (If needed)

```bash
# Connect to database directly (PostgreSQL)
psql -d tmws -c "
INSERT INTO users (id, username, email, password_hash, password_salt, roles, status, agent_namespace)
VALUES (
  gen_random_uuid(),
  'admin',
  'admin@example.com',
  'temp_hash',  -- Will be updated on first login
  'temp_salt',
  ARRAY['SUPER_ADMIN']::user_role[],
  'ACTIVE',
  'default'
);
"
```

---

## 3. Get Your Access Token

### Method 1: Using curl

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your_password"
  }' | jq
```

**Save the tokens**:
```bash
export ACCESS_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
export REFRESH_TOKEN="a1b2c3d4.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Method 2: Using Python

```python
import httpx
import os

async def login():
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/v1/auth/login",
            json={
                "username": "admin",
                "password": os.getenv("ADMIN_PASSWORD")
            }
        )
        data = response.json()

        # Save tokens
        os.environ["ACCESS_TOKEN"] = data["access_token"]
        os.environ["REFRESH_TOKEN"] = data["refresh_token"]

        return data

# Usage
import asyncio
result = asyncio.run(login())
print(f"Token expires in: {result['expires_in']} seconds")
```

---

## 4. Create an API Key (Optional)

API keys are great for automation and service integrations.

```bash
curl -X POST http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My First API Key",
    "scopes": ["READ", "WRITE"],
    "expires_days": 30
  }' | jq
```

**Save the API key**:
```bash
export TMWS_API_KEY="tmws_key_abc123.very_long_secure_random_string"
```

**⚠️ IMPORTANT**: This is your only chance to see the full API key. Store it securely!

---

## 5. Testing Your Setup

### Test 1: List Tasks

**Using JWT Token**:
```bash
curl http://localhost:8000/api/v1/tasks \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**Using API Key**:
```bash
curl http://localhost:8000/api/v1/tasks \
  -H "X-API-Key: $TMWS_API_KEY"
```

### Test 2: Create a Task

```bash
curl -X POST http://localhost:8000/api/v1/tasks \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My First Task",
    "description": "Testing TMWS authentication",
    "priority": "MEDIUM",
    "assigned_persona": "athena-conductor"
  }' | jq
```

### Test 3: Search Memories

```bash
curl -X POST http://localhost:8000/api/v1/memory/search \
  -H "X-API-Key: $TMWS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "authentication",
    "limit": 5
  }' | jq
```

---

## 6. Common Tasks

### Refresh Your Token

When your access token expires (default: 1 hour):

```bash
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" | jq
```

Update your environment:
```bash
export ACCESS_TOKEN="new_token_here"
export REFRESH_TOKEN="new_refresh_token_here"
```

### Change Your Password

```bash
curl -X PUT http://localhost:8000/api/v1/users/me/password \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "old_password",
    "new_password": "NewSecureP@ssw0rd123"
  }'
```

### List Your API Keys

```bash
curl http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq
```

### Revoke an API Key

```bash
curl -X DELETE http://localhost:8000/api/v1/auth/api-keys/tmws_key_abc123 \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

---

## 7. Integration Examples

### Python Client

```python
import httpx
import os
from typing import Optional

class TMWSClient:
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        token: Optional[str] = None
    ):
        self.base_url = base_url
        self.headers = {}

        if api_key:
            self.headers["X-API-Key"] = api_key
        elif token:
            self.headers["Authorization"] = f"Bearer {token}"
        else:
            raise ValueError("Either api_key or token must be provided")

    async def create_task(self, title: str, description: str, priority: str = "MEDIUM"):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/tasks",
                headers=self.headers,
                json={
                    "title": title,
                    "description": description,
                    "priority": priority
                }
            )
            response.raise_for_status()
            return response.json()

    async def list_tasks(self, status: Optional[str] = None):
        async with httpx.AsyncClient() as client:
            params = {"status": status} if status else {}
            response = await client.get(
                f"{self.base_url}/api/v1/tasks",
                headers=self.headers,
                params=params
            )
            response.raise_for_status()
            return response.json()

# Usage with API Key
client = TMWSClient(api_key=os.getenv("TMWS_API_KEY"))

# Or usage with JWT Token
client = TMWSClient(token=os.getenv("ACCESS_TOKEN"))

# Create and list tasks
import asyncio
task = asyncio.run(client.create_task(
    title="Deploy to Production",
    description="Deploy TMWS v2.2.0",
    priority="HIGH"
))
print(f"Created task: {task['id']}")

tasks = asyncio.run(client.list_tasks(status="PENDING"))
print(f"Found {tasks['total']} pending tasks")
```

### JavaScript/TypeScript Client

```typescript
interface TMWSConfig {
  baseUrl: string;
  apiKey?: string;
  token?: string;
}

interface Task {
  id?: string;
  title: string;
  description: string;
  priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT';
  status?: string;
}

class TMWSClient {
  private baseUrl: string;
  private headers: Record<string, string>;

  constructor(config: TMWSConfig) {
    this.baseUrl = config.baseUrl;
    this.headers = {
      'Content-Type': 'application/json'
    };

    if (config.apiKey) {
      this.headers['X-API-Key'] = config.apiKey;
    } else if (config.token) {
      this.headers['Authorization'] = `Bearer ${config.token}`;
    } else {
      throw new Error('Either apiKey or token must be provided');
    }
  }

  async createTask(task: Task): Promise<Task> {
    const response = await fetch(`${this.baseUrl}/api/v1/tasks`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(task)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }

    return response.json();
  }

  async listTasks(status?: string): Promise<{tasks: Task[], total: number}> {
    const url = new URL(`${this.baseUrl}/api/v1/tasks`);
    if (status) {
      url.searchParams.append('status', status);
    }

    const response = await fetch(url.toString(), {
      headers: this.headers
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }

    return response.json();
  }
}

// Usage
const client = new TMWSClient({
  baseUrl: 'http://localhost:8000',
  apiKey: process.env.TMWS_API_KEY
});

// Create task
const task = await client.createTask({
  title: 'Frontend Integration',
  description: 'Integrate TMWS API with React app',
  priority: 'HIGH'
});

console.log(`Created task: ${task.id}`);

// List tasks
const {tasks, total} = await client.listTasks('PENDING');
console.log(`Found ${total} pending tasks`);
```

### Shell Script

```bash
#!/bin/bash
# tmws-client.sh - Simple TMWS CLI wrapper

set -e

TMWS_URL="${TMWS_URL:-http://localhost:8000}"
TMWS_API_KEY="${TMWS_API_KEY}"

if [ -z "$TMWS_API_KEY" ]; then
    echo "Error: TMWS_API_KEY environment variable not set"
    exit 1
fi

# Helper function for API calls
tmws_api() {
    local method="$1"
    local endpoint="$2"
    local data="$3"

    if [ -n "$data" ]; then
        curl -s -X "$method" "$TMWS_URL$endpoint" \
            -H "X-API-Key: $TMWS_API_KEY" \
            -H "Content-Type: application/json" \
            -d "$data"
    else
        curl -s -X "$method" "$TMWS_URL$endpoint" \
            -H "X-API-Key: $TMWS_API_KEY"
    fi
}

# Commands
case "${1:-help}" in
    create-task)
        tmws_api POST "/api/v1/tasks" "{
            \"title\": \"$2\",
            \"description\": \"$3\",
            \"priority\": \"${4:-MEDIUM}\"
        }" | jq
        ;;

    list-tasks)
        tmws_api GET "/api/v1/tasks${2:+?status=$2}" | jq
        ;;

    get-task)
        tmws_api GET "/api/v1/tasks/$2" | jq
        ;;

    search-memory)
        tmws_api POST "/api/v1/memory/search" "{
            \"query\": \"$2\",
            \"limit\": ${3:-10}
        }" | jq
        ;;

    help)
        cat <<EOF
TMWS CLI Wrapper

Usage:
  $0 create-task <title> <description> [priority]
  $0 list-tasks [status]
  $0 get-task <task-id>
  $0 search-memory <query> [limit]

Examples:
  $0 create-task "Deploy v2.2.0" "Production deployment" HIGH
  $0 list-tasks PENDING
  $0 search-memory "authentication" 5

Environment:
  TMWS_URL      - TMWS API URL (default: http://localhost:8000)
  TMWS_API_KEY  - Your TMWS API key (required)
EOF
        ;;

    *)
        echo "Unknown command: $1"
        echo "Run '$0 help' for usage"
        exit 1
        ;;
esac
```

Usage:
```bash
chmod +x tmws-client.sh

export TMWS_API_KEY="your_api_key_here"

./tmws-client.sh create-task "My Task" "Description" HIGH
./tmws-client.sh list-tasks PENDING
./tmws-client.sh search-memory "optimization" 10
```

---

## Troubleshooting

### "Authentication required"

**Problem**: Getting 401 errors when auth is disabled

**Solution**: Check environment variables:
```bash
# Should see auth_enabled: false
curl http://localhost:8000/health | jq
```

### "Token expired"

**Problem**: Access token expired after 1 hour

**Solution**: Use refresh token:
```bash
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}"
```

### "Invalid API key"

**Problem**: API key not working

**Solution**: Check format (should be `key_id.random_string`):
```bash
# Wrong format
TMWS_API_KEY="abc123"

# Correct format
TMWS_API_KEY="tmws_key_abc123.very_long_random_string"
```

### "Permission denied"

**Problem**: 403 Forbidden errors

**Solution**: Check your scopes:
```bash
# List your API keys and check scopes
curl http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq

# Create new key with correct scopes
curl -X POST http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Full Access Key",
    "scopes": ["FULL"],
    "expires_days": 30
  }'
```

---

## Next Steps

1. ✅ **Authentication working** - You're authenticated!
2. 📚 **Read the full guide** - [API Authentication Guide](./API_AUTHENTICATION.md)
3. 🔧 **Integrate with your app** - Use code examples above
4. 🚀 **Deploy to production** - [Deployment Guide](./deployment/DEPLOYMENT_GUIDE_v2.2.0.md)
5. 🎯 **Use MCP protocol** - [MCP Setup Guide](./guides/MCP_SETUP_GUIDE.md)

---

## Security Checklist

Before going to production:

- [ ] Changed default admin password
- [ ] Set strong `TMWS_SECRET_KEY` (32+ random characters)
- [ ] Enabled authentication (`TMWS_AUTH_ENABLED=true`)
- [ ] Using HTTPS in production
- [ ] API keys have appropriate scopes (not `FULL` unless needed)
- [ ] API keys have expiration dates
- [ ] Monitoring authentication logs
- [ ] Rate limiting enabled

---

## Support

- 📖 [Full Authentication Documentation](./API_AUTHENTICATION.md)
- 🐛 [GitHub Issues](https://github.com/apto-as/tmws/issues)
- 💬 [Discussions](https://github.com/apto-as/tmws/discussions)

---

**Last Updated**: 2025-01-09
**TMWS Version**: 2.2.0
