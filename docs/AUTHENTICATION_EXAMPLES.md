# Authentication Examples

Complete code examples for authenticating with TMWS API in multiple programming languages.

---

## Table of Contents

1. [Python Examples](#python-examples)
2. [JavaScript/TypeScript Examples](#javascripttypescript-examples)
3. [Go Examples](#go-examples)
4. [Rust Examples](#rust-examples)
5. [Shell/Bash Examples](#shellbash-examples)
6. [cURL Examples](#curl-examples)

---

## Python Examples

### Basic Client with JWT Authentication

```python
"""
TMWS Python Client with JWT Authentication
Handles automatic token refresh and retry logic
"""

import httpx
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os


class TMWSAuthClient:
    """Production-ready TMWS client with authentication."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.base_url = base_url
        self.username = username or os.getenv("TMWS_USERNAME")
        self.password = password or os.getenv("TMWS_PASSWORD")

        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None

    async def ensure_authenticated(self):
        """Ensure we have a valid access token."""
        if not self.access_token or self._token_needs_refresh():
            if self.refresh_token:
                await self.refresh_access_token()
            else:
                await self.login()

    def _token_needs_refresh(self) -> bool:
        """Check if token needs refresh (5 minute buffer)."""
        if not self.token_expires_at:
            return True
        return datetime.now() >= (self.token_expires_at - timedelta(minutes=5))

    async def login(self):
        """Authenticate and obtain tokens."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"username": self.username, "password": self.password},
            )
            response.raise_for_status()

            data = response.json()
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.token_expires_at = datetime.now() + timedelta(
                seconds=data["expires_in"]
            )

    async def refresh_access_token(self):
        """Refresh the access token."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/auth/refresh",
                json={"refresh_token": self.refresh_token},
            )

            if response.status_code == 401:
                # Refresh token expired, need to login again
                await self.login()
                return

            response.raise_for_status()

            data = response.json()
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.token_expires_at = datetime.now() + timedelta(
                seconds=data["expires_in"]
            )

    async def request(
        self, method: str, endpoint: str, **kwargs
    ) -> Dict[str, Any]:
        """Make authenticated request with automatic retry."""
        await self.ensure_authenticated()

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.access_token}"

        async with httpx.AsyncClient() as client:
            response = await client.request(
                method, f"{self.base_url}{endpoint}", headers=headers, **kwargs
            )

            # Retry once on 401 (token might have expired)
            if response.status_code == 401:
                await self.refresh_access_token()
                headers["Authorization"] = f"Bearer {self.access_token}"
                response = await client.request(
                    method, f"{self.base_url}{endpoint}", headers=headers, **kwargs
                )

            response.raise_for_status()
            return response.json()

    # Convenience methods
    async def get(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        return await self.request("GET", endpoint, **kwargs)

    async def post(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        return await self.request("POST", endpoint, **kwargs)

    async def put(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        return await self.request("PUT", endpoint, **kwargs)

    async def delete(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        return await self.request("DELETE", endpoint, **kwargs)

    # TMWS-specific methods
    async def create_task(
        self, title: str, description: str, priority: str = "MEDIUM"
    ) -> Dict[str, Any]:
        """Create a new task."""
        return await self.post(
            "/api/v1/tasks",
            json={"title": title, "description": description, "priority": priority},
        )

    async def list_tasks(
        self, status: Optional[str] = None, limit: int = 20
    ) -> Dict[str, Any]:
        """List tasks with optional filtering."""
        params = {"limit": limit}
        if status:
            params["status"] = status
        return await self.get("/api/v1/tasks", params=params)

    async def search_memory(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search memories."""
        return await self.post(
            "/api/v1/memory/search", json={"query": query, "limit": limit}
        )


# Usage example
async def main():
    # Initialize client
    client = TMWSAuthClient(
        base_url="http://localhost:8000",
        username="admin",
        password="your_password",
    )

    # Create a task
    task = await client.create_task(
        title="Deploy v2.2.0", description="Production deployment", priority="HIGH"
    )
    print(f"Created task: {task['task']['id']}")

    # List pending tasks
    tasks = await client.list_tasks(status="PENDING")
    print(f"Found {tasks['total']} pending tasks")

    # Search memories
    results = await client.search_memory("optimization", limit=5)
    print(f"Found {len(results.get('results', []))} memories")


if __name__ == "__main__":
    asyncio.run(main())
```

### API Key Authentication

```python
"""TMWS Client with API Key Authentication"""

import httpx
from typing import Optional, Dict, Any


class TMWSAPIKeyClient:
    """Simple client using API key authentication."""

    def __init__(self, api_key: str, base_url: str = "http://localhost:8000"):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {"X-API-Key": api_key}

    async def request(
        self, method: str, endpoint: str, **kwargs
    ) -> Dict[str, Any]:
        """Make authenticated request."""
        headers = {**self.headers, **kwargs.pop("headers", {})}

        async with httpx.AsyncClient() as client:
            response = await client.request(
                method, f"{self.base_url}{endpoint}", headers=headers, **kwargs
            )
            response.raise_for_status()
            return response.json()

    async def create_task(
        self, title: str, description: str
    ) -> Dict[str, Any]:
        return await self.request(
            "POST",
            "/api/v1/tasks",
            json={"title": title, "description": description},
        )


# Usage
import asyncio

client = TMWSAPIKeyClient(api_key="tmws_key_abc123.your_api_key_here")
task = asyncio.run(client.create_task("Test Task", "Description"))
```

---

## JavaScript/TypeScript Examples

### TypeScript Client with JWT

```typescript
/**
 * TMWS TypeScript Client with JWT Authentication
 */

interface TMWSConfig {
  baseUrl: string;
  username?: string;
  password?: string;
}

interface TokenData {
  access_token: string;
  refresh_token: string;
  expires_in: number;
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
  private username?: string;
  private password?: string;
  private accessToken?: string;
  private refreshToken?: string;
  private tokenExpiresAt?: Date;

  constructor(config: TMWSConfig) {
    this.baseUrl = config.baseUrl;
    this.username = config.username;
    this.password = config.password;
  }

  private tokenNeedsRefresh(): boolean {
    if (!this.tokenExpiresAt) return true;

    // Refresh if within 5 minutes of expiration
    const bufferMs = 5 * 60 * 1000;
    return new Date().getTime() >= this.tokenExpiresAt.getTime() - bufferMs;
  }

  private async ensureAuthenticated(): Promise<void> {
    if (!this.accessToken || this.tokenNeedsRefresh()) {
      if (this.refreshToken) {
        await this.refreshAccessToken();
      } else {
        await this.login();
      }
    }
  }

  async login(): Promise<TokenData> {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: this.username,
        password: this.password,
      }),
    });

    if (!response.ok) {
      throw new Error(`Login failed: ${response.status} ${await response.text()}`);
    }

    const data: TokenData = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
    this.tokenExpiresAt = new Date(Date.now() + data.expires_in * 1000);

    return data;
  }

  async refreshAccessToken(): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({refresh_token: this.refreshToken}),
    });

    if (response.status === 401) {
      // Refresh token expired, login again
      await this.login();
      return;
    }

    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.status}`);
    }

    const data: TokenData = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
    this.tokenExpiresAt = new Date(Date.now() + data.expires_in * 1000);
  }

  async request<T = any>(
    method: string,
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    await this.ensureAuthenticated();

    const headers = new Headers(options.headers);
    headers.set('Authorization', `Bearer ${this.accessToken}`);
    headers.set('Content-Type', 'application/json');

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      method,
      headers,
    });

    // Retry once on 401
    if (response.status === 401) {
      await this.refreshAccessToken();
      headers.set('Authorization', `Bearer ${this.accessToken}`);

      const retryResponse = await fetch(`${this.baseUrl}${endpoint}`, {
        ...options,
        method,
        headers,
      });

      if (!retryResponse.ok) {
        throw new Error(`Request failed: ${retryResponse.status}`);
      }

      return retryResponse.json();
    }

    if (!response.ok) {
      throw new Error(`Request failed: ${response.status} ${await response.text()}`);
    }

    return response.json();
  }

  // Convenience methods
  async createTask(task: Task): Promise<Task> {
    return this.request<{task: Task}>('POST', '/api/v1/tasks', {
      body: JSON.stringify(task),
    }).then(r => r.task);
  }

  async listTasks(status?: string): Promise<{tasks: Task[]; total: number}> {
    const url = status ? `/api/v1/tasks?status=${status}` : '/api/v1/tasks';
    return this.request('GET', url);
  }

  async searchMemory(query: string, limit = 10): Promise<any> {
    return this.request('POST', '/api/v1/memory/search', {
      body: JSON.stringify({query, limit}),
    });
  }
}

// Usage
const client = new TMWSClient({
  baseUrl: 'http://localhost:8000',
  username: 'admin',
  password: process.env.TMWS_PASSWORD!,
});

// Create task
const task = await client.createTask({
  title: 'Deploy to Production',
  description: 'Deploy TMWS v2.2.0',
  priority: 'HIGH',
});

console.log(`Created task: ${task.id}`);

// List tasks
const {tasks, total} = await client.listTasks('PENDING');
console.log(`Found ${total} pending tasks`);
```

### Node.js with API Key

```javascript
const fetch = require('node-fetch');

class TMWSClient {
  constructor(apiKey, baseUrl = 'http://localhost:8000') {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
  }

  async request(method, endpoint, body = null) {
    const options = {
      method,
      headers: {
        'X-API-Key': this.apiKey,
        'Content-Type': 'application/json',
      },
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, options);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }

    return response.json();
  }

  async createTask(title, description, priority = 'MEDIUM') {
    return this.request('POST', '/api/v1/tasks', {
      title,
      description,
      priority,
    });
  }

  async listTasks(status = null) {
    const url = status ? `/api/v1/tasks?status=${status}` : '/api/v1/tasks';
    return this.request('GET', url);
  }
}

// Usage
const client = new TMWSClient(process.env.TMWS_API_KEY);

client.createTask('Test Task', 'Testing API key auth').then(result => {
  console.log('Task created:', result.task.id);
});
```

---

## Go Examples

### Go Client with JWT

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type TMWSClient struct {
    BaseURL      string
    Username     string
    Password     string
    AccessToken  string
    RefreshToken string
    ExpiresAt    time.Time
    HTTPClient   *http.Client
}

type LoginResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int    `json:"expires_in"`
}

type Task struct {
    ID          string `json:"id,omitempty"`
    Title       string `json:"title"`
    Description string `json:"description"`
    Priority    string `json:"priority,omitempty"`
    Status      string `json:"status,omitempty"`
}

func NewTMWSClient(baseURL, username, password string) *TMWSClient {
    return &TMWSClient{
        BaseURL:    baseURL,
        Username:   username,
        Password:   password,
        HTTPClient: &http.Client{Timeout: 30 * time.Second},
    }
}

func (c *TMWSClient) Login() error {
    body, _ := json.Marshal(map[string]string{
        "username": c.Username,
        "password": c.Password,
    })

    resp, err := c.HTTPClient.Post(
        c.BaseURL+"/api/v1/auth/login",
        "application/json",
        bytes.NewBuffer(body),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("login failed: %d", resp.StatusCode)
    }

    var loginResp LoginResponse
    if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
        return err
    }

    c.AccessToken = loginResp.AccessToken
    c.RefreshToken = loginResp.RefreshToken
    c.ExpiresAt = time.Now().Add(time.Duration(loginResp.ExpiresIn) * time.Second)

    return nil
}

func (c *TMWSClient) RefreshAccessToken() error {
    body, _ := json.Marshal(map[string]string{
        "refresh_token": c.RefreshToken,
    })

    resp, err := c.HTTPClient.Post(
        c.BaseURL+"/api/v1/auth/refresh",
        "application/json",
        bytes.NewBuffer(body),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusUnauthorized {
        // Refresh token expired, login again
        return c.Login()
    }

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("token refresh failed: %d", resp.StatusCode)
    }

    var loginResp LoginResponse
    if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
        return err
    }

    c.AccessToken = loginResp.AccessToken
    c.RefreshToken = loginResp.RefreshToken
    c.ExpiresAt = time.Now().Add(time.Duration(loginResp.ExpiresIn) * time.Second)

    return nil
}

func (c *TMWSClient) EnsureAuthenticated() error {
    if c.AccessToken == "" || time.Now().After(c.ExpiresAt.Add(-5*time.Minute)) {
        if c.RefreshToken != "" {
            return c.RefreshAccessToken()
        }
        return c.Login()
    }
    return nil
}

func (c *TMWSClient) CreateTask(task Task) (*Task, error) {
    if err := c.EnsureAuthenticated(); err != nil {
        return nil, err
    }

    body, _ := json.Marshal(task)
    req, _ := http.NewRequest(
        "POST",
        c.BaseURL+"/api/v1/tasks",
        bytes.NewBuffer(body),
    )
    req.Header.Set("Authorization", "Bearer "+c.AccessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusCreated {
        return nil, fmt.Errorf("create task failed: %d", resp.StatusCode)
    }

    var result struct {
        Task Task `json:"task"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return &result.Task, nil
}

func main() {
    client := NewTMWSClient("http://localhost:8000", "admin", "password")

    task, err := client.CreateTask(Task{
        Title:       "Deploy v2.2.0",
        Description: "Production deployment",
        Priority:    "HIGH",
    })

    if err != nil {
        panic(err)
    }

    fmt.Printf("Created task: %s\n", task.ID)
}
```

---

## Rust Examples

### Rust Client with JWT

```rust
use serde::{Deserialize, Serialize};
use reqwest::Client;
use chrono::{DateTime, Duration, Utc};
use std::error::Error;

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Task {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    title: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<String>,
}

struct TMWSClient {
    base_url: String,
    username: String,
    password: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    client: Client,
}

impl TMWSClient {
    fn new(base_url: String, username: String, password: String) -> Self {
        TMWSClient {
            base_url,
            username,
            password,
            access_token: None,
            refresh_token: None,
            expires_at: None,
            client: Client::new(),
        }
    }

    async fn login(&mut self) -> Result<(), Box<dyn Error>> {
        let login_req = LoginRequest {
            username: self.username.clone(),
            password: self.password.clone(),
        };

        let resp = self.client
            .post(&format!("{}/api/v1/auth/login", self.base_url))
            .json(&login_req)
            .send()
            .await?;

        let login_resp: LoginResponse = resp.json().await?;

        self.access_token = Some(login_resp.access_token);
        self.refresh_token = Some(login_resp.refresh_token);
        self.expires_at = Some(Utc::now() + Duration::seconds(login_resp.expires_in));

        Ok(())
    }

    async fn ensure_authenticated(&mut self) -> Result<(), Box<dyn Error>> {
        if self.access_token.is_none() || self.token_needs_refresh() {
            if self.refresh_token.is_some() {
                self.refresh_access_token().await?;
            } else {
                self.login().await?;
            }
        }
        Ok(())
    }

    fn token_needs_refresh(&self) -> bool {
        match self.expires_at {
            None => true,
            Some(expires_at) => {
                Utc::now() >= expires_at - Duration::minutes(5)
            }
        }
    }

    async fn refresh_access_token(&mut self) -> Result<(), Box<dyn Error>> {
        // Implementation similar to login
        Ok(())
    }

    async fn create_task(&mut self, task: Task) -> Result<Task, Box<dyn Error>> {
        self.ensure_authenticated().await?;

        let resp = self.client
            .post(&format!("{}/api/v1/tasks", self.base_url))
            .header("Authorization", format!("Bearer {}", self.access_token.as_ref().unwrap()))
            .json(&task)
            .send()
            .await?;

        #[derive(Deserialize)]
        struct TaskResponse {
            task: Task,
        }

        let task_resp: TaskResponse = resp.json().await?;
        Ok(task_resp.task)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut client = TMWSClient::new(
        "http://localhost:8000".to_string(),
        "admin".to_string(),
        "password".to_string(),
    );

    let task = client.create_task(Task {
        id: None,
        title: "Deploy v2.2.0".to_string(),
        description: "Production deployment".to_string(),
        priority: Some("HIGH".to_string()),
    }).await?;

    println!("Created task: {:?}", task.id);

    Ok(())
}
```

---

## Shell/Bash Examples

### Complete Bash Client

```bash
#!/bin/bash
# TMWS Bash Client with JWT Authentication

set -e

# Configuration
TMWS_URL="${TMWS_URL:-http://localhost:8000}"
TOKEN_FILE="${HOME}/.tmws_token"
REFRESH_FILE="${HOME}/.tmws_refresh"

# Login function
tmws_login() {
    local username="$1"
    local password="$2"

    local response=$(curl -s -X POST "$TMWS_URL/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$username\",\"password\":\"$password\"}")

    local access_token=$(echo "$response" | jq -r '.access_token')
    local refresh_token=$(echo "$response" | jq -r '.refresh_token')

    if [ "$access_token" != "null" ]; then
        echo "$access_token" > "$TOKEN_FILE"
        echo "$refresh_token" > "$REFRESH_FILE"
        chmod 600 "$TOKEN_FILE" "$REFRESH_FILE"
        echo "Login successful"
        return 0
    else
        echo "Login failed: $response" >&2
        return 1
    fi
}

# Get valid token (with auto-refresh)
tmws_get_token() {
    if [ ! -f "$TOKEN_FILE" ]; then
        echo "Not logged in. Run: tmws_login <username> <password>" >&2
        return 1
    fi

    cat "$TOKEN_FILE"
}

# API request wrapper
tmws_api() {
    local method="$1"
    local endpoint="$2"
    shift 2
    local data="$@"

    local token=$(tmws_get_token)

    if [ -n "$data" ]; then
        curl -s -X "$method" "$TMWS_URL$endpoint" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$data"
    else
        curl -s -X "$method" "$TMWS_URL$endpoint" \
            -H "Authorization: Bearer $token"
    fi
}

# Create task
tmws_create_task() {
    local title="$1"
    local description="$2"
    local priority="${3:-MEDIUM}"

    tmws_api POST "/api/v1/tasks" "{
        \"title\": \"$title\",
        \"description\": \"$description\",
        \"priority\": \"$priority\"
    }" | jq
}

# List tasks
tmws_list_tasks() {
    local status="$1"

    if [ -n "$status" ]; then
        tmws_api GET "/api/v1/tasks?status=$status" | jq
    else
        tmws_api GET "/api/v1/tasks" | jq
    fi
}

# Search memory
tmws_search_memory() {
    local query="$1"
    local limit="${2:-10}"

    tmws_api POST "/api/v1/memory/search" "{
        \"query\": \"$query\",
        \"limit\": $limit
    }" | jq
}

# Main CLI
case "${1:-help}" in
    login)
        tmws_login "$2" "$3"
        ;;
    create-task)
        tmws_create_task "$2" "$3" "$4"
        ;;
    list-tasks)
        tmws_list_tasks "$2"
        ;;
    search)
        tmws_search_memory "$2" "$3"
        ;;
    help)
        cat <<EOF
TMWS Bash Client

Usage:
  $0 login <username> <password>
  $0 create-task <title> <description> [priority]
  $0 list-tasks [status]
  $0 search <query> [limit]

Examples:
  $0 login admin mypassword
  $0 create-task "Deploy v2.2.0" "Production deployment" HIGH
  $0 list-tasks PENDING
  $0 search "optimization" 5
EOF
        ;;
    *)
        echo "Unknown command: $1"
        echo "Run '$0 help' for usage"
        exit 1
        ;;
esac
```

---

## cURL Examples

### Complete cURL Workflow

```bash
# 1. Login and get tokens
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your_password"
  }' | jq

# Save tokens
export ACCESS_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
export REFRESH_TOKEN="a1b2c3d4.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 2. Create task
curl -X POST http://localhost:8000/api/v1/tasks \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Deploy v2.2.0",
    "description": "Production deployment",
    "priority": "HIGH"
  }' | jq

# 3. List tasks
curl http://localhost:8000/api/v1/tasks \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq

# 4. Search memory
curl -X POST http://localhost:8000/api/v1/memory/search \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "authentication",
    "limit": 5
  }' | jq

# 5. Refresh token (when expired)
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" | jq

# 6. Create API key (for automation)
curl -X POST http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI/CD Pipeline",
    "scopes": ["READ", "WRITE"],
    "expires_days": 30
  }' | jq

# 7. Use API key
export API_KEY="tmws_key_abc123.your_api_key_here"

curl http://localhost:8000/api/v1/tasks \
  -H "X-API-Key: $API_KEY" | jq

# 8. Logout
curl -X POST http://localhost:8000/api/v1/auth/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}"
```

---

## Error Handling Examples

### Python Robust Error Handling

```python
import httpx
from typing import Optional

async def create_task_with_retry(
    client: TMWSAuthClient,
    title: str,
    description: str,
    max_retries: int = 3
) -> Optional[dict]:
    """Create task with automatic retry on auth errors."""

    for attempt in range(max_retries):
        try:
            return await client.create_task(title, description)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                # Token expired, refresh and retry
                await client.refresh_access_token()
                continue
            elif e.response.status_code == 429:
                # Rate limited, wait and retry
                import asyncio
                wait_time = int(e.response.headers.get('Retry-After', 60))
                await asyncio.sleep(wait_time)
                continue
            else:
                # Other error, don't retry
                raise
        except httpx.RequestError as e:
            # Network error, retry with backoff
            if attempt < max_retries - 1:
                import asyncio
                await asyncio.sleep(2 ** attempt)
                continue
            raise

    raise Exception(f"Failed after {max_retries} attempts")
```

---

**Last Updated**: 2025-01-09
**TMWS Version**: 2.2.0
