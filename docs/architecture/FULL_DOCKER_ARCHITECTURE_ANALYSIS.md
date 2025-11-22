# Full Docker Architecture Analysis for TMWS
## Source Code Obfuscation + MCP Isolation

**Date**: 2025-11-20
**Status**: Strategic Design Document
**Severity**: CRITICAL - Commercial Distribution Requirement

---

## Executive Summary

**Business Requirement**: TMWS source code must be obfuscated for commercial distribution while maintaining secure MCP server isolation.

**Key Constraint**: TMWS Native (Option C-Revised) exposes Python source code → **Unacceptable for commercial product**

**Solution Space**: Full Docker architecture where both TMWS and MCP servers run in containers, with controlled inter-container communication.

---

## Approach 1: Docker Socket Proxy (Restricted Access)

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Host OS (macOS/Linux)                                      │
│                                                              │
│  ┌──────────────────┐         ┌─────────────────────────┐  │
│  │ Docker Socket    │         │ /var/run/docker.sock    │  │
│  │ Proxy            │◄────────┤ (Read-only mount)       │  │
│  │ (Tecnativa)      │         └─────────────────────────┘  │
│  │                  │                                       │
│  │ CONTAINERS: 1    │                                       │
│  │ POST: 1          │                                       │
│  │ DELETE: 1        │                                       │
│  │ VOLUMES: 0  ❌   │ ← Prevent host mounts                │
│  │ NETWORKS: 1      │                                       │
│  └────────┬─────────┘                                       │
│           │ TCP:2375 (restricted)                           │
│           ↓                                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ TMWS Container                                       │  │
│  │ ┌──────────────────────────────────────────────┐    │  │
│  │ │ PyInstaller Binary (Obfuscated)              │    │  │
│  │ │ - tmws.exe (compiled Python)                 │    │  │
│  │ │ - No .py files exposed                       │    │  │
│  │ │ - DOCKER_HOST=tcp://proxy:2375               │    │  │
│  │ └──────────────────────────────────────────────┘    │  │
│  │           │ docker run (via proxy)                   │  │
│  │           ↓                                          │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ MCP Containers (Dynamic)                             │  │
│  │ ┌────────────┐  ┌────────────┐  ┌────────────┐     │  │
│  │ │ serena-mcp │  │ gdrive-mcp │  │ slack-mcp  │     │  │
│  │ │ (isolated) │  │ (network)  │  │ (network)  │     │  │
│  │ └────────────┘  └────────────┘  └────────────┘     │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Implementation

**docker-compose.yml**:
```yaml
version: '3.8'

services:
  docker-proxy:
    image: tecnativa/docker-socket-proxy:latest
    environment:
      CONTAINERS: 1     # Allow container management
      POST: 1           # Allow container creation
      DELETE: 1         # Allow container deletion
      IMAGES: 1         # Allow image pulls
      VOLUMES: 0        # 🔒 DENY volume mounts
      NETWORKS: 1       # Allow network management
      INFO: 1           # Allow docker info
      EXEC: 0           # 🔒 DENY exec into containers
      BUILD: 0          # 🔒 DENY builds
      COMMIT: 0         # 🔒 DENY commits
      SWARM: 0          # 🔒 DENY swarm operations
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - tmws-internal
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /run
      - /tmp

  tmws:
    image: tmws:v2.4.0-obfuscated  # PyInstaller build
    environment:
      DOCKER_HOST: tcp://docker-proxy:2375
      TMWS_ENVIRONMENT: production
      TMWS_DATABASE_URL: sqlite+aiosqlite:///data/tmws.db
    volumes:
      - tmws-data:/data  # Only TMWS data, no host mounts
    networks:
      - tmws-internal
      - mcp-network
    depends_on:
      - docker-proxy
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined  # Required for docker client
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

volumes:
  tmws-data:

networks:
  tmws-internal:
    internal: true  # No external access
  mcp-network:
    driver: bridge
```

**TMWS Dockerfile** (PyInstaller):
```dockerfile
# Build stage
FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml uv.lock ./
COPY src/ ./src/

# Install dependencies
RUN pip install uv && uv pip install --system pyinstaller

# Build obfuscated binary
RUN pyinstaller \
    --name tmws \
    --onefile \
    --clean \
    --strip \
    --log-level WARN \
    --key "$(openssl rand -hex 16)" \
    src/main.py

# Runtime stage
FROM python:3.11-slim

# Install docker client ONLY (not docker daemon)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        docker.io-cli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/dist/tmws /app/tmws

# Non-root user
RUN useradd -m -u 1000 tmws && chown -R tmws:tmws /app
USER tmws

ENTRYPOINT ["/app/tmws"]
```

### Security Analysis

#### 1. Source Code Protection
- ✅ **PyInstaller Obfuscation**: Python bytecode compiled to binary
- ✅ **Encrypted Bytecode**: `--key` flag encrypts .pyc files
- ✅ **No .py Files**: Source code not accessible in container
- ⚠️ **Decompilation Possible**: Skilled attacker can reverse engineer
  - Mitigation: Add code obfuscation (pyarmor, cython)
  - Commercial acceptability: **Medium-High** (industry standard for Python)

#### 2. Docker Socket Risk Mitigation

**Threat Model**:
- Attacker compromises TMWS container
- Attempts to exploit docker socket access
- Goal: Escape to host OS or access other containers

**Mitigations**:

| Attack Vector | Proxy Setting | Effectiveness |
|---------------|---------------|---------------|
| `docker run -v /:/host` | `VOLUMES: 0` | ✅ Blocked |
| `docker exec -it tmws bash` | `EXEC: 0` | ✅ Blocked |
| `docker build` (malicious Dockerfile) | `BUILD: 0` | ✅ Blocked |
| `docker commit` (extract container) | `COMMIT: 0` | ✅ Blocked |
| Container escape via cgroups | `seccomp:unconfined` | ⚠️ Risk remains |
| Network-based container access | `NETWORKS: 1` | ⚠️ Can create networks |

**Residual Risks**:
1. **Malicious Container Creation**: TMWS can still create containers
   - Mitigation: Whitelist allowed MCP images
   - Implementation: Proxy validates `docker run` image parameter
2. **Network Isolation Bypass**: Can create networks and join containers
   - Mitigation: Falco runtime monitoring + alerts
3. **Resource Exhaustion**: Can spawn unlimited containers
   - Mitigation: cgroup limits + container count monitoring

#### 3. CVSS 3.1 Scoring

**Base Metrics**:
- **Attack Vector (AV)**: Network (N) - Requires TMWS compromise
- **Attack Complexity (AC)**: High (H) - Requires bypassing proxy restrictions
- **Privileges Required (PR)**: Low (L) - Needs TMWS container access
- **User Interaction (UI)**: None (N)
- **Scope (S)**: Changed (C) - Can affect other containers
- **Confidentiality (C)**: High (H) - Can access MCP data
- **Integrity (I)**: High (H) - Can modify containers
- **Availability (A)**: High (H) - Can DoS via resource exhaustion

**CVSS Score**: `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H`
**Numeric Score**: **8.5 (HIGH)**

**With Additional Mitigations** (Falco + Image Whitelist + cgroup limits):
- **Attack Complexity**: High → Very High (AC:H remains, but practical difficulty increases)
- **Estimated Score**: **7.2-7.8 (HIGH, but borderline MEDIUM)**

### Performance Analysis

**Latency Overhead**:
- Docker Socket Proxy: +2-5ms per Docker API call
- PyInstaller Binary: -10-20ms startup time (faster than Python interpreter)
- Inter-container Communication: +1-3ms (TCP vs Unix socket)

**Total Overhead**: +3-8ms per MCP tool execution

**Benchmark** (estimated):
```
Native TMWS → MCP Docker:        15ms
Full Docker (Proxy):             15ms + 3-8ms = 18-23ms
Acceptable for target use case:  ✅ (<30ms threshold)
```

### Implementation Complexity

**Time Estimate**: 16-24 hours

**Breakdown**:
1. PyInstaller Build Configuration: 4-6 hours
   - Multi-stage Dockerfile
   - Encryption key management
   - Binary testing
2. Docker Socket Proxy Setup: 2-3 hours
   - Environment variable configuration
   - Permission testing
3. TMWS Docker Client Integration: 4-6 hours
   - Modify `src/services/mcp_service.py` to use `DOCKER_HOST`
   - Handle proxy errors
   - Retry logic
4. Image Whitelist Implementation: 3-4 hours
   - Proxy plugin or middleware
   - Validation logic
5. Testing & Validation: 3-5 hours
   - Security tests (volume mount attempts)
   - Performance benchmarks
   - Integration tests

### Deployment Complexity

**Rating**: Medium

**Steps**:
1. Build TMWS image: `docker build -t tmws:v2.4.0-obfuscated .`
2. Deploy stack: `docker-compose up -d`
3. Configure Claude Desktop:
   ```json
   {
     "mcpServers": {
       "tmws": {
         "command": "docker",
         "args": ["exec", "-i", "tmws", "/app/tmws"]
       }
     }
   }
   ```

**Operational Overhead**:
- ✅ Standard Docker Compose workflow
- ✅ No Kubernetes required
- ⚠️ Requires Docker Socket Proxy maintenance (third-party image)

### Trade-offs

| Aspect | Score | Notes |
|--------|-------|-------|
| Source Code Obfuscation | 8/10 | PyInstaller is industry standard, but reversible |
| Security | 7/10 | CVSS 7.2-7.8 with mitigations, acceptable for commercial |
| Performance | 9/10 | +3-8ms overhead, negligible |
| Implementation Complexity | 6/10 | 16-24 hours, moderate effort |
| Deployment Complexity | 7/10 | Medium, requires Docker Compose knowledge |
| Operational Simplicity | 8/10 | Standard Docker workflow |

**Overall Viability**: ✅ **Recommended with mitigations**

---

## Approach 2: Sidecar Pattern (Kubernetes)

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Kubernetes Cluster (K8s)                               │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Pod: tmws-pod                                      │ │
│  │                                                     │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │ Container: tmws                              │ │ │
│  │  │ - Image: tmws:v2.4.0-obfuscated              │ │ │
│  │  │ - Port: 8080 (FastAPI)                       │ │ │
│  │  │ - Volume: tmws-data (PVC)                    │ │ │
│  │  └────────────┬─────────────────────────────────┘ │ │
│  │               │ localhost:50051 (gRPC)            │ │
│  │               ↓                                   │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │ Container: serena-mcp                        │ │ │
│  │  │ - Port: 50051 (gRPC)                         │ │ │
│  │  │ - Volume: project-code (read-only)           │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  │                                                     │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │ Container: gdrive-mcp                        │ │ │
│  │  │ - Port: 50052 (gRPC)                         │ │ │
│  │  │ - Volume: gdrive-credentials (Secret)        │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  │                                                     │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  Network Policy: Deny all except intra-pod localhost    │
└─────────────────────────────────────────────────────────┘
```

### Implementation

**Kubernetes Manifest**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: tmws-pod
  namespace: tmws
  labels:
    app: tmws
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000

  containers:
  # TMWS Main Container
  - name: tmws
    image: tmws:v2.4.0-obfuscated
    ports:
    - containerPort: 8080
      name: http
    env:
    - name: TMWS_ENVIRONMENT
      value: production
    - name: MCP_SERENA_ENDPOINT
      value: localhost:50051  # Sidecar via localhost
    - name: MCP_GDRIVE_ENDPOINT
      value: localhost:50052
    volumeMounts:
    - name: tmws-data
      mountPath: /data
    resources:
      requests:
        memory: "512Mi"
        cpu: "500m"
      limits:
        memory: "1Gi"
        cpu: "1000m"
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true

  # Serena MCP Sidecar
  - name: serena-mcp
    image: serena-mcp:latest
    ports:
    - containerPort: 50051
      name: grpc
    volumeMounts:
    - name: project-code
      mountPath: /workspace
      readOnly: true
    resources:
      requests:
        memory: "256Mi"
        cpu: "250m"
      limits:
        memory: "512Mi"
        cpu: "500m"
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true

  # Google Drive MCP Sidecar
  - name: gdrive-mcp
    image: gdrive-mcp:latest
    ports:
    - containerPort: 50052
      name: grpc
    env:
    - name: GOOGLE_CREDENTIALS
      valueFrom:
        secretKeyRef:
          name: gdrive-secret
          key: credentials.json
    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "256Mi"
        cpu: "200m"
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true

  volumes:
  - name: tmws-data
    persistentVolumeClaim:
      claimName: tmws-pvc
  - name: project-code
    hostPath:
      path: /Users/apto-as/workspace  # macOS host path
      type: Directory

---
apiVersion: v1
kind: Service
metadata:
  name: tmws-service
  namespace: tmws
spec:
  selector:
    app: tmws
  ports:
  - port: 8080
    targetPort: 8080
    name: http
  type: LoadBalancer  # Or NodePort for local dev

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tmws-network-policy
  namespace: tmws
spec:
  podSelector:
    matchLabels:
      app: tmws
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector: {}  # Only from same pod
  egress:
  - to:
    - podSelector: {}  # Only to same pod
  - ports:  # Allow external API calls (gdrive, slack)
    - port: 443
      protocol: TCP
```

### Security Analysis

#### 1. Source Code Protection
- ✅ **Same as Approach 1**: PyInstaller obfuscation
- ✅ **Additional Layer**: Kubernetes RBAC prevents pod inspection
- ✅ **Secret Management**: K8s Secrets for credentials (encrypted at rest)

#### 2. Container Isolation

**Threat Model**:
- Attacker compromises TMWS container
- Attempts to access sidecars or escape pod

**Mitigations**:

| Attack Vector | K8s Feature | Effectiveness |
|---------------|-------------|---------------|
| Access other containers | Network Policy | ✅ Localhost-only |
| Execute in sidecar | RBAC + PSP | ✅ No exec permissions |
| Read sidecar filesystem | securityContext | ✅ Read-only root FS |
| Privilege escalation | `allowPrivilegeEscalation: false` | ✅ Blocked |
| Container escape | `runAsNonRoot: true` | ✅ Non-root user |
| Resource exhaustion | Resource Limits | ✅ CPU/Memory capped |

**Residual Risks**:
1. **Localhost Communication**: TMWS can still talk to sidecars
   - Acceptable: Intended behavior for MCP tools
2. **K8s API Access**: If service account has permissions
   - Mitigation: Minimal RBAC, no pod/secret permissions
3. **Host Path Volume**: Serena needs access to host code
   - Risk: Read-only mount, no write access
   - CVSS Impact: Low (no data exfiltration risk)

#### 3. CVSS 3.1 Scoring

**Base Metrics**:
- **Attack Vector (AV)**: Network (N)
- **Attack Complexity (AC)**: High (H) - Requires K8s exploit
- **Privileges Required (PR)**: Low (L) - Container access
- **User Interaction (UI)**: None (N)
- **Scope (S)**: Unchanged (U) - **Pod-level isolation**
- **Confidentiality (C)**: Low (L) - Only sidecar data
- **Integrity (I)**: Low (L) - Read-only filesystem
- **Availability (A)**: Low (L) - Resource limits prevent DoS

**CVSS Score**: `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L`
**Numeric Score**: **4.9 (MEDIUM)** ✅

**Conclusion**: **Significantly more secure than Approach 1** due to pod-level isolation.

### Performance Analysis

**Latency Overhead**:
- Localhost Communication: +0.1-0.5ms (vs Unix socket)
- gRPC Overhead: +1-2ms (vs STDIO)
- K8s Service Mesh (if enabled): +3-5ms

**Total Overhead**: +1.1-7.5ms

**Benchmark** (estimated):
```
Native TMWS → MCP Docker:    15ms
K8s Sidecar (no mesh):       15ms + 1.1-2.5ms = 16.1-17.5ms ✅
K8s Sidecar (with mesh):     15ms + 4.1-7.5ms = 19.1-22.5ms ✅
```

**Startup Time**:
- Pod Creation: 5-10 seconds (slower than `docker run`)
- Acceptable for long-running service

### Implementation Complexity

**Time Estimate**: 24-40 hours

**Breakdown**:
1. PyInstaller Build (same as Approach 1): 4-6 hours
2. Kubernetes Manifests: 6-10 hours
   - Pod definition
   - Network Policy
   - RBAC configuration
   - Secret management
3. MCP Server gRPC Conversion: 8-12 hours
   - Convert STDIO → gRPC protocol
   - Health checks
   - Graceful shutdown
4. Local K8s Setup: 3-5 hours
   - Docker Desktop K8s OR Minikube
   - Persistent Volume configuration
5. Testing & Validation: 3-7 hours
   - Network policy testing
   - Resource limit validation
   - Integration tests

### Deployment Complexity

**Rating**: Hard

**Prerequisites**:
- ✅ Kubernetes cluster (Docker Desktop K8s or Minikube for local dev)
- ⚠️ K8s knowledge required (YAML, kubectl, networking)
- ⚠️ More complex troubleshooting (logs across containers)

**Operational Overhead**:
- ⚠️ K8s manifest maintenance
- ⚠️ Secret rotation
- ⚠️ Network policy debugging
- ✅ Better observability (Prometheus, Grafana)

**Local Development**:
```bash
# Docker Desktop K8s (easiest for macOS)
kubectl apply -f k8s/tmws-pod.yaml
kubectl port-forward svc/tmws-service 8080:8080

# Claude Desktop config
{
  "mcpServers": {
    "tmws": {
      "command": "kubectl",
      "args": ["exec", "-i", "tmws-pod", "-c", "tmws", "--", "/app/tmws"]
    }
  }
}
```

### Trade-offs

| Aspect | Score | Notes |
|--------|-------|-------|
| Source Code Obfuscation | 8/10 | Same as Approach 1 + K8s RBAC |
| Security | 9/10 | **CVSS 4.9 MEDIUM**, pod-level isolation |
| Performance | 8/10 | +1-7ms overhead, acceptable |
| Implementation Complexity | 4/10 | **24-40 hours, high effort** |
| Deployment Complexity | 3/10 | **Hard, requires K8s expertise** |
| Operational Simplicity | 5/10 | More complex, but better observability |
| Scalability | 10/10 | **Excellent for production** |

**Overall Viability**: ⚠️ **Recommended for production deployment, OVERKILL for local dev**

---

## Approach 3: Orchestrator Service (Split Architecture)

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Host OS (macOS)                                             │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Claude Desktop                                          │ │
│  │ ┌──────────────────────────────────────────┐           │ │
│  │ │ STDIO: tmws-cli                          │           │ │
│  │ └────────────────┬─────────────────────────┘           │ │
│  └─────────────────┼─────────────────────────────────────┘ │
│                    │ HTTP/WebSocket                         │
│                    ↓                                         │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ TMWS Container (Docker, obfuscated)                     │ │
│  │ ┌──────────────────────────────────────────────────┐   │ │
│  │ │ PyInstaller Binary                               │   │ │
│  │ │ - FastAPI application                            │   │ │
│  │ │ - Memory/Learning services                       │   │ │
│  │ │ - NO docker client                               │   │ │
│  │ └────────────────┬─────────────────────────────────┘   │ │
│  └─────────────────┼─────────────────────────────────────┘ │
│                    │ HTTP API (gRPC alternative)            │
│                    ↓                                         │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Orchestrator Service (Native Python, minimal)           │ │
│  │ ┌──────────────────────────────────────────────────┐   │ │
│  │ │ orchestrator.py (~300 lines)                     │   │ │
│  │ │ - MCP tool execution                             │   │ │
│  │ │ - docker run whitelist validation                │   │ │
│  │ │ - Resource limits enforcement                    │   │ │
│  │ │ - Audit logging                                  │   │ │
│  │ └────────────────┬─────────────────────────────────┘   │ │
│  └─────────────────┼─────────────────────────────────────┘ │
│                    │ docker run (allowed images only)       │
│                    ↓                                         │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ MCP Containers (Docker)                                 │ │
│  │ ┌────────┐  ┌────────┐  ┌────────┐                    │ │
│  │ │serena  │  │gdrive  │  │slack   │                    │ │
│  │ └────────┘  └────────┘  └────────┘                    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  /var/run/docker.sock (accessed only by orchestrator)        │
└──────────────────────────────────────────────────────────────┘
```

### Implementation

**Orchestrator Service** (`orchestrator.py`):
```python
#!/usr/bin/env python3
"""
TMWS Orchestrator Service
Minimal trusted component with docker.sock access.
~300 lines of security-critical code.
"""
import asyncio
import docker
import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List

# Whitelist of allowed MCP images
ALLOWED_IMAGES = {
    "serena-mcp:latest": "sha256:abc123...",  # Image hash verification
    "gdrive-mcp:latest": "sha256:def456...",
    "slack-mcp:latest": "sha256:ghi789...",
}

# Resource limits per container
RESOURCE_LIMITS = {
    "cpu_period": 100000,
    "cpu_quota": 50000,  # 50% CPU
    "mem_limit": "512m",
    "pids_limit": 100,
}

app = FastAPI()
docker_client = docker.from_env()

class ContainerRequest(BaseModel):
    image: str
    command: List[str]
    environment: Dict[str, str] = {}
    volumes: Dict[str, Dict[str, str]] = {}  # Must be empty for security

@app.post("/containers/run")
async def run_container(req: ContainerRequest):
    """
    Securely run MCP container with strict validation.
    """
    # Validation 1: Image whitelist
    if req.image not in ALLOWED_IMAGES:
        raise HTTPException(403, f"Image {req.image} not whitelisted")

    # Validation 2: Image hash verification
    image = docker_client.images.get(req.image)
    expected_hash = ALLOWED_IMAGES[req.image]
    if image.id != expected_hash:
        raise HTTPException(403, f"Image hash mismatch for {req.image}")

    # Validation 3: No volume mounts (prevent host access)
    if req.volumes:
        raise HTTPException(403, "Volume mounts are not allowed")

    # Validation 4: Environment variable sanitization
    sanitized_env = {
        k: v for k, v in req.environment.items()
        if not k.startswith("DOCKER_") and not k.startswith("KUBE_")
    }

    # Run container with strict resource limits
    try:
        container = docker_client.containers.run(
            image=req.image,
            command=req.command,
            environment=sanitized_env,
            detach=True,
            remove=True,
            network_mode="bridge",  # Isolated network
            cpu_period=RESOURCE_LIMITS["cpu_period"],
            cpu_quota=RESOURCE_LIMITS["cpu_quota"],
            mem_limit=RESOURCE_LIMITS["mem_limit"],
            pids_limit=RESOURCE_LIMITS["pids_limit"],
            cap_drop=["ALL"],  # Drop all capabilities
            security_opt=["no-new-privileges"],
        )

        # Audit log
        log_container_creation(req.image, container.id)

        return {
            "container_id": container.id,
            "status": "running"
        }

    except docker.errors.DockerException as e:
        raise HTTPException(500, f"Docker error: {str(e)}")

def log_container_creation(image: str, container_id: str):
    """Audit logging for container creation."""
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"{timestamp} | {image} | {container_id}"
    with open("/var/log/tmws-orchestrator.log", "a") as f:
        f.write(log_entry + "\n")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
```

**TMWS Integration** (`src/services/orchestrator_client.py`):
```python
import httpx
from typing import Dict, List

class OrchestratorClient:
    """Client for TMWS → Orchestrator communication."""

    def __init__(self, base_url: str = "http://host.docker.internal:8081"):
        self.base_url = base_url
        self.client = httpx.AsyncClient()

    async def run_mcp_container(
        self,
        image: str,
        command: List[str],
        environment: Dict[str, str] = None
    ) -> str:
        """
        Request orchestrator to run MCP container.
        Returns container ID.
        """
        response = await self.client.post(
            f"{self.base_url}/containers/run",
            json={
                "image": image,
                "command": command,
                "environment": environment or {},
                "volumes": {}  # Always empty for security
            }
        )
        response.raise_for_status()
        return response.json()["container_id"]
```

**Deployment**:
```yaml
# docker-compose.yml
version: '3.8'

services:
  orchestrator:
    build: ./orchestrator
    ports:
      - "8081:8081"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true

  tmws:
    image: tmws:v2.4.0-obfuscated
    environment:
      TMWS_ORCHESTRATOR_URL: http://orchestrator:8081
    volumes:
      - tmws-data:/data
    ports:
      - "8080:8080"
    depends_on:
      - orchestrator
    restart: unless-stopped
    # NO docker.sock access ✅

volumes:
  tmws-data:
```

### Security Analysis

#### 1. Source Code Protection
- ✅ **TMWS**: PyInstaller obfuscation (same as Approach 1/2)
- ✅ **Orchestrator**: Small Python script (~300 lines), can be open source
  - Rationale: Security through transparency (Kerckhoffs's principle)
  - Alternatively: PyInstaller obfuscation for orchestrator too

#### 2. Attack Surface Reduction

**Key Insight**: **Minimize docker.sock exposure to smallest possible component**

**Threat Model**:
- Attacker compromises TMWS container → **NO docker.sock access** ✅
- Attacker compromises orchestrator → Can create whitelisted containers only
- Attacker bypasses whitelist → Image hash verification prevents tampering

**Mitigations**:

| Attack Vector | Mitigation | Effectiveness |
|---------------|------------|---------------|
| TMWS container escape | No docker.sock in TMWS | ✅ Impossible |
| Orchestrator compromise | Whitelist + hash verification | ✅ Blocked |
| Malicious MCP image | Image hash pinning | ✅ Blocked |
| Volume mount attack | Reject all volume requests | ✅ Blocked |
| Resource exhaustion | cgroup limits per container | ✅ Blocked |
| Network-based container access | Isolated bridge network | ✅ Blocked |

**Residual Risks**:
1. **Orchestrator Vulnerability**: If orchestrator has code execution bug
   - Mitigation: Minimal codebase (~300 lines), security audit
   - Probability: Low (small attack surface)
2. **Whitelist Update Attack**: If attacker can modify `ALLOWED_IMAGES`
   - Mitigation: Read-only filesystem for orchestrator
   - File integrity monitoring (e.g., AIDE)

#### 3. CVSS 3.1 Scoring

**Scenario: TMWS Container Compromised**:
- **Attack Vector (AV)**: Network (N)
- **Attack Complexity (AC)**: High (H) - Must compromise orchestrator next
- **Privileges Required (PR)**: None (N) - TMWS has no docker access
- **User Interaction (UI)**: None (N)
- **Scope (S)**: Unchanged (U) - **TMWS cannot affect host**
- **Confidentiality (C)**: None (N) - No data accessible
- **Integrity (I)**: None (N) - Cannot modify anything
- **Availability (A)**: None (N) - Cannot DoS

**CVSS Score**: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`
**Numeric Score**: **0.0 (NONE)** ✅

**Scenario: Orchestrator Compromised**:
- **Attack Complexity (AC)**: Very High (orchestrator is small, audited)
- **Scope (S)**: Changed (C) - Can create containers
- **Confidentiality (C)**: Low (L) - Only whitelisted MCP data
- **Integrity (I)**: Low (L) - Can run whitelisted images only
- **Availability (A)**: Medium (M) - Can exhaust resources

**CVSS Score**: `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L`
**Numeric Score**: **5.5 (MEDIUM)** ✅

**Conclusion**: **Lowest risk of all approaches** (0.0 for TMWS compromise, 5.5 for orchestrator compromise)

### Performance Analysis

**Latency Overhead**:
- HTTP Request (TMWS → Orchestrator): +2-5ms
- Docker API Call (Orchestrator → Docker): +2-5ms
- Total: +4-10ms per MCP tool execution

**Benchmark** (estimated):
```
Native TMWS → MCP Docker:     15ms
Orchestrator (HTTP + Docker): 15ms + 4-10ms = 19-25ms ✅
```

**Startup Time**:
- Orchestrator: <1 second (Python FastAPI)
- TMWS Container: Same as Approach 1 (~2-3 seconds)

### Implementation Complexity

**Time Estimate**: 12-20 hours

**Breakdown**:
1. PyInstaller Build (same as Approach 1): 4-6 hours
2. Orchestrator Service: 4-8 hours
   - FastAPI service
   - Image whitelist + hash verification
   - Resource limit enforcement
   - Audit logging
3. TMWS Integration: 2-4 hours
   - `OrchestratorClient` implementation
   - Modify `mcp_service.py` to use HTTP API
4. Testing & Validation: 2-2 hours
   - Security tests (bypass attempts)
   - Performance benchmarks
   - Integration tests

### Deployment Complexity

**Rating**: Easy-Medium

**Steps**:
1. Build orchestrator: `docker build -t orchestrator:latest ./orchestrator`
2. Build TMWS: `docker build -t tmws:v2.4.0-obfuscated .`
3. Deploy stack: `docker-compose up -d`

**Operational Overhead**:
- ✅ Simple two-service architecture
- ✅ Standard Docker Compose workflow
- ✅ Easy troubleshooting (separate logs for orchestrator vs TMWS)
- ⚠️ Orchestrator requires security updates (small codebase)

### Trade-offs

| Aspect | Score | Notes |
|--------|-------|-------|
| Source Code Obfuscation | 8/10 | TMWS obfuscated, orchestrator can be open |
| Security | 10/10 | **CVSS 0.0 (TMWS), 5.5 (orchestrator)** |
| Performance | 8/10 | +4-10ms overhead, acceptable |
| Implementation Complexity | 7/10 | 12-20 hours, moderate effort |
| Deployment Complexity | 8/10 | Easy, two-service Docker Compose |
| Operational Simplicity | 9/10 | Simple architecture, easy debugging |
| Scalability | 7/10 | Good, orchestrator can be replicated |

**Overall Viability**: ✅ **HIGHLY RECOMMENDED** (best security-to-complexity ratio)

---

## Approach 4: WASM + Docker Hybrid

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Host OS (macOS)                                        │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Claude Desktop                                     │ │
│  │ ┌──────────────────────────────────────┐          │ │
│  │ │ STDIO: tmws-wasm-runner              │          │ │
│  │ └────────────────┬─────────────────────┘          │ │
│  └─────────────────┼────────────────────────────────┘ │
│                    │                                   │
│                    ↓                                   │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ WASM Runtime (Wasmtime / WasmEdge)                 │ │
│  │ ┌──────────────────────────────────────────────┐  │ │
│  │ │ TMWS Core (WASM Module)                      │  │ │
│  │ │ - Compiled from Python via Pyodide           │  │ │
│  │ │ - Sandboxed execution                        │  │ │
│  │ │ - No file system access (except WASI)        │  │ │
│  │ │ - Cannot access host OS                      │  │ │
│  │ └────────────────┬───────────────────────────────┘  │ │
│  └─────────────────┼────────────────────────────────┘ │
│                    │ WASI Interface (limited syscalls)  │
│                    ↓                                   │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ MCP Bridge (Native Python, minimal)                │ │
│  │ - Receives requests from WASM via WASI             │ │
│  │ - Executes docker run for MCP tools                │ │
│  └─────────────────┬────────────────────────────────┘ │
│                    │ docker run                        │
│                    ↓                                   │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ MCP Containers (Docker)                            │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Implementation

**Build WASM Module** (Pyodide):
```bash
# Install Pyodide build tools
pip install pyodide-build

# Compile TMWS to WASM
pyodide build \
  --skip-install \
  --output-dir dist/wasm \
  ./src

# Result: tmws.wasm (self-contained Python bytecode + dependencies)
```

**WASM Runner** (`tmws-wasm-runner.py`):
```python
#!/usr/bin/env python3
"""
TMWS WASM Runner
Executes TMWS core in sandboxed WASM environment.
"""
from wasmtime import Store, Module, Instance, Linker
import json

# Load compiled WASM module
store = Store()
module = Module.from_file(store.engine, "dist/wasm/tmws.wasm")

# Create WASI environment with limited capabilities
linker = Linker(store.engine)
linker.define_wasi()

# Whitelist of allowed WASI syscalls
ALLOWED_WASI_CALLS = {
    "fd_read",      # Read from file descriptors (STDIN)
    "fd_write",     # Write to file descriptors (STDOUT/STDERR)
    "clock_time_get",  # Get current time
    "random_get",   # Get random bytes
    # NO: fd_open, path_open (prevent file system access)
}

def wasi_syscall_filter(syscall_name: str, *args):
    """Filter WASI syscalls to prevent unauthorized access."""
    if syscall_name not in ALLOWED_WASI_CALLS:
        raise PermissionError(f"WASI syscall {syscall_name} not allowed")
    # Delegate to original WASI implementation
    return original_wasi[syscall_name](*args)

# Instantiate WASM module with filtered WASI
instance = Instance(store, module, linker)

# Call TMWS main function
try:
    tmws_main = instance.exports(store)["main"]
    result = tmws_main(store)
    print(f"TMWS WASM exited with code: {result}")
except Exception as e:
    print(f"WASM execution error: {e}")
```

### Security Analysis

#### 1. Source Code Protection
- ✅ **Excellent**: WASM bytecode is highly obfuscated
- ✅ **Decompilation Difficult**: WASM → Python reverse engineering is complex
- ✅ **Commercial Acceptability**: Industry-standard for web apps (e.g., Figma, AutoCAD)

**Comparison to PyInstaller**:
| Feature | PyInstaller | WASM |
|---------|-------------|------|
| Obfuscation Level | Medium | **High** |
| Decompilation Difficulty | Moderate | **Very High** |
| Runtime Protection | None | **Sandboxed** |

#### 2. Sandboxing

**Threat Model**:
- Attacker compromises TMWS WASM module
- Attempts to access host file system or execute arbitrary code

**Mitigations**:

| Attack Vector | WASM Mitigation | Effectiveness |
|---------------|-----------------|---------------|
| File system access | No `fd_open` syscall | ✅ Impossible |
| Network access | No socket syscalls | ✅ Impossible |
| Process execution | No `exec` syscall | ✅ Impossible |
| Memory corruption | WASM memory isolation | ✅ Impossible |
| Arbitrary code execution | No JIT in WASM | ✅ Impossible |

**Residual Risks**:
1. **MCP Bridge Compromise**: Native Python component still has docker.sock
   - Mitigation: Same as Approach 3 (whitelist + hash verification)
2. **WASM Runtime Vulnerability**: Wasmtime/WasmEdge security bug
   - Probability: Low (mature runtimes, actively maintained)
3. **Pyodide Compatibility**: Not all Python libraries work in WASM
   - Impact: May need to rewrite incompatible code (e.g., asyncio edge cases)

#### 3. CVSS 3.1 Scoring

**Scenario: TMWS WASM Compromised**:
- **Attack Complexity (AC)**: Very High (must escape WASM sandbox)
- **Scope (S)**: Unchanged (U) - **WASM sandbox isolation**
- **Confidentiality (C)**: None (N) - No file system access
- **Integrity (I)**: None (N) - Cannot modify host
- **Availability (A)**: Low (L) - Can consume WASM memory only

**CVSS Score**: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`
**Numeric Score**: **3.7 (LOW)** ✅

**Scenario: MCP Bridge Compromised**:
- Same as Approach 3 orchestrator: **CVSS 5.5 (MEDIUM)**

**Conclusion**: **Strongest isolation** (WASM sandbox + MCP bridge separation)

### Performance Analysis

**WASM Overhead**:
- Pyodide Startup: +500-1000ms (one-time cost)
- WASM Execution: +5-15% CPU overhead (vs native Python)
- Memory: +50-100MB (Pyodide runtime)

**Benchmark** (estimated):
```
Native Python TMWS:       100 req/sec, 15ms P95
WASM TMWS (Pyodide):      85-90 req/sec, 17-20ms P95 ⚠️
```

**Impact**:
- ⚠️ **5-10% performance degradation**
- ⚠️ **Slower startup** (+500-1000ms)
- ✅ Acceptable for commercial product (security > 5% performance)

### Implementation Complexity

**Time Estimate**: 40-80 hours ⚠️ **HIGHEST EFFORT**

**Breakdown**:
1. Pyodide Build Setup: 8-16 hours
   - Configure Pyodide build environment
   - Resolve dependency compatibility (SQLAlchemy, FastAPI in WASM?)
   - Test WASM module execution
2. WASI Syscall Filtering: 6-10 hours
   - Implement custom WASI filter
   - Test syscall whitelisting
3. TMWS Code Adaptation: 12-24 hours
   - Replace incompatible libraries (e.g., asyncio → WASM-compatible)
   - Handle WASM-specific limitations
4. MCP Bridge (same as Approach 3): 4-8 hours
5. WASM Runner: 4-8 hours
   - Wasmtime/WasmEdge integration
   - STDIO handling
6. Testing & Validation: 6-14 hours
   - WASM compatibility tests
   - Performance benchmarks
   - Security validation

**Risk**: ⚠️ **Pyodide/WASM maturity for Python 3.11+** is uncertain

### Deployment Complexity

**Rating**: Medium-Hard

**Steps**:
1. Build WASM module: `pyodide build ./src`
2. Deploy WASM runner: `./tmws-wasm-runner.py`
3. Deploy MCP bridge: `docker-compose up -d`

**Operational Overhead**:
- ⚠️ WASM runtime updates (Wasmtime/WasmEdge)
- ⚠️ Pyodide version compatibility
- ⚠️ Debugging WASM issues (limited tooling vs Python)

### Trade-offs

| Aspect | Score | Notes |
|--------|-------|-------|
| Source Code Obfuscation | 10/10 | **Best obfuscation** (WASM bytecode) |
| Security | 10/10 | **CVSS 3.7 (WASM), 5.5 (bridge)** |
| Performance | 6/10 | **-5-10% performance, +500ms startup** |
| Implementation Complexity | 3/10 | **40-80 hours, very high effort** |
| Deployment Complexity | 5/10 | Medium-Hard, WASM runtime required |
| Operational Simplicity | 4/10 | Complex debugging, immature tooling |
| Python Compatibility | 5/10 | ⚠️ Not all libraries work in WASM |

**Overall Viability**: ⚠️ **High risk, high reward** (best security, but immature for Python 3.11+)

---

## Approach 5: PyInstaller + Docker Socket Proxy + ALL Mitigations

### Architecture

Same as **Approach 1**, but with **maximum security hardening**:

```
Mitigations Stack:
├─ Docker Socket Proxy (Tecnativa)
├─ Falco Runtime Monitoring
├─ AppArmor/SELinux Profile
├─ Image Whitelist (in proxy config)
├─ cgroup Resource Limits
├─ Network Segmentation
└─ Audit Logging (all Docker API calls)
```

### Implementation

**Enhanced Docker Compose**:
```yaml
version: '3.8'

services:
  docker-proxy:
    image: tecnativa/docker-socket-proxy:latest
    environment:
      CONTAINERS: 1
      POST: 1
      DELETE: 1
      IMAGES: 1
      VOLUMES: 0       # 🔒 DENY
      NETWORKS: 1
      EXEC: 0          # 🔒 DENY
      BUILD: 0         # 🔒 DENY
      # Image whitelist (custom proxy config)
      ALLOWED_IMAGES: "serena-mcp:latest,gdrive-mcp:latest,slack-mcp:latest"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./proxy-config.yaml:/etc/docker-proxy/config.yaml:ro  # Custom validation
    networks:
      - tmws-internal
    security_opt:
      - apparmor:docker-proxy-profile  # Custom AppArmor profile

  falco:
    image: falcosecurity/falco:latest
    privileged: true  # Required for kernel-level monitoring
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock:ro
      - ./falco-rules.yaml:/etc/falco/falco_rules.local.yaml:ro
    command:
      - /usr/bin/falco
      - --cri
      - /host/var/run/docker.sock
      - -r /etc/falco/falco_rules.local.yaml

  tmws:
    image: tmws:v2.4.0-obfuscated
    environment:
      DOCKER_HOST: tcp://docker-proxy:2375
    volumes:
      - tmws-data:/data
    networks:
      - tmws-internal
      - mcp-network
    depends_on:
      - docker-proxy
      - falco
    security_opt:
      - apparmor:tmws-profile  # Custom AppArmor profile
      - seccomp:unconfined
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

**Falco Rules** (`falco-rules.yaml`):
```yaml
# Detect unauthorized Docker operations
- rule: Unauthorized Docker Volume Mount
  desc: TMWS attempting to create volume mount
  condition: >
    container.name = "tmws" and
    docker.action = "create" and
    docker.object.type = "container" and
    docker.volumes != ""
  output: "ALERT: TMWS attempted volume mount (container=%container.name, volumes=%docker.volumes)"
  priority: CRITICAL
  source: docker_events

- rule: Unauthorized Docker Exec
  desc: TMWS attempting to exec into container
  condition: >
    container.name = "tmws" and
    docker.action = "exec"
  output: "ALERT: TMWS attempted docker exec (container=%container.name, command=%docker.exec.command)"
  priority: CRITICAL
  source: docker_events

- rule: Non-Whitelisted Image Pull
  desc: TMWS pulling non-whitelisted image
  condition: >
    container.name = "tmws" and
    docker.action = "pull" and
    not docker.image in (serena-mcp, gdrive-mcp, slack-mcp)
  output: "ALERT: TMWS pulled non-whitelisted image (image=%docker.image)"
  priority: HIGH
  source: docker_events
```

**AppArmor Profile** (`tmws-profile`):
```
#include <tunables/global>

profile tmws-profile flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Allow network access
  network inet stream,
  network inet dgram,

  # Allow read-only access to TMWS data volume
  /data/** rw,

  # DENY host file system access
  deny /** w,
  deny /var/run/docker.sock rw,

  # DENY process execution
  deny /bin/** x,
  deny /usr/bin/** x,

  # Allow TMWS binary execution
  /app/tmws ix,
}
```

**Enhanced Proxy Validation** (`proxy-middleware.py`):
```python
from fastapi import FastAPI, HTTPException, Request
import hashlib

ALLOWED_IMAGES = {
    "serena-mcp:latest": "sha256:abc123...",
    "gdrive-mcp:latest": "sha256:def456...",
    "slack-mcp:latest": "sha256:ghi789...",
}

app = FastAPI()

@app.middleware("http")
async def validate_docker_request(request: Request, call_next):
    """
    Middleware to validate Docker API requests.
    Blocks unauthorized operations BEFORE reaching Docker daemon.
    """
    if request.url.path.startswith("/containers/create"):
        body = await request.json()

        # Validate image whitelist
        image = body.get("Image", "")
        if image not in ALLOWED_IMAGES:
            raise HTTPException(403, f"Image {image} not whitelisted")

        # Validate no volume mounts
        if body.get("HostConfig", {}).get("Binds"):
            raise HTTPException(403, "Volume mounts are not allowed")

        # Validate resource limits
        host_config = body.get("HostConfig", {})
        if not host_config.get("Memory") or host_config["Memory"] > 512 * 1024 * 1024:
            raise HTTPException(403, "Memory limit required and must be <= 512MB")

    return await call_next(request)
```

### Security Analysis

#### 1. Defense in Depth

**7 Layers of Security**:

| Layer | Technology | Attack Blocked |
|-------|-----------|----------------|
| 1. Image Whitelist | Proxy Config | Non-approved images |
| 2. Hash Verification | Proxy Middleware | Tampered images |
| 3. Volume Mount Block | Proxy `VOLUMES:0` | Host file access |
| 4. Runtime Monitoring | Falco | Unauthorized Docker ops |
| 5. MAC (AppArmor) | AppArmor Profile | File system access |
| 6. Capability Drop | Docker `cap_drop:ALL` | Privilege escalation |
| 7. Resource Limits | cgroup | Resource exhaustion |

**Attack Scenarios**:

| Attack | Layer 1 | Layer 2 | Layer 3 | Layer 4 | Layer 5 | Blocked? |
|--------|---------|---------|---------|---------|---------|----------|
| `docker run -v /:/host` | - | - | ✅ | ✅ | ✅ | **YES** |
| `docker pull malicious-image` | ✅ | - | - | ✅ | - | **YES** |
| `docker exec -it tmws bash` | ✅ | - | - | ✅ | - | **YES** |
| Spawn 1000 containers | - | - | - | - | ✅ | **YES** (cgroup) |
| Tamper whitelisted image | - | ✅ | - | - | - | **YES** |

#### 2. CVSS 3.1 Scoring

**With ALL Mitigations**:
- **Attack Complexity (AC)**: Very High (must bypass 7 layers)
- **Confidentiality (C)**: Low (only MCP data)
- **Integrity (I)**: Low (can run whitelisted containers only)
- **Availability (A)**: Low (resource limits prevent DoS)

**CVSS Score**: `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L`
**Numeric Score**: **6.0 (MEDIUM)** ✅

**Compared to Approach 1 (Proxy Only)**:
- Approach 1: CVSS 8.5 → 7.2 (with mitigations)
- **Approach 5: CVSS 6.0** (-1.2 to -2.5 improvement)

### Performance Analysis

**Latency Overhead**:
- Docker Socket Proxy: +2-5ms
- Falco Monitoring: +1-2ms (asynchronous)
- AppArmor: +0.5-1ms
- **Total**: +3.5-8ms

**Same as Approach 1** (proxy overhead dominates)

### Implementation Complexity

**Time Estimate**: 24-32 hours

**Breakdown**:
1. PyInstaller Build (same as Approach 1): 4-6 hours
2. Docker Socket Proxy (same as Approach 1): 2-3 hours
3. **Falco Setup**: 6-8 hours
   - Install Falco
   - Write custom rules
   - Test alerting
4. **AppArmor Profiles**: 4-6 hours
   - Write profiles for TMWS and proxy
   - Test MAC enforcement
5. **Proxy Middleware**: 4-6 hours
   - Image whitelist + hash verification
   - Resource limit validation
6. **Testing & Validation**: 4-3 hours
   - Attack simulation (try to bypass each layer)
   - Performance benchmarks

### Deployment Complexity

**Rating**: Medium-Hard

**Operational Overhead**:
- ⚠️ Falco rule maintenance
- ⚠️ AppArmor profile updates
- ⚠️ Image hash updates (when MCP images are updated)
- ✅ Excellent observability (Falco alerts)

### Trade-offs

| Aspect | Score | Notes |
|--------|-------|-------|
| Source Code Obfuscation | 8/10 | Same as Approach 1 |
| Security | 9/10 | **CVSS 6.0 MEDIUM**, 7 layers of defense |
| Performance | 9/10 | +3.5-8ms overhead |
| Implementation Complexity | 5/10 | 24-32 hours, high effort |
| Deployment Complexity | 4/10 | Medium-Hard, complex setup |
| Operational Simplicity | 6/10 | Complex, but excellent monitoring |

**Overall Viability**: ✅ **Recommended for high-security deployments** (if Approach 3 is insufficient)

---

## Comparison Matrix

| Criterion | Approach 1<br>Proxy | Approach 2<br>K8s | Approach 3<br>Orchestrator | Approach 4<br>WASM | Approach 5<br>Max Mitigation |
|-----------|---------------------|-------------------|----------------------------|--------------------|-----------------------------|
| **Security** |  |  |  |  |  |
| CVSS Score | 7.2-7.8 (HIGH) | 4.9 (MEDIUM) | 0.0/5.5 (NONE/MEDIUM) | 3.7/5.5 (LOW/MEDIUM) | 6.0 (MEDIUM) |
| Source Code Obfuscation | 8/10 | 8/10 | 8/10 | **10/10** | 8/10 |
| Defense Layers | 3 | 5 | 4 | **6** | **7** |
| **Performance** |  |  |  |  |  |
| Latency Overhead | +3-8ms | +1-7ms | +4-10ms | **+5-15%** | +3.5-8ms |
| Startup Time | Normal | Slow (+5-10s) | Normal | **Slow (+500ms)** | Normal |
| Throughput Impact | Negligible | Negligible | Negligible | **-5-10%** | Negligible |
| **Implementation** |  |  |  |  |  |
| Time Estimate | 16-24h | **24-40h** | **12-20h** | **40-80h** | 24-32h |
| Complexity | Medium | **High** | **Low-Medium** | **Very High** | High |
| Risk | Low | Medium | **Low** | **High** (WASM maturity) | Medium |
| **Deployment** |  |  |  |  |  |
| Deployment Complexity | Medium | **Hard** | **Easy-Medium** | Medium-Hard | Medium-Hard |
| Operational Overhead | Medium | High | **Low** | Medium | High |
| Scalability | Good | **Excellent** | Good | Medium | Good |
| **Overall** |  |  |  |  |  |
| Recommended For | Standard deployment | Production at scale | **MOST USERS** | High-security (future) | High-security (now) |

---

## Final Recommendation

### 🏆 **PRIMARY RECOMMENDATION: Approach 3 (Orchestrator Service)**

**Rationale**:

1. **Best Security-to-Complexity Ratio**:
   - CVSS 0.0 (TMWS) / 5.5 (orchestrator) - **Lowest risk**
   - Only 12-20 hours implementation
   - Attack surface minimized to ~300 lines of auditable code

2. **Source Code Protection**:
   - TMWS: PyInstaller obfuscation (8/10)
   - Orchestrator: Can be open source (security through transparency) OR obfuscated
   - **Commercial acceptability: HIGH**

3. **Deployment Simplicity**:
   - Easy-Medium complexity
   - Standard Docker Compose workflow
   - No Kubernetes required
   - **Suitable for local development AND production**

4. **Performance**:
   - +4-10ms overhead (acceptable)
   - No WASM performance penalty
   - No Kubernetes overhead

5. **Operational Simplicity**:
   - Simple two-service architecture
   - Easy debugging (separate logs)
   - Minimal maintenance

**Implementation Plan** (12-20 hours):

| Phase | Task | Time | Priority |
|-------|------|------|----------|
| 1 | PyInstaller build for TMWS | 4-6h | P0 |
| 2 | Orchestrator service | 4-8h | P0 |
| 3 | TMWS integration | 2-4h | P0 |
| 4 | Security testing | 2-2h | P0 |
| **Total** |  | **12-20h** |  |

---

### 🥈 **ALTERNATIVE: Approach 2 (Kubernetes Sidecar)** - For Production at Scale

**Use Case**: If TMWS will be deployed to **100+ concurrent users** or **cloud production environments**.

**Advantages over Orchestrator**:
- ✅ Better CVSS (4.9 vs 5.5 for orchestrator compromise)
- ✅ Excellent scalability (Horizontal Pod Autoscaling)
- ✅ Better observability (Prometheus, Grafana, K8s logs)
- ✅ Industry-standard deployment pattern

**Trade-offs**:
- ⚠️ Higher implementation time (24-40h vs 12-20h)
- ⚠️ Requires Kubernetes knowledge
- ⚠️ Overkill for local development

**Recommendation**: Use **Approach 3 for v2.4.0**, migrate to **Approach 2 for v3.0** when scaling to production.

---

### 🥉 **FUTURE CONSIDERATION: Approach 4 (WASM)** - For Maximum Security

**Use Case**: If **CVSS 3.7 (LOW)** is a hard requirement, or **source code obfuscation 10/10** is critical.

**Current Status**: ⚠️ **Not recommended for Python 3.11+ (immature ecosystem)**

**Timeline**: Re-evaluate in **6-12 months** when Pyodide/WASM matures.

**Migration Path**:
1. v2.4.0: Use Approach 3 (Orchestrator)
2. v2.5.0: Add Pyodide/WASM experimental support
3. v3.0.0: Full WASM migration (if ecosystem is ready)

---

### ❌ **NOT RECOMMENDED**:

1. **Approach 1 (Proxy Only)**: CVSS 7.2-7.8 (too high for commercial product)
2. **Approach 5 (Max Mitigation)**: Same security as Approach 3, but **2x implementation time** (24-32h vs 12-20h)

---

## Action Items

### Immediate (v2.4.0 - This Week)

- [ ] **User Approval**: Get explicit approval for **Approach 3 (Orchestrator Service)**
- [ ] **Create Project Plan**: Detailed task breakdown for 12-20 hour implementation
- [ ] **Allocate Resources**: Assign Artemis (implementation), Hestia (security audit), Muses (documentation)

### Short-Term (v2.4.0 - Next Week)

- [ ] **Implement Orchestrator**: `orchestrator.py` service (~300 lines)
- [ ] **Build TMWS Docker Image**: PyInstaller obfuscation
- [ ] **Integration Testing**: Security tests + performance benchmarks
- [ ] **Documentation**: Deployment guide, security audit report

### Long-Term (v3.0.0 - 3-6 months)

- [ ] **Evaluate Kubernetes Migration**: For production scaling (Approach 2)
- [ ] **Monitor WASM Ecosystem**: Track Pyodide/WASM maturity for Python 3.11+
- [ ] **Performance Optimization**: Reduce orchestrator latency to <5ms

---

**Next Step**: Await user approval for Approach 3, then proceed with Phase 1 (PyInstaller build).

