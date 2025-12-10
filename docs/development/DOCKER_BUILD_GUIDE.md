# Docker Build Guide

**Version**: 2.4.17
**Status**: Active
**Last Updated**: 2025-12-10
**Issue**: [#55](https://github.com/apto-as/tmws/issues/55)

---

## Overview

This guide covers local Docker image building, multi-platform support, and publishing to container registries (DockerHub, GHCR). TMWS no longer uses GitHub Actions for Docker builds—all builds are performed **locally** using `make` targets.

---

## Quick Start

```bash
# Build Docker image locally
make docker-build

# Build and push to registry
make docker-push

# Build, push, and create GitHub release
make docker-release
```

---

## Prerequisites

### Required Tools

```bash
# Docker Desktop (includes buildx)
brew install --cask docker

# Or Docker CLI + buildx plugin
brew install docker
docker buildx install

# GitHub CLI (for releases)
brew install gh

# Verify installations
docker --version        # 24.0+
docker buildx version   # 0.11+
gh --version            # 2.40+
```

### Docker Buildx Setup

Docker Buildx is required for multi-platform builds:

```bash
# Check if buildx is available
docker buildx version

# Create a new builder instance (first-time setup)
docker buildx create --name tmws-builder --use

# Verify builder
docker buildx inspect --bootstrap

# Expected output:
# Name:   tmws-builder
# Driver: docker-container
# Platforms: linux/amd64, linux/arm64, ...
```

---

## Configuration

### Makefile Variables

The Docker build is configured via `Makefile` variables:

```makefile
# Registry configuration
DOCKER_REGISTRY ?= ghcr.io         # or docker.io
DOCKER_REPO ?= apto-as/tmws
DOCKER_IMAGE = $(DOCKER_REGISTRY)/$(DOCKER_REPO)

# Version detection (from pyproject.toml)
VERSION := $(shell grep '^version = ' pyproject.toml | cut -d'"' -f2)

# Commit hash (for tagging)
COMMIT_HASH := $(shell git rev-parse --short HEAD)
```

### Override Registry

```bash
# Use DockerHub instead of GHCR
make docker-build DOCKER_REGISTRY=docker.io DOCKER_REPO=aptoas/tmws

# Use private registry
make docker-build DOCKER_REGISTRY=registry.example.com DOCKER_REPO=tmws/server
```

---

## Build Targets

### `make docker-build`

Builds a multi-platform Docker image locally.

```bash
make docker-build
```

**Output:**
```
🐳 Building Docker image...
  Version: 2.4.17
  Commit:  a3f9c2b

[+] Building 45.2s (24/24) FINISHED
 => [internal] load build definition from Dockerfile
 => [linux/amd64 1/10] FROM python:3.11-slim
 => [linux/arm64 1/10] FROM python:3.11-slim
 ...
✅ Docker build complete
  Tags: 2.4.17, a3f9c2b, latest
```

**Tags created:**
- `ghcr.io/apto-as/tmws:2.4.17` (version)
- `ghcr.io/apto-as/tmws:a3f9c2b` (commit hash)
- `ghcr.io/apto-as/tmws:latest`

**Platforms:**
- `linux/amd64` (Intel/AMD x86_64)
- `linux/arm64` (Apple Silicon, ARM servers)

---

### `make docker-push`

Builds and pushes the image to the configured registry.

```bash
make docker-push
```

**Authentication required:**
```bash
# For GHCR (GitHub Container Registry)
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# For DockerHub
docker login docker.io
# Username: <your-username>
# Password: <your-token>
```

**Output:**
```
🐳 Building Docker image...
  Version: 2.4.17
  Commit:  a3f9c2b
✅ Docker build complete

📤 Pushing Docker image to ghcr.io...
Checking authentication...
✓ Authenticated

Pushing tags...
2.4.17: digest: sha256:abc123... size: 1234
a3f9c2b: digest: sha256:abc123... size: 1234
latest: digest: sha256:abc123... size: 1234

✅ Docker push complete
  Pull: docker pull ghcr.io/apto-as/tmws:2.4.17
```

---

### `make docker-release`

Full release workflow: build → push → GitHub release.

```bash
make docker-release
```

**Or with Issue tracking:**
```bash
make docker-release ISSUE=55
```

**What it does:**
1. Builds multi-platform image
2. Pushes to registry
3. Creates Git tag `v2.4.17`
4. Creates GitHub release with notes
5. (Optional) Comments on GitHub Issue

**Output:**
```
🐳 Building Docker image...
✅ Docker build complete

📤 Pushing Docker image to ghcr.io...
✅ Docker push complete

🚀 Creating GitHub release...
Creating tag v2.4.17...
✓ Tag created

Creating GitHub release...
https://github.com/apto-as/tmws/releases/tag/v2.4.17
✓ Release created

✅ Docker release complete
  Version: 2.4.17
  Image:   ghcr.io/apto-as/tmws:2.4.17
```

---

### `make docker-clean`

Removes local Docker images.

```bash
make docker-clean
```

**Output:**
```
🧹 Cleaning Docker images...
Untagged: ghcr.io/apto-as/tmws:2.4.17
Untagged: ghcr.io/apto-as/tmws:a3f9c2b
Untagged: ghcr.io/apto-as/tmws:latest
✅ Docker clean complete
```

---

### `make docker-info`

Shows current Docker configuration.

```bash
make docker-info
```

**Output:**
```
Docker Configuration
====================
Registry:     ghcr.io
Repository:   apto-as/tmws
Image:        ghcr.io/apto-as/tmws
Version:      2.4.17
Commit:       a3f9c2b

Available tags:
  - ghcr.io/apto-as/tmws:2.4.17
  - ghcr.io/apto-as/tmws:a3f9c2b
  - ghcr.io/apto-as/tmws:latest
```

---

## Multi-Platform Builds

### Why Multi-Platform?

TMWS supports multiple architectures to ensure compatibility across:

| Platform | Use Case | Examples |
|----------|----------|----------|
| `linux/amd64` | Intel/AMD servers, x86_64 desktops | AWS EC2, GCP Compute, Azure VMs |
| `linux/arm64` | ARM servers, Apple Silicon | AWS Graviton, Oracle Ampere, Apple M1/M2/M3 |

### Build Command

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag ghcr.io/apto-as/tmws:2.4.17 \
  --push \
  .
```

**Flags:**
- `--platform`: Comma-separated list of target platforms
- `--tag`: Image tag(s)
- `--push`: Push to registry immediately (buildx requirement for multi-platform)

### Troubleshooting Multi-Platform Builds

#### Issue: "multiple platforms feature is currently not supported"

**Solution:** Use `buildx` with a container driver:

```bash
# Create a new builder
docker buildx create --name multiarch --use

# Verify
docker buildx inspect --bootstrap
```

#### Issue: "exec user process caused: exec format error"

**Cause:** Running an image built for a different architecture.

**Solution:**
```bash
# Specify platform when running
docker run --platform linux/amd64 ghcr.io/apto-as/tmws:2.4.17

# Or pull platform-specific image
docker pull --platform linux/arm64 ghcr.io/apto-as/tmws:2.4.17
```

---

## Publishing to Registries

### GitHub Container Registry (GHCR)

**Recommended** for TMWS.

#### 1. Create Personal Access Token (PAT)

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Select scopes:
   - `write:packages` (upload packages)
   - `read:packages` (download packages)
   - `delete:packages` (delete packages, optional)
4. Generate token, copy it (show only once!)

#### 2. Authenticate Docker

```bash
# Store token in environment variable
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# Login to GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
```

#### 3. Build and Push

```bash
# Ensure DOCKER_REGISTRY is set to ghcr.io (default)
make docker-push
```

#### 4. Verify

```bash
# View published packages
gh api /users/apto-as/packages

# Pull image
docker pull ghcr.io/apto-as/tmws:2.4.17
```

---

### DockerHub

Alternative to GHCR.

#### 1. Create Access Token

1. Go to DockerHub → Account Settings → Security
2. Click "New Access Token"
3. Description: "TMWS CLI"
4. Permissions: "Read & Write"
5. Generate, copy token

#### 2. Authenticate

```bash
docker login docker.io
# Username: <your-username>
# Password: <paste-access-token>
```

#### 3. Build and Push

```bash
# Override registry to DockerHub
make docker-push DOCKER_REGISTRY=docker.io DOCKER_REPO=aptoas/tmws
```

#### 4. Verify

```bash
# View on DockerHub
open https://hub.docker.com/r/aptoas/tmws

# Pull image
docker pull docker.io/aptoas/tmws:2.4.17
```

---

## Release Workflow

### Complete Release Process

```bash
# Step 1: Update version in pyproject.toml
vim pyproject.toml
# version = "2.4.18"

# Step 2: Commit version bump
git add pyproject.toml
git commit -m "chore: Bump version to 2.4.18"

# Step 3: Push version bump
git push origin main

# Step 4: Build, push, and release
make docker-release ISSUE=55

# Step 5: Verify release
gh release view v2.4.18

# Step 6: Test image
docker pull ghcr.io/apto-as/tmws:2.4.18
docker run --rm ghcr.io/apto-as/tmws:2.4.18 tmws-server --version
# Expected: TMWS v2.4.18
```

---

## Advanced Usage

### Custom Dockerfile

If you need to customize the build:

```bash
# Use a different Dockerfile
docker buildx build -f Dockerfile.custom -t ghcr.io/apto-as/tmws:custom .
```

### Build Arguments

Pass build-time variables:

```bash
docker buildx build \
  --build-arg PYTHON_VERSION=3.12 \
  --build-arg POETRY_VERSION=1.8.0 \
  -t ghcr.io/apto-as/tmws:py312 \
  .
```

### Cache Optimization

Speed up builds by using cache:

```bash
# Enable inline cache
docker buildx build \
  --cache-from type=registry,ref=ghcr.io/apto-as/tmws:buildcache \
  --cache-to type=registry,ref=ghcr.io/apto-as/tmws:buildcache,mode=max \
  -t ghcr.io/apto-as/tmws:2.4.17 \
  --push \
  .
```

### Single-Platform Build (Faster)

For local testing, build only for your platform:

```bash
# Auto-detect platform
docker build -t ghcr.io/apto-as/tmws:local .

# Explicit platform
docker build --platform linux/arm64 -t ghcr.io/apto-as/tmws:arm64 .
```

---

## Troubleshooting

### Issue #1: "buildx" command not found

**Solution:**
```bash
# Install buildx plugin
docker buildx install

# Or update Docker Desktop
brew upgrade --cask docker
```

---

### Issue #2: Authentication failure on push

**Symptom:**
```
Error: denied: permission_denied
```

**Solution:**
```bash
# Re-authenticate
docker logout ghcr.io
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Verify authentication
docker login ghcr.io
# Login Succeeded
```

---

### Issue #3: Multi-platform build takes too long

**Cause:** QEMU emulation for cross-platform builds is slow.

**Solution 1:** Use GitHub Actions with native runners (not applicable post-Issue #55)

**Solution 2:** Build platform-specific images separately:

```bash
# Build for current platform only (fast)
docker build --platform linux/$(uname -m) -t ghcr.io/apto-as/tmws:local .

# For release, accept the longer multi-platform build time
```

---

### Issue #4: Version mismatch

**Symptom:** Docker image shows wrong version:
```bash
docker run ghcr.io/apto-as/tmws:2.4.17 tmws-server --version
# Output: TMWS v2.4.16  ← Wrong!
```

**Cause:** `pyproject.toml` version not updated.

**Solution:**
```bash
# Update version
vim pyproject.toml
# version = "2.4.17"

# Rebuild image
make docker-build
```

---

### Issue #5: Out of disk space

**Symptom:**
```
Error: write /var/lib/docker/...: no space left on device
```

**Solution:**
```bash
# Clean up unused images
docker image prune -a

# Clean up build cache
docker buildx prune -a

# Check disk usage
docker system df
```

---

## Performance Tips

### Optimize Docker Build Speed

1. **Use .dockerignore:**
   ```bash
   # Exclude unnecessary files from build context
   echo "tests/" >> .dockerignore
   echo "docs/" >> .dockerignore
   echo ".git/" >> .dockerignore
   ```

2. **Layer caching:**
   - Copy `pyproject.toml` and `poetry.lock` before source code
   - Dependencies change less frequently than source code

3. **Multi-stage builds:**
   - Use builder stage for compilation
   - Use runtime stage for final image (smaller size)

4. **Parallel builds:**
   ```bash
   # Use all available CPU cores
   docker buildx build --builder multiarch .
   ```

---

## Security Best Practices

### Image Scanning

Scan images for vulnerabilities before publishing:

```bash
# Install Trivy
brew install trivy

# Scan image
trivy image ghcr.io/apto-as/tmws:2.4.17

# Fail on high/critical vulnerabilities
trivy image --severity HIGH,CRITICAL --exit-code 1 ghcr.io/apto-as/tmws:2.4.17
```

### Minimal Base Images

Use slim/alpine base images to reduce attack surface:

```dockerfile
# Current: python:3.11-slim (good ✅)
FROM python:3.11-slim

# Alternative: python:3.11-alpine (smaller, but build issues)
# FROM python:3.11-alpine
```

### Non-Root User

Run as non-root inside container:

```dockerfile
# Create user
RUN adduser --disabled-password --gecos '' tmws

# Switch to user
USER tmws
```

---

## CI/CD Integration (Future)

If GitHub Actions billing is resolved:

### Re-Enable Automated Docker Builds

1. **Restore workflow:**
   ```yaml
   # .github/workflows/docker-publish.yml
   on:
     push:
       tags:
         - 'v*'
   ```

2. **Use GitHub Actions secrets:**
   - `GITHUB_TOKEN` (automatic)
   - `DOCKERHUB_TOKEN` (if using DockerHub)

3. **Workflow example:**
   ```yaml
   - name: Build and push
     uses: docker/build-push-action@v5
     with:
       platforms: linux/amd64,linux/arm64
       push: true
       tags: ghcr.io/apto-as/tmws:${{ github.ref_name }}
   ```

---

## Examples

### Example 1: Local Development Build

```bash
# Quick local build (single platform)
docker build -t tmws:dev .

# Run locally
docker run -p 8000:8000 -e TMWS_LICENSE_KEY=TMWS-FREE-test tmws:dev
```

### Example 2: Release to GHCR

```bash
# Update version
vim pyproject.toml  # version = "2.5.0"

# Commit
git commit -am "chore: Bump to v2.5.0"
git push

# Release
make docker-release ISSUE=60

# Verify
docker pull ghcr.io/apto-as/tmws:2.5.0
```

### Example 3: Publish to DockerHub

```bash
# Authenticate
docker login docker.io

# Build and push
make docker-push \
  DOCKER_REGISTRY=docker.io \
  DOCKER_REPO=aptoas/tmws

# Verify
docker pull docker.io/aptoas/tmws:2.4.17
```

---

## Related Documentation

- [LOCAL_WORKFLOW.md](./LOCAL_WORKFLOW.md) - Local-first development guide
- [CONTRIBUTING.md](../../CONTRIBUTING.md) - Contribution guidelines
- [Dockerfile](../../Dockerfile) - TMWS Dockerfile
- [Issue #55](https://github.com/apto-as/tmws/issues/55) - GitHub-independent workflow

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 2.4.17 | 2025-12-10 | Initial documentation (Issue #55 Phase 5) |

---

**Last Updated**: 2025-12-10
**Maintained by**: Muses 📚 (Knowledge Architect)
**Issue**: [#55](https://github.com/apto-as/tmws/issues/55)
