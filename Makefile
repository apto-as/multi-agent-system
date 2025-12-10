# TMWS Makefile
# Project maintenance and automation tasks

.PHONY: help test lint format clean dead-code-analyze dead-code-remove dead-code-p0

# Default target
help:
	@echo "TMWS Project - Available Commands"
	@echo ""
	@echo "Testing:"
	@echo "  make test              - Run all tests"
	@echo "  make test-unit         - Run unit tests only"
	@echo "  make test-integration  - Run integration tests only"
	@echo "  make test-cov          - Run tests with coverage"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint              - Run ruff linting"
	@echo "  make format            - Format code with ruff"
	@echo "  make typecheck         - Run mypy type checking"
	@echo ""
	@echo "Dead Code Analysis:"
	@echo "  make dead-code-analyze - Analyze dead code with vulture"
	@echo "  make dead-code-preview - Preview dead code removal (dry-run)"
	@echo "  make dead-code-p0      - Remove P0 priority dead code"
	@echo "  make dead-code-p1      - Remove P1 priority dead code"
	@echo "  make dead-code-all     - Remove all dead code (staged)"
	@echo ""
	@echo "Docker (Issue #55 Phase 2):"
	@echo "  make docker-build      - Build Docker image locally"
	@echo "  make docker-push       - Build and push to registry"
	@echo "  make docker-release    - Build, push, and create GitHub release"
	@echo "  make docker-clean      - Remove local Docker images"
	@echo "  make docker-info       - Show Docker configuration"
	@echo ""
	@echo "Database:"
	@echo "  make migrate           - Apply database migrations"
	@echo "  make migrate-create    - Create new migration"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean             - Remove temporary files"
	@echo "  make clean-all         - Remove all generated files"

# Testing
test:
	python -m pytest tests/ -v

test-unit:
	python -m pytest tests/unit/ -v

test-integration:
	python -m pytest tests/integration/ -v

test-cov:
	python -m pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html

# Code Quality
lint:
	ruff check src/ tests/

format:
	ruff check src/ tests/ --fix
	ruff format src/ tests/

typecheck:
	mypy src/ --ignore-missing-imports

# Dead Code Analysis
dead-code-analyze:
	@echo "Running Vulture dead code analysis..."
	python -m vulture src/ --min-confidence 60 | tee /tmp/vulture_report.txt
	@echo ""
	@echo "Analysis complete. Results saved to /tmp/vulture_report.txt"
	@echo "See docs/analysis/DEAD_CODE_ANALYSIS_REPORT.md for detailed report"

dead-code-preview:
	@echo "Previewing dead code removal (DRY RUN)..."
	python scripts/dead_code_removal_automation.py --dry-run

dead-code-p0:
	@echo "Removing P0 priority dead code..."
	python scripts/dead_code_removal_automation.py --priority P0

dead-code-p1:
	@echo "Removing P1 priority dead code..."
	python scripts/dead_code_removal_automation.py --priority P1

dead-code-p2:
	@echo "Removing P2 priority dead code..."
	python scripts/dead_code_removal_automation.py --priority P2

dead-code-all:
	@echo "Removing all dead code (staged by priority)..."
	python scripts/dead_code_removal_automation.py

# Database
migrate:
	alembic upgrade head

migrate-create:
	@read -p "Enter migration message: " msg; \
	alembic revision --autogenerate -m "$$msg"

# Cleanup
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name ".coverage" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf /tmp/vulture_*.txt

clean-all: clean
	rm -rf .venv
	rm -rf .dead_code_backups
	rm -rf dist
	rm -rf build
	rm -rf *.egg-info

# ========================================
# Docker Build & Publish (GitHub-independent)
# Issue #55 Phase 2: Local Docker workflow
# ========================================

# Configuration (DockerHub - GitHub-independent)
DOCKER_REGISTRY ?= docker.io
DOCKER_REPO ?= aptoas/tmws
DOCKER_IMAGE = $(DOCKER_REGISTRY)/$(DOCKER_REPO)
VERSION := $(shell grep '^version = ' pyproject.toml | cut -d'"' -f2)
COMMIT_HASH := $(shell git rev-parse --short HEAD)

# Docker build target
docker-build:
	@echo "🐳 Building Docker image..."
	@echo "  Version: $(VERSION)"
	@echo "  Commit:  $(COMMIT_HASH)"
	@echo ""
	docker build \
		--platform linux/amd64,linux/arm64 \
		--tag $(DOCKER_IMAGE):$(VERSION) \
		--tag $(DOCKER_IMAGE):$(COMMIT_HASH) \
		--tag $(DOCKER_IMAGE):latest \
		--label "org.opencontainers.image.version=$(VERSION)" \
		--label "org.opencontainers.image.revision=$(COMMIT_HASH)" \
		--label "org.opencontainers.image.created=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)" \
		--build-arg BUILD_DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
		--build-arg VERSION=$(VERSION) \
		--build-arg VCS_REF=$(COMMIT_HASH) \
		.
	@echo ""
	@echo "✅ Docker build complete"
	@echo "  Tags: $(VERSION), $(COMMIT_HASH), latest"

# Docker push target (requires authentication)
docker-push: docker-build
	@echo "📤 Pushing Docker image to $(DOCKER_REGISTRY)..."
	@echo ""
	@echo "Checking authentication..."
	@docker login $(DOCKER_REGISTRY) || (echo "❌ Login failed - run: docker login" && exit 1)
	@echo ""
	@echo "Pushing tags..."
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):$(COMMIT_HASH)
	docker push $(DOCKER_IMAGE):latest
	@echo ""
	@echo "✅ Docker push complete"
	@echo "  Pull: docker pull $(DOCKER_IMAGE):$(VERSION)"

# Docker release target (build + push + tag)
docker-release: docker-push
	@echo "🚀 Creating GitHub release..."
	@echo ""
	@if ! command -v gh &> /dev/null; then \
		echo "⚠️  GitHub CLI (gh) not installed - skipping release creation"; \
		echo "  Install: https://cli.github.com/"; \
	else \
		echo "Creating tag v$(VERSION)..."; \
		git tag -a "v$(VERSION)" -m "Release v$(VERSION)" || echo "⚠️  Tag v$(VERSION) already exists"; \
		git push origin "v$(VERSION)" || true; \
		echo ""; \
		echo "Creating GitHub release..."; \
		gh release create "v$(VERSION)" \
			--title "TMWS v$(VERSION)" \
			--notes "Docker image: $(DOCKER_IMAGE):$(VERSION)" \
			--verify-tag || echo "⚠️  Release may already exist"; \
	fi
	@echo ""
	@echo "✅ Docker release complete"
	@echo "  Version: $(VERSION)"
	@echo "  Image:   $(DOCKER_IMAGE):$(VERSION)"

# Docker clean target
docker-clean:
	@echo "🧹 Cleaning Docker images..."
	docker rmi $(DOCKER_IMAGE):$(VERSION) || true
	docker rmi $(DOCKER_IMAGE):$(COMMIT_HASH) || true
	docker rmi $(DOCKER_IMAGE):latest || true
	@echo "✅ Docker clean complete"

# Docker info target
docker-info:
	@echo "Docker Configuration"
	@echo "===================="
	@echo "Registry:     $(DOCKER_REGISTRY)"
	@echo "Repository:   $(DOCKER_REPO)"
	@echo "Image:        $(DOCKER_IMAGE)"
	@echo "Version:      $(VERSION)"
	@echo "Commit:       $(COMMIT_HASH)"
	@echo ""
	@echo "Available tags:"
	@echo "  - $(DOCKER_IMAGE):$(VERSION)"
	@echo "  - $(DOCKER_IMAGE):$(COMMIT_HASH)"
	@echo "  - $(DOCKER_IMAGE):latest"

.PHONY: docker-build docker-push docker-release docker-clean docker-info
