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
