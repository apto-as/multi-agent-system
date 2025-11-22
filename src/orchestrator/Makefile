# TMWS Orchestrator Service - Build System
# Performance Targets: <500ms startup, <100ms discovery, <20ms queries

.PHONY: all build test clean run install lint fmt help

# Default target
all: fmt lint build test

# Build the orchestrator binary
build:
	@echo "Building orchestrator service..."
	@go build -o bin/orchestrator -ldflags="-s -w" ./cmd/orchestrator
	@echo "✅ Build complete: bin/orchestrator"

# Run tests with coverage
test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Tests complete. Coverage: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@echo "✅ Clean complete"

# Run the orchestrator service
run: build
	@echo "Starting orchestrator service..."
	@./bin/orchestrator -config config/orchestrator.yaml

# Install dependencies
install:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy
	@echo "✅ Dependencies installed"

# Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@golangci-lint run --timeout=5m || go vet ./...
	@echo "✅ Lint complete"

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@echo "✅ Format complete"

# Help
help:
	@echo "TMWS Orchestrator Service - Build Targets"
	@echo ""
	@echo "  make build    - Build orchestrator binary"
	@echo "  make test     - Run tests with coverage"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make run      - Build and run orchestrator"
	@echo "  make install  - Download dependencies"
	@echo "  make lint     - Run linter"
	@echo "  make fmt      - Format code"
	@echo "  make all      - Format, lint, build, test"
