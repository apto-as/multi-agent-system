# Trinitas Quality Guardian - Go Makefile
# Build, test, and quality checks for Go projects

.PHONY: all build test clean lint fmt security coverage

# Variables
GOPATH ?= $(shell go env GOPATH)
GOBIN ?= $(GOPATH)/bin
GOLINT ?= $(GOBIN)/golangci-lint
GOSEC ?= $(GOBIN)/gosec

# Artemis: Build targets
all: fmt lint test build

build:
	@echo "🏹 Artemis: Building Go application..."
	go build -v -o bin/app ./...

clean:
	@echo "🏹 Artemis: Cleaning build artifacts..."
	rm -rf bin/ coverage.out coverage.html

# Artemis: Code quality
fmt:
	@echo "🏹 Artemis: Formatting code..."
	go fmt ./...
	gofmt -s -w .
	goimports -w .

lint: $(GOLINT)
	@echo "🏹 Artemis: Running linters..."
	$(GOLINT) run ./...

# Hestia: Security checks
security: $(GOSEC)
	@echo "🔥 Hestia: Running security scan..."
	$(GOSEC) -fmt json -out security-report.json ./...
	@echo "🔥 Hestia: Security scan complete. Check security-report.json"

# Testing
test:
	@echo "⚔️ Eris: Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

coverage: test
	@echo "📚 Muses: Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out
	@echo "📚 Muses: Coverage report available at coverage.html"

# Tool installation
$(GOLINT):
	@echo "Installing golangci-lint..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

$(GOSEC):
	@echo "Installing gosec..."
	go install github.com/securego/gosec/v2/cmd/gosec@latest

# Hera: CI/CD helpers
ci: lint security test
	@echo "🎭 Hera: All CI checks passed!"

# Help target
help:
	@echo "Trinitas Quality Guardian - Go Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make all      - Run fmt, lint, test, and build"
	@echo "  make build    - Build the application"
	@echo "  make test     - Run tests with coverage"
	@echo "  make lint     - Run linters"
	@echo "  make fmt      - Format code"
	@echo "  make security - Run security scan"
	@echo "  make coverage - Generate coverage report"
	@echo "  make clean    - Clean build artifacts"
	@echo "  make ci       - Run CI checks"
	@echo "  make help     - Show this help"