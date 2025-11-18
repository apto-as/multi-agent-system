# Document Registry Performance & Testing Strategy

**Created**: 2025-11-03
**Created by**: Artemis (Technical Perfectionist)
**Purpose**: Define performance optimization and testing strategies for document registry

---

## Performance Optimization Strategies

### 1. Parallel Processing

**Implementation**:
- Use `ThreadPoolExecutor` for I/O-bound operations (file reading, checksum calculation)
- Default: 4 workers (configurable)
- Batch size: 50 documents per batch

**Expected Performance**:
- **Sequential**: ~100ms per document × 100 = 10 seconds
- **Parallel (4 workers)**: ~25 seconds / 4 = ~6.25 seconds
- **Actual target**: < 5 seconds (with optimizations)

**Code Example**:
```python
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = {executor.submit(process_doc, f): f for f in files}
    for future in as_completed(futures):
        result = future.result()
```

### 2. Caching Strategy

**Implementation**:
- Cache checksums in registry (avoid recalculation)
- Cache file stats (size, mtime) for quick staleness check
- In-memory LRU cache for frequently accessed documents

**Cache Invalidation**:
```python
# Check if file changed since last scan
if current_checksum == cached_checksum:
    return cached_metadata  # Skip processing
```

**Expected Impact**:
- **Full scan** (no cache): 5 seconds
- **Incremental scan** (cache hit rate 95%): < 500ms

### 3. Efficient File I/O

**Checksum Calculation**:
```python
# Read in 64KB chunks (memory efficient)
sha256 = hashlib.sha256()
with open(file_path, 'rb') as f:
    for chunk in iter(lambda: f.read(65536), b''):
        sha256.update(chunk)
```

**Benefits**:
- Constant memory usage regardless of file size
- Fast for large files (>1MB)

**Frontmatter Parsing**:
```python
# Only parse YAML frontmatter (first ~100 lines)
# Avoid reading entire file if not needed
content = file_path.read_text(encoding='utf-8')
if content.startswith('---'):
    end_idx = content.find('---', 3)
    yaml_content = content[3:end_idx]
```

### 4. Lazy Loading

**Registry Loading**:
```python
# Load only document paths initially
# Fetch full metadata on demand
class LazyRegistry:
    def __init__(self, registry_path):
        self.registry_path = registry_path
        self._documents = None

    def get_document(self, path):
        if self._documents is None:
            self._documents = self._load_registry()
        return self._documents[path]
```

### 5. Incremental Updates

**Strategy**:
- Only process changed files (use git diff)
- Skip unchanged files (checksum comparison)

**Pre-commit Hook Optimization**:
```bash
# Only process staged documentation files
STAGED_DOCS=$(git diff --cached --name-only --diff-filter=ACM | \
    grep -E '^(docs|trinitas_sources)/.*\.(md|yaml|json)$')

# Skip if no docs changed
if [ -z "$STAGED_DOCS" ]; then
    exit 0
fi
```

**Expected Performance**:
- **Full scan**: 5 seconds (100 documents)
- **Incremental**: < 500ms (1-5 changed files)

---

## Performance Benchmarks

### Target Metrics

| Operation | Target | Acceptable | Unacceptable |
|-----------|--------|------------|--------------|
| **Init (100 docs)** | < 5s | < 10s | > 10s |
| **Add (single doc)** | < 500ms | < 1s | > 1s |
| **Validate (100 docs)** | < 2s | < 5s | > 5s |
| **Index generation** | < 1s | < 2s | > 2s |
| **Pre-commit hook** | < 2s | < 5s | > 5s |

### Bottleneck Analysis

**Potential Bottlenecks**:
1. **File I/O** (reading documents)
   - Mitigation: Parallel processing, caching
2. **Checksum calculation** (CPU-bound)
   - Mitigation: Cache checksums, skip unchanged files
3. **YAML parsing** (Python overhead)
   - Mitigation: Parse only frontmatter, not entire file
4. **Cross-reference validation** (O(n²) worst case)
   - Mitigation: Use sets for lookups, index by path

---

## Testing Strategy

### 1. Unit Tests

**Coverage Target**: >= 90%

**Test Cases**:

#### DocumentMetadata
```python
def test_metadata_to_dict():
    """Test metadata serialization"""
    metadata = DocumentMetadata(
        path="docs/test.md",
        title="Test Document",
        purpose=DocumentPurpose.GUIDE,
        status=DocumentStatus.CURRENT
    )
    data = metadata.to_dict()

    assert data["path"] == "docs/test.md"
    assert data["title"] == "Test Document"
    assert data["purpose"] == "guide"
    assert data["status"] == "current"

def test_metadata_from_dict():
    """Test metadata deserialization"""
    data = {
        "path": "docs/test.md",
        "title": "Test Document",
        "purpose": "guide",
        "status": "current",
        "size": 1024,
        "checksum": "abc123"
    }
    metadata = DocumentMetadata.from_dict(data)

    assert metadata.path == "docs/test.md"
    assert metadata.purpose == DocumentPurpose.GUIDE
```

#### DocumentScanner
```python
def test_checksum_calculation():
    """Test checksum calculation accuracy"""
    test_file = Path("/tmp/test.md")
    test_file.write_text("Test content")

    scanner = DocumentScanner(...)
    checksum = scanner.calculate_checksum(test_file)

    # Verify with known SHA-256
    expected = "9473fdd0d880a43c21b7778d34872157..."
    assert checksum == expected

def test_frontmatter_extraction():
    """Test YAML frontmatter extraction"""
    content = """---
title: Test Document
purpose: guide
---
# Test Content
"""
    scanner = DocumentScanner(...)
    metadata = scanner.extract_metadata_from_content(content)

    assert metadata["title"] == "Test Document"
    assert metadata["purpose"] == "guide"
```

#### RegistryValidator
```python
def test_validate_required_fields():
    """Test required field validation"""
    registry = {
        "docs/test.md": {
            "path": "docs/test.md",
            # Missing 'title' - should trigger error
            "purpose": "guide",
            "status": "current"
        }
    }

    validator = RegistryValidator(...)
    results = validator.validate(registry)

    errors = [r for r in results if r.level == ValidationLevel.ERROR]
    assert len(errors) == 1
    assert "title" in errors[0].message

def test_validate_cross_references():
    """Test cross-reference validation"""
    registry = {
        "docs/a.md": {
            "path": "docs/a.md",
            "dependencies": ["docs/b.md"]  # b.md doesn't exist
        }
    }

    validator = RegistryValidator(...)
    results = validator.validate(registry)

    warnings = [r for r in results if r.level == ValidationLevel.WARNING]
    assert any("docs/b.md" in w.message for w in warnings)
```

### 2. Integration Tests

**Test Scenarios**:

#### Full Workflow Test
```python
def test_full_workflow(tmp_path):
    """Test init -> add -> validate -> index workflow"""
    # Create test repository structure
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()

    (docs_dir / "test1.md").write_text("# Test 1")
    (docs_dir / "test2.md").write_text("# Test 2")

    # Initialize registry
    registry = DocumentRegistry(...)
    registry.init()

    # Verify registry file created
    assert registry.registry_path.exists()

    # Load and check content
    data = registry.load_registry()
    assert len(data) == 2

    # Add new document
    (docs_dir / "test3.md").write_text("# Test 3")
    registry.add(docs_dir / "test3.md", interactive=False)

    # Validate
    assert registry.validate_registry() is True

    # Generate index
    registry.generate_index()
    assert (tmp_path / "docs" / "INDEX.md").exists()
```

#### Pre-commit Hook Test
```bash
#!/usr/bin/env bash
# Test pre-commit hook behavior

test_precommit_hook() {
    # Create test git repo
    TEMP_REPO=$(mktemp -d)
    cd "$TEMP_REPO"
    git init

    # Install registry
    cp -r /path/to/trinitas-agents/scripts .
    cp -r /path/to/trinitas-agents/hooks .

    bash scripts/install_document_registry.sh

    # Create and stage a document
    mkdir docs
    echo "# Test" > docs/test.md
    git add docs/test.md

    # Run pre-commit hook
    time bash hooks/pre-commit-document-registry

    # Verify registry updated
    [ -f docs/DOCUMENT_REGISTRY.yaml ] || exit 1
    grep -q "docs/test.md" docs/DOCUMENT_REGISTRY.yaml || exit 1

    # Verify index generated
    [ -f docs/INDEX.md ] || exit 1

    echo "✅ Pre-commit hook test passed"
}

test_precommit_hook
```

### 3. Performance Tests

#### Benchmark Suite
```python
import time
from pathlib import Path

def benchmark_init(num_docs: int):
    """Benchmark registry initialization"""
    # Create test documents
    docs_dir = Path("/tmp/benchmark/docs")
    docs_dir.mkdir(parents=True, exist_ok=True)

    for i in range(num_docs):
        (docs_dir / f"doc_{i}.md").write_text(f"# Document {i}\n" * 100)

    # Measure init time
    registry = DocumentRegistry(...)
    start = time.perf_counter()
    registry.init()
    duration = time.perf_counter() - start

    print(f"Init ({num_docs} docs): {duration:.2f}s")
    assert duration < 5.0, f"Init took {duration}s (target: < 5s)"

def benchmark_incremental_update():
    """Benchmark incremental update"""
    registry = DocumentRegistry(...)

    # Add single document
    start = time.perf_counter()
    registry.add(Path("docs/new.md"), interactive=False)
    duration = time.perf_counter() - start

    print(f"Add (1 doc): {duration*1000:.0f}ms")
    assert duration < 0.5, f"Add took {duration}s (target: < 500ms)"

def benchmark_validation(num_docs: int):
    """Benchmark validation"""
    registry = DocumentRegistry(...)

    start = time.perf_counter()
    registry.validate_registry()
    duration = time.perf_counter() - start

    print(f"Validate ({num_docs} docs): {duration:.2f}s")
    assert duration < 2.0, f"Validate took {duration}s (target: < 2s)"

# Run benchmarks
if __name__ == "__main__":
    benchmark_init(100)
    benchmark_incremental_update()
    benchmark_validation(100)
```

### 4. Error Handling Tests

#### Edge Cases
```python
def test_symlink_handling():
    """Test symlink protection"""
    # Create symlink to sensitive file
    target = Path("/etc/passwd")
    link = Path("/tmp/test_link.md")
    link.symlink_to(target)

    scanner = DocumentScanner(...)

    # Should detect and reject symlink
    with pytest.raises(SecurityError, match="Symlink.*denied"):
        scanner.create_metadata(link)

def test_corrupted_registry():
    """Test handling of corrupted registry file"""
    registry_path = Path("/tmp/corrupted.yaml")
    registry_path.write_text("invalid: yaml: content: [")

    registry = DocumentRegistry(registry_path=registry_path, ...)

    # Should handle gracefully
    with pytest.raises(yaml.YAMLError):
        registry.load_registry()

def test_missing_dependencies():
    """Test handling of missing dependencies"""
    # PyYAML not installed
    import sys
    sys.modules['yaml'] = None

    with pytest.raises(ImportError):
        import yaml

def test_large_file_handling():
    """Test handling of very large files"""
    large_file = Path("/tmp/large.md")
    large_file.write_text("x" * (10 * 1024 * 1024))  # 10 MB

    scanner = DocumentScanner(...)

    # Should complete without memory issues
    metadata = scanner.create_metadata(large_file)
    assert metadata.size == 10 * 1024 * 1024
```

---

## Continuous Performance Monitoring

### GitHub Actions Integration

```yaml
# .github/workflows/document-registry-performance.yml
name: Document Registry Performance

on:
  pull_request:
    paths:
      - 'scripts/update_document_registry.py'
      - 'docs/**'

jobs:
  performance-test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install PyYAML pytest pytest-benchmark

      - name: Run performance benchmarks
        run: |
          python3 -m pytest tests/test_registry_performance.py \
            --benchmark-only \
            --benchmark-min-rounds=5

      - name: Validate performance targets
        run: |
          # Fail if any benchmark exceeds target
          python3 tests/validate_performance.py
```

---

## Optimization Checklist

### Before Release
- [ ] All unit tests pass (>= 90% coverage)
- [ ] All integration tests pass
- [ ] Performance benchmarks meet targets
- [ ] Error handling tested for edge cases
- [ ] Security tests pass (symlink protection, etc.)
- [ ] Memory profiling completed (no leaks)
- [ ] Code complexity <= 10 per function
- [ ] Type hints 100% complete
- [ ] Documentation complete

### Ongoing Monitoring
- [ ] Weekly performance regression tests
- [ ] Monthly benchmark reviews
- [ ] Quarterly optimization reviews
- [ ] User feedback integration

---

*"Perfection is not negotiable. Excellence is the only acceptable standard."*

**Artemis** - Technical Perfectionist
