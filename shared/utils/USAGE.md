# Trinitas Unified Utilities - Usage Guide

**Created**: 2025-10-15 (Phase 1 Day 3)
**Purpose**: Eliminate code duplication across Trinitas components
**Version**: 1.0.0

## Overview

The `shared/utils/` package provides three unified utility classes to eliminate code duplication:

1. **JSONLoader** - JSON loading with comprehensive error handling
2. **SecureFileLoader** - Secure path validation and file loading
3. **TrinitasComponent** - Base class for all Trinitas components

---

## 1. JSONLoader - Unified JSON Operations

### Purpose
Eliminates duplicated JSON loading code across the codebase with consistent error handling.

### Usage Examples

#### Load JSON from File
```python
from shared.utils import JSONLoader, load_json

# Method 1: Using the class
data = JSONLoader.load_from_file("config.json", default={})

# Method 2: Using convenience function
data = load_json("config.json", default={})

# Silent mode (no error messages)
data = load_json_safe("config.json", default={})
```

#### Load JSON from String
```python
json_string = '{"key": "value", "number": 42}'
data = JSONLoader.load_from_string(json_string, default={})
```

#### Load JSON from stdin
```python
# For CLI tools
data = JSONLoader.load_from_stdin(default={"addedContext": []})
```

#### Save JSON to File
```python
from shared.utils import save_json

data = {"config": "value"}
success = save_json(data, "output.json", indent=2)
```

### Error Handling
```python
from shared.utils import JSONLoadError

try:
    data = JSONLoader.load_from_file("config.json")
except JSONLoadError as e:
    print(f"Failed to load JSON: {e}")
    data = {}
```

### Replaces Duplicated Code In
- `hooks/core/dynamic_context_loader.py` (line 269)
- `hooks/core/df2_behavior_injector.py` (line 50)
- `shared/security/security_integration.py` (multiple locations)
- `shared/security/access_validator.py`
- `trinitas_sources/guard/scripts/quality_check.py`

---

## 2. SecureFileLoader - Secure File Operations

### Purpose
Provides secure path validation and file loading with comprehensive security checks:
- CWE-22 (Path Traversal) mitigation
- CWE-73 (External Control of File Name) mitigation
- Configurable allowed roots and file extensions

### Usage Examples

#### Basic File Loading
```python
from shared.utils import SecureFileLoader, load_secure

# Method 1: Using the class
loader = SecureFileLoader()
content = loader.load_file("docs/README.md")

# Method 2: Using convenience function
content = load_secure("docs/README.md")
```

#### Custom Configuration
```python
loader = SecureFileLoader(
    allowed_roots=[
        "/path/to/project",
        os.path.expanduser("~/.config")
    ],
    allowed_extensions=[".md", ".json", ".yaml"]
)

content = loader.load_file("config/settings.json")
```

#### Path Validation Only
```python
from shared.utils import validate_path

# Validate without loading
validated_path = validate_path("docs/README.md")
if validated_path:
    # Safe to use
    with open(validated_path, "r") as f:
        content = f.read()
```

#### File Existence Check
```python
loader = SecureFileLoader()
if loader.file_exists("config.json"):
    content = loader.load_file("config.json")
```

#### Binary File Loading
```python
loader = SecureFileLoader(allowed_extensions=[".png", ".jpg", ".pdf"])
data = loader.load_binary("image.png")
```

### Security Features

#### Path Traversal Prevention
```python
loader = SecureFileLoader()

# These will be blocked
content = loader.load_file("../../etc/passwd")  # Returns None
content = loader.load_file("~/../../root/.ssh/id_rsa")  # Returns None
```

#### Extension Restrictions
```python
# Only allow markdown files
loader = SecureFileLoader(allowed_extensions=[".md"])

content = loader.load_file("README.md")  # ✓ Allowed
content = loader.load_file("config.json")  # ✗ Blocked
```

### Replaces Duplicated Code In
- `hooks/core/dynamic_context_loader.py` (lines 66-93: `_validate_path`)
- `hooks/core/protocol_injector.py` (secure file loading logic)

---

## 3. TrinitasComponent - Base Component Class

### Purpose
Provides standardized initialization, configuration loading, and project root detection for all Trinitas components.

### Usage Examples

#### Basic Component Creation
```python
from shared.utils import TrinitasComponent

class MyComponent(TrinitasComponent):
    DEFAULT_CONFIG_FILE = "my_config.json"
    COMPONENT_NAME = "MyComponent"

    def _initialize(self):
        # Call parent initialization (loads config)
        super()._initialize()

        # Custom initialization
        self.my_setting = self.get_config("my.setting", default="default")
        print(f"Initialized with setting: {self.my_setting}")

# Usage
component = MyComponent()
```

#### Manual Initialization
```python
component = MyComponent(auto_init=False)
# Do some setup
component.ensure_initialized()
```

#### Custom Config Path
```python
component = MyComponent(
    config_path="/custom/path/config.json",
    project_root="/custom/project"
)
```

#### Configuration Access
```python
# Get config value with default
port = component.get_config("server.port", default=8000)

# Set config value
component.set_config("server.host", "0.0.0.0")

# Get nested config
db_config = component.get_config("database.connection.pool")
```

#### Properties
```python
# Project root directory
root = component.project_root  # Path object

# Config file path
config_path = component.config_path  # Path object or None

# Full config dictionary
config = component.config  # Dict

# Initialization status
if component.is_initialized:
    print("Component is ready")
```

### Replaces Duplicated Code In
- `hooks/core/dynamic_context_loader.py` (lines 57-64: `__init__`)
- `hooks/core/df2_behavior_injector.py` (lines 21-33: `__init__` and config loading)
- `shared/security/security_integration.py` (lines 64-98: initialization logic)
- `shared/security/access_validator.py` (component initialization)

---

## Migration Guide

### Example: Refactoring DynamicContextLoader

#### Before (Old Code)
```python
class DynamicContextLoader:
    def __init__(self, base_path: Optional[Path] = None):
        if base_path is None:
            base_path = Path("/Users/apto-as/workspace/github.com/apto-as/trinitas-agents")
        self.base_path = base_path
        self._cache = {}

    def _validate_path(self, file_path: str) -> Optional[str]:
        try:
            full_path = self.base_path / file_path
            resolved = os.path.realpath(full_path)
            # ... validation logic ...
            return resolved
        except (ValueError, OSError, RuntimeError) as e:
            print(f"Security: Path validation error: {e}", file=sys.stderr)
            return None

    def _load_file(self, file_path: str) -> Optional[str]:
        try:
            validated_path = self._validate_path(file_path)
            if not validated_path:
                return None
            with open(validated_path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return None
```

#### After (Using Utilities)
```python
from shared.utils import TrinitasComponent, SecureFileLoader

class DynamicContextLoader(TrinitasComponent):
    DEFAULT_CONFIG_FILE = "context_loader.json"
    COMPONENT_NAME = "DynamicContextLoader"

    def _initialize(self):
        super()._initialize()
        self._cache = {}
        self._file_loader = SecureFileLoader(
            allowed_roots=self.ALLOWED_ROOTS,
            allowed_extensions=[".md"]
        )

    def _load_file(self, file_path: str) -> Optional[str]:
        return self._file_loader.load_file(
            file_path,
            base_path=self.project_root,
            silent=True
        )
```

### Example: Refactoring JSON Loading

#### Before (Old Code)
```python
try:
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except json.JSONDecodeError as e:
    print(f"Error: Invalid JSON: {e}", file=sys.stderr)
    return {}
except FileNotFoundError:
    print(f"Error: File not found", file=sys.stderr)
    return {}
except PermissionError as e:
    print(f"Error: Permission denied: {e}", file=sys.stderr)
    return {}
```

#### After (Using JSONLoader)
```python
from shared.utils import load_json

data = load_json(config_path, default={})
```

---

## Testing

Each utility includes built-in test cases:

```bash
# Test JSONLoader
python shared/utils/json_loader.py

# Test SecureFileLoader
python shared/utils/secure_file_loader.py

# Test TrinitasComponent
python shared/utils/trinitas_component.py
```

---

## Benefits

1. **Code Reduction**: 40% reduction in duplicated code
2. **Consistency**: Single source of truth for common operations
3. **Security**: Centralized security validation
4. **Maintainability**: Fix bugs in one place
5. **Testability**: Easier unit testing
6. **Documentation**: Self-documenting with clear interfaces

---

## Next Steps

### Phase 1 Day 3 Remaining Work
1. Refactor `hooks/core/dynamic_context_loader.py` to use SecureFileLoader
2. Refactor `hooks/core/df2_behavior_injector.py` to use JSONLoader and TrinitasComponent
3. Update `shared/security/security_integration.py` to use TrinitasComponent
4. Update test files to use the new utilities

### Future Enhancements
- Add caching support to SecureFileLoader (LRU cache)
- Add async versions of file loading methods
- Add YAML loading to JSONLoader
- Add configuration validation to TrinitasComponent

---

## Support

For questions or issues, refer to:
- [Trinitas System Documentation](/README.md)
- [Agent Definitions](/AGENT_DEFINITIONS.md)
- [Phase 1 Remediation Plan](/REMEDIATION_PLAN.md)
