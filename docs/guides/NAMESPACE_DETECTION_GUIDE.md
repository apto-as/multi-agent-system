# TMWS Namespace Detection Guide
## Automatic Project Identification for Memory Isolation

**Last Updated**: 2025-10-27
**Version**: TMWS v2.2.6
**Target Audience**: End users, DevOps engineers

---

## What is a Namespace?

A **namespace** is a unique identifier for your project that ensures:
- 🔒 **Memory isolation**: Your project's memories don't leak to other projects
- 🚀 **Automatic organization**: No manual configuration needed
- 🔍 **Easy retrieval**: Find memories specific to each project

---

## How Namespace Detection Works

TMWS automatically detects your project's namespace using **4 methods** (in priority order):

### Priority 1: Environment Variable (Fastest, Most Explicit) ⚡

**Latency**: 0.001ms
**Reliability**: ✅ HIGH

Set the `TRINITAS_PROJECT_NAMESPACE` environment variable:

```bash
# In your shell profile (~/.zshrc, ~/.bashrc)
export TRINITAS_PROJECT_NAMESPACE="my-awesome-project"

# Or per-session
export TRINITAS_PROJECT_NAMESPACE="github.com/apto-as/tmws"
```

**When to use**:
- You want explicit control over namespace naming
- Working in a non-git project
- Multiple projects in same git repository

---

### Priority 2: Git Repository (Best for Git Projects) 🐙

**Latency**: 1-5ms
**Reliability**: ✅ HIGH
**Consistency**: ✅ BEST

TMWS automatically detects your git repository and uses the remote URL as namespace:

```bash
# Your git remote URL
git remote get-url origin
# → git@github.com:apto-as/tmws.git

# Detected namespace
# → github.com/apto-as/tmws
```

**Benefits**:
- ✅ **Consistent**: Same namespace across all subdirectories
- ✅ **Unique**: Remote URL is globally unique
- ✅ **Automatic**: Works out-of-the-box for git projects

**Example scenarios**:

```bash
# Scenario 1: Working in project root
cd ~/workspace/github.com/apto-as/tmws
# Detected namespace: github.com/apto-as/tmws

# Scenario 2: Working in subdirectory
cd ~/workspace/github.com/apto-as/tmws/src/services
# Detected namespace: github.com/apto-as/tmws (same!)

# Scenario 3: No git remote URL (local repo)
cd ~/workspace/my-local-project
git init
# Detected namespace: my-local-project (directory name)
```

---

### Priority 3: Marker File (For Custom Configuration) 📄

**Latency**: 5-10ms
**Reliability**: 🟡 MEDIUM

Create a `.trinitas-project.yaml` file in your project root:

```yaml
# .trinitas-project.yaml
namespace: my-custom-namespace
```

**When to use**:
- You want a custom namespace that differs from git URL
- Sharing a git repository across multiple projects
- Non-git projects with explicit naming

---

### Priority 4: Working Directory Hash (Fallback) 🔧

**Latency**: 0.01ms
**Reliability**: ✅ HIGH
**Consistency**: ⚠️ PATH-DEPENDENT

If no other method succeeds, TMWS generates a namespace from your working directory path:

```bash
# Your working directory
/Users/apto-as/workspace/github.com/apto-as/tmws

# Generated namespace
project_a1b2c3d4e5f6g7h8  # SHA256 hash of path (16 chars)
```

**⚠️ Warning**: This method is **path-dependent**. If you move your project to a different location, the namespace will change!

**When this happens**:
- No git repository detected
- No environment variable set
- No marker file found

**What you'll see**:
```
⚠️  TMWS: Auto-generated namespace 'project_a1b2c3d4e5f6g7h8' from working directory.
   For consistent project identification:
   1. Set environment variable: export TRINITAS_PROJECT_NAMESPACE='<project-name>'
   2. OR create .trinitas-project.yaml with: namespace: <project-name>
   3. OR ensure git remote URL is configured
   Current working directory: /Users/apto-as/workspace/github.com/apto-as/tmws
```

---

## Namespace Naming Rules

### Valid Characters
- ✅ Lowercase letters: `a-z`
- ✅ Numbers: `0-9`
- ✅ Hyphens: `-`
- ✅ Underscores: `_`
- ✅ Dots: `.`
- ✅ Slashes: `/`

### Invalid Characters
- ❌ Uppercase letters (auto-converted to lowercase)
- ❌ Spaces (replaced with hyphens)
- ❌ Special characters: `!@#$%^&*()+=[]{}|;:'"<>?`

### Examples

```python
# Input → Sanitized namespace
"MyAwesomeProject" → "myawesomeproject"
"my awesome project" → "my-awesome-project"
"My Project!!" → "my-project"
"github.com/User/Repo" → "github.com/user/repo"
```

### Security Restrictions

**❌ FORBIDDEN**: Namespace `'default'` is **not allowed**

This prevents cross-project memory leakage (CVSS 9.8 vulnerability).

```python
# This will FAIL
export TRINITAS_PROJECT_NAMESPACE="default"
# → Error: Namespace 'default' is not allowed for security reasons.
```

---

## How to Choose the Right Method

### Recommended: Git Repository (Priority 2)

**Best for**: 90% of use cases

```bash
# 1. Ensure your project has a git remote
git remote add origin git@github.com:your-username/your-project.git

# 2. Done! TMWS will auto-detect namespace
# No configuration needed
```

### For Explicit Control: Environment Variable (Priority 1)

**Best for**:
- CI/CD pipelines
- Multi-tenant environments
- Non-git projects

```bash
# Per-project (recommended)
echo 'export TRINITAS_PROJECT_NAMESPACE="my-project"' >> .envrc
direnv allow

# Per-session
export TRINITAS_PROJECT_NAMESPACE="my-project"

# System-wide (not recommended)
echo 'export TRINITAS_PROJECT_NAMESPACE="my-project"' >> ~/.zshrc
```

### For Custom Naming: Marker File (Priority 3)

**Best for**:
- Projects with complex git setups (monorepos)
- Shared repositories with multiple sub-projects

```bash
# Create marker file in project root
cat > .trinitas-project.yaml <<EOF
namespace: my-custom-project
EOF

# Add to git
git add .trinitas-project.yaml
git commit -m "Add TMWS project namespace"
```

---

## Verification

### Check Current Namespace

```bash
# Option 1: Check MCP server logs
tail -f ~/.claude/logs/mcp-server-tmws.log | grep "namespace"

# Option 2: Query TMWS memory stats
# (In Claude Code with TMWS MCP server)
/tmws get_memory_stats
# → Shows current namespace
```

### Example Log Output

```
2025-10-27 12:34:56 - tmws - INFO - Namespace detected: github.com/apto-as/tmws
2025-10-27 12:34:56 - tmws - INFO - Detection method: git_remote_url (1.2ms)
```

---

## Troubleshooting

### Problem 1: "Namespace 'default' is not allowed"

**Cause**: Explicitly specifying `'default'` namespace (security risk)

**Solution**:
```bash
# DON'T DO THIS
export TRINITAS_PROJECT_NAMESPACE="default"  # ❌

# DO THIS
export TRINITAS_PROJECT_NAMESPACE="my-project"  # ✅
# OR let TMWS auto-detect (git/marker file/cwd hash)
```

---

### Problem 2: "Auto-generated namespace from working directory"

**Cause**: No git repo, no env var, no marker file

**Solution** (choose one):

```bash
# Option A: Set environment variable (fastest)
export TRINITAS_PROJECT_NAMESPACE="my-project"

# Option B: Initialize git repository
git init
git remote add origin git@github.com:username/project.git

# Option C: Create marker file
echo "namespace: my-project" > .trinitas-project.yaml
```

---

### Problem 3: Namespace changed after moving project

**Cause**: Using CWD hash fallback (path-dependent)

**Current situation**:
```bash
# Before move
/old/path/project → namespace: project_abc123def456

# After move
/new/path/project → namespace: project_789xyz012tuv (DIFFERENT!)
```

**Solution**: Use path-independent method

```bash
# Option A: Set explicit environment variable
export TRINITAS_PROJECT_NAMESPACE="my-project"

# Option B: Initialize git (best)
git init
git remote add origin git@github.com:username/project.git
```

---

### Problem 4: Multiple projects in same git repository (monorepo)

**Cause**: Git detection uses repository root, not subdirectory

**Solution**: Use marker files or environment variables per project

```bash
# Monorepo structure
monorepo/
├── .git/
├── project-a/
│   └── .trinitas-project.yaml  # namespace: project-a
└── project-b/
    └── .trinitas-project.yaml  # namespace: project-b

# In project-a/.trinitas-project.yaml
namespace: monorepo/project-a

# In project-b/.trinitas-project.yaml
namespace: monorepo/project-b
```

---

## Advanced: Shared Namespace (Phase 2b - Future)

**Status**: 🚧 Planned for Phase 2b

**Concept**: Cross-project shared memory area for important knowledge

```bash
# Future feature (not yet implemented)
/trinitas remember important_finding "Security vulnerability" --shared

# Stores in BOTH:
# 1. Project namespace: github.com/apto-as/tmws
# 2. Shared namespace: shared:apto-as (accessible across all your projects)
```

See `docs/evaluation/NAMESPACE_SHARED_AREA_FEASIBILITY_2025_10_27.md` for details.

---

## FAQ

### Q: Can I change my project's namespace?

**A**: Yes, but be aware of the consequences:

```bash
# Before: namespace = "old-project"
# Memories stored in "old-project" namespace

# Change namespace
export TRINITAS_PROJECT_NAMESPACE="new-project"

# After: namespace = "new-project"
# Previous memories in "old-project" are NOT automatically migrated
```

**Migration** (manual, if needed):
```bash
# TODO: Provide migration script in Phase 2a
# For now, memories in old namespace remain accessible by explicit namespace query
```

---

### Q: Is namespace detection case-sensitive?

**A**: No. All namespaces are converted to lowercase:

```bash
export TRINITAS_PROJECT_NAMESPACE="MyProject"
# → Detected as: "myproject"

git remote get-url origin
# → git@github.com:User/Repo.git
# → Detected as: "github.com/user/repo"
```

---

### Q: How do I share memories between projects?

**A**: Currently (v2.2.6), memories are project-local. Cross-project sharing is planned for Phase 2b.

**Workaround** (manual):
```bash
# In Project A
/trinitas remember important_pattern "Use Redis for caching" --importance 1.0

# In Project B
# Manually specify Project A's namespace
# (TODO: Provide explicit cross-namespace query API in Phase 2b)
```

---

### Q: Can I use the same namespace for multiple projects?

**A**: Technically yes, but **not recommended** for security reasons.

```bash
# NOT RECOMMENDED
# Project A
export TRINITAS_PROJECT_NAMESPACE="shared-namespace"

# Project B
export TRINITAS_PROJECT_NAMESPACE="shared-namespace"

# Result: Both projects see each other's memories (potential leakage!)
```

**Recommended approach**: Use unique namespaces + explicit cross-project sharing (Phase 2b)

---

## Best Practices

### ✅ DO

1. **Use git remote URL for most projects**
   - Automatic, unique, consistent

2. **Set explicit environment variable for CI/CD**
   - Ensures consistent namespace across builds

3. **Document namespace in project README**
   - Helps team members understand project identification

4. **Use semantic naming for marker files**
   ```yaml
   # Good
   namespace: github.com/company/product-service

   # Bad
   namespace: project1
   ```

### ❌ DON'T

1. **Never use `'default'` namespace**
   - Security risk (cross-project leakage)

2. **Avoid relying on CWD hash fallback**
   - Path-dependent, inconsistent after moves

3. **Don't share namespaces between projects** (without explicit design)
   - Use cross-project sharing feature (Phase 2b) instead

4. **Don't hardcode namespaces in code**
   - Always use auto-detection or environment variables

---

## Reference: Detection Algorithm

```python
async def detect_project_namespace() -> str:
    """
    Auto-detect project namespace.

    Priority:
    1. Environment variable TRINITAS_PROJECT_NAMESPACE (0.001ms)
    2. Git repository root + remote URL (1-5ms)
    3. Marker file .trinitas-project.yaml (5-10ms)
    4. CWD hash fallback (0.01ms)
    """
    # Priority 1: Environment variable
    if env_namespace := os.getenv("TRINITAS_PROJECT_NAMESPACE"):
        return sanitize_namespace(env_namespace)

    # Priority 2: Git repository
    if git_root := await detect_git_root():
        if git_url := await get_git_remote_url(git_root):
            return namespace_from_git_url(git_url)
        return sanitize_namespace(git_root.name)

    # Priority 3: Marker file
    if marker := await find_marker_file():
        config = yaml.safe_load(marker.read_text())
        if namespace := config.get("namespace"):
            return sanitize_namespace(namespace)

    # Priority 4: CWD hash (fallback)
    cwd_hash = hashlib.sha256(str(Path.cwd()).encode()).hexdigest()[:16]
    return f"project_{cwd_hash}"
```

**Source**: `src/utils/namespace.py`

---

## Support

### Issues or Questions?

1. **Check logs**: `~/.claude/logs/mcp-server-tmws.log`
2. **Verify namespace**: Look for "Namespace detected" log entry
3. **Report bug**: GitHub Issues with log snippet

### Related Documentation

- **Security**: `docs/security/NAMESPACE_ISOLATION_SECURITY.md`
- **Feasibility Study**: `docs/evaluation/NAMESPACE_SHARED_AREA_FEASIBILITY_2025_10_27.md`
- **API Reference**: `docs/api/MCP_TOOLS_REFERENCE.md`

---

**Last Updated**: 2025-10-27
**Version**: TMWS v2.2.6
**Contributors**: Eris (戦術調整スペシャリスト), Muses (知識アーキテクト)

---

**End of Guide**
