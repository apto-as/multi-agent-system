# Platform Separation Roadmap - Immediate Action Plan

**Strategic Commander**: Hera
**Status**: Ready for Execution
**Start Date**: 2025-10-19
**Target Completion**: 2025-11-09 (3 weeks)

---

## Quick Start: 最初の24時間

### Hour 1-2: ステークホルダー承認
- [ ] `PLATFORM_SEPARATION_STRATEGY.md` をレビュー
- [ ] アプローチ選択の確認（Option B）
- [ ] リソース割り当ての承認
- [ ] Go/No-Go決定

### Hour 3-4: プロジェクトセットアップ
```bash
# GitHub Project作成
gh project create --title "Platform Separation Sprint" \
  --body "Claude Code と OpenCode の完全分離"

# マイルストーン作成
gh milestone create "Phase 1: Preparation" --due-date 2025-10-22
gh milestone create "Phase 2: Shared Core" --due-date 2025-10-28
gh milestone create "Phase 3: Claude Code" --due-date 2025-10-31
gh milestone create "Phase 4: OpenCode" --due-date 2025-11-05
gh milestone create "Phase 5: Integration" --due-date 2025-11-09

# Git tag作成（現状のスナップショット）
git tag -a v2.1.0-pre-separation \
  -m "Snapshot before platform separation refactor"
git push origin v2.1.0-pre-separation
```

### Hour 5-8: Phase 1開始
```bash
# 作業ブランチ作成
git checkout -b feature/platform-separation

# 依存関係マップの完成（このドキュメント作成で実質完了）
# 次: 移行スクリプトの作成準備
```

---

## Week 1: Foundation (Day 1-5)

### Day 1: 準備 ✓ (Completed)
**Status**: ✅ 完了
**Deliverables**:
- ✅ `PLATFORM_SEPARATION_STRATEGY.md`
- ✅ 依存関係マップ（Section 1.3）
- ✅ リスク評価（Section 5）

**Completed Analysis**:
```
総ファイル数: 28
  - Shell: 11 files
  - Python: 12 files
  - JSON/YAML: 5 files

Critical Conflicts:
  1. DEFAULT_CONFIG_DIR矛盾
  2. インストールスクリプト対立
  3. セキュリティポリシー不一致
```

---

### Day 2: 移行スクリプト作成
**Priority**: 🔴 CRITICAL

**Tasks**:
1. 自動分類スクリプト
   ```bash
   #!/bin/bash
   # scripts/classify_files.sh

   echo "=== Classifying files by platform ==="

   # Claude Code only
   CLAUDE_ONLY=(
     ".claude/"
     "install_trinitas_config_v2.2.4.sh"
     "hooks/core/df2_behavior_injector.py"
   )

   # OpenCode only
   OPENCODE_ONLY=(
     ".opencode/"
     "opencode.json"
     "install_opencode.sh"
   )

   # Shared (needs refactoring)
   SHARED=(
     "agents/"
     "shared/"
     "scripts/setup_mem0_auto.sh"
   )

   # Generate report
   echo "Claude Code files: ${#CLAUDE_ONLY[@]}"
   echo "OpenCode files: ${#OPENCODE_ONLY[@]}"
   echo "Shared files: ${#SHARED[@]}"
   ```

2. ドライラン移行スクリプト
   ```bash
   #!/bin/bash
   # scripts/migrate_to_separated.sh

   set -e

   DRY_RUN=${1:-"--dry-run"}

   echo "=== Platform Separation Migration ==="
   echo "Mode: $DRY_RUN"

   # Create target directories
   if [ "$DRY_RUN" != "--dry-run" ]; then
     mkdir -p claude-code/{agents,hooks/core,config}
     mkdir -p opencode/{agents,plugins}
     mkdir -p shared/{utils,security,tools,config}
   fi

   # Phase 1: Shared core
   echo "Moving shared utilities..."
   SHARED_FILES=(
     "shared/utils/json_loader.py"
     "shared/utils/secure_file_loader.py"
     "shared/security/access_validator.py"
   )

   for file in "${SHARED_FILES[@]}"; do
     if [ "$DRY_RUN" != "--dry-run" ]; then
       cp -v "$file" "shared/$file"
     else
       echo "[DRY-RUN] Would copy: $file → shared/$file"
     fi
   done

   # Phase 2: Claude Code
   echo "Moving Claude Code files..."
   # ... (implementation)

   # Phase 3: OpenCode
   echo "Moving OpenCode files..."
   # ... (implementation)

   echo "Migration complete (mode: $DRY_RUN)"
   ```

**Success Criteria**:
- ✓ ドライランが成功
- ✓ 分類が100%正確
- ✓ ファイル損失ゼロ

**Estimated Time**: 4時間

---

### Day 3: Phase 1完了 + Phase 2開始
**Priority**: 🔴 CRITICAL

**Morning: Phase 1最終確認**
1. 移行スクリプトのレビュー
2. バックアップ戦略の確認
3. ロールバック手順の文書化

```bash
# Rollback procedure
#!/bin/bash
# scripts/rollback_separation.sh

git checkout v2.1.0-pre-separation
rm -rf claude-code/ opencode/
git checkout main
```

**Afternoon: Phase 2開始**
1. `shared/utils/platform_detector.py` 作成
   ```python
   """Platform detection utility for Trinitas system."""
   from __future__ import annotations

   import os
   from enum import Enum
   from pathlib import Path
   from typing import Literal


   class Platform(Enum):
       """Supported platforms."""
       CLAUDE_CODE = "claude-code"
       OPENCODE = "opencode"


   class PlatformDetectionError(Exception):
       """Raised when platform cannot be determined."""


   def detect_platform(
       project_root: Path | None = None
   ) -> Literal["claude-code", "opencode"]:
       """Auto-detect platform from environment or project markers.

       Detection order:
       1. Environment variable: TRINITAS_PLATFORM
       2. Project markers: .claude-plugin (Claude Code) or .opencode dir
       3. Parent directory name: claude-code/ or opencode/

       Args:
           project_root: Project root directory. If None, uses current dir.

       Returns:
           Platform identifier string.

       Raises:
           PlatformDetectionError: If platform cannot be determined.

       Example:
           >>> platform = detect_platform()
           >>> print(platform)
           'claude-code'
       """
       # Method 1: Environment variable
       env_platform = os.getenv("TRINITAS_PLATFORM")
       if env_platform in ("claude-code", "opencode"):
           return env_platform

       # Method 2: Project markers
       root = project_root or Path.cwd()

       if (root / ".claude-plugin").exists():
           return "claude-code"

       if (root / ".opencode").is_dir():
           return "opencode"

       # Method 3: Parent directory name
       parent_name = root.name
       if parent_name in ("claude-code", "opencode"):
           return parent_name

       # Failed to detect
       raise PlatformDetectionError(
           "Cannot determine platform. Set TRINITAS_PLATFORM environment "
           "variable or ensure .claude-plugin/.opencode markers exist."
       )


   def get_config_dir(platform: str | None = None) -> str:
       """Get platform-specific config directory.

       Args:
           platform: Platform name. If None, auto-detects.

       Returns:
           Config directory path (e.g., ".claude/config").

       Example:
           >>> config_dir = get_config_dir("claude-code")
           >>> print(config_dir)
           '.claude/config'
       """
       if platform is None:
           platform = detect_platform()

       return {
           "claude-code": ".claude/config",
           "opencode": ".opencode/config"
       }[platform]
   ```

2. テスト作成
   ```python
   # tests/unit/shared/test_platform_detector.py
   import pytest
   from pathlib import Path
   from shared.utils.platform_detector import (
       detect_platform,
       get_config_dir,
       PlatformDetectionError
   )


   def test_detect_claude_from_plugin_marker(tmp_path):
       """Test detection from .claude-plugin marker."""
       (tmp_path / ".claude-plugin").touch()
       assert detect_platform(tmp_path) == "claude-code"


   def test_detect_opencode_from_dir(tmp_path):
       """Test detection from .opencode directory."""
       (tmp_path / ".opencode").mkdir()
       assert detect_platform(tmp_path) == "opencode"


   def test_detect_from_env_variable(monkeypatch, tmp_path):
       """Test detection from environment variable."""
       monkeypatch.setenv("TRINITAS_PLATFORM", "claude-code")
       assert detect_platform(tmp_path) == "claude-code"


   def test_detection_failure(tmp_path):
       """Test detection failure when no markers found."""
       with pytest.raises(PlatformDetectionError):
           detect_platform(tmp_path)


   def test_get_config_dir_claude():
       """Test config dir for Claude Code."""
       assert get_config_dir("claude-code") == ".claude/config"


   def test_get_config_dir_opencode():
       """Test config dir for OpenCode."""
       assert get_config_dir("opencode") == ".opencode/config"
   ```

**Success Criteria**:
- ✓ Phase 1 Milestone達成
- ✓ `platform_detector.py` テスト100%パス
- ✓ Git commit: `feat: Phase 2 - Platform detection utility`

**Estimated Time**: 6時間

---

### Day 4-5: TrinitasComponent refactoring
**Priority**: 🟡 HIGH

**Tasks**:
1. `shared/utils/trinitas_component.py` のプラットフォーム対応
   ```python
   # Modification to trinitas_component.py

   from .platform_detector import detect_platform, get_config_dir

   class TrinitasComponent:
       """Base class with platform auto-detection."""

       # Remove hardcoded DEFAULT_CONFIG_DIR
       # DEFAULT_CONFIG_DIR = ".opencode/config"  # REMOVE THIS

       def __init__(
           self,
           config_path: str | Path | None = None,
           project_root: str | Path | None = None,
           platform: str | None = None,  # NEW PARAMETER
           auto_init: bool = True,
       ):
           """Initialize with platform detection.

           Args:
               platform: Explicit platform override. If None, auto-detects.
           """
           # Auto-detect platform
           self.platform = platform or detect_platform(project_root)

           # Get platform-specific config dir
           self.config_dir = get_config_dir(self.platform)

           # ... rest of initialization
   ```

2. `df2_behavior_injector.py` の修正
   ```python
   # hooks/core/df2_behavior_injector.py

   class DF2BehaviorInjector(TrinitasComponent):
       """Now platform-agnostic!"""

       # Remove hardcoded DEFAULT_CONFIG_DIR
       # DEFAULT_CONFIG_DIR = ".claude/config"  # REMOVE THIS

       # TrinitasComponent will handle platform detection automatically
       COMPONENT_NAME = "DF2BehaviorInjector"
       DEFAULT_CONFIG_FILE = "narratives.json"
   ```

3. テストの更新
   ```python
   # tests/unit/hooks/test_df2_behavior_injector.py

   # Update all tests to use platform parameter
   def test_claude_platform(tmp_path):
       """Test with Claude Code platform."""
       config_dir = tmp_path / "claude-code" / ".claude" / "config"
       config_dir.mkdir(parents=True)

       injector = DF2BehaviorInjector(
           project_root=tmp_path / "claude-code",
           platform="claude-code"
       )
       assert injector.config_dir == ".claude/config"


   def test_opencode_platform(tmp_path):
       """Test with OpenCode platform."""
       config_dir = tmp_path / "opencode" / ".opencode" / "config"
       config_dir.mkdir(parents=True)

       injector = DF2BehaviorInjector(
           project_root=tmp_path / "opencode",
           platform="opencode"
       )
       assert injector.config_dir == ".opencode/config"
   ```

**Success Criteria**:
- ✓ すべてのコンポーネントがプラットフォーム対応
- ✓ テストカバレッジ95%以上
- ✓ CI/CD全パス

**Estimated Time**: 8時間

---

## Week 2: Separation (Day 6-10)

### Day 6-7: Claude Code移行
**Priority**: 🔴 CRITICAL

**Directory Structure**:
```bash
claude-code/
├── agents/
│   ├── athena-conductor.md
│   ├── artemis-optimizer.md
│   ├── hestia-auditor.md
│   ├── eris-coordinator.md
│   ├── hera-strategist.md
│   └── muses-documenter.md
├── .claude/
│   ├── settings.json
│   ├── settings.local.json
│   └── CLAUDE.md
├── hooks/
│   └── core/
│       ├── protocol_injector.py
│       └── df2_behavior_injector.py
├── config/
│   └── narratives.json
├── tests/
│   └── test_claude_integration.py
├── install_trinitas.sh
└── README-CLAUDE.md
```

**Migration Commands**:
```bash
#!/bin/bash
# Execute migration for Claude Code

# Create structure
mkdir -p claude-code/{agents,hooks/core,config,tests}

# Copy agents
cp agents/athena-conductor.md claude-code/agents/
cp agents/artemis-optimizer.md claude-code/agents/
cp agents/hestia-auditor.md claude-code/agents/
cp agents/eris-coordinator.md claude-code/agents/
cp agents/hera-strategist.md claude-code/agents/
cp agents/muses-documenter.md claude-code/agents/

# Copy .claude directory
cp -r .claude/ claude-code/.claude/

# Copy hooks
cp hooks/core/protocol_injector.py claude-code/hooks/core/
cp hooks/core/df2_behavior_injector.py claude-code/hooks/core/

# Copy config
cp .opencode/config/narratives.json claude-code/config/

# Create installer
cat > claude-code/install_trinitas.sh << 'EOF'
#!/bin/bash
# Claude Code installer (migrated from install_trinitas_config_v2.2.4.sh)

set -e

echo "Installing Trinitas for Claude Code..."

# Copy to ~/.claude
cp -r .claude/* "$HOME/.claude/"
cp -r agents/* "$HOME/.claude/agents/"

echo "✓ Installation complete!"
EOF

chmod +x claude-code/install_trinitas.sh

# Create README
cat > claude-code/README-CLAUDE.md << 'EOF'
# Trinitas for Claude Code

## Installation

```bash
cd claude-code
./install_trinitas.sh
```

## Features

- ✅ Full Memory Cookbook support
- ✅ DF2 Behavioral Modifiers
- ✅ Protocol Injection (SessionStart, PreCompact)
- ✅ Mem0 Semantic Memory (MCP)
- ✅ 6 Specialized Personas

## Configuration

Edit `.claude/settings.json` to customize hooks and MCP servers.
EOF
```

**Success Criteria**:
- ✓ Claude Code動作確認
- ✓ Memory Cookbook機能テスト
- ✓ インストールスクリプト検証

**Estimated Time**: 8時間

---

### Day 8-9: OpenCode移行
**Priority**: 🔴 CRITICAL

**Directory Structure**:
```bash
opencode/
├── agents/
│   ├── athena.md
│   ├── artemis.md
│   ├── hestia.md
│   ├── eris.md
│   ├── hera.md
│   └── muses.md
├── .opencode/
│   ├── AGENTS.md
│   ├── config/
│   │   └── narratives.json
│   └── docs/
├── plugins/
│   └── README-UNSUPPORTED.md
├── opencode.json
├── tests/
│   └── test_opencode_integration.py
├── install_opencode.sh
└── README-OPENCODE.md
```

**Migration Commands**:
```bash
#!/bin/bash
# Execute migration for OpenCode

# Create structure
mkdir -p opencode/{agents,plugins,tests}

# Copy agents (rename to match OpenCode convention)
cp agents/athena-conductor.md opencode/agents/athena.md
cp agents/artemis-optimizer.md opencode/agents/artemis.md
cp agents/hestia-auditor.md opencode/agents/hestia.md
cp agents/eris-coordinator.md opencode/agents/eris.md
cp agents/hera-strategist.md opencode/agents/hera.md
cp agents/muses-documenter.md opencode/agents/muses.md

# Copy .opencode directory
cp -r .opencode/ opencode/.opencode/

# Copy opencode.json
cp opencode.json opencode/

# Copy installer
cp install_opencode.sh opencode/

# Create plugin notice
cat > opencode/plugins/README-UNSUPPORTED.md << 'EOF'
# JavaScript Plugins - Not Supported

OpenCode does **not** support JavaScript plugins. All Trinitas functionality
is delivered through:

1. **Agent Definitions** (`.opencode/agent/*.md`)
2. **Mem0 Semantic Memory** (MCP server)
3. **System Instructions** (`.opencode/AGENTS.md`)

For plugin-like functionality, use MCP servers instead.
EOF

# Update README
cat > opencode/README-OPENCODE.md << 'EOF'
# Trinitas for OpenCode

## Installation

```bash
cd opencode
./install_opencode.sh
```

## Features

- ✅ 6 Specialized Personas
- ✅ Mem0 Semantic Memory (100% local, no API keys)
- ✅ Agent switching (Tab key)
- ✅ System instructions via AGENTS.md
- ❌ JavaScript plugins (not supported by OpenCode)
- ❌ Memory Cookbook (requires plugin support)

## Limitations

OpenCode does not support:
- Claude Code's Memory Cookbook pattern
- JavaScript-based plugins
- SessionStart/PreCompact hooks

Instead, we provide:
- MCP-based semantic memory (Mem0)
- Agent-specific instructions in markdown
EOF
```

**Success Criteria**:
- ✓ OpenCode動作確認
- ✓ Mem0統合テスト
- ✓ プラグイン警告の表示確認

**Estimated Time**: 8時間

---

### Day 10: Week 2まとめとレビュー
**Priority**: 🟡 HIGH

**Tasks**:
1. 両プラットフォームのE2Eテスト
2. ドキュメントレビュー
3. Git commit整理

```bash
# Merge to main
git checkout feature/platform-separation
git add claude-code/ opencode/ shared/
git commit -m "feat: Platform separation - Phase 3-4 complete

- Claude Code: Full feature support with Memory Cookbook
- OpenCode: Core features with Mem0 semantic memory
- Shared: Platform-agnostic utilities

BREAKING CHANGE: Old installation scripts moved to claude-code/ and opencode/
"

# Create release candidate
git tag v2.2.0-rc1
```

**Success Criteria**:
- ✓ 両プラットフォーム動作確認
- ✓ テストスイート全パス
- ✓ ドキュメント完全性100%

**Estimated Time**: 4時間

---

## Week 3: Integration & Release (Day 11-15)

### Day 11-12: CI/CD構築
**Priority**: 🟡 HIGH

**GitHub Actions Workflows**:

`.github/workflows/test-claude-code.yml`:
```yaml
name: Claude Code Tests

on:
  push:
    paths:
      - 'claude-code/**'
      - 'shared/**'
  pull_request:
    paths:
      - 'claude-code/**'
      - 'shared/**'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          cd claude-code
          pip install -r ../requirements-dev.txt

      - name: Run tests
        run: |
          cd claude-code
          pytest --cov=hooks --cov=shared --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./claude-code/coverage.xml
          flags: claude-code
```

`.github/workflows/test-opencode.yml`:
```yaml
name: OpenCode Tests

on:
  push:
    paths:
      - 'opencode/**'
      - 'shared/**'
  pull_request:
    paths:
      - 'opencode/**'
      - 'shared/**'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          cd opencode
          pip install -r ../requirements-dev.txt

      - name: Run tests
        run: |
          cd opencode
          pytest --cov --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./opencode/coverage.xml
          flags: opencode
```

---

### Day 13: ドキュメント統合
**Priority**: 🟢 MEDIUM

**Root README.md更新**:
```markdown
# Trinitas Multi-Agent System

A powerful AI agent system with 6 specialized personas, supporting both Claude Code and OpenCode platforms.

## Supported Platforms

### 🎨 Claude Code (Full Features)
- **Installation**: [`claude-code/`](claude-code/README-CLAUDE.md)
- **Features**:
  - ✅ Memory Cookbook pattern
  - ✅ DF2 Behavioral Modifiers
  - ✅ SessionStart/PreCompact hooks
  - ✅ Mem0 Semantic Memory (MCP)
  - ✅ Full plugin support

**Quick Start**:
```bash
cd claude-code
./install_trinitas.sh
```

### 🚀 OpenCode (Core Features)
- **Installation**: [`opencode/`](opencode/README-OPENCODE.md)
- **Features**:
  - ✅ 6 Specialized Personas
  - ✅ Mem0 Semantic Memory (MCP)
  - ✅ Agent switching
  - ✅ System instructions
  - ❌ JavaScript plugins (platform limitation)

**Quick Start**:
```bash
cd opencode
./install_opencode.sh
```

## Architecture

```
trinitas-agents/
├── claude-code/      # Claude Code platform
├── opencode/         # OpenCode platform
├── shared/           # Platform-agnostic core
└── docs/            # Documentation
```

## Migration from v2.1.0

If you previously installed Trinitas, please choose your platform:

- **Claude Code users**: `cd claude-code && ./install_trinitas.sh`
- **OpenCode users**: `cd opencode && ./install_opencode.sh`

Old installation scripts at the root are **deprecated** as of v2.2.0.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - See [LICENSE](LICENSE)
```

---

### Day 14: Beta Testing
**Priority**: 🟡 HIGH

**Beta Test Plan**:
1. Internal testing (開発チーム)
2. Alpha testers (5-10名)
3. Feedback収集
4. Critical bug修正

**Test Scenarios**:
```bash
# Scenario 1: Fresh install (Claude Code)
cd claude-code
./install_trinitas.sh
# Verify: Memory Cookbook works

# Scenario 2: Fresh install (OpenCode)
cd opencode
./install_opencode.sh
# Verify: Mem0 integration works

# Scenario 3: Migration from v2.1.0
# User has existing ~/.claude or ~/.config/opencode
# Verify: Backup created, migration successful
```

---

### Day 15: Release
**Priority**: 🔴 CRITICAL

**Release Checklist**:
- [ ] All tests passing
- [ ] Documentation complete
- [ ] Beta feedback addressed
- [ ] Release notes written
- [ ] Changelog updated

**Release Process**:
```bash
# Final version bump
git tag v2.2.0 -m "Platform Separation Release

BREAKING CHANGES:
- Installation scripts moved to claude-code/ and opencode/
- Platform-specific configuration required

NEW FEATURES:
- Platform auto-detection
- Separated Claude Code and OpenCode support
- Improved Mem0 integration

MIGRATION:
- Claude Code: cd claude-code && ./install_trinitas.sh
- OpenCode: cd opencode && ./install_opencode.sh
"

# Push release
git push origin main
git push origin v2.2.0

# GitHub Release
gh release create v2.2.0 \
  --title "v2.2.0 - Platform Separation" \
  --notes-file RELEASE_NOTES.md
```

---

## Success Dashboard

### Progress Tracking
```
Week 1: [████████░░] 80% - Platform detection complete
Week 2: [██████░░░░] 60% - Claude Code migration
Week 3: [░░░░░░░░░░]  0% - Pending
```

### KPIs
| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Platform references mixed | 0% | 100% | 🔴 TODO |
| Test coverage | 95% | TBD | ⚪ Pending |
| CI/CD success | 100% | N/A | ⚪ Pending |
| Documentation | 100% | 60% | 🟡 In Progress |

---

## Emergency Contacts

**Escalation Path**:
1. **Technical Issues**: GitHub Issues
2. **Strategic Decisions**: Project Lead
3. **Blocker Resolution**: Daily Standup

**Rollback Trigger**:
- Critical bug in production
- Test coverage < 80%
- User complaints > 10

**Rollback Command**:
```bash
git revert v2.2.0
git tag v2.2.1-hotfix
```

---

**Hera's Command**:
> "Execute this roadmap with precision. Victory is 3 weeks away."

---

**Status**: ✅ Ready for Execution
**Next Review**: Week 1 Day 3 (Phase 1 complete)
