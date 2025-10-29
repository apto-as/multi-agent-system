# 60%確信度の理由 - 詳細解説
**Date**: 2025-10-29
**Purpose**: Vultureが60%確信度を出す理由の技術的説明

---

## 🎯 60%確信度とは何か？

Vultureは静的解析ツールであり、**Abstract Syntax Tree (AST)** を解析してdead codeを検出します。

**確信度の意味**:
- **100%**: AST解析で確実に未使用と判定
- **80-99%**: 高い確率で未使用だが、例外パターンが存在
- **60-79%**: 未使用の可能性が高いが、動的パターンの影響大

**60%確信度になる理由**: Vultureが検出できない**5つの動的パターン**が存在するため。

---

## 🔍 Vultureが検出できない5つの動的パターン

### Pattern 1: 環境変数からの動的読み込み (Pydantic Settings)

**問題**: Pydantic Settingsは環境変数から動的にフィールドを読み込む。

#### 例: Config Fields (35項目が60%確信度)

```python
# src/core/config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Vultureは「コード内に参照がない」と判定 → 60%確信度
    db_max_connections: int = 10
    ws_enabled: bool = False
    jwt_algorithm: str = "HS256"

    model_config = SettingsConfigDict(
        env_prefix="TMWS_",  # 環境変数から読み込む
        case_sensitive=False
    )

# 実際の使用方法 (Vultureが追跡できない)
settings = Settings()  # 環境変数 TMWS_DB_MAX_CONNECTIONS から読み込み

# または
import os
os.environ["TMWS_DB_MAX_CONNECTIONS"] = "20"
settings = Settings()
print(settings.db_max_connections)  # 20 (環境変数から取得)
```

**なぜ60%確信度か？**:
- Vultureは`settings.db_max_connections`の参照を検出できない
- 環境変数経由のアクセスは実行時まで不明
- しかし、実際には未使用の可能性が高い(だから60%)

**Phase 0の検証結果**:
```bash
# 実際に使用されているか確認
rg "settings\.db_max_connections" src/ tests/
# Result: No matches found

# 環境変数として参照されているか確認
rg "TMWS_DB_MAX_CONNECTIONS" src/ tests/ .env*
# Result: No matches found
```

**結論**: `db_max_connections`は**実際に未使用** → Phase 2-1で削除可能 ✅

---

### Pattern 2: SQLAlchemy ORM Magic (Model Columns)

**問題**: SQLAlchemyのリレーションシップ、動的クエリ、lazy loading。

#### 例: Model Properties (45項目が60%確信度)

```python
# src/models/user.py
class User(Base):
    __tablename__ = "users"

    # Vultureは「直接アクセスされていない」と判定 → 60%確信度
    mfa_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    backup_codes: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    last_failed_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # リレーションシップ
    api_keys: Mapped[list["APIKey"]] = relationship("APIKey", back_populates="user")

# 使用方法 1: 直接アクセス (Vultureが検出可能)
user = session.get(User, user_id)
print(user.mfa_secret)  # ✅ Vultureが検出

# 使用方法 2: リレーションシップ経由 (Vultureが検出不可)
user = session.get(User, user_id)
for api_key in user.api_keys:  # ← Vultureは api_keys が User.id を参照することを理解できない
    print(api_key.key)

# 使用方法 3: 動的クエリ (Vultureが検出不可)
field_name = "mfa_secret"
query = session.query(User).filter(getattr(User, field_name).is_not(None))
# ← Vultureは getattr 経由のアクセスを追跡できない

# 使用方法 4: JSON serialization (Vultureが検出不可)
user_dict = user.to_dict()  # BaseModel.to_dict() が全カラムを serialize
# ← Vultureは to_dict() 内部での暗黙的アクセスを理解できない
```

**なぜ60%確信度か？**:
- Vultureは`user.mfa_secret`の直接参照しか検出できない
- リレーションシップ、`getattr`、`to_dict()`経由のアクセスは追跡不能
- しかし、MFA機能が未実装なら未使用の可能性が高い(だから60%)

**Phase 0の検証結果**:
```bash
# 直接アクセスを確認
rg "\.mfa_secret" src/ tests/
# Result: No matches found

# 動的アクセスを確認
rg "getattr.*mfa_secret" src/ tests/
# Result: No matches found

# MFA機能の実装を確認
rg "mfa|multi.*factor|two.*factor" src/ --ignore-case
# Result: 定義のみ、実装なし
```

**結論**: `mfa_secret`は**将来機能として設計済み** → Phase 3+で慎重に削除検討 ⚠️

---

### Pattern 3: 動的属性アクセス (`getattr`/`setattr`)

**問題**: `getattr`/`setattr`経由のアクセスは実行時まで不明。

#### 例: Base Service Dynamic Updates (12箇所検出)

```python
# src/services/base_service.py:90
async def update(self, record_id, **kwargs):
    record = await self.get(record_id)

    # 動的属性更新 (Vultureが追跡できない)
    for key, value in kwargs.items():
        if hasattr(record, key):
            setattr(record, key, value)  # ← どの属性が更新されるか実行時まで不明

    await self.db.commit()
    return record

# 使用例
await user_service.update(user_id, last_login_at=datetime.now())
# ← Vultureは last_login_at が使用されることを理解できない
```

**なぜ60%確信度か？**:
- `setattr(record, "last_login_at", value)`は実行時に解決
- Vultureは`record.last_login_at`への参照と認識できない
- しかし、全ての属性が`setattr`で更新されるわけではない(だから60%)

**Phase 0の検証結果**:
```bash
# setattr での使用を確認
rg "setattr" src/ --type py
# Result: 12箇所 (すべてORM操作で安全)

# 各属性の直接アクセスを確認
rg "\.last_login_at" src/ tests/
# Result: 5 matches (使用中)
```

**結論**: `last_login_at`は**実際に使用中** → 保持 ✅

---

### Pattern 4: リフレクション/イントロスペクション

**問題**: テスト、デバッグ、ドキュメント生成での使用。

#### 例: Model Inspection for Testing

```python
# tests/unit/test_models.py (仮想例)
def test_model_has_all_security_fields():
    """セキュリティ関連フィールドが定義されているか確認"""
    user = User()

    # リフレクション経由でのアクセス (Vultureが検出不可)
    security_fields = ["mfa_secret", "backup_codes", "last_failed_login_at"]
    for field in security_fields:
        assert hasattr(user, field), f"User model should have {field}"
        # ← Vultureは hasattr() の引数を追跡できない

# ドキュメント生成
def generate_api_docs():
    """API仕様書を自動生成"""
    for column in User.__table__.columns:
        # ← SQLAlchemy metadata からカラムを列挙
        print(f"- {column.name}: {column.type}")
        # ← Vultureはこのパターンを理解できない
```

**なぜ60%確信度か？**:
- `hasattr(user, "mfa_secret")`は文字列引数
- Vultureは文字列引数を属性参照と認識できない
- しかし、テストでのみ使用される可能性もある(だから60%)

**Phase 0の検証結果**:
```bash
# hasattr での使用を確認
rg "hasattr.*mfa" tests/
# Result: No matches found

# __table__ での使用を確認
rg "__table__.*columns" src/ tests/
# Result: 3 matches (models/base.py:74 で使用)
```

**結論**: `models/base.py:74`の`to_dict()`で**すべてのカラムが serialize される** → 保持 ✅

---

### Pattern 5: 将来の機能 (Planned but not implemented)

**問題**: 設計段階で定義されたが、実装が未完了。

#### 例: Workflow Methods (5項目が60%確信度)

```python
# src/models/workflow.py:171-205
class Workflow(Base):
    __tablename__ = "workflows"

    status: Mapped[str] = mapped_column(String(20), default="draft")

    # 将来機能として定義されているが未実装 (Vultureが60%確信度)
    def pause(self) -> None:
        """Pause the workflow execution."""
        self.status = "paused"

    def resume(self) -> None:
        """Resume the workflow execution."""
        self.status = "running"

    def activate(self) -> None:
        """Activate the workflow."""
        self.is_active = True

    def deactivate(self) -> None:
        """Deactivate the workflow."""
        self.is_active = False

    def advance_step(self) -> None:
        """Advance to the next workflow step."""
        self.current_step += 1

# 実装状況
# - WorkflowService: 基本CRUD機能のみ実装
# - WorkflowExecutor: 未実装
# - ステップ管理: 未実装
# - pause/resume機能: 未実装
```

**なぜ60%確信度か？**:
- Vultureは`workflow.pause()`の呼び出しを検出できない
- しかし、将来実装される可能性がある(だから60%)
- 設計ドキュメントに記載されている場合もある

**Phase 0の検証結果**:
```bash
# pause/resume の使用を確認
rg "\.pause\(\)|\.resume\(\)" src/ tests/
# Result: No matches found

# WorkflowExecutor の実装を確認
rg "WorkflowExecutor" src/ --type py
# Result: No matches found (未実装)

# 設計ドキュメントを確認
rg "pause|resume" docs/ --type md
# Result: No mentions (計画なし？)
```

**結論**: Workflow機能は**完全に未実装** → Phase 2-2で削除可能 ✅

---

## 📊 60%確信度アイテムの削除判断フローチャート

```
┌─────────────────────────────────────┐
│ Vulture: 60%確信度アイテム検出      │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Pattern 1: 環境変数アクセス？        │
│ (Pydantic Settings, os.environ)    │
└──────┬──────────────────────────────┘
       │ Yes
       ├─→ 環境変数として参照されている？
       │   ├─ Yes → 保持 ✅
       │   └─ No  → 削除可能 ❌
       │
       │ No
       ▼
┌─────────────────────────────────────┐
│ Pattern 2: ORM Magic？               │
│ (Relationship, Dynamic query)       │
└──────┬──────────────────────────────┘
       │ Yes
       ├─→ リレーションシップで使用？
       │   ├─ Yes → 保持 ✅
       │   └─ No  → to_dict()で serialize？
       │            ├─ Yes → 保持 ✅
       │            └─ No  → 削除検討 ⚠️
       │
       │ No
       ▼
┌─────────────────────────────────────┐
│ Pattern 3: 動的属性アクセス？         │
│ (getattr, setattr, hasattr)        │
└──────┬──────────────────────────────┘
       │ Yes
       ├─→ 動的更新対象？
       │   ├─ Yes → 保持 ✅
       │   └─ No  → 削除可能 ❌
       │
       │ No
       ▼
┌─────────────────────────────────────┐
│ Pattern 4: リフレクション？           │
│ (テスト, ドキュメント生成)           │
└──────┬──────────────────────────────┘
       │ Yes
       ├─→ テスト/ドキュメントで使用？
       │   ├─ Yes → 保持 ✅
       │   └─ No  → 削除可能 ❌
       │
       │ No
       ▼
┌─────────────────────────────────────┐
│ Pattern 5: 将来の機能？               │
│ (Planned but not implemented)       │
└──────┬──────────────────────────────┘
       │ Yes
       ├─→ 実装計画がある？
       │   ├─ Yes → 保持 ✅ (Phase 3+)
       │   └─ No  → 削除可能 ❌ (Phase 2)
       │
       │ No
       ▼
┌─────────────────────────────────────┐
│ Vultureの誤検出 (False Positive)    │
│ → 実際には使用されている            │
└─────────────────────────────────────┘
       │
       └─→ 保持 ✅
```

---

## 🎯 Phase 0での分類結果

| Pattern | 項目数 | 削除可能 | 削除率 | 例 |
|---------|--------|----------|--------|---|
| **Pattern 1: 環境変数** | 35 | 20-25 | 57-71% | `db_max_connections`, `ws_enabled` |
| **Pattern 2: ORM Magic** | 45 | 0-5 | 0-11% | `mfa_secret`, `api_keys` (保持) |
| **Pattern 3: 動的属性** | 40 | 0-2 | 0-5% | `_memory_service` (保持) |
| **Pattern 4: リフレクション** | 9 | 0 | 0% | `to_dict()` で使用 (保持) |
| **Pattern 5: 将来機能** | 15 | 5-8 | 33-53% | `pause()`, `resume()` (削除可能) |
| **TOTAL** | 144 | 30-45 | 21-31% | - |

---

## 🔑 重要なポイント

### なぜVultureは60%確信度なのか？

**技術的理由**: Vultureは**静的解析 (Static Analysis)** ツールであり、**実行時の動的な振る舞い (Dynamic Behavior)** を追跡できない。

**5つの動的パターン**が存在するため、確実に「未使用」と判定できない → 60%確信度

### Phase 0で実施したこと

1. **環境変数アクセスの確認** (`rg "TMWS_*"`)
2. **ORM Magicの確認** (リレーションシップ、`to_dict()`)
3. **動的属性アクセスの確認** (`getattr`/`setattr`)
4. **リフレクションの確認** (`hasattr`, `__table__`)
5. **将来機能の確認** (実装計画、ドキュメント)

### Phase 2での削除基準

```
削除可能 ❌ = 以下のすべてを満たす:
  1. 環境変数として参照されていない
  2. ORM Magicで使用されていない
  3. 動的属性アクセスで使用されていない
  4. リフレクションで使用されていない
  5. 将来機能として計画されていない
```

---

## 📚 参考資料

### Vultureの動作原理

```python
# Vultureの検出ロジック (簡略版)
import ast

class UnusedCodeDetector(ast.NodeVisitor):
    def __init__(self):
        self.defined = set()  # 定義されたもの
        self.used = set()     # 使用されたもの

    def visit_FunctionDef(self, node):
        self.defined.add(node.name)  # 関数定義を記録

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            self.used.add(node.func.id)  # 関数呼び出しを記録

    def get_unused(self):
        return self.defined - self.used  # 定義されたが使用されていない

# 問題点: 動的な呼び出しを検出できない
getattr(obj, "function_name")()  # ← Vultureは検出不可
```

### 動的パターンの実例

```python
# Pattern 1: 環境変数
os.environ["TMWS_DB_MAX_CONNECTIONS"]  # ← Vultureは追跡不可

# Pattern 2: ORM Magic
user.api_keys  # リレーションシップ ← Vultureは追跡不可

# Pattern 3: 動的属性
setattr(obj, "attr_name", value)  # ← Vultureは追跡不可

# Pattern 4: リフレクション
hasattr(obj, "attr_name")  # ← Vultureは追跡不可

# Pattern 5: 将来機能
workflow.pause()  # 未実装だが将来使用予定 ← Vultureは判断不可
```

---

**Document Generated**: 2025-10-29
**Author**: Athena (Harmonious Conductor)
**Purpose**: Technical explanation of Vulture's 60% confidence threshold

---

**結論**:

60%確信度は、Vultureの**静的解析の限界**を示すものです。5つの動的パターンが存在するため、「未使用」と確実に判定できません。

Phase 0では、これらの動的パターンを**手動で検証**し、実際の削除可能性を評価しました。その結果、144項目中30-45項目(21-31%)が安全に削除可能と判定されました。

Phase 2では、この検証結果に基づいて削除を実行します 💫
