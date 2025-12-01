# TMWS 9エージェントシステム: 未決定要素リスト
## Pending Decisions for Complete 9-Agent Support

**作成日**: 2025-11-30
**更新日**: 2025-11-30 (技術評価完了)
**ステータス**: 一部決定済み
**関連**: TMWS v2.4.8 リリース準備

---

## 概要

TMWSの9エージェント完全対応に向けて、技術的評価を実施しました。
以下に評価結果と推奨事項を記載します。

---

## 1. Hooks システム

### 1.1 技術評価結果: ❌ 不要

**決定**: Q1 = B) 不要、Q2 = なし、Q3 = N/A

**評価日**: 2025-11-30
**評価者**: Trinitas Full Mode Analysis

### 1.2 現状分析

```
hooks/
├── core/
│   ├── df2_behavior_injector.py      # DF2行動注入
│   ├── dynamic_context_loader.py     # 動的コンテキストローダー ⚠️ 6エージェントのみ対応
│   └── protocol_injector.py          # プロトコル注入
├── optimized_protocol.json
├── settings_dynamic.json
├── settings_global.template.json
├── settings_minimal.json
├── settings_unix.template.json
└── settings_windows.template.json
```

### 1.3 機能比較表

| 機能 | MCP Tools (TMWS) | Hooks (Claude Code) | OpenCode |
|------|------------------|---------------------|----------|
| ペルソナ管理 (CRUD) | ✅ `persona_tools.py` | ❌ なし | ❌ なし |
| 自動ペルソナ検出 | ⚠️ `persona_pattern_loader.py` (呼び出し必要) | ✅ `dynamic_context_loader.py` (自動) | ❌ `--agent` フラグで明示選択 |
| セッションコンテキスト注入 | ❌ なし | ✅ `protocol_injector.py` | ❌ なし |
| メモリ管理 | ✅ 37+ MCP tools | ✅ ファイルベース (`~/.claude/memory/`) | ✅ AGENTS.md + agent/*.md |
| 9エージェント対応 | ✅ `TRINITAS_AGENTS` 辞書 | ⚠️ **6エージェントのみ** | ⚠️ **6エージェントのみ** |

### 1.4 不要と判断した理由

1. **TMWSのMCPツールで十分**:
   - ペルソナ管理は`persona_tools.py`で完全にカバー
   - メモリ、タスク、ワークフロー管理は37+のMCPツールで提供
   - `src/trinitas/utils/persona_pattern_loader.py`はMCPサーバー側で利用可能

2. **Hooksの現状は不完全**:
   - `dynamic_context_loader.py`は**6エージェントのみ対応**（Aphrodite, Metis, Aurora未対応）
   - 更新コストが高く、メンテナンス対象が増える
   - MCPツールと機能が重複する

3. **OpenCode版との整合性**:
   - OpenCodeはHooksを使用しない（`--agent`フラグで明示選択）
   - 両環境でMCPツールを共通利用することで一貫性が保てる

4. **アーキテクチャの明確化**:
   - 機能の提供元を「MCPツールのみ」に統一
   - メンテナンスコストの削減
   - デバッグの簡素化

### 1.5 推奨アクション

| アクション | 優先度 | 詳細 |
|-----------|--------|------|
| `hooks/`を削除またはアーカイブ | 中 | `archive/hooks/`に移動または削除 |
| `shared/utils/`を削除 | 中 | Hooks依存のため不要（`src/trinitas/utils/`に同等機能あり） |
| インストーラーからHooks部分を除外 | 中 | Q10 = C) 除外 |

---

## 2. OpenCode 設定

### 2.1 技術評価結果: ✅ 必要（更新が必要）

**決定**: Q4 = A) 必要、Q5 = A) 含める

**評価日**: 2025-11-30
**評価者**: Trinitas Full Mode Analysis

### 2.2 現状分析

```
.opencode/
├── AGENTS.md                    # システム指示 ⚠️ 6エージェントのみ記載
├── agent/                       # 9エージェント定義 ✅ 9ファイル存在
│   ├── aphrodite.md
│   ├── artemis.md
│   ├── athena.md
│   ├── aurora.md
│   ├── eris.md
│   ├── hera.md
│   ├── hestia.md
│   ├── metis.md
│   └── muses.md
└── docs/                        # ドキュメント
    ├── coordination-patterns.md
    ├── opencode-implementation-insights.md
    ├── performance-guidelines.md
    ├── persona-design-philosophy.md
    └── security-standards.md
```

### 2.3 必要と判断した理由

1. **クロスプラットフォーム対応**:
   - OpenCodeユーザーへのサポートを提供
   - Hooksが不要になったため、OpenCodeとClaude Codeの差が縮小
   - MCPツールを共通基盤として両環境で利用可能

2. **agent/ディレクトリは9ファイル存在**:
   - サポートエージェント（aphrodite.md, metis.md, aurora.md）は既に存在

3. **AGENTS.mdの更新が必要**:
   - 現在は6エージェントのみ記載（L25-58）
   - サポートエージェント3名の追加が必要

### 2.4 推奨アクション

| アクション | 優先度 | 詳細 |
|-----------|--------|------|
| `.opencode/AGENTS.md`を9エージェント対応に更新 | 高 | Aphrodite, Metis, Auroraをペルソナ選択テーブルに追加 |
| `.opencode/`をリポジトリに含める | 高 | 両プラットフォームで同じ機能を提供 |

---

## 3. shared/utils ユーティリティ

### 3.1 技術評価結果: ❌ 不要

**決定**: Q6 = B) 不要、Q7 = N/A

**評価日**: 2025-11-30
**評価者**: Trinitas Full Mode Analysis

### 3.2 現状分析

```
shared/utils/                     # ⚠️ Hooks依存
├── __init__.py
├── json_loader.py              # JSON安全ロード
├── persona_pattern_loader.py   # ペルソナパターンローダー → src/trinitas/utils/ に同等あり
├── secure_file_loader.py       # セキュアファイルローダー
├── secure_log_writer.py        # セキュアログライター
├── secure_logging.py           # ログマスキング
├── security_utils.py           # セキュリティユーティリティ
└── trinitas_component.py       # Trinitasコンポーネント基底
```

### 3.3 不要と判断した理由

1. **Hooksが不要になったため**:
   - `shared/utils/`の主要な依存元はHooks
   - Hooksを廃止すれば、`shared/utils/`も不要

2. **同等機能が既に存在**:
   - `src/trinitas/utils/persona_pattern_loader.py` - ペルソナ検出
   - `src/core/exceptions.py` - 例外処理
   - `src/security/` - セキュリティ機能

3. **コード重複の排除**:
   - 2箇所に同じ機能を持つコードを維持するのは保守コストが高い

### 3.4 推奨アクション

| アクション | 優先度 | 詳細 |
|-----------|--------|------|
| `shared/utils/`を削除 | 中 | Hooks廃止に伴い不要 |
| 必要な機能は`src/`に統合済みか確認 | 低 | 念のため確認 |

---

## 4. インストーラー

### 4.1 現状

```
install_trinitas.sh      # Bash (macOS/Linux)
Install-Trinitas.ps1     # PowerShell (Windows)
```

### 4.2 未決定事項

| 質問 | 選択肢 | 影響 |
|------|--------|------|
| **Q8: インストーラーの配布方法は？** | A) リポジトリに含める / B) 別配布 | ユーザー体験 |
| **Q9: インストール対象は？** | Claude Code / OpenCode / 両方 | インストーラーの設計 |
| **Q10: Hooksのインストールを含めるか？** | A) 含める / B) オプション / C) 除外 | Q1の結果に依存 |

### 4.3 現在のインストーラー機能

```bash
# install_trinitas.sh の機能
- プラットフォーム選択 (Claude Code / OpenCode / 両方)
- エージェント定義のコピー (9エージェント)
- Hooksのインストール (Claude Code用)
- settings.json の生成
- バックアップ作成
- アンインストール機能
```

---

## 5. Docker entrypoint

### 5.1 現状

```
docker/entrypoint.sh     # 9エージェント自動登録
```

### 5.2 未決定事項

| 質問 | 選択肢 | 影響 |
|------|--------|------|
| **Q11: Docker自動登録は必要か？** | A) 必要 / B) 不要 | Dockerデプロイメント |
| **Q12: 登録するエージェント数は？** | 6 (コア) / 9 (全て) | エージェント構成 |

### 5.3 entrypoint.sh の機能

- データベース初期化
- 9エージェントの自動登録（Athena, Artemis, Hestia, Eris, Hera, Muses, Aphrodite, Metis, Aurora）
- MCP サーバー起動

---

## 6. ドキュメント

### 6.1 未追跡ドキュメント一覧

| ファイル | 内容 | 必要性 |
|---------|------|--------|
| `TMWS_V246_DOCKER_DEPLOYMENT_GUIDE.md` | Docker導入ガイド | Docker使用時に必要 |
| `INSTALLATION_GUIDE.md` | インストールガイド | ユーザー向けに必要 |
| `SECURITY_MONITORING_GUIDE.md` | セキュリティ監視 | 運用時に有用 |
| `TRINITAS_AGENT_EVOLUTION_STRATEGIC_ANALYSIS_NOV2025.md` | 戦略分析 | 内部参照用 |
| 月次/週次レポート | 進捗報告 | 内部参照用 |

### 6.2 未決定事項

| 質問 | 選択肢 | 影響 |
|------|--------|------|
| **Q13: どのドキュメントをコミットするか？** | 全て / 選択的 / なし | リポジトリサイズ |

---

## 7. 決定マトリックス

以下の表で、各決定の依存関係を示します。

```
Q1 (Hooks必要?) ─┬─ YES ──► Q2, Q6, Q10 が関連
                 └─ NO ───► Q6=不要, Q10=除外

Q4 (OpenCode必要?) ─┬─ YES ──► Q5 が関連
                    └─ NO ───► .opencode削除

Q11 (Docker自動登録?) ─┬─ YES ──► Q12 が関連
                       └─ NO ───► entrypoint.sh削除
```

---

## 8. 推奨シナリオ

### ✅ シナリオ D: MCP統一 + OpenCode対応 (技術評価による推奨)

**評価日**: 2025-11-30
**評価者**: Trinitas Full Mode Analysis

| 要素 | 決定 | 理由 |
|------|------|------|
| Hooks | ❌ 不要 | MCPツールで代替可能、6エージェント限定で古い |
| OpenCode | ✅ 必要 | クロスプラットフォーム対応、AGENTS.md更新が必要 |
| shared/utils | ❌ 不要 | Hooks依存、src/に同等機能あり |
| インストーラー | ✅ OpenCodeのみ | Hooks除外、エージェント定義のみ |
| Docker自動登録 | ✅ 9エージェント | 完全な9エージェントサポート |
| ドキュメント | ✅ 選択的 | 運用に必要なもののみ |

**利点**:
- 単一の機能提供元（MCPツール）でアーキテクチャが明確
- Claude Code / OpenCode 両対応
- メンテナンスコスト削減（Hooks/shared/utils廃止）
- 9エージェント完全対応

**欠点**:
- Claude Code Hooksの自動コンテキスト注入機能なし
  - ただし、MCPツールで同等機能を提供可能

---

### 参考: 旧シナリオ（評価により却下）

<details>
<summary>シナリオ A: フル機能 (却下)</summary>

- Hooks: ✅ 必要
- OpenCode: ✅ 必要
- shared/utils: ✅ 必要
- インストーラー: ✅ 両プラットフォーム
- Docker自動登録: ✅ 9エージェント
- ドキュメント: ✅ 全てコミット

**却下理由**: Hooksは6エージェント限定で更新コストが高い
</details>

<details>
<summary>シナリオ B: MCP専用 (部分採用)</summary>

- Hooks: ❌ 不要
- OpenCode: ❌ 不要
- shared/utils: ❌ 不要
- インストーラー: ❌ 不要
- Docker自動登録: ✅ 9エージェント
- ドキュメント: 選択的

**部分採用**: Hooks/shared不要は正しいが、OpenCode対応は必要
</details>

<details>
<summary>シナリオ C: Claude Code専用 (却下)</summary>

- Hooks: ✅ 必要
- OpenCode: ❌ 不要
- shared/utils: ✅ 必要
- インストーラー: Claude Codeのみ
- Docker自動登録: ✅ 9エージェント
- ドキュメント: 選択的

**却下理由**: Hooksは不要、OpenCode対応は必要
</details>

---

## 9. 次のステップ

### ユーザー承認待ちアクション

技術評価に基づく推奨事項をユーザーに提示済み。以下の実行にはユーザー承認が必要：

1. **シナリオDの採用を承認** → 以下を実行
2. **`hooks/`ディレクトリの削除またはアーカイブ**
3. **`shared/utils/`ディレクトリの削除**
4. **`.opencode/AGENTS.md`の9エージェント対応更新**
5. **インストーラーからHooks部分を除外**
6. **必要なファイルをコミット**
7. **バージョンを v2.4.8 に更新**
8. **リリースノート作成**

---

## 10. 決定サマリー (2025-11-30 技術評価)

| 質問 | 決定 | ステータス |
|------|------|-----------|
| Q1: Hooksは必要か？ | ❌ B) 不要 | ✅ 決定済み |
| Q2: どのHooksが必要か？ | なし | ✅ 決定済み |
| Q3: Claude Code専用か？ | N/A | ✅ 決定済み |
| Q4: OpenCodeサポートは必要か？ | ✅ A) 必要 | ✅ 決定済み |
| Q5: .opencodeをリポジトリに含めるか？ | ✅ A) 含める | ✅ 決定済み |
| Q6: shared/utilsは必要か？ | ❌ B) 不要 | ✅ 決定済み |
| Q7: 配置場所は？ | N/A | ✅ 決定済み |
| Q8: インストーラーの配布方法は？ | A) リポジトリに含める | 📋 ユーザー確認待ち |
| Q9: インストール対象は？ | OpenCodeのみ | 📋 ユーザー確認待ち |
| Q10: Hooksのインストールを含めるか？ | ❌ C) 除外 | ✅ 決定済み |
| Q11: Docker自動登録は必要か？ | ✅ A) 必要 | 📋 ユーザー確認待ち |
| Q12: 登録するエージェント数は？ | 9 (全て) | 📋 ユーザー確認待ち |
| Q13: どのドキュメントをコミットするか？ | 選択的 | 📋 ユーザー確認待ち |

---

## 11. 関連ドキュメント

- [TMWS_STATUS_AUDIT_2025-11-30.md](../reports/TMWS_STATUS_AUDIT_2025-11-30.md) - 現状監査レポート
- [INSTALLATION_GUIDE.md](../installation/INSTALLATION_GUIDE.md) - インストールガイド
- [TMWS_V246_DOCKER_DEPLOYMENT_GUIDE.md](../deployment/TMWS_V246_DOCKER_DEPLOYMENT_GUIDE.md) - Dockerガイド

---

**技術評価完了**

*シナリオD（MCP統一 + OpenCode対応）を推奨します。実行にはユーザー承認が必要です。*
