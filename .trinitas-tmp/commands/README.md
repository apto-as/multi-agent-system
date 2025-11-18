# Trinitas Custom Commands

## 概要

Trinitasシステム用のカスタムコマンドを提供します。

## 利用可能なコマンド

### `/trinitas` - メインコマンド
Trinitasの統合知能システムを操作するための高レベルインターフェース。

- **ペルソナ実行**: 特定のペルソナでタスクを実行
- **メモリ操作**: TMWSメモリシステムの操作
- **並列分析**: 複数ペルソナによる協調分析
- **ワークフロー**: 複雑なタスクの段階的実行

### `/tmws` - システム管理コマンド
TMWS (Trinitas Memory & Workflow System)の直接操作。

- **データベース管理**: PostgreSQLの操作・監視
- **ベクトル管理**: pgvectorの操作・最適化
- **サービス管理**: TMWSサービスの起動・停止
- **ヘルスチェック**: システム状態の確認

## インストール方法

### 前提条件

1. **TMWS MCPサーバーのセットアップ**
   ```bash
   cd tmws
   uv sync  # 依存関係のインストール
   ```

2. **Claude Desktop設定にTMWS MCPサーバーを登録**
   ```json
   {
     "mcpServers": {
       "tmws": {
         "command": "uv",
         "args": ["run", "python", "mcp_server.py"],
         "cwd": "/path/to/trinitas-agents/tmws"
       }
     }
   }
   ```

3. **カスタムコマンドの登録**
   ```bash
   # プロジェクトのコマンドを使用
   cp commands/*.md ~/.claude/commands/
   ```

4. **Claude Desktopを再起動**してMCPサーバーとコマンドを読み込み

## 実装詳細

### アーキテクチャ

```
User → /trinitas command → MCP Tools → TMWS MCP Server → PostgreSQL/Services
         /tmws command →
```

各コマンドは**MCPツールを直接呼び出し**、REST APIは使用しません：

- **YAMLヘッダー**: コマンドメタデータ定義
- **使用方法**: 詳細な使用例
- **Python実装**: MCPツール呼び出しロジック

### MCPツール命名規則

TMWS MCPサーバーが提供するツール：
- `mcp__tmws__create_memory` - メモリ作成
- `mcp__tmws__recall_memory` - メモリ取得
- `mcp__tmws__search_memories` - ベクトル検索
- `mcp__tmws__execute_persona` - ペルソナ実行
- `mcp__tmws__create_workflow` - ワークフロー作成
- `mcp__tmws__get_system_status` - ステータス取得
- など

## システム要件

### TMWS動作要件
- PostgreSQL 14+ (pgvector拡張付き)
- Redis 6+
- Python 3.10+
- FastAPI

### 環境変数

TMWSは`.env`ファイルで設定：

```bash
# tmws/.env
TMWS_ENVIRONMENT=development
TMWS_DB_HOST=localhost
TMWS_DB_PORT=5432
TMWS_DB_NAME=tmws_db
TMWS_DB_USER=tmws_user
TMWS_DB_PASSWORD=tmws_pass

# Vector設定
TMWS_VECTOR_DIMENSION=1536
TMWS_SIMILARITY_THRESHOLD=0.7

# セキュリティ（本番環境では必須）
TMWS_AUTH_ENABLED=true
TMWS_SECRET_KEY=<generate-secure-key>
```

## ペルソナ一覧

| ペルソナ | 役割 | 専門分野 |
|---------|------|----------|
| Athena | Strategic Architect | 戦略設計・アーキテクチャ |
| Artemis | Technical Perfectionist | 技術最適化・品質管理 |
| Hestia | Security Guardian | セキュリティ監査・リスク管理 |
| Eris | Tactical Coordinator | 戦術調整・競合解決 |
| Hera | System Conductor | システム指揮・統合管理 |
| Muses | Knowledge Architect | 知識管理・ドキュメント |

## 使用例

### 基本的な使用
```bash
# ペルソナ実行
/trinitas execute athena "システムアーキテクチャの設計"

# メモリ保存
/trinitas remember architecture "マイクロサービス設計" --importance 0.9

# 並列分析
/trinitas analyze "セキュリティ監査" --personas hestia,artemis

# システム状態確認
/tmws health
```

### 高度な使用
```bash
# ワークフロー作成と実行
/trinitas workflow create deployment "デプロイメント手順"
/trinitas workflow execute workflow_001

# データベース管理
/tmws db stats
/tmws db backup

# ベクトル検索最適化
/tmws vector reindex
```

## トラブルシューティング

### TMWSが起動しない場合
```bash
# サービス再起動
/tmws service restart

# ログ確認
/tmws service logs

# ヘルスチェック
/tmws health all
```

### メモリ検索が遅い場合
```bash
# ベクトルインデックス再構築
/tmws vector reindex

# 統計情報確認
/tmws vector stats
```

## 更新履歴

- **v2.0.0** (2024-01-09)
  - trinitas-mcpからTMWSへ移行
  - PostgreSQL + pgvectorベースに変更
  - 6ペルソナ体制に拡張
  
- **v1.0.0** (2023-12-28)
  - 初期リリース
  - 5ペルソナ体制
  - Redis/SQLiteベース

## ライセンス

This project is part of Trinitas Agents System.