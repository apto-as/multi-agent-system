# PostgreSQL完全削除アーカイブ (2025-11-08)

## 概要

TMWSプロジェクトからPostgreSQL参照を完全に削除するための作業記録。

## アーカイブされたファイル

### 設定ファイル (`config_backups/`)

1. **development.env** - 開発環境のPostgreSQL設定
2. **production.env.template** - 本番環境のPostgreSQL設定テンプレート
3. **production.env.secure** - 本番環境のPostgreSQL設定（シークレット）
4. **tmws.yaml** - TMWS設定ファイル（PostgreSQL参照あり）
5. **.env.cloud** - Supabase PostgreSQL設定
6. **docker-compose.trinitas.yml** - PostgreSQL + pgvectorのDocker Compose設定
7. **docker-compose.test.yml** - テスト用PostgreSQL Docker Compose設定

## 修正されたファイル

### ソースコード

1. **src/tools/system_tools.py:741**
   - `"driver": "asyncpg"` → `"driver": "aiosqlite"`
   - システムステータスで正しいドライバー名を返すように修正

### テストコード

1. **tests/integration/test_memory_service.py**
   - すべての `postgresql_session` を `test_session` に置換（10箇所）
   - ドキュメント文字列を "PostgreSQL backend" → "SQLite backend" に修正

2. **tests/performance/test_mem0_feature_benchmarks.py**
   - `from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TEXT` を削除

### 環境設定

1. **.env.example**
   - `TMWS_DATABASE_URL=postgresql://...` → `TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db`
   - コメント更新: "PostgreSQL with pgvector extension" → "SQLite with WAL mode"

## PostgreSQL参照の分類

| カテゴリ | 削除前 | 削除後 | 状態 |
|---------|--------|--------|------|
| ACTIVEソースコード | 1 | 0 | ✅ 完全削除 |
| TESTコード | 10 | 0 | ✅ 完全削除 |
| 環境設定ファイル | 11 | 0 | ✅ アーカイブ |
| Docker/YAML | 14 | 0 | ✅ アーカイブ |
| アクティブドキュメント | 219 | TBD | 🔄 作業中 |
| アーカイブドキュメント | 32 | 32 | ✅ 保持 |

## 検証

```bash
# ACTIVE参照がゼロであることを確認
grep -r "postgresql\|postgres\|psycopg\|asyncpg\|pgvector" --include="*.py" src/ tests/ | grep -v "archive\|backup"
# → 0件であるべき

# 環境設定からPostgreSQL参照がゼロであることを確認
grep -r "postgresql\|postgres" .env* config/ | grep -v "archive\|backup"
# → 0件であるべき
```

## 次のステップ

1. ドキュメントファイル（*.md）のPostgreSQL参照を更新
2. 最終検証（ACTIVEコードにPostgreSQL参照がないことを確認）
3. gitコミット

## 変更理由

ユーザー様からの強い要望：「まだこの単語を報告で見ることが驚愕」

TMWSは2025-10-24にPostgreSQLからSQLiteに完全移行済みですが、ドキュメントやテストコード、設定ファイルに古いPostgreSQL参照が残っていたため、完全削除を実施。

## アーカイブポリシー

- **ACTIVE参照**: 完全削除（動作に影響）
- **DORMANT参照**: 技術的に必要なコメントのみ許可
- **HISTORICAL参照**: アーカイブディレクトリ内のみ保持
