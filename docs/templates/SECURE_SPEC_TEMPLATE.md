# ブランド管理機能 セキュアAPI仕様書 v1.0

**作成日**: 2025-10-28
**レビュー担当**: Hestia (Security Auditor)
**セキュリティレベル**: HIGH

---

## 1. 概要

ブランド情報の作成、検索、更新、削除、CSV入出力を提供するAPIシステム。

### 1.1 セキュリティ目標
- SQLインジェクション: 100%防御
- 不正アクセス: ロールベース認可で防止
- データ破損: トランザクション + 監査ログで防止
- DDoS: レート制限で緩和

---

## 2. データモデル

### 2.1 brands テーブル定義

```sql
CREATE TYPE brand_usage AS ENUM ('sales', 'purchase');

CREATE TABLE brands (
    id bigserial PRIMARY KEY,
    usage brand_usage NOT NULL,
    brand_name text NOT NULL CHECK (length(brand_name) > 0 AND length(brand_name) <= 255),
    disp_name text NOT NULL CHECK (length(disp_name) > 0 AND length(disp_name) <= 255),
    sort_order int DEFAULT 0 CHECK (sort_order >= 0),
    brand_name_kana text CHECK (length(brand_name_kana) <= 255),
    disp_name_kana text CHECK (length(disp_name_kana) <= 255),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (usage, brand_name)
);

CREATE INDEX idx_brands_usage_name ON brands (usage, brand_name);
CREATE INDEX idx_brands_sort_order ON brands (sort_order);

-- 更新日時自動更新
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER brands_updated_at
BEFORE UPDATE ON brands
FOR EACH ROW
EXECUTE FUNCTION update_updated_at();
```

### 2.2 制約と検証ルール

#### 必須項目
- `usage`: 'sales' または 'purchase' (ENUM型で強制)
- `brand_name`: 1-255文字、空白のみ禁止
- `disp_name`: 1-255文字、空白のみ禁止

#### オプション項目
- `sort_order`: 0以上の整数（デフォルト: 0）
- `brand_name_kana`: 0-255文字
- `disp_name_kana`: 0-255文字

#### 一意性制約
- (usage, brand_name) の組み合わせは一意
- 例: 'sales'の"Sony" と 'purchase'の"Sony" は共存可能

---

## 3. セキュリティ要件

### 3.1 認証・認可

#### 3.1.1 ロール定義

| ロール | 説明 | 許可操作 |
|--------|------|---------|
| admin | システム管理者 | すべての操作 |
| editor | データ編集者 | 作成、更新、CSV出力 |
| viewer | 閲覧者 | 検索、取得のみ |

#### 3.1.2 操作と必要権限

| API エンドポイント | 必要権限 | 許可ロール |
|-------------------|----------|-----------|
| GET /brands | brand:read | admin, editor, viewer |
| GET /brands/:id | brand:read | admin, editor, viewer |
| POST /brands | brand:create | admin, editor |
| PUT /brands/:id | brand:update | admin, editor |
| DELETE /brands/:id | brand:delete | admin のみ |
| POST /brands/export | brand:export_csv | admin, editor |
| POST /brands/import | brand:import_csv | admin のみ |

#### 3.1.3 認証方式
- JWTトークン（Authorization: Bearer <token>）
- トークン有効期限: 24時間（更新可能）
- 失敗ログイン: 5回失敗で30分ロックアウト

### 3.2 入力検証

#### 3.2.1 禁止パターン（SQLインジェクション対策）

**禁止文字列**:
- SQLメタ文字: `'`, `"`, `\`, `;`, `--`, `/*`, `*/`
- SQLキーワード: SELECT, INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, EXEC, UNION

**検証コード例**:
```python
import re

FORBIDDEN_PATTERNS = [
    r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
    r"[';\"\\]",
    r"--",
    r"/\*|\*/",
]

def validate_text_field(value: str, field_name: str):
    if not value or not value.strip():
        raise ValidationError(f"{field_name} cannot be empty")

    if len(value) > 255:
        raise ValidationError(f"{field_name} exceeds 255 characters")

    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, value):
            raise ValidationError(f"Forbidden pattern in {field_name}")
```

#### 3.2.2 バリデーションルール

**usage**:
- 値: 'sales' または 'purchase' のみ
- 検証: ENUM型で強制（データベースレベル）

**brand_name / disp_name**:
- 長さ: 1-255文字
- 禁止: 空白のみ、制御文字（0x00-0x1F）
- 必須: トリミング後に1文字以上

**sort_order**:
- 型: 整数
- 範囲: 0以上
- デフォルト: 0

**kanaフィールド**:
- 長さ: 0-255文字
- NULL許可
- 全角カタカナ推奨（強制はしない）

### 3.3 レート制限

| エンドポイント | 制限 | ウィンドウ |
|---------------|------|-----------|
| GET /brands | 100回 | 1分 |
| POST /brands | 10回 | 1分 |
| PUT /brands/:id | 10回 | 1分 |
| DELETE /brands/:id | 5回 | 1分 |
| POST /brands/export | 10回 | 1時間 |
| POST /brands/import | 5回 | 1時間 |

**制限超過時**:
- HTTPステータス: 429 Too Many Requests
- レスポンスヘッダー: `Retry-After: 60`（秒）
- 監査ログに記録

---

## 4. API エンドポイント

### 4.1 検索 (GET /brands)

#### リクエスト
```http
GET /brands?usage=sales&brand_name=Sony&limit=50&offset=0
Authorization: Bearer <JWT_TOKEN>
```

#### クエリパラメータ
| パラメータ | 型 | 必須 | 説明 |
|-----------|-----|------|------|
| usage | string | No | フィルタ: 'sales' or 'purchase' |
| brand_name | string | No | 部分一致検索（LIKE） |
| limit | integer | No | 最大取得件数（デフォルト: 50, 最大: 100） |
| offset | integer | No | オフセット（デフォルト: 0） |

#### レスポンス (200 OK)
```json
{
  "data": [
    {
      "id": 1,
      "usage": "sales",
      "brand_name": "Sony",
      "disp_name": "ソニー",
      "sort_order": 10,
      "brand_name_kana": "ソニー",
      "disp_name_kana": "ソニー",
      "created_at": "2025-01-15T10:30:00Z",
      "updated_at": "2025-01-20T15:45:00Z"
    }
  ],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

#### セキュリティチェック
- [ ] JWTトークン検証
- [ ] `brand:read` 権限確認
- [ ] `brand_name` パラメータの SQLインジェクション検証
- [ ] レート制限チェック（100回/分）

---

### 4.2 取得 (GET /brands/:id)

#### リクエスト
```http
GET /brands/123
Authorization: Bearer <JWT_TOKEN>
```

#### レスポンス (200 OK)
```json
{
  "id": 123,
  "usage": "sales",
  "brand_name": "Sony",
  "disp_name": "ソニー",
  "sort_order": 10,
  "brand_name_kana": "ソニー",
  "disp_name_kana": "ソニー",
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-20T15:45:00Z"
}
```

#### エラーレスポンス (404 Not Found)
```json
{
  "error": "Brand not found",
  "code": "NOT_FOUND",
  "timestamp": "2025-10-28T12:34:56Z",
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

### 4.3 作成 (POST /brands)

#### リクエスト
```http
POST /brands
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "usage": "sales",
  "brand_name": "Panasonic",
  "disp_name": "パナソニック",
  "sort_order": 20,
  "brand_name_kana": "パナソニック",
  "disp_name_kana": "パナソニック"
}
```

#### レスポンス (201 Created)
```json
{
  "id": 456,
  "usage": "sales",
  "brand_name": "Panasonic",
  "disp_name": "パナソニック",
  "sort_order": 20,
  "brand_name_kana": "パナソニック",
  "disp_name_kana": "パナソニック",
  "created_at": "2025-10-28T12:34:56Z",
  "updated_at": "2025-10-28T12:34:56Z"
}
```

#### セキュリティチェック
- [ ] JWTトークン検証
- [ ] `brand:create` 権限確認（admin, editor）
- [ ] 全フィールドのバリデーション
- [ ] SQLインジェクション検証
- [ ] 一意性制約チェック（usage, brand_name）
- [ ] 監査ログ記録
- [ ] レート制限チェック（10回/分）

---

### 4.4 更新 (PUT /brands/:id)

#### リクエスト
```http
PUT /brands/123
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "disp_name": "ソニー株式会社",
  "sort_order": 15
}
```

#### レスポンス (200 OK)
```json
{
  "id": 123,
  "usage": "sales",
  "brand_name": "Sony",
  "disp_name": "ソニー株式会社",
  "sort_order": 15,
  "brand_name_kana": "ソニー",
  "disp_name_kana": "ソニー",
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-10-28T12:40:00Z"
}
```

#### セキュリティチェック
- [ ] JWTトークン検証
- [ ] `brand:update` 権限確認（admin, editor）
- [ ] 更新対象の存在確認
- [ ] 変更フィールドのバリデーション
- [ ] 監査ログ記録（変更前後の値）
- [ ] レート制限チェック（10回/分）

---

### 4.5 削除 (DELETE /brands/:id)

#### リクエスト
```http
DELETE /brands/123
Authorization: Bearer <JWT_TOKEN>
```

#### レスポンス (204 No Content)
```
（レスポンスボディなし）
```

#### セキュリティチェック
- [ ] JWTトークン検証
- [ ] `brand:delete` 権限確認（admin のみ）
- [ ] 削除対象の存在確認
- [ ] 外部キー参照チェック（CASCADE設定確認）
- [ ] 監査ログ記録（削除されたデータ全体）
- [ ] 管理者への即時通知
- [ ] レート制限チェック（5回/分）

---

### 4.6 CSV出力 (POST /brands/export)

#### リクエスト
```http
POST /brands/export
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "usage": "sales"
}
```

#### レスポンス (200 OK)
```http
Content-Type: text/csv; charset=utf-8
Content-Disposition: attachment; filename="brands_sales_20251028.csv"

id,usage,brand_name,disp_name,sort_order,brand_name_kana,disp_name_kana,created_at,updated_at
1,sales,Sony,ソニー,10,ソニー,ソニー,2025-01-15T10:30:00Z,2025-01-20T15:45:00Z
```

#### セキュリティチェック
- [ ] JWTトークン検証
- [ ] `brand:export_csv` 権限確認（admin, editor）
- [ ] フィルタパラメータのバリデーション
- [ ] 監査ログ記録（エクスポート件数）
- [ ] レート制限チェック（10回/時間）

---

### 4.7 CSV取り込み (POST /brands/import)

#### リクエスト
```http
POST /brands/import
Authorization: Bearer <JWT_TOKEN>
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="brands.csv"
Content-Type: text/csv

usage,brand_name,disp_name,sort_order,brand_name_kana,disp_name_kana
sales,Toshiba,東芝,30,トウシバ,トウシバ
------WebKitFormBoundary--
```

#### レスポンス (200 OK)
```json
{
  "created": 150,
  "updated": 25,
  "total": 175,
  "file_hash": "a7f8b3c9d1e2f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"
}
```

#### CSV形式要件
- エンコーディング: UTF-8
- 形式: RFC 4180準拠
- 最大ファイルサイズ: 10MB
- 最大行数: 10,000行

#### 必須列
- `usage` (sales/purchase)
- `brand_name`
- `disp_name`

#### オプション列
- `sort_order`
- `brand_name_kana`
- `disp_name_kana`

#### 処理フロー
1. ファイルサイズチェック（10MB制限）
2. UTF-8デコード検証
3. CSV構造検証（列名確認）
4. **全行バリデーション（一括）**
5. トランザクション開始
6. 一行ずつ作成/更新
7. エラー発生時はロールバック
8. 成功時のみコミット + 監査ログ

#### セキュリティチェック
- [ ] JWTトークン検証
- [ ] `brand:import_csv` 権限確認（admin のみ）
- [ ] ファイルサイズ検証（10MB制限）
- [ ] UTF-8エンコーディング検証
- [ ] 全行のSQLインジェクション検証
- [ ] 一意性制約の事前チェック
- [ ] トランザクション処理（all-or-nothing）
- [ ] ファイルハッシュ（SHA-256）記録
- [ ] 監査ログ記録（作成/更新件数）
- [ ] 管理者への即時通知
- [ ] レート制限チェック（5回/時間）
- [ ] アップロードファイルの即時削除

---

## 5. 監査ログ

### 5.1 記録対象

すべての以下の操作を記録：
- CRUD操作（作成、取得、更新、削除）
- CSV出力・取り込み
- 認証失敗（ログイン試行）
- 権限エラー（403 Forbidden）
- レート制限超過（429 Too Many Requests）

### 5.2 ログ項目

| 項目 | 説明 | 例 |
|------|------|---|
| timestamp | UTC時刻 | 2025-10-28T12:34:56Z |
| operation | 操作種別 | create, update, delete, export, import |
| brand_id | 対象ブランドID | 123 (NULL for import) |
| user_id | 実行ユーザーID | 456 |
| user_role | ユーザーロール | admin, editor, viewer |
| ip_address | クライアントIP | 203.0.113.42 |
| user_agent | User-Agent | Mozilla/5.0... |
| changes | 変更内容（JSON） | {"before": {...}, "after": {...}} |
| result | 操作結果 | success, failure, unauthorized |
| request_id | リクエストID（UUID） | 550e8400-... |

### 5.3 保存期間

- 通常ログ: 1年間
- 削除操作ログ: 7年間（法令遵守）

### 5.4 アラート条件

即座に管理者に通知する条件：
- 削除操作の実行時
- CSV一括取り込み（100件以上の変更）
- 連続5回の認証失敗（同一ユーザー）
- 深夜時間帯（22時-6時）の操作
- 同一IPからのレート制限超過（10回以上）

---

## 6. エラーハンドリング

### 6.1 エラーレスポンス形式

```json
{
  "error": "General error message for users",
  "code": "ERROR_CODE",
  "timestamp": "2025-10-28T12:34:56Z",
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 6.2 エラーコード一覧

| コード | HTTPステータス | 説明 | 例 |
|--------|---------------|------|---|
| VALIDATION_ERROR | 400 | 入力検証エラー | "brand_name is required" |
| UNAUTHORIZED | 401 | 認証失敗 | "Invalid or expired token" |
| FORBIDDEN | 403 | 権限不足 | "Insufficient permissions" |
| NOT_FOUND | 404 | リソース未発見 | "Brand not found" |
| CONFLICT | 409 | 一意性制約違反 | "Brand name already exists" |
| RATE_LIMIT_EXCEEDED | 429 | レート制限超過 | "Too many requests" |
| INTERNAL_ERROR | 500 | サーバーエラー | "An error occurred" |

### 6.3 セキュリティ要件

⚠️ **重要**: エラーメッセージによる情報漏洩を防止

- SQLエラーメッセージを露出しない
- スタックトレースをユーザーに返さない
- 詳細ログはサーバー側のみ記録
- エラーレスポンスに request_id を含める（サポート用）
- データベーステーブル名やカラム名を含めない

#### 良い例
```json
{
  "error": "An error occurred. Please contact support.",
  "code": "INTERNAL_ERROR",
  "request_id": "550e8400-..."
}
```

#### 悪い例（絶対禁止）
```json
{
  "error": "psycopg2.errors.UniqueViolation: duplicate key value violates unique constraint \"brands_usage_brand_name_key\"",
  "stack": "Traceback (most recent call last):\n  File ...",
  "table": "brands"
}
```

---

## 7. パフォーマンス要件

### 7.1 応答時間目標

| 操作 | 目標応答時間 | 最大許容時間 |
|------|-------------|-------------|
| GET /brands (100件) | < 200ms | < 500ms |
| GET /brands/:id | < 50ms | < 100ms |
| POST /brands | < 100ms | < 300ms |
| PUT /brands/:id | < 100ms | < 300ms |
| DELETE /brands/:id | < 150ms | < 500ms |
| POST /brands/export (1000件) | < 2s | < 5s |
| POST /brands/import (1000件) | < 10s | < 30s |

### 7.2 インデックス戦略

```sql
-- 検索パフォーマンス最適化
CREATE INDEX idx_brands_usage_name ON brands (usage, brand_name);
CREATE INDEX idx_brands_sort_order ON brands (sort_order);
CREATE INDEX idx_brands_updated_at ON brands (updated_at DESC);
```

---

## 8. テストケース

### 8.1 セキュリティテスト

#### SQLインジェクション対策
```python
# Test Case: SQL Injection in brand_name
payload = "'; DROP TABLE brands; --"
response = await client.post("/brands", json={
    "usage": "sales",
    "brand_name": payload,
    "disp_name": "Test"
})
assert response.status_code == 400
assert "Forbidden pattern" in response.json()["error"]
```

#### 権限チェック
```python
# Test Case: Unauthorized deletion
viewer_token = get_viewer_token()
response = await client.delete("/brands/123", headers={
    "Authorization": f"Bearer {viewer_token}"
})
assert response.status_code == 403
assert response.json()["code"] == "FORBIDDEN"
```

#### CSV取り込み攻撃
```python
# Test Case: Malicious CSV with SQL injection
malicious_csv = """usage,brand_name,disp_name
sales,"'; DROP TABLE brands; --","Test"
"""
response = await client.post("/brands/import", files={
    "file": ("malicious.csv", malicious_csv, "text/csv")
})
assert response.status_code == 400
assert "Forbidden pattern" in response.json()["error"]
```

### 8.2 データ整合性テスト

#### 一意性制約
```python
# Test Case: Duplicate brand name in same usage
await client.post("/brands", json={
    "usage": "sales",
    "brand_name": "Sony",
    "disp_name": "ソニー"
})

response = await client.post("/brands", json={
    "usage": "sales",
    "brand_name": "Sony",  # 重複
    "disp_name": "別のソニー"
})
assert response.status_code == 409
assert response.json()["code"] == "CONFLICT"
```

#### トランザクション保証
```python
# Test Case: CSV import rollback on error
csv_with_error = """usage,brand_name,disp_name
sales,Brand1,Display1
sales,Brand2,Display2
invalid_usage,Brand3,Display3
"""
response = await client.post("/brands/import", files={
    "file": ("test.csv", csv_with_error, "text/csv")
})
assert response.status_code == 400

# 確認: Brand1, Brand2 が作成されていないこと
count = await db.count("brands", {"brand_name": ["Brand1", "Brand2"]})
assert count == 0
```

---

## 9. デプロイ前チェックリスト

### 9.1 セキュリティ
- [ ] SQLインジェクション対策の実装確認
- [ ] 認証・認可の実装確認
- [ ] レート制限の動作確認
- [ ] 監査ログの記録確認
- [ ] エラーメッセージの情報漏洩チェック
- [ ] HTTPS強制の確認（本番環境）
- [ ] セキュリティヘッダーの設定（CSP, X-Frame-Options等）

### 9.2 データ整合性
- [ ] データベース制約の実装確認（ENUM, CHECK, UNIQUE）
- [ ] トランザクション処理の動作確認
- [ ] 外部キー参照の CASCADE設定確認
- [ ] updated_at トリガーの動作確認

### 9.3 パフォーマンス
- [ ] インデックスの作成確認
- [ ] 応答時間の測定（目標値以内）
- [ ] 大量データでの動作確認（10,000件）

### 9.4 監査
- [ ] すべての操作が監査ログに記録されることを確認
- [ ] アラート通知の動作確認
- [ ] ログ保存期間の設定確認

---

## 10. 運用

### 10.1 監視項目

- API応答時間（P50, P95, P99）
- エラー率（4xx, 5xx）
- レート制限超過回数
- 削除操作の頻度
- CSV取り込みの成功率
- データベースクエリのスロークエリ

### 10.2 定期レビュー

- 月次: 監査ログのレビュー（異常操作の検出）
- 四半期: セキュリティ脆弱性スキャン
- 年次: アクセス権限の見直し

---

## 11. 参考資料

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-61: UNIX Symbolic Link Following](https://cwe.mitre.org/data/definitions/61.html)
- [RFC 4180: Common Format and MIME Type for CSV Files](https://www.rfc-editor.org/rfc/rfc4180)

---

**レビュー履歴**:
- 2025-10-28: 初版作成（Hestia）

**承認**:
- セキュリティレビュー: ✅ Hestia (2025-10-28)
- 技術レビュー: ⏳ Artemis（保留中）
- ドキュメントレビュー: ⏳ Muses（保留中）
