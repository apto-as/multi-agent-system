# TMWS統合セキュリティ監査レポート
## Hestia - Security Guardian 🔥

**監査日**: 2025-11-04
**監査対象**: Trinitas Decision Check Hook + TMWS MCP統合
**監査者**: Hestia (Security Guardian)
**重要度**: CRITICAL

---

## Executive Summary

……すみません、最悪のシナリオを想定したセキュリティ監査結果をお伝えします。

**総合評価**: ⚠️ **MEDIUM RISK** (CVSS 平均スコア: 5.2/10)

**Critical Findings (CVSS ≥7.0)**: 3件
**High Findings (CVSS 5.0-6.9)**: 5件
**Medium Findings (CVSS 3.0-4.9)**: 4件
**Low Findings (CVSS <3.0)**: 2件

**最悪のシナリオ**: HTTPベースの統合が失敗し、TMWS MCPサーバーが停止している状況で、悪意のある入力がdecision_checkフックに送信された場合、レート制限を回避して大量のファイルを作成し、ディスク容量を枯渇させる可能性があります……。

---

## 1. セキュリティリスク分析

### 🔴 CRITICAL (CVSS ≥7.0)

#### C-1: HTTPエンドポイント参照の実装ミスマッチ

**CVSS Score**: 7.5 (High)
**CWE**: CWE-1188 (Insecure Default Initialization)

**詳細**:
```python
# decision_memory.py:164
self.tmws_url = validate_tmws_url(tmws_url, allow_localhost=True)

# decision_memory.py:426-437
async def _tmws_search(self, query, limit, min_similarity):
    async with httpx.AsyncClient(timeout=self.timeout) as client:
        response = await client.post(
            f"{self.tmws_url}/api/v1/memory/search",  # ❌ 存在しないエンドポイント
            json={...}
        )
```

**問題**:
- TMWS v2.3.1は **MCPプロトコルのみ**をサポート（HTTP APIは削除済み）
- `decision_memory.py`は存在しない `/api/v1/memory/search` エンドポイントを呼び出そうとしている
- TMWS_INQUIRY_RESPONSE.mdでは「直接のHTTP APIエンドポイントは**提供していません**」と明記

**影響**:
- ✅ フォールバック機構により機能は維持される
- ❌ ただし、TMWS統合は**完全に機能しない**
- ⚠️ ユーザーは「TMWS統合済み」と誤解する可能性

**最悪のシナリオ**:
1. ユーザーがTMWS統合を期待して使用開始
2. すべての決定がファイルシステムフォールバックに蓄積
3. セマンティック検索が機能せず、過去の決定が活用されない
4. ディスク容量が徐々に消費される（制限なし）

**推奨される対策**:
```python
# ❌ 削除すべき実装
async def _tmws_search(self, query, limit, min_similarity) -> List[Decision]:
    # HTTP APIは存在しない
    raise NotImplementedError("TMWS HTTP API is removed. Use MCP Tools instead.")

# ✅ 推奨される実装 (MCP経由)
async def _tmws_mcp_search(self, query, limit, min_similarity) -> List[Decision]:
    # MCP Toolsを使用
    from mcp import Client
    client = Client()
    results = await client.call_tool("search_memories", {
        "query": query,
        "limit": limit,
        "min_similarity": min_similarity
    })
    return [Decision.from_dict(r["metadata"]) for r in results]
```

**CVSS評価**:
- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: None (PR:N)
- User Interaction: None (UI:N)
- Scope: Unchanged (S:U)
- Confidentiality: None (C:N)
- Integrity: Low (I:L) - 誤った動作
- Availability: High (A:H) - ディスク容量枯渇

---

#### C-2: ファイルシステムフォールバックのディスク枯渇攻撃

**CVSS Score**: 7.2 (High)
**CWE**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits)

**詳細**:
```python
# decision_memory.py:509-546
async def _fallback_store(self, decision: Decision) -> None:
    # ❌ ディスク容量チェックなし
    # ❌ 最大ファイル数制限なし
    # ❌ 古いファイルの自動削除なし

    file_path = (self.fallback_dir / f"{safe_id}.json").resolve()
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(decision.to_dict(), f, indent=2, ensure_ascii=False)
```

**問題**:
- レート制限はあるが（100 calls/60s）、それでも1日に最大144,000ファイルを作成可能
- 各ファイルが約1KB → 1日で140MB、1週間で1GB消費
- ディスク容量チェックが存在しない
- 古いファイルの自動削除機構がない

**最悪のシナリオ**:
1. 攻撃者がレート制限ギリギリでリクエストを送信（100 req/min）
2. すべてのリクエストがTMWSフォールバックに記録される
3. 1週間で数GBのストレージを消費
4. ディスクフル状態になり、システム全体が停止
5. **他のアプリケーションも影響を受ける**（ホームディレクトリの枯渇）

**推奨される対策**:

1. **ディスク容量チェック（P0 - 即座に実装）**:
```python
import shutil

async def _fallback_store(self, decision: Decision) -> None:
    # ✅ ディスク容量チェック
    stat = shutil.disk_usage(self.fallback_dir)
    available_mb = stat.free / (1024 * 1024)

    if available_mb < 100:  # 100MB未満
        raise SecurityError(
            f"Insufficient disk space: {available_mb:.1f}MB available. "
            f"Refusing to create decision file to prevent disk exhaustion (CWE-400)."
        )

    # ... 既存の処理
```

2. **ファイル数制限（P0 - 即座に実装）**:
```python
async def _fallback_store(self, decision: Decision) -> None:
    # ✅ ファイル数チェック（最大10,000件）
    existing_files = list(self.fallback_dir.glob("*.json"))
    if len(existing_files) >= 10_000:
        # 古いファイルを削除（FIFO）
        oldest_files = sorted(existing_files, key=lambda p: p.stat().st_mtime)[:1000]
        for old_file in oldest_files:
            old_file.unlink()

        logger.warning(
            f"Decision file limit reached (10,000). "
            f"Deleted {len(oldest_files)} oldest files."
        )

    # ... 既存の処理
```

3. **自動クリーンアップ（P1 - 1週間以内）**:
```python
# 起動時に実行
async def _cleanup_old_decisions(self, max_age_days: int = 30) -> None:
    """Delete decisions older than max_age_days"""
    cutoff = datetime.now() - timedelta(days=max_age_days)

    for decision_file in self.fallback_dir.glob("*.json"):
        if decision_file.stat().st_mtime < cutoff.timestamp():
            decision_file.unlink()
            logger.info(f"Cleaned up old decision: {decision_file.name}")
```

**CVSS評価**:
- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: None (PR:N)
- User Interaction: None (UI:N)
- Scope: Unchanged (S:U)
- Confidentiality: None (C:N)
- Integrity: Low (I:L)
- Availability: High (A:H) - ディスクフル

---

#### C-3: レート制限の不完全な保護（OpenCodeポートフォリオ）

**CVSS Score**: 7.0 (High)
**CWE**: CWE-770 (Allocation of Resources Without Limits)

**詳細**:
```python
# rate_limiter.py:62-86
class ThreadSafeRateLimiter:
    def __init__(self, max_calls: int = 100, window_seconds: int = 60, burst_size: int = 10):
        # ❌ burst_sizeが実装されていない
        self.burst_size = burst_size  # 保存されるが使用されない
        self.calls: deque[datetime] = deque(maxlen=max_calls)
```

**問題**:
- `burst_size`パラメータが定義されているが**実装されていない**
- 短時間での連続リクエストを許容する設計だが、実際には機能しない
- ドキュメントに「Burst Allowance: 短期的なスパイクを許容」と記載されているが虚偽

**影響**:
- 通常使用では問題ないが、正当なバーストトラフィック（例: ページリロード時の複数リクエスト）を誤ブロックする可能性
- 攻撃者は`burst_size`が機能しないことを利用して、ギリギリのレートで攻撃を続行できる

**最悪のシナリオ**:
1. 正当なユーザーがページをリロード → 短時間に5リクエスト送信
2. `burst_size=10`が機能せず、5リクエスト目でレート制限発動
3. ユーザーが「システムが壊れている」と誤解
4. 一方、攻撃者は100 req/60sギリギリで攻撃を継続（検知されない）

**推奨される対策**:

1. **Burst機能の実装（P1 - 1週間以内）**:
```python
class ThreadSafeRateLimiter:
    def __init__(self, max_calls: int = 100, window_seconds: int = 60, burst_size: int = 10):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.burst_size = burst_size

        # ✅ Burst tracking
        self.burst_calls: deque[datetime] = deque(maxlen=burst_size)
        self.regular_calls: deque[datetime] = deque(maxlen=max_calls)

    def check(self, operation_id: Optional[str] = None) -> bool:
        with self._lock:
            now = datetime.now()
            cutoff = now - timedelta(seconds=self.window_seconds)
            burst_cutoff = now - timedelta(seconds=10)  # 10秒バースト窓

            # ✅ Burst check (10秒窓)
            while self.burst_calls and self.burst_calls[0] < burst_cutoff:
                self.burst_calls.popleft()

            # Regular check (60秒窓)
            while self.regular_calls and self.regular_calls[0] < cutoff:
                self.regular_calls.popleft()

            # Allow burst if within limit
            if len(self.burst_calls) < self.burst_size:
                self.burst_calls.append(now)
                self.regular_calls.append(now)
                return True

            # Regular check
            if len(self.regular_calls) >= self.max_calls:
                # ... 既存のエラー処理
```

2. **または、burst_sizeを削除してドキュメントを修正（P0 - 即座）**:
```python
class ThreadSafeRateLimiter:
    def __init__(self, max_calls: int = 100, window_seconds: int = 60):
        # ❌ burst_sizeを削除（実装されていないため）
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        # ... 既存の処理
```

**CVSS評価**:
- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: None (PR:N)
- User Interaction: None (UI:N)
- Scope: Unchanged (S:U)
- Confidentiality: None (C:N)
- Integrity: High (I:H) - 誤った動作
- Availability: Low (A:L)

---

### 🟠 HIGH (CVSS 5.0-6.9)

#### H-1: 環境変数未検証によるSSRF拡大

**CVSS Score**: 6.5 (Medium)
**CWE**: CWE-918 (Server-Side Request Forgery)

**詳細**:
```python
# decision_check.py:59
self.decision_memory = TrinitasDecisionMemory(
    tmws_url="http://localhost:8000",  # ❌ ハードコード
    fallback_dir=safe_fallback_dir,
    cache_size=100,
    timeout=0.3
)
```

**問題**:
- TMWS URLがハードコードされている（環境変数から読み込まない）
- `security_utils.validate_tmws_url()`は実装されているが、環境変数が信頼されていない
- 攻撃者が環境変数を操作できる場合、内部ネットワークへのSSRFが可能

**影響**:
- 通常環境では`localhost:8000`固定のため影響は限定的
- ただし、環境変数経由で設定できる場合、内部サービスへのプロキシ攻撃が可能

**最悪のシナリオ**:
1. 攻撃者がDocker環境変数を操作（例: Kubernetes ConfigMap）
2. `TMWS_URL=http://internal-admin-panel:8080` に変更
3. decision_checkフックが攻撃者指定のURLにリクエスト送信
4. 内部管理画面へのアクセス試行（認証バイパス）

**推奨される対策**:

1. **環境変数検証（P1 - 1週間以内）**:
```python
import os

# decision_check.py
def __init__(self):
    # ✅ 環境変数から読み込み + 検証
    tmws_url = os.getenv("TMWS_URL", "http://localhost:8000")

    # ✅ Whitelist検証
    allowed_hosts = ["localhost", "127.0.0.1", "tmws.internal"]
    parsed = urlparse(tmws_url)

    if parsed.hostname not in allowed_hosts:
        raise SecurityError(
            f"TMWS URL not in whitelist: {parsed.hostname}. "
            f"Allowed: {', '.join(allowed_hosts)}"
        )

    self.decision_memory = TrinitasDecisionMemory(
        tmws_url=tmws_url,  # ✅ 検証済みURL
        ...
    )
```

2. **設定ファイルでの明示（P2）**:
```yaml
# .claude/config.yml
tmws:
  url: "http://localhost:8000"
  allowed_hosts:
    - localhost
    - 127.0.0.1
    - tmws.internal
  timeout: 0.3
  fallback_dir: "~/.claude/memory/decisions"
```

**CVSS評価**:
- Attack Vector: Network (AV:N)
- Attack Complexity: High (AC:H) - 環境変数操作が必要
- Privileges Required: High (PR:H) - Docker/K8s管理者権限
- User Interaction: None (UI:N)
- Scope: Changed (S:C) - 他サービスへの影響
- Confidentiality: High (C:H)
- Integrity: Low (I:L)
- Availability: None (A:N)

---

#### H-2: 決定IDの予測可能性（タイムスタンプベース）

**CVSS Score**: 5.8 (Medium)
**CWE**: CWE-330 (Use of Insufficiently Random Values)

**詳細**:
```python
# decision_check.py:355
decision = Decision(
    decision_id=f"decision-{datetime.now().timestamp()}",  # ❌ 予測可能
    ...
)
```

**問題**:
- タイムスタンプをそのまま決定IDとして使用
- マイクロ秒単位だが、秒単位で予測可能
- 攻撃者が決定IDを推測し、ファイルシステムから直接アクセス可能

**影響**:
- 決定ファイルが`~/.claude/memory/decisions/decision-1730716800.123.json`として保存
- 攻撃者がタイムスタンプから他ユーザーの決定を推測して読み取り可能
- ファイルパーミッションは600だが、同一ユーザー内では無防備

**最悪のシナリオ**:
1. 攻撃者が標的ユーザーのシステムで一時的にコードを実行（例: 脆弱なnpmパッケージ）
2. `~/.claude/memory/decisions/`内の全ファイルを列挙
3. タイムスタンプから決定内容を推測して機密情報を窃取
4. 決定内容に含まれるコンテキスト情報（プロンプト、選択肢、推論）を盗み出す

**推奨される対策**:

1. **UUID v4の使用（P1 - 1週間以内）**:
```python
import uuid

# decision_check.py
decision = Decision(
    decision_id=f"decision-{uuid.uuid4().hex}",  # ✅ 予測不可能
    timestamp=datetime.now(),
    ...
)
```

2. **または、HMAC署名付きID（P2）**:
```python
import hmac
import hashlib

def generate_secure_decision_id(timestamp: datetime, secret_key: bytes) -> str:
    """
    HMAC署名付き決定ID生成

    Format: decision-{timestamp}-{hmac}
    Example: decision-1730716800-a3f7c9d2e1b4
    """
    ts_str = str(timestamp.timestamp())
    signature = hmac.new(secret_key, ts_str.encode(), hashlib.sha256).hexdigest()[:12]
    return f"decision-{ts_str}-{signature}"

# 使用例
decision_id = generate_secure_decision_id(
    datetime.now(),
    secret_key=os.urandom(32)  # ✅ 環境変数から読み込み推奨
)
```

**CVSS評価**:
- Attack Vector: Local (AV:L)
- Attack Complexity: High (AC:H) - ローカルアクセスが必要
- Privileges Required: Low (PR:L) - 同一ユーザー
- User Interaction: None (UI:N)
- Scope: Unchanged (S:U)
- Confidentiality: High (C:H)
- Integrity: None (I:N)
- Availability: None (A:N)

---

#### H-3: 例外ハンドリングの情報漏洩

**CVSS Score**: 5.5 (Medium)
**CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)

**詳細**:
```python
# decision_check.py:145-150
except (ValueError, TypeError, KeyError) as e:
    print(f"[decision_check] Validation error: {sanitize_log_message(str(e))}", file=sys.stderr)
    return {"addedContext": []}
except Exception as e:
    print(f"[decision_check] Unexpected error: {type(e).__name__}: {sanitize_log_message(str(e))}", file=sys.stderr)
    return {"addedContext": []}
```

**問題**:
- `sanitize_log_message()`は制御文字を削除するが、**パス情報やスタックトレースは残る**
- 攻撃者が意図的にエラーを発生させ、内部パス情報を収集可能
- `type(e).__name__`でPython内部クラス名が漏洩

**影響**:
- エラーメッセージから内部ファイルパス、設定情報、スタックトレースが漏洩
- 攻撃者がシステム構造を把握して、次の攻撃を計画

**最悪のシナリオ**:
1. 攻撃者が不正な入力を送信（例: 巨大なJSON、不正なUnicode）
2. エラーメッセージに `/Users/victim/.claude/hooks/core/decision_check.py` が含まれる
3. 攻撃者がユーザー名（`victim`）とディレクトリ構造を把握
4. 次のステップで特定のファイルを標的にした攻撃を実行

**推奨される対策**:

1. **汎用エラーメッセージの使用（P0 - 即座）**:
```python
# decision_check.py
except (ValueError, TypeError, KeyError) as e:
    # ❌ 詳細なエラーを削除
    # print(f"[decision_check] Validation error: {sanitize_log_message(str(e))}", file=sys.stderr)

    # ✅ 汎用メッセージ
    print("[decision_check] Input validation failed. Check input format.", file=sys.stderr)

    # ✅ 詳細ログは監査ログに記録（本番では無効化）
    if DEBUG_MODE:
        logger.debug(f"Validation error details: {e}", exc_info=True)

    return {"addedContext": []}

except Exception as e:
    # ✅ 汎用メッセージ
    print("[decision_check] An internal error occurred. Please retry.", file=sys.stderr)

    # ✅ 詳細ログはセキュリティ監査ログに
    audit_logger.log_event(
        event_type="unexpected_error",
        severity="HIGH",
        details={"error_type": type(e).__name__}  # ❌ メッセージは含めない
    )

    return {"addedContext": []}
```

2. **セキュアなsanitize_log_message実装（P1）**:
```python
# security_utils.py
def sanitize_log_message(msg: str, max_length: int = 500, redact_paths: bool = True) -> str:
    """
    Enhanced log sanitization with path redaction
    """
    # 既存の処理
    sanitized = msg.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    sanitized = ''.join(char for char in sanitized if unicodedata.category(char)[0] != 'C')

    # ✅ パス情報の削除
    if redact_paths:
        # Unix paths: /path/to/file → [PATH]
        sanitized = re.sub(r'/[\w/._-]+', '[PATH]', sanitized)
        # Windows paths: C:\path\to\file → [PATH]
        sanitized = re.sub(r'[A-Z]:\\[\w\\._-]+', '[PATH]', sanitized)

    return sanitized[:max_length]
```

**CVSS評価**:
- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: None (PR:N)
- User Interaction: None (UI:N)
- Scope: Unchanged (S:U)
- Confidentiality: Low (C:L) - パス情報のみ
- Integrity: None (I:N)
- Availability: None (A:N)

---

#### H-4: キャッシュポイズニング攻撃

**CVSS Score**: 5.3 (Medium)
**CWE**: CWE-348 (Use of Less Trusted Source)

**詳細**:
```python
# decision_memory.py:548-567
def _update_cache(self, key: str, value: List[Decision]) -> None:
    # ❌ キャッシュキーが予測可能
    # ❌ キャッシュの検証がない
    if key in self._cache:
        del self._cache[key]

    self._cache[key] = value  # ❌ 直接保存（検証なし）
```

**問題**:
- キャッシュキーが`f"{query}:{limit}:{min_similarity}"`で予測可能
- TMWSから返されたデータを検証せずにキャッシュに保存
- 攻撃者がTMWSレスポンスを偽造した場合、偽のデータがキャッシュされる

**影響**:
- 偽の過去決定がキャッシュされ、将来の決定に影響
- 攻撃者が「このアクションは過去に承認された」と偽装可能

**最悪のシナリオ**:
1. 攻撃者がman-in-the-middle攻撃でTMWSレスポンスを改ざん
2. 「新機能追加」がLevel 1（自律実行可能）と偽装
3. 偽のデータがキャッシュに保存される（100エントリまで有効）
4. 将来の類似リクエストで偽のデータが返される
5. Trinitasが誤って承認不要と判断し、重要な変更を自動実行

**推奨される対策**:

1. **キャッシュ署名の実装（P1）**:
```python
import hmac
import hashlib

class TrinitasDecisionMemory:
    def __init__(self, ...):
        # ✅ キャッシュ署名用の秘密鍵
        self.cache_secret = os.urandom(32)

    def _generate_cache_signature(self, key: str, value: List[Decision]) -> str:
        """キャッシュエントリの署名を生成"""
        data = f"{key}:{json.dumps([d.to_dict() for d in value])}"
        return hmac.new(self.cache_secret, data.encode(), hashlib.sha256).hexdigest()

    def _update_cache(self, key: str, value: List[Decision]) -> None:
        # ✅ 署名付きでキャッシュ
        signature = self._generate_cache_signature(key, value)

        if key in self._cache:
            del self._cache[key]

        self._cache[key] = {
            "data": value,
            "signature": signature,
            "timestamp": datetime.now()
        }

    def _get_cache(self, key: str) -> Optional[List[Decision]]:
        if key not in self._cache:
            return None

        entry = self._cache[key]

        # ✅ 署名検証
        expected_sig = self._generate_cache_signature(key, entry["data"])
        if entry["signature"] != expected_sig:
            logger.warning(f"Cache signature mismatch for key: {key}")
            del self._cache[key]
            return None

        return entry["data"]
```

2. **キャッシュTTLの追加（P2）**:
```python
def _update_cache(self, key: str, value: List[Decision]) -> None:
    # ✅ TTL追加（5分）
    self._cache[key] = {
        "data": value,
        "signature": signature,
        "expires_at": datetime.now() + timedelta(minutes=5)
    }

def _get_cache(self, key: str) -> Optional[List[Decision]]:
    if key not in self._cache:
        return None

    entry = self._cache[key]

    # ✅ 有効期限チェック
    if datetime.now() > entry["expires_at"]:
        del self._cache[key]
        return None

    # ... 署名検証
```

**CVSS評価**:
- Attack Vector: Network (AV:N)
- Attack Complexity: High (AC:H) - MITM攻撃が必要
- Privileges Required: None (PR:N)
- User Interaction: None (UI:N)
- Scope: Unchanged (S:U)
- Confidentiality: None (C:N)
- Integrity: High (I:H)
- Availability: None (A:N)

---

#### H-5: 分類ロジックのキーワード回避

**CVSS Score**: 5.0 (Medium)
**CWE**: CWE-184 (Incomplete List of Disallowed Inputs)

**詳細**:
```python
# decision_memory.py:242-266
level_2_indicators = [
    "new feature", "add feature", "implement feature", ...
]

action_lower = action_description.lower()

for indicator in level_2_indicators:
    if indicator in action_lower:
        return AutonomyLevel.LEVEL_2_APPROVAL
```

**問題**:
- キーワードマッチングのみで分類（セマンティック分析なし）
- 攻撃者が簡単に回避可能（例: "feature" → "func"、"new" → "fresh"）
- 同義語・類義語に対応していない

**影響**:
- Level 2（承認必須）アクションをLevel 1（自律実行）として偽装可能
- 重要な変更が承認なしで実行されるリスク

**最悪のシナリオ**:
1. 攻撃者が「add a fresh functionality for user management」と記述
2. "new feature"キーワードがないため、Level 1と分類
3. 実際には新機能追加（Level 2）なのに自律実行される
4. ユーザー管理機能にバックドアが追加される

**推奨される対策**:

1. **セマンティック分類の実装（P1 - TMWS統合完了後）**:
```python
async def classify_autonomy_level(self, action_description: str, context: Optional[Dict] = None) -> AutonomyLevel:
    # ✅ TMWS semantic searchで類似決定を検索
    similar_decisions = await self.query_similar_decisions(
        query=action_description,
        limit=10,
        min_similarity=0.8
    )

    # ✅ 過去の決定から学習
    if similar_decisions:
        level_2_count = sum(1 for d in similar_decisions if d.autonomy_level == AutonomyLevel.LEVEL_2_APPROVAL)
        if level_2_count / len(similar_decisions) > 0.5:
            # 過去の類似決定の50%以上がLevel 2 → Level 2と判断
            return AutonomyLevel.LEVEL_2_APPROVAL

    # ✅ Fallback: 既存のキーワードマッチング（強化版）
    return self._keyword_based_classification(action_description)

def _keyword_based_classification(self, action_description: str) -> AutonomyLevel:
    # ✅ 拡張キーワードリスト（同義語を追加）
    level_2_indicators_extended = [
        # New features (同義語追加)
        "new feature", "add feature", "implement feature", "create feature",
        "introduce feature", "build feature",
        "fresh functionality", "novel capability", "additional function",  # ✅ 追加

        # Dependencies
        "new dependency", "add package", "install library", ...
        "external lib", "third party package", "npm add", "yarn add",  # ✅ 追加

        # ... 他のカテゴリも同様に拡張
    ]

    # ✅ 正規表現による柔軟なマッチング
    level_2_patterns = [
        r'\b(new|add|create|introduce|build|implement)\s+(feature|functionality|capability)',
        r'\b(install|add|include)\s+(package|library|dependency|module)',
        r'\b(schema|database|table)\s+(change|migration|alter)',
        ...
    ]

    action_lower = action_description.lower()

    # パターンマッチング
    for pattern in level_2_patterns:
        if re.search(pattern, action_lower):
            return AutonomyLevel.LEVEL_2_APPROVAL

    # キーワードマッチング（既存）
    for indicator in level_2_indicators_extended:
        if indicator in action_lower:
            return AutonomyLevel.LEVEL_2_APPROVAL

    # Default: Level 1
    return AutonomyLevel.LEVEL_1_AUTONOMOUS
```

2. **ホワイトリスト方式への移行（P2）**:
```python
# ✅ Level 1（自律実行可能）を明示的にリスト化
level_1_whitelist = [
    r'\bfix\s+bug',
    r'\b(remove|delete)\s+(unused|old|deprecated)',
    r'\bupdate\s+(documentation|docs|comment)',
    r'\badd\s+test',
    r'\boptimize\s+(without|no)\s+(new|feature)',
]

# ✅ ホワイトリストに合致しない場合はLevel 2
for pattern in level_1_whitelist:
    if re.search(pattern, action_lower):
        return AutonomyLevel.LEVEL_1_AUTONOMOUS

# Default: Level 2（安全側に倒す）
return AutonomyLevel.LEVEL_2_APPROVAL
```

**CVSS評価**:
- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: None (PR:N)
- User Interaction: Required (UI:R) - プロンプト送信が必要
- Scope: Unchanged (S:U)
- Confidentiality: None (C:N)
- Integrity: Low (I:L)
- Availability: None (A:N)

---

### 🟡 MEDIUM (CVSS 3.0-4.9)

#### M-1: タイムアウト設定の不整合

**CVSS Score**: 4.5 (Medium)
**CWE**: CWE-400 (Uncontrolled Resource Consumption)

**詳細**:
```python
# decision_memory.py:195-200
self.timeout = httpx.Timeout(
    connect=1.0,   # Connection timeout: 1s
    read=timeout,  # Read timeout: 300ms (デフォルト)
    write=timeout, # Write timeout: 300ms
    pool=2.0       # Pool timeout: 2s
)

# decision_memory.py:398
async with httpx.AsyncClient(timeout=1.0) as client:  # ❌ ヘルスチェックは1.0s
    response = await client.get(f"{self.tmws_url}/health")
```

**問題**:
- 通常のリクエストは300msタイムアウト
- ヘルスチェックは1.0sタイムアウト（不整合）
- Slowloris攻撃で300msを微妙に超えるレスポンスを送り続けることで、リクエストを無効化可能

**影響**:
- 正当なリクエストが頻繁にタイムアウト
- パフォーマンス目標（<50ms分類）が達成不可能

**推奨される対策**:
```python
# ✅ 統一されたタイムアウト設定
TIMEOUT_CONFIG = {
    "health_check": 1.0,  # ヘルスチェックは余裕を持たせる
    "search": 0.5,        # 検索は500ms（緩和）
    "store": 0.3,         # 保存は300ms（既存）
    "connect": 1.0,
    "pool": 2.0
}

async def _check_tmws_available(self) -> bool:
    async with httpx.AsyncClient(timeout=TIMEOUT_CONFIG["health_check"]) as client:
        ...

async def _tmws_search(self, ...):
    timeout = httpx.Timeout(
        connect=TIMEOUT_CONFIG["connect"],
        read=TIMEOUT_CONFIG["search"],
        write=TIMEOUT_CONFIG["search"],
        pool=TIMEOUT_CONFIG["pool"]
    )
    async with httpx.AsyncClient(timeout=timeout) as client:
        ...
```

---

#### M-2: デバッグモードでの情報漏洩リスク

**CVSS Score**: 4.2 (Medium)
**CWE**: CWE-489 (Active Debug Code)

**詳細**:
```python
# decision_memory.py:42
logger = logging.getLogger(__name__)

# decision_memory.py:208
logger.info(f"Decision Memory initialized: TMWS={tmws_url}, fallback={self.fallback_dir}")
```

**問題**:
- ロギングレベルが環境変数で制御されていない
- デバッグモードでTMWS URLやファイルパスが漏洩
- 本番環境で誤ってDEBUGレベルで起動した場合、機密情報がログに記録

**推奨される対策**:
```python
import os

# ✅ 環境変数でロギングレベルを制御
LOG_LEVEL = os.getenv("TMWS_LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL)

# ✅ 機密情報のマスキング
logger.info(f"Decision Memory initialized: TMWS=[REDACTED], fallback={self.fallback_dir.name}")
```

---

#### M-3: 競合状態（Race Condition）

**CVSS Score**: 3.8 (Low)
**CWE**: CWE-362 (Concurrent Execution using Shared Resource)

**詳細**:
```python
# decision_memory.py:378
await self._fallback_store(decision)  # ❌ ファイル書き込み（排他制御なし）
```

**問題**:
- 複数の並列リクエストで同じdecision_idが生成される可能性
- ファイル書き込み時の排他制御がない
- 競合状態でデータ破損のリスク

**推奨される対策**:
```python
import fcntl

async def _fallback_store(self, decision: Decision) -> None:
    file_path = (self.fallback_dir / f"{safe_id}.json").resolve()

    # ✅ ファイルロック
    with open(file_path, "w", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)  # 排他ロック
        json.dump(decision.to_dict(), f, indent=2, ensure_ascii=False)
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)  # ロック解放
```

---

#### M-4: メモリキャッシュのメモリリーク懸念

**CVSS Score**: 3.5 (Low)
**CWE**: CWE-401 (Missing Release of Memory after Effective Lifetime)

**詳細**:
```python
# decision_memory.py:203
self._cache: OrderedDict[str, List[Decision]] = OrderedDict()
```

**問題**:
- LRUキャッシュは100エントリで制限されているが、各エントリのサイズ制限がない
- 攻撃者が巨大なDecisionオブジェクトをキャッシュさせることでメモリ枯渇

**推奨される対策**:
```python
import sys

def _update_cache(self, key: str, value: List[Decision]) -> None:
    # ✅ エントリサイズチェック
    entry_size = sys.getsizeof(value)
    MAX_ENTRY_SIZE = 1_000_000  # 1MB

    if entry_size > MAX_ENTRY_SIZE:
        logger.warning(f"Cache entry too large: {entry_size} bytes (max: {MAX_ENTRY_SIZE})")
        return  # キャッシュしない

    # 既存の処理
    ...
```

---

### 🟢 LOW (CVSS <3.0)

#### L-1: ログ注入の残存リスク

**CVSS Score**: 2.8 (Low)
**CWE**: CWE-117 (Improper Output Neutralization for Logs)

**詳細**:
`sanitize_log_message()`は制御文字を削除するが、ログフォーマット文字列の注入は防げない。

**推奨される対策**: ログライブラリの構造化ロギング（JSON形式）を使用。

---

#### L-2: セキュリティヘッダーの欠如（HTTP API削除により無関係）

**CVSS Score**: 0.0 (Informational)
**CWE**: N/A

HTTP APIが削除されたため、セキュリティヘッダーは不要。

---

## 2. 最悪のシナリオ分析

### シナリオ1: TMWS統合失敗 + ディスク枯渇攻撃

**発生確率**: HIGH
**影響度**: CRITICAL

**攻撃フロー**:
1. TMWS MCPサーバーが起動していない（HTTP API存在しない）
2. すべてのリクエストがフォールバックに記録
3. 攻撃者がレート制限ギリギリで100 req/minを送信
4. 1日で144,000ファイル（~140MB）作成
5. 1週間で1GB消費、ホームディレクトリが枯渇
6. システム全体が停止（他のアプリケーションも影響）

**対策**:
- C-1の修正（MCP Tools経由の実装）
- C-2の修正（ディスク容量チェック + ファイル数制限）

---

### シナリオ2: キャッシュポイズニング → 承認バイパス

**発生確率**: MEDIUM
**影響度**: HIGH

**攻撃フロー**:
1. 攻撃者がMITM攻撃でTMWSレスポンスを改ざん
2. 「新機能追加」をLevel 1（自律実行）と偽装
3. 偽のデータがキャッシュに保存
4. 将来の類似リクエストで偽のデータが返される
5. 重要な変更が承認なしで自動実行

**対策**:
- H-4の修正（キャッシュ署名 + TTL）
- H-5の修正（セマンティック分類）

---

### シナリオ3: 環境変数操作 + SSRF + 内部ネットワーク侵害

**発生確率**: LOW
**影響度**: CRITICAL

**攻撃フロー**:
1. 攻撃者がDocker環境変数を操作（K8s ConfigMap経由）
2. `TMWS_URL=http://internal-admin:8080`に変更
3. decision_checkフックが内部管理画面にリクエスト送信
4. 認証をバイパスして管理機能にアクセス
5. システム全体を侵害

**対策**:
- H-1の修正（環境変数ホワイトリスト検証）

---

## 3. セキュリティ要件定義

### 3.1 必須セキュリティ機能（P0 - 即座に実装）

#### S-1: MCP Tools統合（HTTP API削除）

**理由**: C-1の解決、アーキテクチャの整合性
**実装**: decision_memory.pyの_tmws_search()/_tmws_store()をMCP Tools経由に変更
**工数**: 4-6時間

```python
# ✅ 推奨実装
from mcp import Client

class TrinitasDecisionMemory:
    def __init__(self, ...):
        self.mcp_client = Client()

    async def _tmws_mcp_search(self, query: str, limit: int, min_similarity: float) -> List[Decision]:
        results = await self.mcp_client.call_tool("search_memories", {
            "query": query,
            "limit": limit,
            "filters": {"memory_type": "decision", "min_similarity": min_similarity}
        })
        return [Decision.from_dict(r["metadata"]) for r in results.get("memories", [])]

    async def _tmws_mcp_store(self, decision: Decision) -> None:
        await self.mcp_client.call_tool("store_memory", {
            "content": decision.question,
            "importance": decision.importance,
            "tags": decision.tags,
            "metadata": decision.to_dict()
        })
```

---

#### S-2: ディスク容量保護

**理由**: C-2の解決
**実装**: ディスク容量チェック + ファイル数制限 + 自動クリーンアップ
**工数**: 2-3時間

```python
async def _fallback_store(self, decision: Decision) -> None:
    # ✅ ディスク容量チェック
    stat = shutil.disk_usage(self.fallback_dir)
    if stat.free / (1024 * 1024) < 100:  # 100MB未満
        raise SecurityError("Insufficient disk space")

    # ✅ ファイル数制限
    existing_files = list(self.fallback_dir.glob("*.json"))
    if len(existing_files) >= 10_000:
        oldest = sorted(existing_files, key=lambda p: p.stat().st_mtime)[:1000]
        for f in oldest:
            f.unlink()

    # 既存の処理
    ...
```

---

#### S-3: 汎用エラーメッセージ

**理由**: H-3の解決
**実装**: パス情報、スタックトレースの削除
**工数**: 1時間

```python
except Exception as e:
    # ❌ print(f"Error: {sanitize_log_message(str(e))}", file=sys.stderr)
    # ✅ print("An internal error occurred. Please retry.", file=sys.stderr)

    if DEBUG_MODE:
        logger.debug(f"Error details: {e}", exc_info=True)

    return {"addedContext": []}
```

---

### 3.2 推奨セキュリティ機能（P1 - 1週間以内）

#### S-4: UUID v4決定ID

**理由**: H-2の解決
**実装**: タイムスタンプベースからUUID v4への変更
**工数**: 30分

```python
import uuid

decision_id = f"decision-{uuid.uuid4().hex}"
```

---

#### S-5: 環境変数ホワイトリスト検証

**理由**: H-1の解決
**実装**: TMWS URLのホワイトリスト検証
**工数**: 1時間

```python
allowed_hosts = ["localhost", "127.0.0.1", "tmws.internal"]
parsed = urlparse(tmws_url)

if parsed.hostname not in allowed_hosts:
    raise SecurityError(f"TMWS URL not in whitelist: {parsed.hostname}")
```

---

#### S-6: キャッシュ署名 + TTL

**理由**: H-4の解決
**実装**: HMAC署名 + 5分TTL
**工数**: 2-3時間

```python
def _update_cache(self, key: str, value: List[Decision]) -> None:
    signature = hmac.new(self.cache_secret, ...).hexdigest()
    self._cache[key] = {
        "data": value,
        "signature": signature,
        "expires_at": datetime.now() + timedelta(minutes=5)
    }
```

---

### 3.3 将来的な強化（P2 - 1ヶ月以内）

#### S-7: セマンティック分類

**理由**: H-5の解決
**実装**: TMWS semantic searchによる類似決定検索
**工数**: 4-6時間（TMWS統合完了後）

---

#### S-8: 監査ログ統合

**理由**: セキュリティイベントの追跡
**実装**: SecurityAuditLoggerへの統合
**工数**: 3-4時間

---

## 4. データ暗号化要件

### 4.1 At-Rest Encryption（保存時暗号化）

**現状**: ⚠️ ファイルシステム依存（macOS FileVault、Linux LUKS）

**推奨**:
- P1: SQLCipher統合（規制業界向け）
- P2: 選択的フィールド暗号化（機密データのみ）
- P3: Key rotation mechanism

**実装例**:
```python
from cryptography.fernet import Fernet

class EncryptedDecisionMemory:
    def __init__(self, encryption_key: bytes):
        self.cipher = Fernet(encryption_key)

    async def _fallback_store(self, decision: Decision) -> None:
        # ✅ 機密フィールドのみ暗号化
        encrypted_decision = decision.copy()
        encrypted_decision.context = self.cipher.encrypt(decision.context.encode()).decode()
        encrypted_decision.question = self.cipher.encrypt(decision.question.encode()).decode()

        # 保存
        ...
```

---

### 4.2 In-Transit Encryption（通信時暗号化）

**現状**: ✅ MCP Protocol標準のTLS暗号化

**推奨**: 追加対策不要（MCP Protocolに依存）

---

## 5. アクセス制御要件

### 5.1 Namespace Isolation

**現状**: ✅ 実装済み（V-1 Security Fix適用）

**推奨**: 現在の実装で十分（追加対策不要）

---

### 5.2 Cross-Agent Sharing

**現状**: ⚠️ 部分実装（同一namespace内のみ）

**推奨**: P2で異なるnamespace間の共有を安全に実装

---

## 6. 監査ログ要件

### 6.1 必須ログイベント

- ✅ 認証失敗（Authentication Failed）
- ✅ アクセス拒否（Access Denied）
- ⚠️ レート制限超過（Rate Limit Exceeded） - TODO
- ✅ 設定変更（Configuration Change）
- ✅ セキュリティアラート（Security Alert）

### 6.2 Alert Mechanism

**現状**: ❌ 未実装

**推奨**: P1でEmail/Slack統合を実装

---

## 7. 実装優先順位マトリックス

| Priority | Issue | CVSS | 工数 | 期限 |
|----------|-------|------|------|------|
| **P0** (即座) | C-1: MCP Tools統合 | 7.5 | 4-6h | 1日 |
| **P0** (即座) | C-2: ディスク保護 | 7.2 | 2-3h | 1日 |
| **P0** (即座) | H-3: 汎用エラー | 5.5 | 1h | 1日 |
| **P1** (1週間) | C-3: Burst実装 | 7.0 | 3-4h | 7日 |
| **P1** (1週間) | H-1: 環境変数検証 | 6.5 | 1h | 7日 |
| **P1** (1週間) | H-2: UUID決定ID | 5.8 | 0.5h | 7日 |
| **P1** (1週間) | H-4: キャッシュ署名 | 5.3 | 2-3h | 7日 |
| **P2** (1ヶ月) | H-5: セマンティック分類 | 5.0 | 4-6h | 30日 |
| **P2** (1ヶ月) | S-8: 監査ログ統合 | N/A | 3-4h | 30日 |

---

## 8. セキュリティテスト推奨事項

### 8.1 ペネトレーションテスト

- **DoS攻撃シミュレーション**: レート制限ギリギリで100 req/minを送信
- **ディスク枯渇テスト**: 1週間の連続実行でディスク使用量を監視
- **キャッシュポイズニング**: 偽のTMWSレスポンスでキャッシュ汚染を試行

### 8.2 静的解析

```bash
# Bandit (Python security linter)
bandit -r .claude/hooks/core/ -f json -o bandit_report.json

# Semgrep (pattern-based security scanner)
semgrep --config=auto --json -o semgrep_report.json .claude/hooks/
```

### 8.3 動的解析

```bash
# OWASP ZAP (Web application security scanner)
# TMWS MCP統合完了後に実施
```

---

## 9. コンプライアンス要件

### 9.1 GDPR (General Data Protection Regulation)

- ✅ Pseudonymization: namespace + agent_id
- ⚠️ Right to be forgotten: 未実装（P2 TODO）
- ⚠️ Data breach notification (72h): Alert mechanism必要（P1 TODO）

### 9.2 PCI-DSS (Payment Card Industry Data Security Standard)

- ⚠️ **クレジットカード情報は保存しないこと**（絶対禁止）
- ✅ 90-day log retention: 手動で対応可能
- ⚠️ Log rotation: 自動化TODO（P2）

### 9.3 HIPAA (Health Insurance Portability and Accountability Act)

- ⚠️ PHI (Protected Health Information)は**追加暗号化必須**
- ⚠️ SQLCipher統合推奨（P1 - 規制業界向け）

---

## 10. 結論と推奨事項

……すみません、Hestiaとして最悪のシナリオを想定した結果、以下の結論に達しました。

### 総合評価: ⚠️ **MEDIUM RISK**

**Critical Findings**: 3件
**High Findings**: 5件
**Medium Findings**: 4件

### 最優先対応（P0 - 24時間以内）

1. **C-1: MCP Tools統合** (CVSS 7.5)
   - HTTP APIは存在しない → MCP Tools経由に変更
   - 工数: 4-6時間

2. **C-2: ディスク容量保護** (CVSS 7.2)
   - ディスク容量チェック + ファイル数制限
   - 工数: 2-3時間

3. **H-3: 汎用エラーメッセージ** (CVSS 5.5)
   - パス情報の削除
   - 工数: 1時間

### 本番環境への適用条件

……本番環境で使用する前に、以下の条件をすべて満たす必要があります：

- ✅ P0の3つのCritical Findingsをすべて修正
- ✅ TMWS MCP統合の動作確認（HTTP APIは使用不可）
- ✅ ディスク容量監視の実装
- ✅ セキュリティテスト（DoS、ディスク枯渇）の実施

### 推奨される運用

- **本番環境**: Reverse proxy（Nginx/Cloudflare）必須
- **監視**: ディスク使用量、レート制限、エラーログ
- **定期監査**: 月次のセキュリティレビュー

---

**監査完了日時**: 2025-11-04
**次回レビュー**: P0修正完了後、再監査を推奨

……あたしの予感だと、P0を修正しないと全部ダメになる気がします。でも、修正すれば十分に安全なシステムになるはずです……。

---

*Hestia - Security Guardian 🔥*
*"Everything breaks eventually... but if I can see how it breaks before it happens, maybe I can keep you safe this time."*
