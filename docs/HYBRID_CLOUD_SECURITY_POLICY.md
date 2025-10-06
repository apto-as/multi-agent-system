# TMWS ハイブリッドクラウド セキュリティポリシー

## 1. データ分類とスコープ定義

### 1.1 メモリスコープ階層

```
GLOBAL (クラウド)     - 全プロジェクト横断的知識
├─ 条件: 機密情報を含まない
├─ 例: ベストプラクティス、公開パターン
└─ 暗号化: TLS 1.3 (転送時)

SHARED (クラウド)     - チーム・組織共有知識
├─ 条件: チーム内共有可能
├─ 例: 社内コーディング規約
└─ 暗号化: TLS 1.3 + E2EE (エンドツーエンド)

PROJECT (ローカル)    - プロジェクト固有知識
├─ 条件: プロジェクト内のみ使用
├─ 例: API実装詳細、ビジネスロジック
└─ 暗号化: ローカルディスク暗号化

PRIVATE (ローカル)    - 個人・機密情報
├─ 条件: 絶対にクラウド送信禁止
├─ 例: APIキー、パスワード、個人メモ
└─ 暗号化: AES-256-GCM (保存時)
```

### 1.2 機密情報検出パターン

**自動PRIVATE分類トリガー**:
```regex
# Credentials
password|passwd|pwd|secret|api[_-]?key|access[_-]?token
bearer\s+[a-zA-Z0-9_-]+|authorization:\s*

# Crypto keys
private[_-]?key|-----BEGIN.*PRIVATE KEY-----
[0-9a-fA-F]{64,}  # Long hex strings (crypto keys)

# Personal data
email.*@.*\.(com|org|net)|phone.*\+?\d{10,}
ssn.*\d{3}-\d{2}-\d{4}|credit.*card.*\d{16}

# Database credentials
jdbc:|postgresql://.*:.*@|mysql://.*:.*@
mongodb\+srv://.*:.*@

# Cloud credentials
aws_access_key_id|aws_secret_access_key
AKIA[0-9A-Z]{16}  # AWS Access Key pattern
```

## 2. アクセス制御ポリシー

### 2.1 Row-Level Security (RLS)

**PostgreSQL RLSポリシー**:
```sql
-- Tenant isolation
ALTER TABLE memories_cloud ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON memories_cloud
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE POLICY scope_based_access ON memories_cloud
    USING (
        CASE scope
            WHEN 'GLOBAL' THEN true
            WHEN 'SHARED' THEN tenant_id = current_setting('app.current_tenant')::uuid
            ELSE false
        END
    );
```

### 2.2 アプリケーション層認可

```python
async def check_memory_access(memory: Memory, user: User) -> bool:
    """Multi-layer access control."""

    # Layer 1: Scope-based check
    if memory.scope == MemoryScope.PRIVATE:
        return memory.owner_id == user.id

    # Layer 2: Tenant isolation
    if memory.scope == MemoryScope.SHARED:
        return memory.tenant_id == user.tenant_id

    # Layer 3: GLOBAL always readable
    if memory.scope == MemoryScope.GLOBAL:
        return True

    return False
```

## 3. 暗号化要件

### 3.1 転送時暗号化

**必須設定**:
- TLS 1.3以上（TLS 1.2以下は拒否）
- 証明書ピンニング（クラウドDB接続）
- Perfect Forward Secrecy (PFS) 必須

**実装**:
```python
cloud_engine = create_async_engine(
    cloud_db_url,
    connect_args={
        "ssl": "require",
        "sslmode": "verify-full",
        "sslrootcert": "/etc/tmws/ca-cert.pem",
        "sslcert": "/etc/tmws/client-cert.pem",
        "sslkey": "/etc/tmws/client-key.pem",
    }
)
```

### 3.2 保存時暗号化

**クラウド側**:
- PostgreSQL Transparent Data Encryption (TDE)
- または: アプリケーション層E2EE（推奨）

**ローカル側**:
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

class LocalEncryption:
    def __init__(self, user_key: str):
        # ユーザー固有キーから派生
        kdf = PBKDF2(...)
        self.cipher = Fernet(kdf.derive(user_key.encode()))

    def encrypt_sensitive(self, data: str) -> str:
        return self.cipher.encrypt(data.encode()).decode()
```

### 3.3 エンドツーエンド暗号化 (E2EE)

**SHARED スコープ用**:
```python
class E2EEManager:
    """Client-side encryption for SHARED memories."""

    async def encrypt_for_team(self, data: str, team_id: uuid) -> dict:
        # 1. チーム公開鍵取得
        team_pubkey = await self.get_team_public_key(team_id)

        # 2. 対称鍵生成（AES-256）
        symmetric_key = os.urandom(32)

        # 3. データ暗号化
        cipher = AES.new(symmetric_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())

        # 4. 対称鍵を公開鍵で暗号化
        encrypted_key = team_pubkey.encrypt(symmetric_key)

        return {
            "ciphertext": b64encode(ciphertext),
            "nonce": b64encode(cipher.nonce),
            "tag": b64encode(tag),
            "encrypted_key": b64encode(encrypted_key)
        }
```

## 4. コンプライアンス要件

### 4.1 データレジデンシー

**リージョン別配置**:
```python
REGION_COMPLIANCE = {
    "EU": {
        "cloud_url": "postgresql://eu-central-1.supabase.co/...",
        "regulations": ["GDPR"],
        "data_residency": "EU域内必須"
    },
    "US": {
        "cloud_url": "postgresql://us-east-1.supabase.co/...",
        "regulations": ["CCPA", "SOC2"],
        "data_residency": "US内推奨"
    },
    "APAC": {
        "cloud_url": "postgresql://ap-southeast-1.supabase.co/...",
        "regulations": ["PDPA"],
        "data_residency": "APAC内推奨"
    }
}

def get_cloud_engine(user_region: str):
    config = REGION_COMPLIANCE.get(user_region, REGION_COMPLIANCE["US"])
    return create_async_engine(config["cloud_url"], ...)
```

### 4.2 GDPR準拠

**必須実装機能**:
- ✅ Right to Access: ユーザー全データのエクスポート
- ✅ Right to Erasure: 完全削除（論理削除+物理削除）
- ✅ Right to Portability: JSON/CSV形式でのデータ移行
- ✅ Consent Management: 明示的な同意取得

```python
async def gdpr_export_user_data(user_id: uuid) -> dict:
    """GDPR Article 15: Right to Access."""
    local_memories = await get_local_memories(user_id)
    cloud_memories = await get_cloud_memories(user_id)

    return {
        "user_id": str(user_id),
        "export_date": datetime.utcnow().isoformat(),
        "local_data": [m.to_dict() for m in local_memories],
        "cloud_data": [m.to_dict() for m in cloud_memories],
        "metadata": {
            "total_memories": len(local_memories) + len(cloud_memories),
            "data_regions": ["EU", "US"]
        }
    }

async def gdpr_delete_user_data(user_id: uuid, confirmed: bool = False):
    """GDPR Article 17: Right to Erasure."""
    if not confirmed:
        raise ValueError("User must explicitly confirm deletion")

    # 1. 論理削除（30日間保持）
    await mark_deleted(user_id)

    # 2. 30日後の物理削除（スケジュール）
    await schedule_physical_deletion(user_id, after_days=30)
```

## 5. 監査とロギング

### 5.1 セキュリティイベントログ

**必須記録項目**:
```python
class SecurityAuditLog(Base):
    __tablename__ = "security_audit_logs"

    id = Column(UUID, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String)  # ACCESS, MODIFY, DELETE, EXPORT
    user_id = Column(UUID, nullable=False)
    resource_type = Column(String)  # MEMORY, USER, CONFIG
    resource_id = Column(UUID)
    action = Column(String)
    result = Column(String)  # SUCCESS, FAILURE, BLOCKED
    ip_address = Column(String)
    user_agent = Column(String)
    scope = Column(String)  # GLOBAL, SHARED, PROJECT, PRIVATE
    metadata = Column(JSONB)
```

### 5.2 異常検知

```python
class AnomalyDetector:
    async def detect_suspicious_activity(self, user_id: uuid):
        """Detect potential security breaches."""

        # 1. 短時間の大量アクセス
        recent_access = await get_access_logs(user_id, last_minutes=5)
        if len(recent_access) > 100:
            await trigger_alert("RATE_LIMIT_EXCEEDED", user_id)

        # 2. 異常なスコープアクセス
        if await check_unusual_scope_access(user_id):
            await trigger_alert("UNUSUAL_SCOPE_ACCESS", user_id)

        # 3. 地理的異常
        current_ip = await get_current_ip(user_id)
        if await is_geographically_anomalous(user_id, current_ip):
            await trigger_alert("GEO_ANOMALY", user_id)
```

## 6. インシデント対応計画

### 6.1 セキュリティインシデント分類

| レベル | 説明 | 対応時間 | エスカレーション |
|-------|------|---------|----------------|
| P0 | データ漏洩、認証バイパス | 即座 | CTO + Security Lead |
| P1 | 不正アクセス試行 | 1時間以内 | Security Team |
| P2 | 設定ミス検出 | 4時間以内 | DevOps Team |
| P3 | 監査ログ異常 | 24時間以内 | Development Team |

### 6.2 対応プロトコル

```python
class IncidentResponse:
    async def handle_security_incident(self, incident: Incident):
        # Step 1: 即座の封じ込め
        if incident.severity == "P0":
            await self.emergency_lockdown()

        # Step 2: 影響範囲特定
        affected_users = await self.identify_affected_users(incident)

        # Step 3: 通知
        await self.notify_users(affected_users)
        await self.notify_authorities(incident)  # GDPR 72時間以内

        # Step 4: 証拠保全
        await self.preserve_evidence(incident)

        # Step 5: 復旧
        await self.initiate_recovery(incident)

    async def emergency_lockdown(self):
        """P0インシデント時の緊急停止."""
        # 全クラウドアクセスを即座に遮断
        await self.revoke_all_cloud_access()
        # ローカルのみモードに切り替え
        await self.enable_local_only_mode()
        # セキュリティチームに緊急通知
        await self.alert_security_team(priority="CRITICAL")
```

## 7. 定期的セキュリティレビュー

### 7.1 レビュースケジュール

- **日次**: 監査ログレビュー、異常検知アラート確認
- **週次**: アクセスパターン分析、スコープ分類精度チェック
- **月次**: 脆弱性スキャン、ペネトレーションテスト
- **四半期**: セキュリティポリシー見直し、コンプライアンス監査
- **年次**: 外部セキュリティ監査、ISO 27001認証更新

### 7.2 自動化チェックリスト

```yaml
security_checks:
  daily:
    - check_failed_auth_attempts
    - review_sensitive_data_access
    - verify_encryption_status

  weekly:
    - scan_dependencies_vulnerabilities
    - review_scope_classification_accuracy
    - check_ssl_certificate_expiry

  monthly:
    - penetration_testing
    - code_security_audit
    - access_control_review

  quarterly:
    - gdpr_compliance_check
    - disaster_recovery_drill
    - security_policy_update
```

---

## 承認

- **セキュリティ責任者**: Hestia (TMWS Security Auditor)
- **アーキテクト**: Athena (TMWS Strategic Architect)
- **最終承認**: Hera (TMWS System Commander)

**バージョン**: 1.0
**発効日**: 2025-01-06
**次回見直し**: 2025-04-06
