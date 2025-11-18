## Trinitasコマンド実行方法

### 基本構造
```bash
/trinitas <operation> [args] [--options]
```

### 利用可能なオペレーション

#### 1. ペルソナ実行 (execute)
```bash
# 特定のペルソナでタスクを実行
/trinitas execute athena "システムアーキテクチャの分析"
/trinitas execute artemis "パフォーマンス最適化"
/trinitas execute hestia "セキュリティ監査"
/trinitas execute eris "チーム調整と競合解決"
/trinitas execute hera "ワークフロー自動化"
/trinitas execute muses "ドキュメント生成"
```

#### 2. 並列分析 (analyze)
```bash
# 複数ペルソナによる並列分析
/trinitas analyze "包括的システム分析" --personas athena,artemis,hestia
/trinitas analyze "セキュリティレビュー" --personas all --mode parallel
/trinitas analyze "アーキテクチャ評価" --mode wave  # 段階的実行
```

#### 3. メモリ操作 (remember/recall)
```bash
# 記憶の保存
/trinitas remember project_architecture "マイクロサービス設計" --importance 0.9
/trinitas remember security_finding "SQLインジェクション脆弱性" --importance 1.0 --persona hestia

# 記憶の取得
/trinitas recall architecture --semantic --limit 10
/trinitas recall "security patterns" --persona hestia --semantic
/trinitas recall optimization --limit 5
```

#### 4. 学習システム (learn/apply)
```bash
# パターン学習
/trinitas learn optimization_pattern "インデックス追加で90%高速化" --category performance
/trinitas learn security_pattern "入力検証の強化" --category security

# パターン適用
/trinitas apply optimization_pattern "新しいAPIエンドポイント"
/trinitas apply security_pattern "ユーザー入力処理"
```

#### 5. ステータスとレポート (status/report)
```bash
# ステータス確認
/trinitas status         # 全体ステータス
/trinitas status memory  # メモリシステム状態
/trinitas status eris    # Erisのタスク分配状態

# レポート生成
/trinitas report usage        # 使用状況レポート
/trinitas report optimization # 最適化レポート
/trinitas report security     # セキュリティレポート
```