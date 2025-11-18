# Responsible Vibe Coding Standards
## AI時代のソフトウェア開発品質基準

## はじめに

Vibe Coding（AIアシスト開発）は、開発速度を劇的に向上させる一方で、新たな品質課題をもたらします。本文書は、Trinitasシステムが推奨する品質基準を定義します。

## 7つの原則

### 1. TDD/BDD First（テスト駆動開発の徹底）
AIがコードを生成する前に、期待される動作を明確に定義する。

**実践方法**:
```python
# GIVEN: 前提条件
def test_user_authentication():
    user = User(email="test@example.com")

    # WHEN: 動作
    result = authenticate(user, password="secure123")

    # THEN: 期待される結果
    assert result.is_authenticated
    assert result.token is not None
```

### 2. Clean Code by Default（デフォルトでクリーンなコード）
AIは読みやすく、保守しやすいコードを生成すべき。

**チェックリスト**:
- [ ] 変数名は意味が明確
- [ ] 関数は単一責任
- [ ] コメントは「なぜ」を説明
- [ ] 重複コードなし

### 3. Security by Design（設計段階からのセキュリティ）
セキュリティは後付けではなく、最初から組み込む。

**必須対策**:
- 入力検証
- SQLインジェクション対策
- XSS対策
- 認証・認可の実装
- センシティブデータの暗号化

### 4. No Useless Tests（無意味なテストの禁止）
カバレッジ率のためだけのテストは書かない。

**悪い例**:
```python
def test_function():
    print("test passed")  # これは無意味
```

**良い例**:
```python
def test_user_creation():
    user = User.create(name="Alice", age=30)
    assert user.name == "Alice"
    assert user.age == 30
    assert user.id is not None
```

### 5. Continuous Quality Gates（継続的な品質ゲート）
すべての変更は自動チェックを通過する必要がある。

**必須ゲート**:
1. Lintingとフォーマット
2. 単体テスト
3. 統合テスト
4. セキュリティスキャン
5. コードレビュー

### 6. Documentation as Code（ドキュメントもコード）
ドキュメントはコードと共に管理し、常に最新を保つ。

**実践方法**:
```python
def calculate_discount(price: float, discount_rate: float) -> float:
    """
    商品の割引後価格を計算する。

    Args:
        price: 元の価格（円）
        discount_rate: 割引率（0.0〜1.0）

    Returns:
        割引後の価格

    Raises:
        ValueError: 価格が負数または割引率が範囲外の場合

    Examples:
        >>> calculate_discount(1000, 0.2)
        800.0
    """
```

### 7. Learn from Failures（失敗から学ぶ）
エラーやバグは学習機会として活用する。

**実践方法**:
1. エラー発生時は根本原因を分析
2. 再発防止策をドキュメント化
3. テストケースに追加
4. チーム全体で共有

## アンチパターンの回避

### 1. ファイルの散乱
**問題**: 一時ファイルやテストスクリプトでプロジェクトが汚れる

**解決策**:
```bash
# .gitignoreに追加
temp_*
test_*.py
*.tmp
scratch/
```

### 2. Print文デバッグ
**問題**: print文だけのデバッグ

**解決策**:
```python
# loggingを使用
import logging
logger = logging.getLogger(__name__)
logger.debug("Variable state: %s", variable)
```

### 3. エラーの無視
**問題**: CIのエラーを無視して「完璧」と答える

**解決策**:
- すべてのCIチェックをグリーンに
- エラーは必ず対処
- 技術的負債として記録

## 品質メトリクス

### 必須メトリクス
| メトリクス | 最小値 | 推奨値 |
|-----------|--------|--------|
| テストカバレッジ | 70% | 85% |
| 循環的複雑度 | < 15 | < 10 |
| 重複コード | < 5% | < 2% |
| セキュリティ脆弱性 | 0 (Critical) | 0 (All) |

### 追跡メトリクス
- デプロイ頻度
- 平均修復時間（MTTR）
- 変更失敗率
- リードタイム

## ツールチェーン

### 必須ツール
- **Ruff**: Pythonのlinting/formatting
- **pytest**: テストフレームワーク
- **pre-commit**: Gitフック
- **GitHub Actions**: CI/CD

### 推奨ツール
- **mutmut**: ミューテーションテスト
- **bandit**: セキュリティスキャン
- **coverage.py**: カバレッジ測定
- **mypy**: 型チェック

## 実装ガイドライン

### 1. 新機能の追加
```bash
# 1. テストを書く（RED）
pytest tests/test_new_feature.py  # 失敗することを確認

# 2. 実装する（GREEN）
# 最小限の実装でテストを通す

# 3. リファクタリング（REFACTOR）
# コードをクリーンアップ

# 4. 品質チェック
trinitas-guard check

# 5. コミット
git commit -m "feat: Add new feature with tests"
```

### 2. バグ修正
```bash
# 1. 再現テストを書く
pytest tests/test_bug_regression.py

# 2. 修正を実装

# 3. すべてのテストを実行
pytest

# 4. セキュリティチェック
trinitas-guard check
```

## チームでの実践

### 1. コードレビュー文化
- すべての変更はレビューを受ける
- 建設的なフィードバック
- 学習機会として活用

### 2. ペアプログラミング
- 複雑な機能は2人で開発
- AIアシストでも人間のレビューは必須

### 3. 知識共有
- 週次で学んだことを共有
- エラーパターンをドキュメント化
- ベストプラクティスを更新

## 継続的改善

### 月次レビュー
1. メトリクスの確認
2. プロセスの改善点を特定
3. ツールの見直し
4. チームフィードバック

### 四半期評価
1. 品質目標の達成度
2. 技術的負債の状況
3. チームスキルの成長
4. 次期目標の設定

## まとめ

Vibe Codingの成功は、速度と品質のバランスにあります。Trinitas Quality Guardian Frameworkは、このバランスを実現するための実践的なツールとプロセスを提供します。

**覚えておくべきこと**:
- 品質は全員の責任
- 自動化できることは自動化する
- 継続的な改善を心がける
- 失敗から学ぶ文化を育てる

> "Quality is not an act, it is a habit." - Aristotle

Trinitasシステムと共に、高品質なソフトウェア開発を実現しましょう。