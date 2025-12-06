#!/usr/bin/env python3
"""
埋め込み移行スクリプト: 768次元 → 1024次元

このスクリプトは、既存のmultilingual-e5-base（768次元）埋め込みを
Ollama multilingual-e5-large（1024次元）埋め込みに移行します。

使用方法:
    python scripts/migrate_embeddings_to_1024.py [--batch-size 100] [--dry-run]

オプション:
    --batch-size N    バッチサイズ（デフォルト: 100）
    --dry-run         実際の更新を行わずに計画のみ表示
    --force           エラーが発生しても続行
    --skip-errors     個別のエラーをスキップして続行

前提条件:
1. Ollamaサーバーが実行中（localhost:11434）
2. zylonai/multilingual-e5-largeモデルがダウンロード済み
3. データベースマイグレーション#008が適用済み
"""

import argparse
import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.config import get_settings
from src.models.memory import Memory
from src.services.ollama_embedding_service import OllamaEmbeddingService


class EmbeddingMigrator:
    """埋め込み移行マネージャー"""

    def __init__(
        self,
        batch_size: int = 100,
        dry_run: bool = False,
        force: bool = False,
        skip_errors: bool = False,
    ):
        self.batch_size = batch_size
        self.dry_run = dry_run
        self.force = force
        self.skip_errors = skip_errors

        # 設定取得
        settings = get_settings()

        # データベース接続
        self.engine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_size=10,
            max_overflow=20,
        )
        self.async_session_maker = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # Ollama埋め込みサービス
        self.embedding_service = OllamaEmbeddingService(
            ollama_base_url=settings.ollama_base_url,
            model_name=settings.ollama_embedding_model,
            fallback_enabled=False,  # 移行時はfallbackなし
            timeout=60.0,  # 長めのタイムアウト
        )

        # 統計情報
        self.stats = {
            "total": 0,
            "migrated": 0,
            "skipped": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
        }

    async def check_prerequisites(self) -> bool:
        """前提条件の確認"""
        print("==" * 35)
        print("前提条件の確認")
        print("==" * 35)

        # 1. Ollamaサーバー確認
        model_info = self.embedding_service.get_model_info()
        if not model_info.get("ollama_available", False):
            print("❌ Ollamaサーバーに接続できません")
            print("   解決方法:")
            print("   1. Ollamaを起動: ollama serve")
            print("   2. モデルをダウンロード: ollama pull zylonai/multilingual-e5-large")
            return False
        print(f"✅ Ollamaサーバー接続: {model_info.get('model_name')}")

        # 2. モデル次元確認
        dimension = await self.embedding_service.get_dimension()
        if dimension != 1024:
            print(f"❌ モデル次元が不正: {dimension}次元（期待: 1024次元）")
            print("   zylonai/multilingual-e5-large を使用してください")
            return False
        print(f"✅ モデル次元: {dimension}次元")

        # 3. データベース接続確認
        try:
            async with self.async_session_maker() as session:
                result = await session.execute(text("SELECT 1"))
                result.scalar()
            print("✅ データベース接続成功")
        except Exception as e:
            print(f"❌ データベース接続エラー: {e}")
            return False

        # 4. embedding_v3カラム確認
        try:
            async with self.async_session_maker() as session:
                result = await session.execute(
                    text(
                        """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'memories_v2'
                    AND column_name = 'embedding_v3'
                """
                    )
                )
                if not result.scalar():
                    print("❌ embedding_v3カラムが存在しません")
                    print("   マイグレーション#008を実行してください:")
                    print("   alembic upgrade 008")
                    return False
            print("✅ embedding_v3カラム確認")
        except Exception as e:
            print(f"❌ データベーススキーマ確認エラー: {e}")
            return False

        print()
        return True

    async def get_migration_plan(self) -> dict[str, Any]:
        """移行計画の取得"""
        print("==" * 35)
        print("移行計画の作成")
        print("==" * 35)

        async with self.async_session_maker() as session:
            # 移行対象のメモリ数
            result = await session.execute(
                select(Memory).where(
                    # embedding_v2が存在し、embedding_v3がNULL
                    Memory.embedding_v2.isnot(None),
                    Memory.embedding_v3.is_(None),
                )
            )
            memories_to_migrate = result.scalars().all()

            # 統計情報
            total_count = len(memories_to_migrate)
            batch_count = (total_count + self.batch_size - 1) // self.batch_size

            # モデル別集計
            model_counts: dict[str, int] = {}
            for memory in memories_to_migrate:
                model = memory.embedding_model or "unknown"
                model_counts[model] = model_counts.get(model, 0) + 1

            plan = {
                "total_count": total_count,
                "batch_count": batch_count,
                "batch_size": self.batch_size,
                "model_counts": model_counts,
                "memories": memories_to_migrate,
            }

            print(f"📊 移行対象メモリ: {total_count}件")
            print(f"📦 バッチ数: {batch_count}バッチ（{self.batch_size}件/バッチ）")
            print(f"\nモデル別内訳:")
            for model, count in sorted(model_counts.items()):
                print(f"  {model}: {count}件")
            print()

            return plan

    async def migrate_batch(
        self,
        memories: list[Memory],
        batch_num: int,
        total_batches: int,
    ) -> tuple[int, int]:
        """バッチ移行処理

        Returns:
            (success_count, error_count)
        """
        success_count = 0
        error_count = 0

        print(f"📦 バッチ {batch_num}/{total_batches} 処理中（{len(memories)}件）...")

        # コンテンツを抽出
        contents = [memory.content for memory in memories]

        # バッチで埋め込み生成
        try:
            embeddings = await self.embedding_service.encode_document(
                contents,
                normalize=True,
                batch_size=self.batch_size,
            )

            if embeddings.ndim == 1:
                # 単一埋め込みの場合は2次元に変換
                embeddings = embeddings.reshape(1, -1)

            # 各メモリを更新
            async with self.async_session_maker() as session:
                for memory, embedding in zip(memories, embeddings):
                    try:
                        if not self.dry_run:
                            # 埋め込み更新
                            await session.execute(
                                update(Memory)
                                .where(Memory.id == memory.id)
                                .values(
                                    embedding_v3=embedding.tolist(),
                                    embedding_model="multilingual-e5-large",
                                    updated_at=datetime.utcnow(),
                                )
                            )
                        success_count += 1
                    except Exception as e:
                        error_count += 1
                        print(f"  ⚠️ メモリ {memory.id} の更新エラー: {e}")
                        if not self.skip_errors:
                            raise

                if not self.dry_run:
                    await session.commit()

            print(f"  ✅ 成功: {success_count}件, エラー: {error_count}件")

        except Exception as e:
            error_count = len(memories)
            print(f"  ❌ バッチ処理エラー: {e}")
            if not self.force:
                raise

        return success_count, error_count

    async def run_migration(self) -> bool:
        """移行実行"""
        self.stats["start_time"] = datetime.utcnow()

        # 1. 前提条件確認
        if not await self.check_prerequisites():
            return False

        # 2. 移行計画取得
        plan = await self.get_migration_plan()
        self.stats["total"] = plan["total_count"]

        if plan["total_count"] == 0:
            print("✅ 移行対象のメモリはありません")
            return True

        # 3. 確認（dry-runでない場合）
        if not self.dry_run:
            print("==" * 35)
            print("⚠️ 確認")
            print("==" * 35)
            print(f"以下の操作を実行します:")
            print(f"  - {plan['total_count']}件のメモリを移行")
            print(f"  - embedding_v3（1024次元）を生成")
            print(f"  - embedding_modelを'multilingual-e5-large'に更新")
            print()
            response = input("続行しますか？ (yes/no): ")
            if response.lower() not in ["yes", "y"]:
                print("❌ キャンセルされました")
                return False
            print()

        # 4. バッチ処理
        print("==" * 35)
        print("移行実行")
        print("==" * 35)

        memories = plan["memories"]
        total_batches = plan["batch_count"]

        for i in range(0, len(memories), self.batch_size):
            batch_num = i // self.batch_size + 1
            batch = memories[i : i + self.batch_size]

            success, errors = await self.migrate_batch(
                batch,
                batch_num,
                total_batches,
            )

            self.stats["migrated"] += success
            self.stats["errors"] += errors

        self.stats["end_time"] = datetime.utcnow()

        # 5. サマリー
        await self.print_summary()

        return self.stats["errors"] == 0

    async def print_summary(self):
        """サマリー表示"""
        print()
        print("==" * 35)
        print("移行サマリー")
        print("==" * 35)

        if self.dry_run:
            print("🔍 DRY RUN モード（実際の変更なし）")

        print(f"\n移行統計:")
        print(f"  対象: {self.stats['total']}件")
        print(f"  成功: {self.stats['migrated']}件")
        print(f"  スキップ: {self.stats['skipped']}件")
        print(f"  エラー: {self.stats['errors']}件")

        if self.stats["start_time"] and self.stats["end_time"]:
            duration = (
                self.stats["end_time"] - self.stats["start_time"]
            ).total_seconds()
            print(f"  所要時間: {duration:.2f}秒")

            if self.stats["migrated"] > 0:
                rate = self.stats["migrated"] / duration
                print(f"  処理速度: {rate:.2f}件/秒")

        print()

        if self.stats["errors"] == 0:
            print("✅ 移行完了")
        else:
            print(f"⚠️ 移行完了（{self.stats['errors']}件のエラー）")


async def main():
    """メイン処理"""
    parser = argparse.ArgumentParser(
        description="埋め込み移行: 768次元 → 1024次元"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="バッチサイズ（デフォルト: 100）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="実際の更新を行わずに計画のみ表示",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="エラーが発生しても続行",
    )
    parser.add_argument(
        "--skip-errors",
        action="store_true",
        help="個別のエラーをスキップして続行",
    )

    args = parser.parse_args()

    print()
    print("==" * 35)
    print("TMWS 埋め込み移行スクリプト v2.2.5")
    print("768次元（multilingual-e5-base）→ 1024次元（multilingual-e5-large）")
    print("==" * 35)
    print()

    migrator = EmbeddingMigrator(
        batch_size=args.batch_size,
        dry_run=args.dry_run,
        force=args.force,
        skip_errors=args.skip_errors,
    )

    try:
        success = await migrator.run_migration()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n❌ 中断されました")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ 予期しないエラー: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
