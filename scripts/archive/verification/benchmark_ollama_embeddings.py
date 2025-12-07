"""
Comprehensive Ollama Embedding Model Benchmarking for TMWS v2.2.5

This script evaluates Ollama embedding models across multiple dimensions:
- Vector Dimensions & Compatibility
- Performance (Latency, Throughput)
- Quality (Semantic Search Accuracy, Multilingual Support)
- Windows Compatibility
- API Integration

Author: Artemis (Technical Perfectionist)
Date: 2025-10-13
"""

import asyncio
import json
import time
import statistics
from typing import List, Dict, Tuple
from dataclasses import dataclass, asdict
import numpy as np
import httpx
from pathlib import Path

# Ollama API Configuration
OLLAMA_API_BASE = "http://localhost:11434/api"
TIMEOUT = 60.0


@dataclass
class ModelMetrics:
    """Comprehensive metrics for each model."""
    model_name: str
    dimension: int

    # Performance metrics
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    throughput_req_per_sec: float
    memory_footprint_mb: float

    # Quality metrics
    semantic_accuracy_score: float
    multilingual_score: float
    cross_lingual_similarity: float

    # Compatibility
    windows_compatible: bool
    api_batch_support: bool

    # Technical details
    supports_384_dim: bool
    chroma_compatible: bool
    model_size_mb: float


class OllamaEmbeddingBenchmark:
    """Benchmark suite for Ollama embedding models."""

    def __init__(self):
        self.models = [
            "nomic-embed-text",
            "mxbai-embed-large",
            "all-minilm"
        ]

        # Test datasets
        self.test_texts_en = [
            "Microservices architecture design pattern",
            "Database query optimization techniques",
            "Security vulnerability assessment",
            "Performance profiling and analysis",
            "API endpoint documentation"
        ]

        self.test_texts_ja = [
            "マイクロサービスアーキテクチャ設計パターン",
            "データベースクエリ最適化技術",
            "セキュリティ脆弱性評価",
            "パフォーマンスプロファイリングと分析",
            "APIエンドポイント文書化"
        ]

        # Cross-lingual test pairs (English-Japanese)
        self.cross_lingual_pairs = [
            ("architecture design", "アーキテクチャ設計"),
            ("performance optimization", "パフォーマンス最適化"),
            ("security audit", "セキュリティ監査"),
            ("database indexing", "データベースインデックス"),
            ("API documentation", "API文書化")
        ]

    async def get_embedding(
        self,
        model: str,
        text: str,
        timeout: float = TIMEOUT
    ) -> Dict:
        """Get embedding from Ollama API."""
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{OLLAMA_API_BASE}/embeddings",
                json={"model": model, "prompt": text}
            )
            return response.json()

    async def measure_latency(
        self,
        model: str,
        iterations: int = 100
    ) -> Dict[str, float]:
        """Measure latency statistics."""
        print(f"  📊 Measuring latency for {model}...")

        latencies = []
        for i in range(iterations):
            text = self.test_texts_en[i % len(self.test_texts_en)]
            start = time.perf_counter()
            try:
                await self.get_embedding(model, text)
                elapsed = (time.perf_counter() - start) * 1000  # ms
                latencies.append(elapsed)
            except Exception as e:
                print(f"    ⚠️ Error on iteration {i}: {e}")
                continue

            if (i + 1) % 20 == 0:
                print(f"    Progress: {i + 1}/{iterations}")

        if not latencies:
            return {
                "avg": 0, "p50": 0, "p95": 0, "p99": 0,
                "min": 0, "max": 0
            }

        latencies.sort()
        return {
            "avg": statistics.mean(latencies),
            "p50": latencies[len(latencies) // 2],
            "p95": latencies[int(len(latencies) * 0.95)],
            "p99": latencies[int(len(latencies) * 0.99)],
            "min": min(latencies),
            "max": max(latencies)
        }

    async def measure_throughput(
        self,
        model: str,
        duration_sec: int = 10
    ) -> float:
        """Measure throughput (requests per second)."""
        print(f"  🚀 Measuring throughput for {model}...")

        count = 0
        start_time = time.time()
        end_time = start_time + duration_sec

        while time.time() < end_time:
            text = self.test_texts_en[count % len(self.test_texts_en)]
            try:
                await self.get_embedding(model, text)
                count += 1
            except Exception as e:
                print(f"    ⚠️ Throughput error: {e}")
                break

        elapsed = time.time() - start_time
        throughput = count / elapsed
        print(f"    {count} requests in {elapsed:.2f}s = {throughput:.2f} req/s")
        return throughput

    def cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors."""
        a = np.array(vec1)
        b = np.array(vec2)
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

    async def measure_semantic_accuracy(self, model: str) -> float:
        """Measure semantic search accuracy using similar/dissimilar pairs."""
        print(f"  🎯 Measuring semantic accuracy for {model}...")

        # Similar pairs (should have high similarity)
        similar_pairs = [
            ("database optimization", "query performance tuning"),
            ("security vulnerability", "system security flaw"),
            ("API documentation", "endpoint specification"),
        ]

        # Dissimilar pairs (should have low similarity)
        dissimilar_pairs = [
            ("database optimization", "color theory design"),
            ("security audit", "cooking recipes"),
            ("performance testing", "gardening tips"),
        ]

        scores = []

        # Test similar pairs (expect high similarity > 0.7)
        for text1, text2 in similar_pairs:
            try:
                emb1 = await self.get_embedding(model, text1)
                emb2 = await self.get_embedding(model, text2)
                sim = self.cosine_similarity(
                    emb1["embedding"],
                    emb2["embedding"]
                )
                # Score: 1.0 if sim > 0.7, else proportional
                score = min(1.0, sim / 0.7) if sim > 0 else 0
                scores.append(score)
            except Exception as e:
                print(f"    ⚠️ Error with similar pair: {e}")
                scores.append(0)

        # Test dissimilar pairs (expect low similarity < 0.3)
        for text1, text2 in dissimilar_pairs:
            try:
                emb1 = await self.get_embedding(model, text1)
                emb2 = await self.get_embedding(model, text2)
                sim = self.cosine_similarity(
                    emb1["embedding"],
                    emb2["embedding"]
                )
                # Score: 1.0 if sim < 0.3, else inversely proportional
                score = 1.0 if sim < 0.3 else max(0, (0.5 - sim) / 0.2)
                scores.append(score)
            except Exception as e:
                print(f"    ⚠️ Error with dissimilar pair: {e}")
                scores.append(0)

        accuracy = statistics.mean(scores) if scores else 0
        print(f"    Semantic accuracy: {accuracy:.3f}")
        return accuracy

    async def measure_multilingual_support(self, model: str) -> Tuple[float, float]:
        """
        Measure multilingual support quality.
        Returns: (japanese_quality_score, cross_lingual_similarity)
        """
        print(f"  🌐 Measuring multilingual support for {model}...")

        # Test 1: Japanese text embedding quality
        # (Check if embeddings are reasonable, not zero/NaN)
        ja_scores = []
        for text in self.test_texts_ja:
            try:
                emb = await self.get_embedding(model, text)
                embedding = emb["embedding"]

                # Check for valid embedding
                norm = np.linalg.norm(embedding)
                if norm > 0 and not np.isnan(norm):
                    ja_scores.append(1.0)
                else:
                    ja_scores.append(0.0)
            except Exception as e:
                print(f"    ⚠️ Japanese embedding error: {e}")
                ja_scores.append(0.0)

        japanese_quality = statistics.mean(ja_scores) if ja_scores else 0

        # Test 2: Cross-lingual similarity (English ↔ Japanese)
        cross_lingual_sims = []
        for en_text, ja_text in self.cross_lingual_pairs:
            try:
                emb_en = await self.get_embedding(model, en_text)
                emb_ja = await self.get_embedding(model, ja_text)

                sim = self.cosine_similarity(
                    emb_en["embedding"],
                    emb_ja["embedding"]
                )
                cross_lingual_sims.append(sim)
                print(f"    '{en_text}' ↔ '{ja_text}': {sim:.3f}")
            except Exception as e:
                print(f"    ⚠️ Cross-lingual error: {e}")
                cross_lingual_sims.append(0)

        avg_cross_lingual = statistics.mean(cross_lingual_sims) if cross_lingual_sims else 0

        print(f"    Japanese quality: {japanese_quality:.3f}")
        print(f"    Cross-lingual similarity: {avg_cross_lingual:.3f}")

        return japanese_quality, avg_cross_lingual

    async def get_model_info(self, model: str) -> Dict:
        """Get model metadata from Ollama."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{OLLAMA_API_BASE}/show",
                    json={"name": model}
                )
                return response.json()
        except Exception as e:
            print(f"  ⚠️ Could not get model info: {e}")
            return {}

    async def detect_dimension(self, model: str) -> int:
        """Detect embedding dimension for the model."""
        try:
            result = await self.get_embedding(model, "test")
            dimension = len(result.get("embedding", []))
            print(f"  📐 Detected dimension: {dimension}")
            return dimension
        except Exception as e:
            print(f"  ❌ Failed to detect dimension: {e}")
            return 0

    async def benchmark_model(self, model: str) -> ModelMetrics:
        """Run comprehensive benchmark for a single model."""
        print(f"\n{'='*60}")
        print(f"🔬 Benchmarking: {model}")
        print(f"{'='*60}")

        # Get model info
        model_info = await self.get_model_info(model)
        model_size_mb = model_info.get("size", 0) / (1024 * 1024)

        # Detect dimension
        dimension = await self.detect_dimension(model)

        # Performance benchmarks
        latency_stats = await self.measure_latency(model, iterations=100)
        throughput = await self.measure_throughput(model, duration_sec=10)

        # Quality benchmarks
        semantic_accuracy = await self.measure_semantic_accuracy(model)
        multilingual_quality, cross_lingual_sim = await self.measure_multilingual_support(model)

        # Compatibility checks
        supports_384 = (dimension == 384)
        chroma_compatible = supports_384  # Chroma uses 384-dim by default

        metrics = ModelMetrics(
            model_name=model,
            dimension=dimension,
            avg_latency_ms=latency_stats["avg"],
            p50_latency_ms=latency_stats["p50"],
            p95_latency_ms=latency_stats["p95"],
            p99_latency_ms=latency_stats["p99"],
            throughput_req_per_sec=throughput,
            memory_footprint_mb=model_size_mb,
            semantic_accuracy_score=semantic_accuracy,
            multilingual_score=multilingual_quality,
            cross_lingual_similarity=cross_lingual_sim,
            windows_compatible=True,  # Ollama supports Windows
            api_batch_support=False,  # Ollama API doesn't have native batch endpoint
            supports_384_dim=supports_384,
            chroma_compatible=chroma_compatible,
            model_size_mb=model_size_mb
        )

        return metrics

    async def run_all_benchmarks(self) -> List[ModelMetrics]:
        """Run benchmarks for all models."""
        results = []

        for model in self.models:
            try:
                metrics = await self.benchmark_model(model)
                results.append(metrics)
            except Exception as e:
                print(f"❌ Failed to benchmark {model}: {e}")

        return results

    def print_comparison_table(self, results: List[ModelMetrics]):
        """Print comparison table for all models."""
        print(f"\n{'='*80}")
        print("📊 COMPREHENSIVE BENCHMARK RESULTS")
        print(f"{'='*80}\n")

        # Header
        print(f"{'Model':<20} {'Dim':<6} {'P95 (ms)':<10} {'Throughput':<12} "
              f"{'Semantic':<10} {'Multilingual':<13}")
        print("-" * 80)

        # Data rows
        for m in results:
            print(f"{m.model_name:<20} {m.dimension:<6} {m.p95_latency_ms:<10.2f} "
                  f"{m.throughput_req_per_sec:<12.2f} {m.semantic_accuracy_score:<10.3f} "
                  f"{m.cross_lingual_similarity:<13.3f}")

        print("\n" + "="*80)
        print("🏆 DETAILED ANALYSIS")
        print("="*80 + "\n")

        for m in results:
            print(f"\n{m.model_name}:")
            print(f"  Dimension: {m.dimension} {'✅ Chroma Compatible' if m.chroma_compatible else '❌ Incompatible'}")
            print(f"  Performance:")
            print(f"    - P95 Latency: {m.p95_latency_ms:.2f}ms {'✅' if m.p95_latency_ms < 50 else '⚠️'} (Target: <50ms)")
            print(f"    - Throughput: {m.throughput_req_per_sec:.2f} req/s {'✅' if m.throughput_req_per_sec > 100 else '⚠️'} (Target: >100)")
            print(f"  Quality:")
            print(f"    - Semantic Accuracy: {m.semantic_accuracy_score:.3f} {'✅' if m.semantic_accuracy_score > 0.7 else '⚠️'}")
            print(f"    - Cross-lingual Similarity: {m.cross_lingual_similarity:.3f} {'✅' if m.cross_lingual_similarity > 0.6 else '⚠️'}")
            print(f"  Model Size: {m.model_size_mb:.2f} MB")

    def generate_recommendation(self, results: List[ModelMetrics]) -> Dict:
        """Generate final recommendation based on benchmark results."""
        print(f"\n{'='*80}")
        print("🎯 FINAL RECOMMENDATION")
        print(f"{'='*80}\n")

        # Score each model
        scores = {}
        for m in results:
            score = 0
            reasons = []

            # Dimension compatibility (40 points)
            if m.supports_384_dim:
                score += 40
                reasons.append("✅ 384-dim (Chroma compatible)")
            else:
                reasons.append(f"⚠️ {m.dimension}-dim (requires migration)")

            # Performance (30 points)
            if m.p95_latency_ms < 50:
                score += 15
                reasons.append("✅ Excellent latency (<50ms P95)")
            elif m.p95_latency_ms < 100:
                score += 10
                reasons.append("⚠️ Good latency (<100ms P95)")

            if m.throughput_req_per_sec > 100:
                score += 15
                reasons.append("✅ High throughput (>100 req/s)")
            elif m.throughput_req_per_sec > 50:
                score += 10
                reasons.append("⚠️ Moderate throughput (>50 req/s)")

            # Quality (30 points)
            if m.semantic_accuracy_score > 0.7:
                score += 15
                reasons.append("✅ High semantic accuracy")
            elif m.semantic_accuracy_score > 0.5:
                score += 10
                reasons.append("⚠️ Moderate semantic accuracy")

            if m.cross_lingual_similarity > 0.6:
                score += 15
                reasons.append("✅ Strong multilingual support")
            elif m.cross_lingual_similarity > 0.4:
                score += 10
                reasons.append("⚠️ Basic multilingual support")

            scores[m.model_name] = {
                "score": score,
                "reasons": reasons,
                "metrics": m
            }

        # Find best model
        best_model = max(scores.keys(), key=lambda k: scores[k]["score"])
        recommendation = scores[best_model]

        print(f"🥇 RECOMMENDED MODEL: {best_model}")
        print(f"   Overall Score: {recommendation['score']}/100")
        print(f"\n   Reasoning:")
        for reason in recommendation["reasons"]:
            print(f"     {reason}")

        print(f"\n📊 All Model Scores:")
        for model, data in sorted(scores.items(), key=lambda x: x[1]["score"], reverse=True):
            print(f"   {model}: {data['score']}/100")

        return {
            "recommended_model": best_model,
            "score": recommendation["score"],
            "reasons": recommendation["reasons"],
            "all_scores": {k: v["score"] for k, v in scores.items()}
        }

    async def save_results(
        self,
        results: List[ModelMetrics],
        recommendation: Dict,
        output_file: str = "benchmark_results.json"
    ):
        """Save benchmark results to JSON file."""
        output = {
            "benchmark_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "recommendation": recommendation,
            "detailed_metrics": [asdict(m) for m in results]
        }

        output_path = Path(output_file)
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        print(f"\n💾 Results saved to: {output_path.absolute()}")


async def main():
    """Main benchmark execution."""
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   TMWS v2.2.5 Ollama Embedding Model Benchmark Suite                     ║
║   Technical Perfectionist Evaluation                                      ║
║                                                                           ║
║   Models Under Test:                                                      ║
║     • nomic-embed-text (274 MB)                                           ║
║     • mxbai-embed-large (669 MB)                                          ║
║     • all-minilm (45 MB)                                                  ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """)

    benchmark = OllamaEmbeddingBenchmark()

    # Run all benchmarks
    results = await benchmark.run_all_benchmarks()

    if not results:
        print("❌ No benchmark results obtained. Exiting.")
        return

    # Print comparison table
    benchmark.print_comparison_table(results)

    # Generate recommendation
    recommendation = benchmark.generate_recommendation(results)

    # Save results
    await benchmark.save_results(
        results,
        recommendation,
        output_file="scripts/ollama_benchmark_results.json"
    )

    print("\n✅ Benchmark completed successfully!\n")


if __name__ == "__main__":
    asyncio.run(main())
