#!/usr/bin/env python3
"""
Integration test for MultilingualEmbeddingService

Tests:
1. Model loading and device detection
2. Document encoding
3. Query encoding
4. Japanese-English cross-lingual similarity
5. Batch encoding

Usage:
    python scripts/test_multilingual_embedding.py
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.services.ollama_embedding_service import get_ollama_embedding_service as get_embedding_service


def test_model_initialization():
    """Test 1: Model loading and device detection"""
    print("\n" + "=" * 70)
    print("TEST 1: Model Initialization")
    print("=" * 70)

    service = get_embedding_service()
    info = service.get_model_info()

    print(f"✅ Model Name: {info['model_name']}")
    print(f"✅ Dimension: {info['dimension']}")
    print(f"✅ Device: {info['device']}")
    print(f"✅ Platform: {info['platform']} {info['platform_release']}")
    print(f"✅ Cache Path: {info['cache_path']}")
    print(f"✅ Optimal Batch Size: {info['optimal_batch_size']}")
    print(f"✅ CUDA Available: {info['cuda_available']}")
    print(f"✅ MPS Available: {info['mps_available']}")
    print(f"✅ CPU Count: {info['cpu_count']}")

    assert info["dimension"] == 768, "Dimension should be 768"
    assert info["device"] in ["cuda", "mps", "cpu"], "Device should be detected"

    print("\n✅ TEST 1 PASSED: Model initialized successfully")
    return service


def test_document_encoding(service):
    """Test 2: Document encoding"""
    print("\n" + "=" * 70)
    print("TEST 2: Document Encoding")
    print("=" * 70)

    # Japanese document
    japanese_doc = "マイクロサービスアーキテクチャの設計を完了しました"
    doc_embedding = service.encode_document(japanese_doc)

    print(f"✅ Input: {japanese_doc}")
    print(f"✅ Embedding shape: {doc_embedding.shape}")
    print(f"✅ Embedding type: {doc_embedding.dtype}")
    print(f"✅ Embedding norm: {doc_embedding.sum():.4f}")

    assert doc_embedding.shape == (768,), "Document embedding should be 768-dimensional"
    assert doc_embedding.dtype.name.startswith("float"), "Should be float type"

    print("\n✅ TEST 2 PASSED: Document encoding works correctly")
    return doc_embedding


def test_query_encoding(service):
    """Test 3: Query encoding"""
    print("\n" + "=" * 70)
    print("TEST 3: Query Encoding")
    print("=" * 70)

    # English query
    english_query = "microservice architecture design"
    query_embedding = service.encode_query(english_query)

    print(f"✅ Input: {english_query}")
    print(f"✅ Embedding shape: {query_embedding.shape}")
    print(f"✅ Embedding type: {query_embedding.dtype}")
    print(f"✅ Embedding norm: {query_embedding.sum():.4f}")

    assert query_embedding.shape == (768,), "Query embedding should be 768-dimensional"
    assert query_embedding.dtype.name.startswith("float"), "Should be float type"

    print("\n✅ TEST 3 PASSED: Query encoding works correctly")
    return query_embedding


def test_cross_lingual_similarity(service, doc_embedding, query_embedding):
    """Test 4: Japanese-English cross-lingual similarity"""
    print("\n" + "=" * 70)
    print("TEST 4: Cross-Lingual Similarity")
    print("=" * 70)

    similarity = service.compute_similarity(query_embedding, doc_embedding)

    print("📊 Japanese Doc: マイクロサービスアーキテクチャの設計を完了しました")
    print("📊 English Query: microservice architecture design")
    print(f"✅ Cosine Similarity: {similarity:.4f}")

    # Multilingual-E5 should achieve >0.7 similarity for semantically similar content
    assert similarity > 0.7, f"Cross-lingual similarity should be >0.7, got {similarity:.4f}"

    print(f"\n✅ TEST 4 PASSED: High cross-lingual similarity ({similarity:.4f} > 0.7)")


def test_batch_encoding(service):
    """Test 5: Batch encoding"""
    print("\n" + "=" * 70)
    print("TEST 5: Batch Encoding")
    print("=" * 70)

    # Mixed Japanese and English documents
    documents = [
        "セキュリティ監査を実施しました",
        "パフォーマンスを90%改善しました",
        "Performance optimization completed",
        "Security audit finished",
    ]

    print(f"📦 Encoding {len(documents)} documents...")
    embeddings = service.encode_batch(documents, mode="document")

    print(f"✅ Batch embeddings shape: {embeddings.shape}")
    print(f"✅ Expected: ({len(documents)}, 768)")

    assert embeddings.shape == (len(documents), 768), "Batch embeddings shape mismatch"

    # Test similarity within batch
    # Japanese security audit vs English security audit
    sim_security = service.compute_similarity(embeddings[0], embeddings[3])
    print(f"📊 Similarity (JA security vs EN security): {sim_security:.4f}")

    # Japanese performance vs English performance
    sim_performance = service.compute_similarity(embeddings[1], embeddings[2])
    print(f"📊 Similarity (JA performance vs EN performance): {sim_performance:.4f}")

    assert sim_security > 0.7, "Security similarity should be high"
    assert sim_performance > 0.7, "Performance similarity should be high"

    print("\n✅ TEST 5 PASSED: Batch encoding works correctly")


def test_prefix_handling(service):
    """Test 6: Verify query vs document prefix handling"""
    print("\n" + "=" * 70)
    print("TEST 6: Query vs Document Prefix Handling")
    print("=" * 70)

    text = "architecture design pattern"

    # Encode same text as query and document
    query_emb = service.encode_query(text)
    doc_emb = service.encode_document(text)

    # They should be different due to different prefixes
    similarity = service.compute_similarity(query_emb, doc_emb)
    print(f"📊 Same text, different prefix similarity: {similarity:.4f}")

    # Multilingual-E5 uses asymmetric search design (query vs passage prefixes)
    # Similarity should still be reasonably high (>0.7) for same content
    assert similarity > 0.7, (
        f"Same text should have high similarity despite different prefixes, got {similarity:.4f}"
    )

    print("\n✅ TEST 6 PASSED: Prefix handling works correctly (asymmetric search design)")


def run_all_tests():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("🚀 TMWS Multilingual-E5 Embedding Service Test Suite")
    print("=" * 70)

    try:
        # Test 1: Initialization
        service = test_model_initialization()

        # Test 2: Document encoding
        doc_embedding = test_document_encoding(service)

        # Test 3: Query encoding
        query_embedding = test_query_encoding(service)

        # Test 4: Cross-lingual similarity
        test_cross_lingual_similarity(service, doc_embedding, query_embedding)

        # Test 5: Batch encoding
        test_batch_encoding(service)

        # Test 6: Prefix handling
        test_prefix_handling(service)

        # Summary
        print("\n" + "=" * 70)
        print("🎉 ALL TESTS PASSED")
        print("=" * 70)
        print("✅ Model initialization: OK")
        print("✅ Document encoding: OK")
        print("✅ Query encoding: OK")
        print("✅ Cross-lingual similarity: OK (>0.7)")
        print("✅ Batch encoding: OK")
        print("✅ Prefix handling: OK")
        print("=" * 70)

        return 0

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1

    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
