
"""
Embedding generation utilities for TMWS semantic search.
Artemis's optimized vector embedding service.
"""

import logging
import math
import os
from functools import lru_cache
from typing import List

import numpy as np

logger = logging.getLogger(__name__)

# Global model instance for efficient reuse
_embedding_model = None


def _get_embedding_model():
    """Get or initialize the embedding model."""
    global _embedding_model

    if _embedding_model is None:
        try:
            # Try to import sentence-transformers
            from sentence_transformers import SentenceTransformer

            # Use a lightweight, efficient model for semantic search
            model_name = os.getenv("TMWS_EMBEDDING_MODEL", "all-MiniLM-L6-v2")

            logger.info(f"Loading embedding model: {model_name}")
            _embedding_model = SentenceTransformer(model_name)
            logger.info(f"Embedding model loaded successfully. Dimension: {_embedding_model.get_sentence_embedding_dimension()}")

        except ImportError:
            logger.warning("sentence-transformers not available, using fallback implementation")
            _embedding_model = "fallback"
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            _embedding_model = "fallback"

    return _embedding_model


@lru_cache(maxsize=1000)
def get_embedding(text: str) -> List[float]:
    """
    Generate embedding vector for text.

    Args:
        text: Input text to embed

    Returns:
        List[float]: 384-dimensional embedding vector

    Note:
        Results are cached for performance. Uses sentence-transformers
        if available, otherwise falls back to simple hash-based vectors.
    """
    if not text or not text.strip():
        # Return zero vector for empty text
        return [0.0] * 384

    model = _get_embedding_model()

    if model == "fallback":
        # Simple fallback using text hash and basic features
        return _fallback_embedding(text)

    try:
        # Generate embedding using sentence-transformers
        embedding = model.encode(text.strip(), convert_to_numpy=True)

        # Ensure consistent dimension (384 for all-MiniLM-L6-v2)
        if len(embedding) != 384:
            logger.warning(f"Unexpected embedding dimension: {len(embedding)}, padding/truncating to 384")
            if len(embedding) > 384:
                embedding = embedding[:384]
            else:
                embedding = np.pad(embedding, (0, 384 - len(embedding)), mode='constant')

        return embedding.tolist()

    except Exception as e:
        logger.error(f"Embedding generation failed: {e}, using fallback")
        return _fallback_embedding(text)


def _fallback_embedding(text: str) -> List[float]:
    """
    Fallback embedding generation when sentence-transformers is unavailable.

    Creates a deterministic but less sophisticated embedding based on:
    - Text hash for consistency
    - Basic text features (length, character distribution)
    - Simple n-gram analysis
    """
    import hashlib

    # Normalize text
    text = text.lower().strip()

    # Base hash for deterministic starting point
    text_hash = int(hashlib.md5(text.encode()).hexdigest(), 16)

    # Initialize vector
    vector = [0.0] * 384

    # Hash-based pseudo-random values
    np.random.seed(text_hash % (2**32))
    base_vector = np.random.normal(0, 0.1, 384)

    # Text features
    text_len = len(text)
    word_count = len(text.split())
    char_diversity = len(set(text)) / max(len(text), 1)

    # Feature scaling
    len_feature = math.tanh(text_len / 100.0)  # Normalize length
    word_feature = math.tanh(word_count / 50.0)  # Normalize word count

    # Apply features to vector
    for i in range(384):
        # Combine hash-based value with text features
        vector[i] = base_vector[i] + (
            len_feature * math.sin(i * 0.1) * 0.1 +
            word_feature * math.cos(i * 0.1) * 0.1 +
            char_diversity * math.sin(i * 0.2) * 0.05
        )

    # Normalize vector (unit length)
    norm = math.sqrt(sum(x*x for x in vector))
    if norm > 0:
        vector = [x / norm for x in vector]

    return vector


def get_embeddings_batch(texts: List[str]) -> List[List[float]]:
    """
    Generate embeddings for multiple texts efficiently.

    Args:
        texts: List of input texts

    Returns:
        List[List[float]]: List of embedding vectors
    """
    if not texts:
        return []

    model = _get_embedding_model()

    if model == "fallback":
        return [get_embedding(text) for text in texts]

    try:
        # Batch processing for efficiency
        embeddings = model.encode(texts, convert_to_numpy=True, show_progress_bar=False)

        # Ensure consistent dimensions
        result = []
        for embedding in embeddings:
            if len(embedding) != 384:
                if len(embedding) > 384:
                    embedding = embedding[:384]
                else:
                    embedding = np.pad(embedding, (0, 384 - len(embedding)), mode='constant')
            result.append(embedding.tolist())

        return result

    except Exception as e:
        logger.error(f"Batch embedding generation failed: {e}, using individual fallback")
        return [get_embedding(text) for text in texts]


def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """
    Calculate cosine similarity between two vectors.

    Args:
        vec1, vec2: Embedding vectors

    Returns:
        float: Cosine similarity (-1 to 1)
    """
    if len(vec1) != len(vec2):
        raise ValueError("Vectors must have same dimension")

    # Calculate dot product and norms
    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = math.sqrt(sum(a * a for a in vec1))
    norm2 = math.sqrt(sum(b * b for b in vec2))

    # Avoid division by zero
    if norm1 == 0 or norm2 == 0:
        return 0.0

    return dot_product / (norm1 * norm2)


def embedding_dimension() -> int:
    """Get the embedding vector dimension."""
    return 384


def clear_embedding_cache():
    """Clear the LRU cache for embeddings."""
    get_embedding.cache_clear()
    logger.info("Embedding cache cleared")


# Model information
def get_model_info() -> dict:
    """Get information about the current embedding model."""
    model = _get_embedding_model()

    if model == "fallback":
        return {
            "model_type": "fallback",
            "model_name": "hash_based_fallback",
            "dimension": 384,
            "description": "Simple hash-based fallback embedding"
        }

    try:
        return {
            "model_type": "sentence_transformer",
            "model_name": getattr(model, 'model_name', 'unknown'),
            "dimension": model.get_sentence_embedding_dimension(),
            "description": "SentenceTransformer-based semantic embedding"
        }
    except Exception:
        return {
            "model_type": "unknown",
            "model_name": "unknown",
            "dimension": 384,
            "description": "Unknown model configuration"
        }
