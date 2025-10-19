"""
Multilingual Embedding Service for TMWS v2.2.6 - Internal Implementation
Provides cross-platform support for Multilingual-E5 embeddings with Japanese-English capabilities.

⚠️ INTERNAL USE ONLY
This module is an internal implementation detail used by UnifiedEmbeddingService.
For embedding operations, use:
    from src.services import get_embedding_service

This will automatically use the best available provider (Ollama → SentenceTransformers).
"""

import logging
import os
import platform
from pathlib import Path
from typing import Literal

import numpy as np
import torch
from sentence_transformers import SentenceTransformer

from ..core.config import get_settings

logger = logging.getLogger(__name__)


class MultilingualEmbeddingService:
    """
    Cross-platform embedding service using intfloat/multilingual-e5-base.

    Features:
    - Supports Japanese-English cross-lingual semantic search
    - Automatic device detection (CUDA/MPS/CPU)
    - Platform-specific optimizations (Windows/macOS/Linux)
    - Query/Document prefix handling for optimal similarity
    - 768-dimensional embeddings (vs 384 for all-MiniLM-L6-v2)

    Usage:
        service = MultilingualEmbeddingService()

        # Encode documents (for storage)
        doc_embedding = service.encode_document("重要な設計決定")

        # Encode queries (for search)
        query_embedding = service.encode_query("architecture decision")

        # Cross-lingual similarity
        similarity = service.compute_similarity(query_embedding, doc_embedding)
    """

    MODEL_NAME = "intfloat/multilingual-e5-base"
    DIMENSION = 768

    # Singleton instance
    _instance = None
    _model = None
    _device = None

    def __new__(cls):
        """Singleton pattern for model reuse."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the embedding service with platform detection."""
        if self._model is None:
            self._initialize_model()

    def _initialize_model(self):
        """Initialize model with device detection and platform optimizations."""
        get_settings()

        # Detect optimal device
        self._device = self._detect_device()
        logger.info(f"🚀 Initializing Multilingual-E5 on device: {self._device}")

        # Platform-specific optimizations
        self._apply_platform_optimizations()

        # Load model
        cache_folder = self._get_cache_path()
        logger.info(f"📦 Cache directory: {cache_folder}")

        try:
            self._model = SentenceTransformer(
                self.MODEL_NAME, device=self._device, cache_folder=str(cache_folder)
            )
            logger.info(f"✅ Multilingual-E5 loaded successfully (dimension: {self.DIMENSION})")
        except Exception as e:
            logger.error(f"❌ Failed to load Multilingual-E5: {e}")
            raise

    def _detect_device(self) -> str:
        """
        Detect optimal device for inference.

        Priority: CUDA > MPS (Apple Silicon) > CPU

        Returns:
            Device string: "cuda", "mps", or "cpu"
        """
        # CUDA (NVIDIA GPU)
        if torch.cuda.is_available():
            device = "cuda"
            gpu_name = torch.cuda.get_device_name(0)
            logger.info(f"🎮 CUDA detected: {gpu_name}")
            return device

        # MPS (Apple Silicon M1/M2)
        if torch.backends.mps.is_available():
            device = "mps"
            logger.info("🍎 Apple MPS (Metal Performance Shaders) detected")
            return device

        # CPU fallback
        device = "cpu"
        cpu_count = os.cpu_count() or 1
        logger.info(f"💻 CPU mode: {cpu_count} cores available")
        return device

    def _apply_platform_optimizations(self):
        """Apply platform-specific optimizations."""
        system = platform.system()

        if system == "Windows":
            # Windows-specific: Limit threads to prevent crashes
            max_threads = min(8, os.cpu_count() or 4)
            torch.set_num_threads(max_threads)
            logger.info(f"🪟 Windows optimization: Limited to {max_threads} threads")

        elif system == "Darwin":  # macOS
            # macOS-specific: Optimize for Apple Silicon
            if self._device == "mps":
                logger.info("🍎 macOS Apple Silicon optimization enabled")

        elif system == "Linux":
            # Linux-specific: Use all available cores
            torch.set_num_threads(os.cpu_count() or 4)
            logger.info(f"🐧 Linux optimization: Using all {os.cpu_count()} threads")

    def _get_cache_path(self) -> Path:
        """
        Get platform-appropriate cache directory.

        Returns:
            Path to cache directory
        """
        system = platform.system()

        if system == "Windows":
            # Windows: Use short path to avoid MAX_PATH issues
            cache_path = Path("C:/tmws_cache/models")
        elif system == "Darwin":  # macOS
            cache_path = Path.home() / ".cache" / "tmws" / "models"
        else:  # Linux
            cache_path = Path.home() / ".cache" / "tmws" / "models"

        # Create directory if it doesn't exist
        cache_path.mkdir(parents=True, exist_ok=True)
        return cache_path

    def _get_batch_size(self) -> int:
        """
        Determine optimal batch size based on device.

        Returns:
            Optimal batch size for current device
        """
        if self._device == "cuda":
            return 64  # High throughput for GPU
        elif self._device == "mps":
            return 32  # Moderate for Apple Silicon
        else:  # CPU
            return 16  # Conservative for CPU

    def encode_document(
        self, text: str | list[str], normalize: bool = True, batch_size: int | None = None
    ) -> np.ndarray:
        """
        Encode document(s) for storage with "passage:" prefix.

        Args:
            text: Document text(s) to encode
            normalize: Whether to L2-normalize embeddings (recommended for cosine similarity)
            batch_size: Batch size (uses optimal default if None)

        Returns:
            Numpy array of embeddings (768 dimensions)
            - Single text: shape (768,)
            - Multiple texts: shape (n, 768)

        Example:
            >>> service = MultilingualEmbeddingService()
            >>> embedding = service.encode_document("マイクロサービス設計完了")
            >>> embedding.shape
            (768,)
        """
        # Add "passage:" prefix for documents
        single_input = isinstance(text, str)
        prefixed_text = [f"passage: {text}"] if single_input else [f"passage: {t}" for t in text]

        # Encode with optimal batch size
        batch_size = batch_size or self._get_batch_size()

        embeddings = self._model.encode(
            prefixed_text,
            normalize_embeddings=normalize,
            batch_size=batch_size,
            show_progress_bar=False,
            convert_to_numpy=True,
        )

        # Return single embedding if single input
        if single_input:
            return embeddings[0]

        return embeddings

    def encode_query(
        self, text: str | list[str], normalize: bool = True, batch_size: int | None = None
    ) -> np.ndarray:
        """
        Encode query text(s) for search with "query:" prefix.

        Args:
            text: Query text(s) to encode
            normalize: Whether to L2-normalize embeddings (recommended for cosine similarity)
            batch_size: Batch size (uses optimal default if None)

        Returns:
            Numpy array of embeddings (768 dimensions)
            - Single text: shape (768,)
            - Multiple texts: shape (n, 768)

        Example:
            >>> service = MultilingualEmbeddingService()
            >>> query_emb = service.encode_query("architecture decision")
            >>> query_emb.shape
            (768,)
        """
        # Add "query:" prefix for queries
        single_input = isinstance(text, str)
        prefixed_text = [f"query: {text}"] if single_input else [f"query: {t}" for t in text]

        # Encode with optimal batch size
        batch_size = batch_size or self._get_batch_size()

        embeddings = self._model.encode(
            prefixed_text,
            normalize_embeddings=normalize,
            batch_size=batch_size,
            show_progress_bar=False,
            convert_to_numpy=True,
        )

        # Return single embedding if single input
        if single_input:
            return embeddings[0]

        return embeddings

    def encode_batch(
        self,
        texts: list[str],
        mode: Literal["document", "query"] = "document",
        batch_size: int | None = None,
        show_progress: bool = False,
    ) -> np.ndarray:
        """
        Encode a batch of texts efficiently.

        Args:
            texts: List of texts to encode
            mode: "document" for storage, "query" for search
            batch_size: Batch size (uses optimal default if None)
            show_progress: Whether to show progress bar

        Returns:
            Numpy array of shape (n, 768)

        Example:
            >>> service = MultilingualEmbeddingService()
            >>> docs = ["文書1", "文書2", "文書3"]
            >>> embeddings = service.encode_batch(docs, mode="document")
            >>> embeddings.shape
            (3, 768)
        """
        if not texts:
            return np.array([])

        # Add appropriate prefix
        prefix = "passage: " if mode == "document" else "query: "
        prefixed_texts = [f"{prefix}{t}" for t in texts]

        # Encode with optimal batch size
        batch_size = batch_size or self._get_batch_size()

        embeddings = self._model.encode(
            prefixed_texts,
            normalize_embeddings=True,
            batch_size=batch_size,
            show_progress_bar=show_progress,
            convert_to_numpy=True,
        )

        logger.info(f"✅ Encoded {len(texts)} texts ({mode} mode) in batches of {batch_size}")

        return embeddings

    def compute_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """
        Compute cosine similarity between two embeddings.

        Args:
            embedding1: First embedding (768,)
            embedding2: Second embedding (768,)

        Returns:
            Cosine similarity score (-1 to 1, typically 0.5-1.0 for Multilingual-E5)

        Example:
            >>> query_emb = service.encode_query("architecture")
            >>> doc_emb = service.encode_document("アーキテクチャ設計")
            >>> similarity = service.compute_similarity(query_emb, doc_emb)
            >>> similarity > 0.85  # High cross-lingual similarity
            True
        """
        # Normalize if not already normalized
        norm1 = embedding1 / (np.linalg.norm(embedding1) + 1e-9)
        norm2 = embedding2 / (np.linalg.norm(embedding2) + 1e-9)

        # Compute cosine similarity
        similarity = float(np.dot(norm1, norm2))

        return similarity

    def get_model_info(self) -> dict:
        """
        Get information about the current model and device.

        Returns:
            Dictionary with model information
        """
        return {
            "model_name": self.MODEL_NAME,
            "dimension": self.DIMENSION,
            "device": self._device,
            "platform": platform.system(),
            "platform_release": platform.release(),
            "cache_path": str(self._get_cache_path()),
            "optimal_batch_size": self._get_batch_size(),
            "cuda_available": torch.cuda.is_available(),
            "mps_available": torch.backends.mps.is_available(),
            "cpu_count": os.cpu_count(),
        }


# Singleton instance for easy access
_embedding_service_instance = None


def get_embedding_service() -> MultilingualEmbeddingService:
    """
    Get singleton instance of MultilingualEmbeddingService.

    Returns:
        Singleton instance of the embedding service

    Example:
        >>> from src.services.embedding_service import get_embedding_service
        >>> service = get_embedding_service()
        >>> embedding = service.encode_document("テストドキュメント")
    """
    global _embedding_service_instance

    if _embedding_service_instance is None:
        _embedding_service_instance = MultilingualEmbeddingService()

    return _embedding_service_instance
