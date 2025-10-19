#!/usr/bin/env python3
"""
Unified Embedding Service for TMWS v2.2.5

Provides automatic provider selection and management:
- Ollama (primary for Windows compatibility)
- SentenceTransformers (stable fallback)
- Automatic failover and recovery

Configuration-based provider selection:
- "auto": Try Ollama, fallback to SentenceTransformers
- "ollama": Ollama only (fail if unavailable)
- "sentence-transformers": SentenceTransformers only
"""

import logging
from typing import Protocol

import numpy as np

from ..core.config import get_settings

logger = logging.getLogger(__name__)


class EmbeddingProvider(Protocol):
    """
    Protocol defining the embedding provider interface.

    All embedding providers must implement these methods.
    """

    async def encode_document(
        self,
        text: str | list[str],
        normalize: bool = True,
        batch_size: int = 32,
    ) -> np.ndarray:
        """Encode document(s) for storage."""
        ...

    async def encode_query(
        self,
        text: str | list[str],
        normalize: bool = True,
        batch_size: int = 32,
    ) -> np.ndarray:
        """Encode query for retrieval."""
        ...

    def get_model_info(self) -> dict:
        """Get model metadata."""
        ...


class UnifiedEmbeddingService:
    """
    Unified embedding service with automatic provider selection.

    Provider Selection Logic:
    - "auto": Ollama (if available) → SentenceTransformers (fallback)
    - "ollama": Ollama only (fail if unavailable)
    - "sentence-transformers": SentenceTransformers only

    Usage:
        service = UnifiedEmbeddingService()

        # Automatically uses best available provider
        embedding = await service.encode_document("text")

        # Check active provider
        info = service.get_model_info()
        print(f"Using: {info['provider']}")
    """

    def __init__(self, force_provider: str | None = None):
        """
        Initialize unified embedding service.

        Args:
            force_provider: Override config provider selection
                ("ollama", "sentence-transformers", or None for config)
        """
        self.settings = get_settings()
        self._provider: EmbeddingProvider | None = None
        self._provider_type: str | None = None

        # Initialize provider
        provider_type = force_provider or self.settings.embedding_provider
        self._initialize_provider(provider_type)

    def _initialize_provider(self, provider_type: str) -> None:
        """
        Initialize embedding provider based on type.

        Args:
            provider_type: Provider type ("auto", "ollama", "sentence-transformers")
        """
        logger.info(f"🔧 Initializing embedding provider: {provider_type}")

        if provider_type == "sentence-transformers":
            self._init_sentence_transformers()

        elif provider_type == "ollama":
            self._init_ollama(fallback_enabled=False)

        elif provider_type == "auto":
            self._init_ollama(fallback_enabled=True)

        else:
            raise ValueError(
                f"Invalid provider type: {provider_type}. "
                f"Must be 'auto', 'ollama', or 'sentence-transformers'"
            )

    def _init_sentence_transformers(self) -> None:
        """Initialize SentenceTransformers provider."""
        from .embedding_service import get_embedding_service

        self._provider = get_embedding_service()
        self._provider_type = "sentence-transformers"

        logger.info("✅ SentenceTransformers provider initialized")

    def _init_ollama(self, fallback_enabled: bool) -> None:
        """
        Initialize Ollama provider with optional fallback.

        Args:
            fallback_enabled: Enable automatic fallback to SentenceTransformers
        """
        from .ollama_embedding_service import OllamaEmbeddingService

        self._provider = OllamaEmbeddingService(
            ollama_base_url=self.settings.ollama_base_url,
            model_name=self.settings.ollama_embedding_model,
            fallback_enabled=fallback_enabled,
            timeout=self.settings.ollama_timeout,
        )

        model_info = self._provider.get_model_info()

        if model_info["ollama_available"]:
            self._provider_type = "ollama"
            logger.info(f"✅ Ollama provider initialized: {model_info['model_name']}")
        elif fallback_enabled:
            self._provider_type = "sentence-transformers (fallback)"
            logger.warning("⚠️ Ollama unavailable, using SentenceTransformers fallback")
        else:
            raise RuntimeError(
                f"Ollama server not available at {self.settings.ollama_base_url} "
                f"and fallback is disabled"
            )

    async def encode_document(
        self,
        text: str | list[str],
        normalize: bool = True,
        batch_size: int = 32,
    ) -> np.ndarray:
        """
        Encode document(s) for storage/indexing.

        Args:
            text: Single text or list of texts to encode
            normalize: Normalize embeddings to unit length
            batch_size: Batch size for processing

        Returns:
            Embedding array (1D for single text, 2D for multiple)
        """
        if self._provider is None:
            raise RuntimeError("Embedding provider not initialized")

        return await self._provider.encode_document(
            text=text,
            normalize=normalize,
            batch_size=batch_size,
        )

    async def encode_query(
        self,
        text: str | list[str],
        normalize: bool = True,
        batch_size: int = 32,
    ) -> np.ndarray:
        """
        Encode query/question for retrieval.

        Args:
            text: Single query or list of queries to encode
            normalize: Normalize embeddings to unit length
            batch_size: Batch size for processing

        Returns:
            Embedding array (1D for single query, 2D for multiple)
        """
        if self._provider is None:
            raise RuntimeError("Embedding provider not initialized")

        return await self._provider.encode_query(
            text=text,
            normalize=normalize,
            batch_size=batch_size,
        )

    def get_model_info(self) -> dict:
        """
        Get information about the active embedding model.

        Returns:
            Dictionary with model metadata including:
            - provider: Active provider name
            - model_name: Model identifier
            - dimension: Embedding dimension
            - Additional provider-specific info
        """
        if self._provider is None:
            return {"provider": "none", "error": "Not initialized"}

        info = self._provider.get_model_info()
        info["provider_type"] = self._provider_type

        return info

    async def get_dimension(self) -> int:
        """
        Get the embedding dimension.

        Returns:
            Embedding dimension size
        """
        if hasattr(self._provider, "get_dimension"):
            return await self._provider.get_dimension()

        # Fallback: detect from test encoding
        test_embedding = await self.encode_query("test", normalize=False)
        return test_embedding.shape[0]

    def is_ollama_active(self) -> bool:
        """
        Check if Ollama provider is currently active.

        Returns:
            True if Ollama is the active provider
        """
        return self._provider_type == "ollama"

    def get_provider_type(self) -> str:
        """
        Get the current provider type.

        Returns:
            Provider type string
        """
        return self._provider_type or "unknown"


# Singleton instance
_unified_service_instance = None


def get_unified_embedding_service() -> UnifiedEmbeddingService:
    """
    Get singleton instance of UnifiedEmbeddingService.

    Returns:
        Shared UnifiedEmbeddingService instance
    """
    global _unified_service_instance

    if _unified_service_instance is None:
        _unified_service_instance = UnifiedEmbeddingService()

    return _unified_service_instance


# Convenience functions for backward compatibility
async def encode_document(
    text: str | list[str],
    normalize: bool = True,
) -> np.ndarray:
    """
    Encode document using unified service.

    Args:
        text: Text(s) to encode
        normalize: Normalize embeddings

    Returns:
        Embedding array
    """
    service = get_unified_embedding_service()
    return await service.encode_document(text, normalize=normalize)


async def encode_query(
    text: str | list[str],
    normalize: bool = True,
) -> np.ndarray:
    """
    Encode query using unified service.

    Args:
        text: Query/queries to encode
        normalize: Normalize embeddings

    Returns:
        Embedding array
    """
    service = get_unified_embedding_service()
    return await service.encode_query(text, normalize=normalize)
