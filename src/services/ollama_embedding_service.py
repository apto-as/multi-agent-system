#!/usr/bin/env python3
"""
Ollama Embedding Service for TMWS v2.2.5 - Internal Implementation

This module provides embedding generation using Ollama's local inference server,
with automatic fallback to sentence-transformers for high availability.

⚠️ INTERNAL USE ONLY
This module is an internal implementation detail used by UnifiedEmbeddingService.
For embedding operations, use:
    from src.services import get_embedding_service

This will automatically use the best available provider (Ollama → SentenceTransformers).

Key Features:
- Windows-compatible embedding generation via Ollama
- Automatic fallback to sentence-transformers
- Uses zylonai/multilingual-e5-large for multilingual support
- Cross-platform compatibility (Windows/Mac/Linux)

Architecture:
- Primary: Ollama API (http://localhost:11434)
- Fallback: SentenceTransformers (local PyTorch)
- Model: zylonai/multilingual-e5-large (1024-dim expected)
"""

import asyncio
import logging

import httpx
import numpy as np

logger = logging.getLogger(__name__)


class OllamaEmbeddingService:
    """
    Ollama-based embedding service with automatic fallback.

    This service provides robust embedding generation with:
    - Primary: Ollama server (Windows-friendly)
    - Fallback: SentenceTransformers (existing implementation)
    - Zero-downtime operation

    Usage:
        service = OllamaEmbeddingService()

        # Document embedding
        doc_embedding = await service.encode_document("This is a document")

        # Query embedding
        query_embedding = await service.encode_query("search query")

        # Batch processing
        docs = ["doc1", "doc2", "doc3"]
        embeddings = await service.encode_document(docs)
    """

    # Model configuration
    DEFAULT_MODEL = "zylonai/multilingual-e5-large"
    DEFAULT_DIMENSION = 1024  # Expected for "large" variant

    # API configuration
    DEFAULT_OLLAMA_URL = "http://localhost:11434"
    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        ollama_base_url: str | None = None,
        model_name: str | None = None,
        fallback_enabled: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
        auto_detect: bool = True,
    ):
        """
        Initialize Ollama embedding service.

        Args:
            ollama_base_url: Ollama server URL (default: http://localhost:11434)
            model_name: Model name (default: zylonai/multilingual-e5-large)
            fallback_enabled: Enable automatic fallback to sentence-transformers
            timeout: Request timeout in seconds
            auto_detect: Automatically detect Ollama availability on init
        """
        self.ollama_base_url = ollama_base_url or self.DEFAULT_OLLAMA_URL
        self.model_name = model_name or self.DEFAULT_MODEL
        self.fallback_enabled = fallback_enabled
        self.timeout = timeout

        # State tracking
        self._is_ollama_available = False
        self._fallback_service = None
        self._model_dimension = None

        # Auto-detect Ollama server
        if auto_detect:
            self._detect_ollama_server()

    def _detect_ollama_server(self) -> bool:
        """
        Detect if Ollama server is available and responsive.

        Returns:
            True if Ollama server is available, False otherwise
        """
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.ollama_base_url}/api/tags")

                if response.status_code == 200:
                    tags_data = response.json()
                    models = tags_data.get("models", [])

                    # Check if our model is available
                    model_available = any(
                        m.get("name", "").startswith(self.model_name.split(":")[0]) for m in models
                    )

                    if model_available:
                        logger.info(f"✅ Ollama server detected: {self.ollama_base_url}")
                        logger.info(f"✅ Model available: {self.model_name}")
                        self._is_ollama_available = True
                        return True
                    else:
                        logger.warning(
                            f"⚠️ Ollama server found but model '{self.model_name}' not available"
                        )
                        logger.info(f"Run: ollama pull {self.model_name}")
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.warning(f"⚠️ Ollama server not reachable: {e}", exc_info=False)

        self._is_ollama_available = False
        return False

    async def _get_fallback_service(self):
        """
        Lazy-load fallback embedding service.

        ⚠️ DIMENSION SAFETY: Validates dimension compatibility with primary model.
        Ollama (1024-dim) → SentenceTransformers (768-dim) is incompatible!

        Returns:
            Existing EmbeddingService instance

        Raises:
            RuntimeError: If fallback dimension doesn't match Ollama dimension
        """
        if self._fallback_service is None:
            from .embedding_service import get_embedding_service

            self._fallback_service = get_embedding_service()
            fallback_dim = self._fallback_service.get_model_info()["dimension"]

            # CRITICAL: Dimension validation
            if fallback_dim != self.DEFAULT_DIMENSION:
                logger.critical(
                    f"🚨 DIMENSION MISMATCH: Ollama={self.DEFAULT_DIMENSION}d, "
                    f"Fallback={fallback_dim}d - THIS WILL BREAK VECTOR SEARCH!"
                )
                raise RuntimeError(
                    f"Embedding dimension mismatch: Primary model uses {self.DEFAULT_DIMENSION}d "
                    f"but fallback provides {fallback_dim}d. Vector database operations will fail. "
                    f"Ensure Ollama server is running: ollama serve"
                )

            logger.info(f"✅ Fallback service initialized (dimension: {fallback_dim})")

        return self._fallback_service

    async def encode_document(
        self,
        text: str | list[str],
        normalize: bool = True,
        batch_size: int = 32,
    ) -> np.ndarray:
        """
        Encode document(s) for storage/indexing.

        Uses "passage: " prefix for E5-style encoding.

        Args:
            text: Single text or list of texts to encode
            normalize: Normalize embeddings to unit length
            batch_size: Batch size for processing multiple texts

        Returns:
            Embedding array (1D for single text, 2D for multiple)
        """
        if self._is_ollama_available:
            try:
                return await self._encode_ollama(
                    text=text,
                    prefix="passage: ",
                    normalize=normalize,
                    batch_size=batch_size,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                logger.error(f"❌ Ollama encoding failed: {e}", exc_info=True)

                if self.fallback_enabled:
                    logger.info("🔄 Falling back to SentenceTransformers")
                    fallback = await self._get_fallback_service()
                    return fallback.encode_document(text, normalize=normalize)

                raise

        # Ollama not available, use fallback
        if self.fallback_enabled:
            logger.debug("Using fallback service (Ollama not available)")
            fallback = await self._get_fallback_service()
            return fallback.encode_document(text, normalize=normalize)

        raise RuntimeError(
            f"Ollama server unavailable at {self.ollama_base_url} and fallback is disabled"
        )

    async def encode_query(
        self,
        text: str | list[str],
        normalize: bool = True,
        batch_size: int = 32,
    ) -> np.ndarray:
        """
        Encode query/question for retrieval.

        Uses "query: " prefix for E5-style encoding.

        Args:
            text: Single query or list of queries to encode
            normalize: Normalize embeddings to unit length
            batch_size: Batch size for processing multiple queries

        Returns:
            Embedding array (1D for single query, 2D for multiple)
        """
        if self._is_ollama_available:
            try:
                return await self._encode_ollama(
                    text=text,
                    prefix="query: ",
                    normalize=normalize,
                    batch_size=batch_size,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                logger.error(f"❌ Ollama encoding failed: {e}", exc_info=True)

                if self.fallback_enabled:
                    logger.info("🔄 Falling back to SentenceTransformers")
                    fallback = await self._get_fallback_service()
                    return fallback.encode_query(text, normalize=normalize)

                raise

        # Ollama not available, use fallback
        if self.fallback_enabled:
            logger.debug("Using fallback service (Ollama not available)")
            fallback = await self._get_fallback_service()
            return fallback.encode_query(text, normalize=normalize)

        raise RuntimeError(
            f"Ollama server unavailable at {self.ollama_base_url} and fallback is disabled"
        )

    async def _encode_ollama(
        self,
        text: str | list[str],
        prefix: str,
        normalize: bool,
        batch_size: int,
    ) -> np.ndarray:
        """
        Internal method to encode using Ollama API.

        Args:
            text: Text(s) to encode
            prefix: E5-style prefix ("passage: " or "query: ")
            normalize: Normalize embeddings
            batch_size: Batch size for API requests

        Returns:
            Embedding array
        """
        # Normalize input
        single_input = isinstance(text, str)
        texts = [text] if single_input else text

        embeddings = []

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Process in batches
            for i in range(0, len(texts), batch_size):
                batch = texts[i : i + batch_size]

                # Encode each text in batch
                batch_embeddings = await asyncio.gather(
                    *[self._encode_single_ollama(client, f"{prefix}{t}") for t in batch]
                )

                embeddings.extend(batch_embeddings)

        # Convert to numpy array
        embeddings_array = np.vstack(embeddings)

        # Normalize if requested
        if normalize:
            norms = np.linalg.norm(embeddings_array, axis=1, keepdims=True)
            embeddings_array = embeddings_array / (norms + 1e-9)

        # Cache dimension on first call
        if self._model_dimension is None:
            self._model_dimension = embeddings_array.shape[1]
            logger.info(f"✅ Model dimension detected: {self._model_dimension}")

        # Return single embedding or batch
        return embeddings_array[0] if single_input else embeddings_array

    async def _encode_single_ollama(
        self,
        client: httpx.AsyncClient,
        text: str,
    ) -> np.ndarray:
        """
        Encode a single text using Ollama API.

        Args:
            client: HTTP client instance
            text: Prefixed text to encode

        Returns:
            1D embedding array
        """
        response = await client.post(
            f"{self.ollama_base_url}/api/embeddings",
            json={"model": self.model_name, "prompt": text},
        )

        if response.status_code != 200:
            raise RuntimeError(f"Ollama API error: {response.status_code} - {response.text}")

        response_data = response.json()
        embedding = np.array(response_data["embedding"], dtype=np.float32)

        return embedding

    def get_model_info(self) -> dict:
        """
        Get information about the current embedding model.

        Returns:
            Dictionary with model metadata
        """
        return {
            "provider": "ollama" if self._is_ollama_available else "sentence-transformers",
            "model_name": self.model_name,
            "dimension": self._model_dimension or self.DEFAULT_DIMENSION,
            "ollama_url": self.ollama_base_url,
            "fallback_enabled": self.fallback_enabled,
            "ollama_available": self._is_ollama_available,
        }

    async def get_dimension(self) -> int:
        """
        Get the embedding dimension.

        If not yet determined, encodes a test text to detect dimension.

        Returns:
            Embedding dimension size
        """
        if self._model_dimension is None:
            # Encode test text to detect dimension
            test_embedding = await self.encode_query("test", normalize=False)
            self._model_dimension = test_embedding.shape[0]

        return self._model_dimension


# Singleton accessor (optional, for backward compatibility)
_ollama_service_instance = None


def get_ollama_embedding_service() -> OllamaEmbeddingService:
    """
    Get singleton instance of OllamaEmbeddingService.

    Returns:
        Shared OllamaEmbeddingService instance
    """
    global _ollama_service_instance

    if _ollama_service_instance is None:
        _ollama_service_instance = OllamaEmbeddingService()

    return _ollama_service_instance
