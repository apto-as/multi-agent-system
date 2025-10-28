#!/usr/bin/env python3
"""
Ollama Embedding Service for TMWS v2.3.0 - Ollama-Only Architecture

This module provides embedding generation using Ollama's local inference server.

⚠️ CRITICAL: Ollama is REQUIRED for TMWS operation
- No fallback mechanisms (anti-pattern - hides configuration issues)
- Clear error messages guide users to fix Ollama setup
- Fail-fast approach ensures proper infrastructure

Key Features:
- Ollama-only embedding generation (no hidden dependencies)
- Uses zylonai/multilingual-e5-large for multilingual support (1024-dim)
- Cross-platform compatibility (Windows/Mac/Linux)
- Clear error messages when Ollama is unavailable

Architecture:
- Embedding Provider: Ollama API (http://localhost:11434)
- Model: zylonai/multilingual-e5-large (1024-dim)
- Storage: ChromaDB for vector search
- Metadata: SQLite for relational data

Setup Instructions:
1. Install Ollama: https://ollama.ai/download
2. Pull model: ollama pull zylonai/multilingual-e5-large
3. Start server: ollama serve
"""

import asyncio
import logging

import httpx
import numpy as np

from ..core.exceptions import IntegrationError, log_and_raise

logger = logging.getLogger(__name__)


class OllamaConnectionError(IntegrationError):
    """Raised when Ollama server is unavailable or unreachable."""

    pass


class OllamaModelNotFoundError(IntegrationError):
    """Raised when required model is not available in Ollama."""

    pass


class OllamaEmbeddingService:
    """
    Ollama-based embedding service (required dependency).

    This service requires Ollama to be installed and running.
    There is no fallback - this ensures consistent embedding dimensions
    and prevents silent failures.

    Usage:
        service = OllamaEmbeddingService()

        # Document embedding
        doc_embedding = await service.encode_document("This is a document")

        # Query embedding
        query_embedding = await service.encode_query("search query")

        # Batch processing
        docs = ["doc1", "doc2", "doc3"]
        embeddings = await service.encode_document(docs)

    Error Handling:
        If Ollama is not available, clear error messages guide users:
        - OllamaConnectionError: Server not reachable
        - OllamaModelNotFoundError: Model not pulled
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
        timeout: float = DEFAULT_TIMEOUT,
        auto_detect: bool = True,
    ):
        """
        Initialize Ollama embedding service.

        Args:
            ollama_base_url: Ollama server URL (default: http://localhost:11434)
            model_name: Model name (default: zylonai/multilingual-e5-large)
            timeout: Request timeout in seconds
            auto_detect: Automatically detect Ollama availability on init

        Raises:
            OllamaConnectionError: If auto_detect=True and Ollama is unreachable
            OllamaModelNotFoundError: If auto_detect=True and model is not available
        """
        self.ollama_base_url = ollama_base_url or self.DEFAULT_OLLAMA_URL
        self.model_name = model_name or self.DEFAULT_MODEL
        self.timeout = timeout

        # State tracking
        self._is_ollama_available = False
        self._model_dimension = None

        # Auto-detect Ollama server
        if auto_detect:
            self._detect_ollama_server()

    def _detect_ollama_server(self) -> bool:
        """
        Detect if Ollama server is available and responsive.

        Returns:
            True if Ollama server is available

        Raises:
            OllamaConnectionError: If Ollama server is unreachable
            OllamaModelNotFoundError: If required model is not available
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
                        # Model not found - provide clear instructions
                        log_and_raise(
                            OllamaModelNotFoundError,
                            f"Ollama model '{self.model_name}' not found. "
                            f"Please pull the model: ollama pull {self.model_name}",
                            details={
                                "ollama_url": self.ollama_base_url,
                                "model_name": self.model_name,
                                "available_models": [m.get("name") for m in models],
                            },
                        )
        except (KeyboardInterrupt, SystemExit):
            raise
        except OllamaModelNotFoundError:
            # Re-raise our custom exception
            raise
        except Exception as e:
            # Connection error - provide clear instructions
            log_and_raise(
                OllamaConnectionError,
                f"Ollama server is not reachable at {self.ollama_base_url}. "
                f"Please ensure Ollama is installed and running:\n"
                f"  1. Install: https://ollama.ai/download\n"
                f"  2. Start server: ollama serve\n"
                f"  3. Pull model: ollama pull {self.model_name}",
                original_exception=e,
                details={
                    "ollama_url": self.ollama_base_url,
                    "model_name": self.model_name,
                },
            )

        return False  # Unreachable due to log_and_raise, but satisfies type checker

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

        Raises:
            OllamaConnectionError: If Ollama server is unavailable
            RuntimeError: If encoding fails
        """
        if not self._is_ollama_available:
            # Re-check availability before failing
            self._detect_ollama_server()

        return await self._encode_ollama(
            text=text,
            prefix="passage: ",
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

        Uses "query: " prefix for E5-style encoding.

        Args:
            text: Single query or list of queries to encode
            normalize: Normalize embeddings to unit length
            batch_size: Batch size for processing multiple queries

        Returns:
            Embedding array (1D for single query, 2D for multiple)

        Raises:
            OllamaConnectionError: If Ollama server is unavailable
            RuntimeError: If encoding fails
        """
        if not self._is_ollama_available:
            # Re-check availability before failing
            self._detect_ollama_server()

        return await self._encode_ollama(
            text=text,
            prefix="query: ",
            normalize=normalize,
            batch_size=batch_size,
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

        Raises:
            RuntimeError: If API call fails
        """
        # Normalize input
        single_input = isinstance(text, str)
        texts = [text] if single_input else text

        embeddings = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Process in batches
                for i in range(0, len(texts), batch_size):
                    batch = texts[i : i + batch_size]

                    # Encode each text in batch
                    batch_embeddings = await asyncio.gather(
                        *[self._encode_single_ollama(client, f"{prefix}{t}") for t in batch]
                    )

                    embeddings.extend(batch_embeddings)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            log_and_raise(
                OllamaConnectionError,
                f"Failed to encode text using Ollama. "
                f"Please check that Ollama server is running at {self.ollama_base_url}",
                original_exception=e,
                details={
                    "ollama_url": self.ollama_base_url,
                    "model_name": self.model_name,
                    "batch_size": len(texts),
                },
            )

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

        Raises:
            RuntimeError: If API call fails
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
            "provider": "ollama",
            "model_name": self.model_name,
            "dimension": self._model_dimension or self.DEFAULT_DIMENSION,
            "ollama_url": self.ollama_base_url,
            "ollama_available": self._is_ollama_available,
        }

    async def get_dimension(self) -> int:
        """
        Get the embedding dimension.

        If not yet determined, encodes a test text to detect dimension.

        Returns:
            Embedding dimension size

        Raises:
            OllamaConnectionError: If Ollama is unavailable
        """
        if self._model_dimension is None:
            # Encode test text to detect dimension
            test_embedding = await self.encode_query("test", normalize=False)
            self._model_dimension = test_embedding.shape[0]

        return self._model_dimension


# Singleton accessor
_ollama_service_instance = None


def get_ollama_embedding_service() -> OllamaEmbeddingService:
    """
    Get singleton instance of OllamaEmbeddingService.

    Returns:
        Shared OllamaEmbeddingService instance

    Raises:
        OllamaConnectionError: If Ollama server is not available
        OllamaModelNotFoundError: If required model is not pulled
    """
    global _ollama_service_instance

    if _ollama_service_instance is None:
        _ollama_service_instance = OllamaEmbeddingService()

    return _ollama_service_instance
