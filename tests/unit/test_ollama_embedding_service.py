#!/usr/bin/env python3
"""
Unit tests for OllamaEmbeddingService (Ollama-only, no fallback).

Tests cover:
- Ollama server detection (with clear error messages when unavailable)
- Embedding generation (document/query)
- Error handling (explicit failures, no silent fallback)
- Model dimension detection
"""

from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from src.services.ollama_embedding_service import (
    OllamaConnectionError,
    OllamaEmbeddingService,
    OllamaModelNotFoundError,
)


@pytest.fixture
def mock_httpx_client():
    """Mock httpx client for Ollama API calls."""
    client = AsyncMock()
    return client


@pytest.fixture
def ollama_service_with_server():
    """OllamaEmbeddingService with mocked server detection (available)."""
    with patch.object(
        OllamaEmbeddingService,
        "_detect_ollama_server",
        return_value=True,
    ):
        service = OllamaEmbeddingService(auto_detect=False)
        service._is_ollama_available = True
        service._model_dimension = 1024  # Assume large variant
        return service


class TestOllamaServerDetection:
    """Test Ollama server detection and initialization."""

    @patch("httpx.Client")
    def test_detect_ollama_available(self, mock_client):
        """Test successful Ollama server detection."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "models": [{"name": "zylonai/multilingual-e5-large:latest"}]
        }

        mock_client.return_value.__enter__.return_value.get.return_value = mock_response

        service = OllamaEmbeddingService(auto_detect=True)

        assert service._is_ollama_available is True

    @patch("httpx.Client")
    def test_detect_ollama_unavailable_raises_error(self, mock_client):
        """Test Ollama server unavailable raises clear error."""
        # Mock connection error
        mock_client.return_value.__enter__.return_value.get.side_effect = Exception(
            "Connection refused"
        )

        # Should raise OllamaConnectionError with clear message
        with pytest.raises(OllamaConnectionError, match="not reachable"):
            OllamaEmbeddingService(auto_detect=True)

    @patch("httpx.Client")
    def test_detect_ollama_model_not_available_raises_error(self, mock_client):
        """Test Ollama server available but model not pulled raises error."""
        # Mock response with different model
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"models": [{"name": "llama2:latest"}]}

        mock_client.return_value.__enter__.return_value.get.return_value = mock_response

        # Should raise OllamaModelNotFoundError
        with pytest.raises(OllamaModelNotFoundError, match="not found"):
            OllamaEmbeddingService(auto_detect=True)


class TestEmbeddingGeneration:
    """Test embedding generation with Ollama."""

    @pytest.mark.asyncio
    async def test_encode_document_single_text(self, ollama_service_with_server):
        """Test encoding a single document."""
        test_text = "This is a test document"
        expected_embedding = np.random.rand(1024).astype(np.float32)

        # Mock Ollama API response
        with patch.object(
            ollama_service_with_server,
            "_encode_single_ollama",
            return_value=expected_embedding,
        ):
            result = await ollama_service_with_server.encode_document(test_text, normalize=False)

            assert isinstance(result, np.ndarray)
            assert result.shape == (1024,)

    @pytest.mark.asyncio
    async def test_encode_document_batch(self, ollama_service_with_server):
        """Test encoding multiple documents."""
        test_texts = ["Document 1", "Document 2", "Document 3"]
        expected_embedding = np.random.rand(1024).astype(np.float32)

        # Mock Ollama API response
        with patch.object(
            ollama_service_with_server,
            "_encode_single_ollama",
            return_value=expected_embedding,
        ):
            result = await ollama_service_with_server.encode_document(test_texts, normalize=False)

            assert isinstance(result, np.ndarray)
            assert result.shape == (3, 1024)

    @pytest.mark.asyncio
    async def test_encode_query_with_prefix(self, ollama_service_with_server):
        """Test encoding query with 'query:' prefix."""
        test_query = "search query"
        expected_embedding = np.random.rand(1024).astype(np.float32)

        with patch.object(
            ollama_service_with_server,
            "_encode_single_ollama",
            return_value=expected_embedding,
        ) as mock_encode:
            await ollama_service_with_server.encode_query(test_query, normalize=False)

            # Verify 'query:' prefix was used
            mock_encode.assert_called()
            call_args = mock_encode.call_args[0]
            assert "query: " in str(call_args)

    @pytest.mark.asyncio
    async def test_normalization(self, ollama_service_with_server):
        """Test embedding normalization."""
        test_text = "Test normalization"
        unnormalized = np.array([3.0, 4.0] + [0.0] * 1022, dtype=np.float32)

        with patch.object(
            ollama_service_with_server,
            "_encode_single_ollama",
            return_value=unnormalized,
        ):
            result = await ollama_service_with_server.encode_document(test_text, normalize=True)

            # Check if normalized (L2 norm should be ~1.0)
            norm = np.linalg.norm(result)
            assert np.isclose(norm, 1.0, atol=1e-5)


class TestDimensionDetection:
    """Test embedding dimension detection."""

    @pytest.mark.asyncio
    async def test_dimension_auto_detection(self, ollama_service_with_server):
        """Test automatic dimension detection from first encoding."""
        # Initially no dimension set
        ollama_service_with_server._model_dimension = None

        test_embedding = np.random.rand(1024).astype(np.float32)

        with patch.object(
            ollama_service_with_server,
            "_encode_single_ollama",
            return_value=test_embedding,
        ):
            await ollama_service_with_server.encode_document("test")

            # Dimension should be detected
            assert ollama_service_with_server._model_dimension == 1024

    @pytest.mark.asyncio
    async def test_get_dimension(self, ollama_service_with_server):
        """Test get_dimension method."""
        test_embedding = np.random.rand(1024).astype(np.float32)

        with patch.object(
            ollama_service_with_server,
            "_encode_single_ollama",
            return_value=test_embedding,
        ):
            dimension = await ollama_service_with_server.get_dimension()

            assert dimension == 1024


class TestModelInfo:
    """Test model information retrieval."""

    def test_get_model_info(self, ollama_service_with_server):
        """Test model info (Ollama-only, no fallback)."""
        info = ollama_service_with_server.get_model_info()

        assert info["provider"] == "ollama"
        assert info["model_name"] == "zylonai/multilingual-e5-large"
        assert info["ollama_available"] is True
        # No fallback_enabled field anymore
        assert "fallback_enabled" not in info


class TestBatchProcessing:
    """Test batch processing capabilities."""

    @pytest.mark.asyncio
    async def test_batch_size_limit(self, ollama_service_with_server):
        """Test processing respects batch size."""
        texts = [f"Document {i}" for i in range(100)]
        batch_size = 10

        call_count = 0

        async def count_calls(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return np.random.rand(1024).astype(np.float32)

        with patch.object(
            ollama_service_with_server,
            "_encode_single_ollama",
            side_effect=count_calls,
        ):
            await ollama_service_with_server.encode_document(texts, batch_size=batch_size)

            # Should be called 100 times (once per text)
            assert call_count == 100


class TestErrorHandling:
    """Test error handling scenarios (Ollama-only, no fallback)."""

    @pytest.mark.asyncio
    async def test_ollama_error_raises_clear_exception(self, ollama_service_with_server):
        """Test that Ollama errors raise clear exceptions (no silent fallback)."""
        with patch.object(
            ollama_service_with_server,
            "_encode_ollama",
            side_effect=RuntimeError("Ollama API error"),
        ):
            # Should raise RuntimeError, NOT fallback silently
            with pytest.raises(RuntimeError, match="Ollama API error"):
                await ollama_service_with_server.encode_document("test")

    @pytest.mark.asyncio
    async def test_api_error_response(self, ollama_service_with_server):
        """Test handling of Ollama API error response."""

        async def mock_encode_single(client, text):
            raise RuntimeError("Ollama API error: 500 - Internal Server Error")

        with patch.object(
            ollama_service_with_server,
            "_encode_single_ollama",
            side_effect=mock_encode_single,
        ):
            # Should raise OllamaConnectionError with clear message
            with pytest.raises(OllamaConnectionError, match="Failed to encode text"):
                await ollama_service_with_server.encode_document("test")
