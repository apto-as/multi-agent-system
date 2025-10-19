#!/usr/bin/env python3
"""
Unit tests for OllamaEmbeddingService.

Tests cover:
- Ollama server detection
- Embedding generation (document/query)
- Fallback mechanism
- Error handling
- Model dimension detection
"""

from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from src.services.ollama_embedding_service import OllamaEmbeddingService


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


@pytest.fixture
def ollama_service_without_server():
    """OllamaEmbeddingService with mocked server detection (unavailable)."""
    with patch.object(
        OllamaEmbeddingService,
        "_detect_ollama_server",
        return_value=False,
    ):
        service = OllamaEmbeddingService(auto_detect=False, fallback_enabled=True)
        service._is_ollama_available = False
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
    def test_detect_ollama_unavailable(self, mock_client):
        """Test Ollama server unavailable detection."""
        # Mock connection error
        mock_client.return_value.__enter__.return_value.get.side_effect = Exception(
            "Connection refused"
        )

        service = OllamaEmbeddingService(auto_detect=True)

        assert service._is_ollama_available is False

    @patch("httpx.Client")
    def test_detect_ollama_model_not_available(self, mock_client):
        """Test Ollama server available but model not pulled."""
        # Mock response with different model
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"models": [{"name": "llama2:latest"}]}

        mock_client.return_value.__enter__.return_value.get.return_value = mock_response

        service = OllamaEmbeddingService(auto_detect=True)

        assert service._is_ollama_available is False


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


class TestFallbackMechanism:
    """Test fallback to sentence-transformers."""

    @pytest.mark.asyncio
    async def test_fallback_on_ollama_error(self, ollama_service_with_server):
        """Test fallback when Ollama API fails."""
        test_text = "Fallback test"
        fallback_embedding = np.random.rand(768).astype(np.float32)  # ST is 768-dim

        # Mock Ollama error
        with patch.object(
            ollama_service_with_server,
            "_encode_ollama",
            side_effect=Exception("Ollama API error"),
        ):
            # Mock fallback service
            mock_fallback = AsyncMock()
            mock_fallback.encode_document.return_value = fallback_embedding

            with patch.object(
                ollama_service_with_server,
                "_get_fallback_service",
                return_value=mock_fallback,
            ):
                result = await ollama_service_with_server.encode_document(test_text)

                assert isinstance(result, np.ndarray)
                # Fallback was called
                mock_fallback.encode_document.assert_called_once()

    @pytest.mark.asyncio
    async def test_use_fallback_when_ollama_unavailable(self, ollama_service_without_server):
        """Test using fallback when Ollama server is unavailable."""
        test_text = "No Ollama server"
        fallback_embedding = np.random.rand(768).astype(np.float32)

        # Mock fallback service
        mock_fallback = AsyncMock()
        mock_fallback.encode_document.return_value = fallback_embedding

        with patch.object(
            ollama_service_without_server,
            "_get_fallback_service",
            return_value=mock_fallback,
        ):
            result = await ollama_service_without_server.encode_document(test_text)

            assert isinstance(result, np.ndarray)
            # Fallback was used
            mock_fallback.encode_document.assert_called_once()

    @pytest.mark.asyncio
    async def test_raise_error_when_fallback_disabled(self):
        """Test error when Ollama unavailable and fallback disabled."""
        service = OllamaEmbeddingService(
            auto_detect=False,
            fallback_enabled=False,
        )
        service._is_ollama_available = False

        with pytest.raises(RuntimeError, match="Ollama server unavailable"):
            await service.encode_document("test")


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

    def test_get_model_info_ollama_active(self, ollama_service_with_server):
        """Test model info when Ollama is active."""
        info = ollama_service_with_server.get_model_info()

        assert info["provider"] == "ollama"
        assert info["model_name"] == "zylonai/multilingual-e5-large"
        assert info["ollama_available"] is True
        assert info["fallback_enabled"] is True

    def test_get_model_info_fallback(self, ollama_service_without_server):
        """Test model info when using fallback."""
        info = ollama_service_without_server.get_model_info()

        assert info["provider"] == "sentence-transformers"
        assert info["ollama_available"] is False


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
    """Test error handling scenarios."""

    @pytest.mark.asyncio
    async def test_timeout_handling(self, ollama_service_with_server):
        """Test handling of API timeout."""
        import asyncio

        with patch.object(
            ollama_service_with_server,
            "_encode_ollama",
            side_effect=asyncio.TimeoutError("Request timeout"),
        ):
            # Mock fallback
            mock_fallback = AsyncMock()
            mock_fallback.encode_document.return_value = np.random.rand(768)

            with patch.object(
                ollama_service_with_server,
                "_get_fallback_service",
                return_value=mock_fallback,
            ):
                result = await ollama_service_with_server.encode_document("test")

                # Should fallback successfully
                assert result is not None

    @pytest.mark.asyncio
    async def test_api_error_response(self, ollama_service_with_server):
        """Test handling of Ollama API error response."""

        async def mock_encode_single(client, text):
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.text = "Internal Server Error"

            type("Response", (), {"status_code": 500, "text": "Internal Server Error"})()

            raise RuntimeError("Ollama API error: 500 - Internal Server Error")

        with patch.object(
            ollama_service_with_server,
            "_encode_single_ollama",
            side_effect=mock_encode_single,
        ):
            # Mock fallback
            mock_fallback = AsyncMock()
            mock_fallback.encode_document.return_value = np.random.rand(768)

            with patch.object(
                ollama_service_with_server,
                "_get_fallback_service",
                return_value=mock_fallback,
            ):
                result = await ollama_service_with_server.encode_document("test")

                # Should fallback on API error
                assert result is not None
