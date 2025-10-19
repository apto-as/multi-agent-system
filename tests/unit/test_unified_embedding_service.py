#!/usr/bin/env python3
"""
Unit tests for UnifiedEmbeddingService.

Tests cover:
- Provider selection logic (auto/ollama/sentence-transformers)
- Configuration-based initialization
- Provider switching
- Fallback behavior
"""

from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from src.services.unified_embedding_service import UnifiedEmbeddingService


@pytest.fixture
def mock_settings_auto():
    """Mock settings with 'auto' provider."""
    settings = MagicMock()
    settings.embedding_provider = "auto"
    settings.ollama_base_url = "http://localhost:11434"
    settings.ollama_embedding_model = "zylonai/multilingual-e5-large"
    settings.ollama_timeout = 30.0
    return settings


@pytest.fixture
def mock_settings_ollama():
    """Mock settings with 'ollama' provider."""
    settings = MagicMock()
    settings.embedding_provider = "ollama"
    settings.ollama_base_url = "http://localhost:11434"
    settings.ollama_embedding_model = "zylonai/multilingual-e5-large"
    settings.ollama_timeout = 30.0
    return settings


@pytest.fixture
def mock_settings_st():
    """Mock settings with 'sentence-transformers' provider."""
    settings = MagicMock()
    settings.embedding_provider = "sentence-transformers"
    return settings


class TestProviderInitialization:
    """Test provider initialization based on configuration."""

    @patch("src.services.unified_embedding_service.get_settings")
    @patch("src.services.unified_embedding_service.OllamaEmbeddingService")
    def test_init_auto_provider_ollama_available(
        self, mock_ollama_class, mock_get_settings, mock_settings_auto
    ):
        """Test 'auto' provider initialization when Ollama is available."""
        mock_get_settings.return_value = mock_settings_auto

        # Mock Ollama service as available
        mock_ollama_instance = MagicMock()
        mock_ollama_instance.get_model_info.return_value = {
            "ollama_available": True,
            "model_name": "zylonai/multilingual-e5-large",
        }
        mock_ollama_class.return_value = mock_ollama_instance

        service = UnifiedEmbeddingService()

        assert service._provider_type == "ollama"
        mock_ollama_class.assert_called_once_with(
            ollama_base_url="http://localhost:11434",
            model_name="zylonai/multilingual-e5-large",
            fallback_enabled=True,
            timeout=30.0,
        )

    @patch("src.services.unified_embedding_service.get_settings")
    @patch("src.services.unified_embedding_service.OllamaEmbeddingService")
    def test_init_auto_provider_ollama_unavailable(
        self, mock_ollama_class, mock_get_settings, mock_settings_auto
    ):
        """Test 'auto' provider initialization when Ollama is unavailable."""
        mock_get_settings.return_value = mock_settings_auto

        # Mock Ollama service as unavailable (fallback active)
        mock_ollama_instance = MagicMock()
        mock_ollama_instance.get_model_info.return_value = {
            "ollama_available": False,
            "model_name": "zylonai/multilingual-e5-large",
        }
        mock_ollama_class.return_value = mock_ollama_instance

        service = UnifiedEmbeddingService()

        assert service._provider_type == "sentence-transformers (fallback)"

    @patch("src.services.unified_embedding_service.get_settings")
    @patch("src.services.unified_embedding_service.get_embedding_service")
    def test_init_sentence_transformers_provider(
        self, mock_get_st_service, mock_get_settings, mock_settings_st
    ):
        """Test 'sentence-transformers' provider initialization."""
        mock_get_settings.return_value = mock_settings_st

        mock_st_instance = MagicMock()
        mock_get_st_service.return_value = mock_st_instance

        service = UnifiedEmbeddingService()

        assert service._provider_type == "sentence-transformers"
        mock_get_st_service.assert_called_once()

    @patch("src.services.unified_embedding_service.get_settings")
    @patch("src.services.unified_embedding_service.OllamaEmbeddingService")
    def test_init_ollama_only_provider(
        self, mock_ollama_class, mock_get_settings, mock_settings_ollama
    ):
        """Test 'ollama' provider initialization (no fallback)."""
        mock_get_settings.return_value = mock_settings_ollama

        mock_ollama_instance = MagicMock()
        mock_ollama_instance.get_model_info.return_value = {
            "ollama_available": True,
            "model_name": "zylonai/multilingual-e5-large",
        }
        mock_ollama_class.return_value = mock_ollama_instance

        UnifiedEmbeddingService()

        # Ollama with fallback_enabled=False
        mock_ollama_class.assert_called_once_with(
            ollama_base_url="http://localhost:11434",
            model_name="zylonai/multilingual-e5-large",
            fallback_enabled=False,
            timeout=30.0,
        )

    @patch("src.services.unified_embedding_service.get_settings")
    def test_init_invalid_provider_raises_error(self, mock_get_settings):
        """Test that invalid provider raises ValueError."""
        settings = MagicMock()
        settings.embedding_provider = "invalid_provider"
        mock_get_settings.return_value = settings

        with pytest.raises(ValueError, match="Invalid provider type"):
            UnifiedEmbeddingService()


class TestEmbeddingOperations:
    """Test embedding generation through unified interface."""

    @pytest.mark.asyncio
    @patch("src.services.unified_embedding_service.get_settings")
    async def test_encode_document(self, mock_get_settings, mock_settings_auto):
        """Test document encoding."""
        mock_get_settings.return_value = mock_settings_auto

        service = UnifiedEmbeddingService()

        # Mock provider
        expected_embedding = np.random.rand(1024).astype(np.float32)
        service._provider = AsyncMock()
        service._provider.encode_document.return_value = expected_embedding

        result = await service.encode_document("test document")

        assert np.array_equal(result, expected_embedding)
        service._provider.encode_document.assert_called_once_with(
            text="test document", normalize=True, batch_size=32
        )

    @pytest.mark.asyncio
    @patch("src.services.unified_embedding_service.get_settings")
    async def test_encode_query(self, mock_get_settings, mock_settings_auto):
        """Test query encoding."""
        mock_get_settings.return_value = mock_settings_auto

        service = UnifiedEmbeddingService()

        # Mock provider
        expected_embedding = np.random.rand(1024).astype(np.float32)
        service._provider = AsyncMock()
        service._provider.encode_query.return_value = expected_embedding

        result = await service.encode_query("test query")

        assert np.array_equal(result, expected_embedding)
        service._provider.encode_query.assert_called_once_with(
            text="test query", normalize=True, batch_size=32
        )

    @pytest.mark.asyncio
    @patch("src.services.unified_embedding_service.get_settings")
    async def test_encode_raises_error_when_not_initialized(
        self, mock_get_settings, mock_settings_auto
    ):
        """Test that encoding raises error when provider not initialized."""
        mock_get_settings.return_value = mock_settings_auto

        service = UnifiedEmbeddingService()
        service._provider = None  # Simulate uninitialized

        with pytest.raises(RuntimeError, match="Embedding provider not initialized"):
            await service.encode_document("test")


class TestModelInfo:
    """Test model information retrieval."""

    @patch("src.services.unified_embedding_service.get_settings")
    def test_get_model_info(self, mock_get_settings, mock_settings_auto):
        """Test retrieving model info."""
        mock_get_settings.return_value = mock_settings_auto

        service = UnifiedEmbeddingService()

        # Mock provider
        service._provider = MagicMock()
        service._provider.get_model_info.return_value = {
            "provider": "ollama",
            "model_name": "zylonai/multilingual-e5-large",
            "dimension": 1024,
        }
        service._provider_type = "ollama"

        info = service.get_model_info()

        assert info["provider"] == "ollama"
        assert info["model_name"] == "zylonai/multilingual-e5-large"
        assert info["dimension"] == 1024
        assert info["provider_type"] == "ollama"

    @patch("src.services.unified_embedding_service.get_settings")
    def test_get_model_info_not_initialized(self, mock_get_settings, mock_settings_auto):
        """Test model info when provider not initialized."""
        mock_get_settings.return_value = mock_settings_auto

        service = UnifiedEmbeddingService()
        service._provider = None

        info = service.get_model_info()

        assert info["provider"] == "none"
        assert "error" in info


class TestDimensionDetection:
    """Test embedding dimension detection."""

    @pytest.mark.asyncio
    @patch("src.services.unified_embedding_service.get_settings")
    async def test_get_dimension_with_method(self, mock_get_settings, mock_settings_auto):
        """Test get_dimension when provider has get_dimension method."""
        mock_get_settings.return_value = mock_settings_auto

        service = UnifiedEmbeddingService()

        # Mock provider with get_dimension
        service._provider = AsyncMock()
        service._provider.get_dimension = AsyncMock(return_value=1024)

        dimension = await service.get_dimension()

        assert dimension == 1024
        service._provider.get_dimension.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.services.unified_embedding_service.get_settings")
    async def test_get_dimension_fallback(self, mock_get_settings, mock_settings_auto):
        """Test get_dimension fallback (encode test text)."""
        mock_get_settings.return_value = mock_settings_auto

        service = UnifiedEmbeddingService()

        # Mock provider without get_dimension method
        test_embedding = np.random.rand(768).astype(np.float32)
        service._provider = AsyncMock()
        service._provider.encode_query.return_value = test_embedding
        # Remove get_dimension method
        delattr(service._provider, "get_dimension")

        dimension = await service.get_dimension()

        assert dimension == 768


class TestProviderChecks:
    """Test provider type checking."""

    @patch("src.services.unified_embedding_service.get_settings")
    def test_is_ollama_active_true(self, mock_get_settings, mock_settings_ollama):
        """Test is_ollama_active when Ollama is active."""
        mock_get_settings.return_value = mock_settings_ollama

        with patch("src.services.unified_embedding_service.OllamaEmbeddingService") as mock_ollama:
            mock_instance = MagicMock()
            mock_instance.get_model_info.return_value = {"ollama_available": True}
            mock_ollama.return_value = mock_instance

            service = UnifiedEmbeddingService()
            service._provider_type = "ollama"

            assert service.is_ollama_active() is True

    @patch("src.services.unified_embedding_service.get_settings")
    def test_is_ollama_active_false(self, mock_get_settings, mock_settings_st):
        """Test is_ollama_active when using sentence-transformers."""
        mock_get_settings.return_value = mock_settings_st

        with patch("src.services.unified_embedding_service.get_embedding_service"):
            service = UnifiedEmbeddingService()
            service._provider_type = "sentence-transformers"

            assert service.is_ollama_active() is False

    @patch("src.services.unified_embedding_service.get_settings")
    def test_get_provider_type(self, mock_get_settings, mock_settings_ollama):
        """Test get_provider_type method."""
        mock_get_settings.return_value = mock_settings_ollama

        with patch("src.services.unified_embedding_service.OllamaEmbeddingService") as mock_ollama:
            mock_instance = MagicMock()
            mock_instance.get_model_info.return_value = {"ollama_available": True}
            mock_ollama.return_value = mock_instance

            service = UnifiedEmbeddingService()
            service._provider_type = "ollama"

            assert service.get_provider_type() == "ollama"


class TestForceProvider:
    """Test force provider override."""

    @patch("src.services.unified_embedding_service.get_settings")
    @patch("src.services.unified_embedding_service.get_embedding_service")
    def test_force_sentence_transformers(self, mock_get_st, mock_get_settings, mock_settings_auto):
        """Test forcing sentence-transformers provider."""
        mock_get_settings.return_value = mock_settings_auto
        mock_st_instance = MagicMock()
        mock_get_st.return_value = mock_st_instance

        # Force sentence-transformers even though config says "auto"
        service = UnifiedEmbeddingService(force_provider="sentence-transformers")

        assert service._provider_type == "sentence-transformers"
        mock_get_st.assert_called_once()

    @patch("src.services.unified_embedding_service.get_settings")
    @patch("src.services.unified_embedding_service.OllamaEmbeddingService")
    def test_force_ollama(self, mock_ollama_class, mock_get_settings, mock_settings_st):
        """Test forcing ollama provider."""
        mock_get_settings.return_value = mock_settings_st
        mock_settings_st.ollama_base_url = "http://localhost:11434"
        mock_settings_st.ollama_embedding_model = "zylonai/multilingual-e5-large"
        mock_settings_st.ollama_timeout = 30.0

        mock_ollama_instance = MagicMock()
        mock_ollama_instance.get_model_info.return_value = {"ollama_available": True}
        mock_ollama_class.return_value = mock_ollama_instance

        # Force ollama even though config says "sentence-transformers"
        service = UnifiedEmbeddingService(force_provider="ollama")

        assert service._provider_type == "ollama"


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    @pytest.mark.asyncio
    @patch("src.services.unified_embedding_service.get_unified_embedding_service")
    async def test_encode_document_convenience(self, mock_get_service):
        """Test encode_document convenience function."""
        from src.services.unified_embedding_service import encode_document

        expected_embedding = np.random.rand(1024).astype(np.float32)

        mock_service = AsyncMock()
        mock_service.encode_document.return_value = expected_embedding
        mock_get_service.return_value = mock_service

        result = await encode_document("test document")

        assert np.array_equal(result, expected_embedding)
        mock_service.encode_document.assert_called_once_with("test document", normalize=True)

    @pytest.mark.asyncio
    @patch("src.services.unified_embedding_service.get_unified_embedding_service")
    async def test_encode_query_convenience(self, mock_get_service):
        """Test encode_query convenience function."""
        from src.services.unified_embedding_service import encode_query

        expected_embedding = np.random.rand(1024).astype(np.float32)

        mock_service = AsyncMock()
        mock_service.encode_query.return_value = expected_embedding
        mock_get_service.return_value = mock_service

        result = await encode_query("test query")

        assert np.array_equal(result, expected_embedding)
        mock_service.encode_query.assert_called_once_with("test query", normalize=True)
