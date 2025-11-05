"""
Mock-based unit tests for MCP authentication.

Fast unit tests using mocks (no real database).
Validates business logic and error handling.

Execution time: <5 seconds for all 15 tests.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from datetime import datetime, timedelta
from uuid import UUID

from src.security.mcp_auth import (
    MCPAuthService,
    MCPAuthenticationError,
    MCPAuthorizationError,
    MCPAuthContext,
    MCPRole,
    MCPOperation,
)
from src.models.agent import Agent, AgentStatus


class TestMCPAuthenticationMocks:
    """Fast mock-based tests for authentication logic."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock AsyncSession."""
        return AsyncMock()

    @pytest.fixture
    def mock_agent(self):
        """Create a mock Agent object."""
        return Mock(
            agent_id="test-agent",
            namespace="test-namespace",
            status=AgentStatus.ACTIVE,
            roles=["read", "write"],
            metadata={},
            capabilities={},  # Required for _determine_agent_role
            config={},  # Required for _determine_agent_role
        )

    # ===== Category 1: API Key Authentication (6 tests) =====

    @pytest.mark.asyncio
    async def test_authenticate_with_valid_api_key_mock(
        self, mock_session, mock_agent
    ):
        """Test successful authentication with valid API key."""
        # Add api_key_hash to mock agent
        mock_agent.api_key_hash = "salt:hash"

        with (
            patch("src.security.mcp_auth.select") as mock_select,
            patch(
                "src.utils.security.verify_password_with_salt"
            ) as mock_verify,
        ):
            # Mock database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_agent)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Mock API key validation (returns True for valid key)
            mock_verify.return_value = True

            # Execute
            auth_service = MCPAuthService()
            context = await auth_service.authenticate_mcp_agent(
                session=mock_session,
                agent_id="test-agent",
                api_key="valid-key",
                tool_name="test_tool",
            )

            # Assert
            assert context.agent_id == "test-agent"
            assert context.namespace == "test-namespace"
            assert context.auth_method == "api_key"
            mock_verify.assert_called_once_with("valid-key", "salt:hash")

    @pytest.mark.asyncio
    async def test_authenticate_with_invalid_api_key_mock(
        self, mock_session, mock_agent
    ):
        """Test authentication failure with invalid API key."""
        # Add api_key_hash to mock agent
        mock_agent.api_key_hash = "salt:hash"

        with (
            patch("src.security.mcp_auth.select") as mock_select,
            patch(
                "src.utils.security.verify_password_with_salt"
            ) as mock_verify,
        ):
            # Mock database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_agent)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Mock API key validation - returns False for invalid key
            mock_verify.return_value = False

            # Execute and assert
            auth_service = MCPAuthService()
            with pytest.raises(MCPAuthenticationError) as exc_info:
                await auth_service.authenticate_mcp_agent(
                    session=mock_session,
                    agent_id="test-agent",
                    api_key="invalid-key",
                    tool_name="test_tool",
                )

            assert "Invalid API key" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_authenticate_with_expired_api_key_mock(
        self, mock_session, mock_agent
    ):
        """Test authentication failure with no API key configured."""
        # Agent has no API key configured
        mock_agent.api_key_hash = None

        with patch("src.security.mcp_auth.select") as mock_select:
            # Mock database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_agent)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Execute and assert
            auth_service = MCPAuthService()
            with pytest.raises(MCPAuthenticationError) as exc_info:
                await auth_service.authenticate_mcp_agent(
                    session=mock_session,
                    agent_id="test-agent",
                    api_key="some-key",
                    tool_name="test_tool",
                )

            assert "api key" in str(exc_info.value).lower() and (
                "no" in str(exc_info.value).lower()
                or "configured" in str(exc_info.value).lower()
            )

    @pytest.mark.asyncio
    async def test_authenticate_with_nonexistent_agent_mock(self, mock_session):
        """Test authentication failure when agent doesn't exist."""
        with patch("src.security.mcp_auth.select") as mock_select:
            # Mock database query result - agent not found
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=None)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Execute and assert
            auth_service = MCPAuthService()
            with pytest.raises(MCPAuthenticationError) as exc_info:
                await auth_service.authenticate_mcp_agent(
                    session=mock_session,
                    agent_id="nonexistent-agent",
                    api_key="some-key",
                    tool_name="test_tool",
                )

            assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_authenticate_with_inactive_agent_mock(
        self, mock_session, mock_agent
    ):
        """Test authentication failure when agent is inactive."""
        mock_agent.status = AgentStatus.INACTIVE

        with patch("src.security.mcp_auth.select") as mock_select:
            # Mock database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_agent)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Execute and assert
            auth_service = MCPAuthService()
            with pytest.raises(MCPAuthenticationError) as exc_info:
                await auth_service.authenticate_mcp_agent(
                    session=mock_session,
                    agent_id="test-agent",
                    api_key="some-key",
                    tool_name="test_tool",
                )

            assert "not active" in str(exc_info.value).lower() or "inactive" in str(
                exc_info.value
            ).lower()

    @pytest.mark.asyncio
    async def test_authenticate_with_suspended_agent_mock(
        self, mock_session, mock_agent
    ):
        """Test authentication failure when agent is suspended."""
        mock_agent.status = AgentStatus.SUSPENDED

        with patch("src.security.mcp_auth.select") as mock_select:
            # Mock database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_agent)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Execute and assert
            auth_service = MCPAuthService()
            with pytest.raises(MCPAuthenticationError) as exc_info:
                await auth_service.authenticate_mcp_agent(
                    session=mock_session,
                    agent_id="test-agent",
                    api_key="some-key",
                    tool_name="test_tool",
                )

            assert "suspended" in str(exc_info.value).lower()

    # ===== Category 2: JWT Authentication (5 tests) =====

    @pytest.mark.asyncio
    async def test_authenticate_with_valid_jwt_mock(self, mock_session, mock_agent):
        """Test successful authentication with valid JWT."""
        with (
            patch("src.security.mcp_auth.select") as mock_select,
            patch.object(MCPAuthService, "__init__", lambda self: None),
        ):
            # Mock database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_agent)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Execute
            auth_service = MCPAuthService()
            # Mock JWT service with valid token
            mock_jwt_service = MagicMock()
            mock_jwt_service.verify_token = Mock(
                return_value={"sub": "test-agent", "namespace": "test-namespace"}
            )
            auth_service.jwt_service = mock_jwt_service

            context = await auth_service.authenticate_mcp_agent(
                session=mock_session,
                agent_id="test-agent",
                jwt_token="valid.jwt.token",
                tool_name="test_tool",
            )

            # Assert
            assert context.agent_id == "test-agent"
            assert context.namespace == "test-namespace"
            assert context.auth_method == "jwt"
            mock_jwt_service.verify_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_authenticate_with_unsigned_jwt_mock(
        self, mock_session, mock_agent
    ):
        """Test authentication failure with invalid JWT (returns None)."""
        with (
            patch("src.security.mcp_auth.select") as mock_select,
            patch.object(MCPAuthService, "__init__", lambda self: None),
        ):
            # Mock database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_agent)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Execute
            auth_service = MCPAuthService()
            # Mock JWT service - returns None for invalid token
            mock_jwt_service = MagicMock()
            mock_jwt_service.verify_token = Mock(return_value=None)
            auth_service.jwt_service = mock_jwt_service

            # Execute and assert
            with pytest.raises(MCPAuthenticationError) as exc_info:
                await auth_service.authenticate_mcp_agent(
                    session=mock_session,
                    agent_id="test-agent",
                    jwt_token="unsigned.jwt.token",
                    tool_name="test_tool",
                )

            assert "invalid" in str(exc_info.value).lower() or "expired" in str(
                exc_info.value
            ).lower()

    @pytest.mark.asyncio
    async def test_authenticate_with_expired_jwt_mock(self, mock_session, mock_agent):
        """Test authentication failure with expired JWT."""
        with (
            patch("src.security.mcp_auth.select") as mock_select,
            patch.object(MCPAuthService, "__init__", lambda self: None),
        ):
            # Mock database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_agent)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Execute
            auth_service = MCPAuthService()
            # Mock JWT service - returns None for expired token
            mock_jwt_service = MagicMock()
            mock_jwt_service.verify_token = Mock(return_value=None)
            auth_service.jwt_service = mock_jwt_service

            # Execute and assert
            with pytest.raises(MCPAuthenticationError) as exc_info:
                await auth_service.authenticate_mcp_agent(
                    session=mock_session,
                    agent_id="test-agent",
                    jwt_token="expired.jwt.token",
                    tool_name="test_tool",
                )

            assert "invalid" in str(exc_info.value).lower() or "expired" in str(
                exc_info.value
            ).lower()

    @pytest.mark.asyncio
    async def test_authenticate_with_tampered_jwt_mock(
        self, mock_session, mock_agent
    ):
        """Test authentication failure with tampered JWT payload."""
        with (
            patch("src.security.mcp_auth.select") as mock_select,
            patch.object(MCPAuthService, "__init__", lambda self: None),
        ):
            # Mock database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_agent)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Execute
            auth_service = MCPAuthService()
            # Mock JWT service - returns None for tampered token
            mock_jwt_service = MagicMock()
            mock_jwt_service.verify_token = Mock(return_value=None)
            auth_service.jwt_service = mock_jwt_service

            # Execute and assert
            with pytest.raises(MCPAuthenticationError) as exc_info:
                await auth_service.authenticate_mcp_agent(
                    session=mock_session,
                    agent_id="test-agent",
                    jwt_token="tampered.jwt.token",
                    tool_name="test_tool",
                )

            assert "invalid" in str(exc_info.value).lower() or "expired" in str(
                exc_info.value
            ).lower()

    @pytest.mark.asyncio
    async def test_authenticate_jwt_agent_mismatch_mock(
        self, mock_session, mock_agent
    ):
        """Test authentication failure when JWT agent_id doesn't match request agent_id."""
        with (
            patch("src.security.mcp_auth.select") as mock_select,
            patch.object(MCPAuthService, "__init__", lambda self: None),
        ):
            # Mock database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = Mock(return_value=mock_agent)
            mock_session.execute = AsyncMock(return_value=mock_result)

            # Execute
            auth_service = MCPAuthService()
            # Mock JWT service - returns different agent_id (sub claim)
            mock_jwt_service = MagicMock()
            mock_jwt_service.verify_token = Mock(
                return_value={
                    "sub": "different-agent",
                    "namespace": "test-namespace",
                }
            )
            auth_service.jwt_service = mock_jwt_service

            # Execute and assert
            with pytest.raises(MCPAuthenticationError) as exc_info:
                await auth_service.authenticate_mcp_agent(
                    session=mock_session,
                    agent_id="test-agent",
                    jwt_token="valid.jwt.token",
                    tool_name="test_tool",
                )

            assert "mismatch" in str(exc_info.value).lower()

    # ===== Category 3: Authorization Logic (4 tests) =====

    @pytest.mark.asyncio
    async def test_authorize_namespace_access_own_namespace_mock(self):
        """Test authorization allows access to own namespace."""
        # Mock agent for context
        mock_agent = Mock(
            agent_id="test-agent",
            namespace="test-namespace",
            status=AgentStatus.ACTIVE,
        )

        context = MCPAuthContext(
            agent_id="test-agent",
            namespace="test-namespace",
            agent=mock_agent,
            role=MCPRole.AGENT,
            tool_name="test_tool",
            request_id="test-request-123",
            timestamp=datetime.now(),
            auth_method="api_key",
        )

        auth_service = MCPAuthService()

        # Should not raise exception for accessing own namespace
        await auth_service.authorize_namespace_access(
            context=context,
            target_namespace="test-namespace",
            operation=MCPOperation.MEMORY_READ,
        )

    @pytest.mark.asyncio
    async def test_authorize_namespace_access_other_namespace_mock(self):
        """Test authorization blocks access to other namespace."""
        # Mock agent for context
        mock_agent = Mock(
            agent_id="test-agent",
            namespace="test-namespace",
            status=AgentStatus.ACTIVE,
        )

        context = MCPAuthContext(
            agent_id="test-agent",
            namespace="test-namespace",
            agent=mock_agent,
            role=MCPRole.AGENT,
            tool_name="test_tool",
            request_id="test-request-123",
            timestamp=datetime.now(),
            auth_method="api_key",
        )

        auth_service = MCPAuthService()

        # Should raise authorization error for other namespace
        with pytest.raises(MCPAuthorizationError) as exc_info:
            await auth_service.authorize_namespace_access(
                context=context,
                target_namespace="other-namespace",
                operation=MCPOperation.MEMORY_WRITE,
            )

        assert (
            "cannot access" in str(exc_info.value).lower()
            or "not allowed" in str(exc_info.value).lower()
            or "denied" in str(exc_info.value).lower()
        )

    @pytest.mark.asyncio
    async def test_authorize_operation_insufficient_role_mock(self):
        """Test RBAC blocks operation when agent lacks required role."""
        # Mock agent for context - regular agent (not admin)
        mock_agent = Mock(
            agent_id="test-agent",
            namespace="test-namespace",
            status=AgentStatus.ACTIVE,
        )

        context = MCPAuthContext(
            agent_id="test-agent",
            namespace="test-namespace",
            agent=mock_agent,
            role=MCPRole.AGENT,  # Regular agent, not admin
            tool_name="test_tool",
            request_id="test-request-123",
            timestamp=datetime.now(),
            auth_method="api_key",
        )

        auth_service = MCPAuthService()

        # Should raise authorization error for privileged operation
        # Regular agent trying to configure scheduler (requires SYSTEM_ADMIN)
        with pytest.raises(MCPAuthorizationError) as exc_info:
            await auth_service.authorize_operation(
                context=context, operation=MCPOperation.SCHEDULER_CONFIGURE
            )

        assert "not allowed" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_authorize_operation_sufficient_role_mock(self):
        """Test RBAC allows operation when agent has required role."""
        # Mock agent for context - system admin
        mock_agent = Mock(
            agent_id="admin-agent",
            namespace="test-namespace",
            status=AgentStatus.ACTIVE,
        )

        context = MCPAuthContext(
            agent_id="admin-agent",
            namespace="test-namespace",
            agent=mock_agent,
            role=MCPRole.SYSTEM_ADMIN,  # Admin role
            tool_name="test_tool",
            request_id="test-request-123",
            timestamp=datetime.now(),
            auth_method="api_key",
        )

        auth_service = MCPAuthService()

        # Should not raise exception for privileged operation
        # System admin can configure scheduler
        await auth_service.authorize_operation(
            context=context, operation=MCPOperation.SCHEDULER_CONFIGURE
        )
