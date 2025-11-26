"""
Unit tests for P0 Critical Authentication Bug Fix.

Tests verify the fix for API key authentication with "salt:hash" format.

Bug: verify_password_with_salt() was called with 2 arguments instead of 3.
Fix: Parse "salt:hash" format and pass salt as 3rd argument.

Test Coverage:
- Valid salt:hash format authentication (happy path)
- Invalid hash format error handling
- Wrong API key rejection
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.agent import Agent
from src.security.mcp_auth import MCPAuthenticationError, MCPAuthService
from src.utils.security import hash_password_with_salt


@pytest.mark.asyncio
async def test_api_key_auth_with_valid_salt_hash_format(test_session: AsyncSession):
    """Test API key authentication works with 'salt:hash' format.

    This test verifies the P0 fix where verify_password_with_salt()
    now correctly receives 3 arguments (password, hashed, salt) after
    parsing the "salt:hash" format.
    """
    # Setup: Create agent with API key
    api_key = "test-api-key-12345"
    hashed, salt = hash_password_with_salt(api_key)

    test_agent = Agent(
        agent_id="test-agent-p0",
        namespace="test-namespace",
        display_name="Test Agent P0 Fix",
        capabilities=["test"],
        status="active",
        metadata={"test": True},
        api_key_hash=f"{salt}:{hashed}",  # Store in "salt:hash" format
    )
    test_session.add(test_agent)
    await test_session.commit()

    # Execute: Authenticate with API key
    handler = MCPAuthService()
    context = await handler.authenticate_mcp_agent(
        session=test_session,
        agent_id=test_agent.agent_id,
        api_key=api_key,
        tool_name="test_tool",
    )

    # Verify: Authentication successful
    assert context.agent_id == test_agent.agent_id
    assert context.namespace == test_agent.namespace
    assert context.auth_method == "api_key"
    # Role should be MCPRole enum, not string
    from src.security.mcp_auth import MCPRole

    assert context.role == MCPRole.AGENT


@pytest.mark.asyncio
async def test_api_key_auth_fails_with_invalid_hash_format(test_session: AsyncSession):
    """Test API key auth fails gracefully with invalid hash format.

    This test verifies that when api_key_hash is corrupted (no colon separator),
    the code raises a clear error instead of crashing with ValueError.
    """
    # Setup: Create agent with corrupted api_key_hash (no colon)
    test_agent = Agent(
        agent_id="test-agent-invalid-format",
        namespace="test-namespace",
        display_name="Test Agent Invalid Format",
        capabilities=["test"],
        status="active",
        metadata={"test": True},
        api_key_hash="invalid_no_colon_separator_hash",  # Missing colon
    )
    test_session.add(test_agent)
    await test_session.commit()

    # Execute & Verify: Should raise authentication error
    handler = MCPAuthService()
    with pytest.raises(MCPAuthenticationError, match="Authentication failed"):
        await handler.authenticate_mcp_agent(
            session=test_session,
            agent_id=test_agent.agent_id,
            api_key="any-key",
            tool_name="test_tool",
        )


@pytest.mark.asyncio
async def test_api_key_auth_fails_with_wrong_key(test_session: AsyncSession):
    """Test API key authentication fails with incorrect key.

    This test verifies that verify_password_with_salt() correctly rejects
    wrong API keys when called with the proper 3 arguments.
    """
    # Setup: Create agent with valid API key
    correct_key = "correct-api-key-xyz"
    hashed, salt = hash_password_with_salt(correct_key)

    test_agent = Agent(
        agent_id="test-agent-wrong-key",
        namespace="test-namespace",
        display_name="Test Agent Wrong Key",
        capabilities=["test"],
        status="active",
        metadata={"test": True},
        api_key_hash=f"{salt}:{hashed}",
    )
    test_session.add(test_agent)
    await test_session.commit()

    # Execute & Verify: Wrong key should fail
    handler = MCPAuthService()
    with pytest.raises(MCPAuthenticationError, match="Invalid API key"):
        await handler.authenticate_mcp_agent(
            session=test_session,
            agent_id=test_agent.agent_id,
            api_key="wrong-api-key-abc",  # Different key
            tool_name="test_tool",
        )


@pytest.mark.asyncio
async def test_api_key_auth_with_empty_hash_component(test_session: AsyncSession):
    """Test API key auth handles edge case of 'salt:' or ':hash' format.

    This test verifies the fix handles malformed hashes where either
    salt or hash component is empty after split.
    """
    # Setup: Create agent with empty hash component
    test_agent = Agent(
        agent_id="test-agent-empty-hash",
        namespace="test-namespace",
        display_name="Test Agent Empty Hash",
        capabilities=["test"],
        status="active",
        metadata={"test": True},  # Add metadata to avoid _determine_agent_role bug
        api_key_hash="some_salt:",  # Empty hash component
    )
    test_session.add(test_agent)
    await test_session.commit()

    # Execute & Verify: Should fail (verify_password_with_salt checks for empty)
    handler = MCPAuthService()
    with pytest.raises(MCPAuthenticationError, match="Invalid API key"):
        await handler.authenticate_mcp_agent(
            session=test_session,
            agent_id=test_agent.agent_id,
            api_key="any-key",
            tool_name="test_tool",
        )
