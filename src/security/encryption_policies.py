"""Cross-Agent Access Policies for Field-Level Encryption.

Unified access control logic for Memory and FieldEncryption.

Hestia's Paranoid Security: 5 Access Levels Implementation
"""

import logging
from typing import Any

from src.models.agent import AccessLevel

logger = logging.getLogger(__name__)


class CrossAgentAccessPolicy:
    """Unified cross-agent access policy checker.

    This class centralizes access control logic for both:
    - Memory model (memory.py:158-200)
    - FieldEncryption (data_encryption.py)

    Philosophy:
    - DRY: Single source of truth for access control
    - Zero Trust: Verify every access attempt
    - Fail Closed: Deny on error or missing metadata
    """

    @staticmethod
    def check_access(
        *,
        owner_agent_id: str,
        owner_namespace: str,
        requesting_agent_id: str,
        requesting_namespace: str,
        access_level: AccessLevel | str,
        shared_with_agents: list[str] | None = None,
    ) -> tuple[bool, str]:
        """Check if requesting agent can access data.

        Args:
            owner_agent_id: ID of data owner
            owner_namespace: Verified namespace of owner (from DB)
            requesting_agent_id: ID of requesting agent
            requesting_namespace: Verified namespace of requester (MUST be from DB)
            access_level: Access level (enum or string)
            shared_with_agents: Explicit sharing list (for SHARED level)

        Returns:
            tuple[bool, str]: (is_allowed, reason)

        Security Notes:
            - Both namespaces MUST be verified from database
            - Never accept namespace from JWT claims directly
            - Always fail closed (deny on error)
        """
        # Convert string to enum if needed
        if isinstance(access_level, str):
            try:
                access_level = AccessLevel(access_level)
            except ValueError:
                logger.error(f"Invalid access_level: {access_level}")
                return (False, f"Invalid access level: {access_level}")

        # 1. PRIVATE: Owner only
        if access_level == AccessLevel.PRIVATE:
            if requesting_agent_id == owner_agent_id:
                return (True, "Owner access")
            else:
                return (False, "Access denied: PRIVATE data (owner only)")

        # 2. TEAM: Same namespace
        elif access_level == AccessLevel.TEAM:
            # Owner always has access
            if requesting_agent_id == owner_agent_id:
                return (True, "Owner access")

            # SECURITY FIX: Verify namespace matches AND it's the owner's namespace
            # This prevents cross-namespace access attacks
            if requesting_namespace == owner_namespace:
                return (True, f"Team access (namespace: {owner_namespace})")
            else:
                return (
                    False,
                    (
                        f"Access denied: Different namespace "
                        f"(owner: {owner_namespace}, requester: {requesting_namespace})"
                    ),
                )

        # 3. SHARED: Explicit agent list
        elif access_level == AccessLevel.SHARED:
            # Owner always has access
            if requesting_agent_id == owner_agent_id:
                return (True, "Owner access")

            # Must be explicitly shared with this agent
            if not shared_with_agents or requesting_agent_id not in shared_with_agents:
                return (
                    False,
                    (
                        f"Access denied: Not in shared agent list "
                        f"(allowed: {shared_with_agents or []})"
                    ),
                )

            # Additional check: verify namespace matches
            # This prevents namespace spoofing attacks
            if requesting_namespace != owner_namespace:
                return (
                    False,
                    (
                        f"Access denied: Namespace mismatch in SHARED access "
                        f"(owner: {owner_namespace}, requester: {requesting_namespace})"
                    ),
                )

            return (True, f"Shared access (agent: {requesting_agent_id})")

        # 4. PUBLIC: All agents
        elif access_level == AccessLevel.PUBLIC:
            return (True, "Public access")

        # 5. SYSTEM: All agents (system-level knowledge)
        elif access_level == AccessLevel.SYSTEM:
            return (True, "System-level access")

        else:
            logger.error(f"Unknown access level: {access_level}")
            return (False, f"Unknown access level: {access_level}")

    @staticmethod
    def validate_metadata(metadata: dict[str, Any]) -> tuple[bool, str | None]:
        """Validate encryption metadata for access control.

        Args:
            metadata: Encryption metadata dict

        Returns:
            tuple[bool, str | None]: (is_valid, error_message)

        Note:
            Backward compatibility: v1.0 metadata (encryption_version < 2.0)
            doesn't require 'namespace' and 'access_level' fields.
        """
        # agent_id is always required
        if "agent_id" not in metadata:
            return (False, "Missing required field: agent_id")

        # Check if this is v2.0+ metadata (has access control fields)
        encryption_version = metadata.get("encryption_version", "1.0")
        is_v2_or_later = encryption_version >= "2.0"

        # For v2.0+, namespace and access_level are required
        if is_v2_or_later:
            required_fields = ["namespace", "access_level"]
            for field in required_fields:
                if field not in metadata:
                    return (False, f"Missing required field: {field}")

        # Validate access_level value
        access_level = metadata.get("access_level")
        if isinstance(access_level, str):
            try:
                AccessLevel(access_level)
            except ValueError:
                return (False, f"Invalid access_level: {access_level}")

        # If SHARED, must have shared_with_agents
        if metadata.get("access_level") == AccessLevel.SHARED.value and (
            "shared_with_agents" not in metadata
            or not isinstance(metadata["shared_with_agents"], list)
        ):
            return (
                False,
                "SHARED access level requires 'shared_with_agents' list",
            )

        return (True, None)


__all__ = ["CrossAgentAccessPolicy"]
