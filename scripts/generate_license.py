#!/usr/bin/env python3
"""
TMWS License Key Generator

Generates valid license keys for TMWS and saves them to the database.

Usage:
    # Generate a FREE perpetual license
    python scripts/generate_license.py --tier FREE --agent-id <UUID>

    # Generate a PRO license with 365-day expiration
    python scripts/generate_license.py --tier PRO --agent-id <UUID> --expires-days 365

    # Generate license for a new agent (auto-create agent if not exists)
    python scripts/generate_license.py --tier ENTERPRISE --namespace "my-team" --auto-create-agent

Examples:
    # For existing agent
    python scripts/generate_license.py --tier FREE --agent-id 550e8400-e29b-41d4-a716-446655440000

    # For new agent (auto-create)
    python scripts/generate_license.py --tier PRO --namespace "team-alpha" --auto-create-agent --expires-days 365

Output:
    - License key printed to stdout
    - License metadata saved to database
    - Ready to use in TMWS_LICENSE_KEY environment variable
"""

import asyncio
import os
import sys
from pathlib import Path
from uuid import UUID, uuid4

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv(project_root / ".env")

from src.core.database import get_db_session
from src.models.agent import Agent
from src.services.license_service import LicenseService, TierEnum
from sqlalchemy import select


async def ensure_agent_exists(
    session, agent_id: UUID | None, namespace: str | None
) -> UUID:
    """
    Ensure an agent exists in the database.

    If agent_id is provided, verify it exists.
    If namespace is provided, create a new agent.

    Args:
        session: Database session
        agent_id: Optional existing agent ID
        namespace: Optional namespace for new agent

    Returns:
        UUID of the agent (existing or newly created)

    Raises:
        ValueError: If agent_id doesn't exist or neither agent_id nor namespace provided
    """
    if agent_id is not None:
        # Verify existing agent
        stmt = select(Agent).where(Agent.id == str(agent_id))
        result = await session.execute(stmt)
        agent = result.scalar_one_or_none()

        if agent is None:
            raise ValueError(f"Agent not found: {agent_id}")

        print(f"✅ Found existing agent: {agent.namespace} (ID: {agent_id})")
        return agent_id

    elif namespace is not None:
        # Create new agent
        new_agent_id = uuid4()
        agent = Agent(
            id=str(new_agent_id),
            agent_id=f"agent-{namespace}",
            display_name=namespace.replace("-", " ").title(),
            namespace=namespace,
            capabilities={},
            config={},
            default_access_level="private",
            status="active",
            health_score=100.0,
            total_memories=0,
            total_tasks=0,
            successful_tasks=0,
        )
        session.add(agent)
        await session.commit()
        await session.refresh(agent)

        print(f"✅ Created new agent: {namespace} (ID: {new_agent_id})")
        return new_agent_id

    else:
        raise ValueError("Either --agent-id or --namespace (with --auto-create-agent) must be provided")


async def generate_license(
    agent_id: UUID | None,
    namespace: str | None,
    tier: str,
    expires_days: int | None,
    auto_create_agent: bool,
) -> None:
    """
    Generate a license key and save to database.

    Args:
        agent_id: Existing agent ID (or None if creating new)
        namespace: Namespace for new agent (or None if using existing)
        tier: License tier (FREE, PRO, ENTERPRISE)
        expires_days: Days until expiration (None = perpetual)
        auto_create_agent: Whether to create agent if namespace provided
    """
    async with get_db_session() as session:
        # 1. Ensure agent exists
        if auto_create_agent and namespace:
            final_agent_id = await ensure_agent_exists(session, None, namespace)
        elif agent_id:
            final_agent_id = await ensure_agent_exists(session, agent_id, None)
        else:
            raise ValueError("Either --agent-id or --namespace (with --auto-create-agent) required")

        # 2. Generate license key
        service = LicenseService(session)

        try:
            tier_enum = TierEnum[tier.upper()]
        except KeyError:
            raise ValueError(f"Invalid tier: {tier}. Must be one of: FREE, PRO, ENTERPRISE")

        print(f"\n🔑 Generating {tier} license key...")

        license_key = await service.generate_license_key(
            agent_id=final_agent_id,
            tier=tier_enum,
            expires_days=expires_days,
        )

        # 3. Output results
        print("\n" + "=" * 80)
        print("✅ LICENSE KEY GENERATED SUCCESSFULLY")
        print("=" * 80)
        print(f"\nLicense Key:\n{license_key}")
        print(f"\nAgent ID: {final_agent_id}")
        print(f"Tier: {tier}")

        if expires_days:
            print(f"Expires: {expires_days} days from now")
        else:
            print("Expires: NEVER (perpetual license)")

        print("\n" + "=" * 80)
        print("NEXT STEPS")
        print("=" * 80)
        print("\n1. Add to .env file:")
        print(f"   TMWS_LICENSE_KEY={license_key}")
        print("\n2. Or set as environment variable:")
        print(f"   export TMWS_LICENSE_KEY='{license_key}'")
        print("\n3. Or add to docker-compose.yml:")
        print("   environment:")
        print(f"     - TMWS_LICENSE_KEY={license_key}")
        print("\n" + "=" * 80)


def main():
    """Main entry point with argument parsing."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate TMWS license keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Agent identification (mutually exclusive)
    agent_group = parser.add_mutually_exclusive_group(required=True)
    agent_group.add_argument(
        "--agent-id",
        type=str,
        help="Existing agent UUID (e.g., 550e8400-e29b-41d4-a716-446655440000)",
    )
    agent_group.add_argument(
        "--namespace",
        type=str,
        help="Namespace for new agent (requires --auto-create-agent)",
    )

    # License configuration
    parser.add_argument(
        "--tier",
        required=True,
        choices=["FREE", "PRO", "ENTERPRISE"],
        help="License tier",
    )
    parser.add_argument(
        "--expires-days",
        type=int,
        help="Days until expiration (omit for perpetual license)",
    )

    # Agent creation flag
    parser.add_argument(
        "--auto-create-agent",
        action="store_true",
        help="Auto-create agent if --namespace is provided",
    )

    args = parser.parse_args()

    # Validation: --namespace requires --auto-create-agent
    if args.namespace and not args.auto_create_agent:
        parser.error("--namespace requires --auto-create-agent flag")

    # Parse agent_id if provided
    agent_uuid = None
    if args.agent_id:
        try:
            agent_uuid = UUID(args.agent_id)
        except ValueError:
            parser.error(f"Invalid UUID format: {args.agent_id}")

    # Validation: expires_days must be positive
    if args.expires_days is not None and args.expires_days <= 0:
        parser.error("--expires-days must be positive")

    # Run async generator
    try:
        asyncio.run(
            generate_license(
                agent_id=agent_uuid,
                namespace=args.namespace,
                tier=args.tier,
                expires_days=args.expires_days,
                auto_create_agent=args.auto_create_agent,
            )
        )
    except Exception as e:
        print(f"\n❌ ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
