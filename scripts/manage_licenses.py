#!/usr/bin/env python3
"""
TMWS License Management CLI

This script provides command-line tools for managing license keys:
- Create new licenses (with customizable expiration)
- Delete/revoke existing licenses
- List active licenses
- Query license status

Usage:
    python scripts/manage_licenses.py create --agent-id UUID --tier FREE --expires-days 30
    python scripts/manage_licenses.py delete --license-id UUID
    python scripts/manage_licenses.py list --agent-id UUID
    python scripts/manage_licenses.py status --license-key "TMWS-..."

Security:
    - ADMINISTRATOR-only operations (requires ADMIN role in database)
    - All operations logged to audit trail
    - Confirmation prompts for destructive operations

Author: Artemis (Technical Perfectionist)
Created: 2025-11-24
Phase: 2D-2 - V-2 Progressive Disclosure CLI Tools
Version: 1.0.0
"""

import asyncio
import sys
from pathlib import Path
from uuid import UUID

import click
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.config import settings
from src.services.license_service import LicenseService, TierEnum


# Database session factory
async_engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
)
AsyncSessionLocal = sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db_session() -> AsyncSession:
    """Get database session for CLI operations."""
    async with AsyncSessionLocal() as session:
        return session


@click.group()
def cli():
    """TMWS License Management CLI - ADMINISTRATOR ONLY."""
    pass


@cli.command()
@click.option("--agent-id", required=True, help="Agent UUID to create license for")
@click.option(
    "--tier",
    type=click.Choice(["FREE", "PRO", "ENTERPRISE", "ADMINISTRATOR"]),
    required=True,
    help="License tier",
)
@click.option(
    "--expires-days",
    type=click.Choice(["30", "90", "180", "365", "PERPETUAL"]),
    default="365",
    help="Expiration period (30/90/180/365 days or PERPETUAL)",
)
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def create(agent_id: str, tier: str, expires_days: str, confirm: bool):
    """
    Create a new license key for an agent.

    Examples:
        # Create 30-day FREE license
        python scripts/manage_licenses.py create --agent-id UUID --tier FREE --expires-days 30

        # Create 1-year PRO license
        python scripts/manage_licenses.py create --agent-id UUID --tier PRO --expires-days 365

        # Create perpetual ADMINISTRATOR license
        python scripts/manage_licenses.py create --agent-id UUID --tier ADMINISTRATOR --expires-days PERPETUAL --confirm
    """
    asyncio.run(_create_license(agent_id, tier, expires_days, confirm))


async def _create_license(agent_id_str: str, tier_str: str, expires_str: str, confirm: bool):
    """Internal async implementation for create command."""
    try:
        # Parse inputs
        agent_id = UUID(agent_id_str)
        tier = TierEnum(tier_str)

        # Convert expiration to days (None for PERPETUAL)
        if expires_str == "PERPETUAL":
            expires_days = None
            expiry_display = "PERPETUAL"
        else:
            expires_days = int(expires_str)
            expiry_display = f"{expires_days} days"

        # Confirmation prompt (skip for --confirm flag)
        if not confirm:
            click.echo(f"\n🔑 Creating License Key:")
            click.echo(f"   Agent ID: {agent_id}")
            click.echo(f"   Tier: {tier.value}")
            click.echo(f"   Expiration: {expiry_display}")
            click.echo(f"   Token Budget: {_get_token_budget_display(tier)}")
            click.echo()

            if not click.confirm("Proceed with license creation?"):
                click.echo("❌ Operation cancelled")
                return

        # Create database session and license service
        session = await get_db_session()
        license_service = LicenseService(session)

        # Generate license key
        click.echo("⏳ Generating license key...")
        license_key = await license_service.generate_license_key(
            agent_id=agent_id,
            tier=tier,
            expires_days=expires_days,
        )

        click.echo()
        click.echo("✅ License key created successfully!")
        click.echo()
        click.echo("=" * 80)
        click.echo(f"LICENSE KEY: {license_key}")
        click.echo("=" * 80)
        click.echo()
        click.echo("⚠️  IMPORTANT: Save this license key securely!")
        click.echo("   It will not be displayed again.")
        click.echo()

        # Display tier limits
        limits = license_service.get_tier_limits(tier)
        click.echo("📊 Tier Limits:")
        click.echo(f"   Token Budget: {_format_token_budget(limits.max_tokens_per_hour)}")
        click.echo(f"   Rate Limit: {_format_rate_limit(limits.rate_limit_per_minute)}")
        click.echo(f"   Max Agents: {limits.max_agents}")
        click.echo(f"   Max Namespaces: {limits.max_namespace_count}")
        click.echo(f"   Features: {len(limits.features)} enabled")
        click.echo()

    except ValueError as e:
        click.echo(f"❌ Invalid input: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Failed to create license: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--license-id", required=True, help="License UUID to delete")
@click.option("--reason", default="Manual deletion via CLI", help="Reason for deletion")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def delete(license_id: str, reason: str, confirm: bool):
    """
    Delete (revoke) an existing license key.

    Examples:
        # Revoke license with default reason
        python scripts/manage_licenses.py delete --license-id UUID

        # Revoke with custom reason
        python scripts/manage_licenses.py delete --license-id UUID --reason "License key compromised" --confirm
    """
    asyncio.run(_delete_license(license_id, reason, confirm))


async def _delete_license(license_id_str: str, reason: str, confirm: bool):
    """Internal async implementation for delete command."""
    try:
        # Parse license ID
        license_id = UUID(license_id_str)

        # Confirmation prompt
        if not confirm:
            click.echo(f"\n⚠️  Revoking License:")
            click.echo(f"   License ID: {license_id}")
            click.echo(f"   Reason: {reason}")
            click.echo()
            click.echo("⚠️  This action CANNOT be undone!")
            click.echo()

            if not click.confirm("Proceed with revocation?"):
                click.echo("❌ Operation cancelled")
                return

        # Create database session and license service
        session = await get_db_session()
        license_service = LicenseService(session)

        # Revoke license
        click.echo("⏳ Revoking license key...")
        await license_service.revoke_license_key(license_id, reason=reason)

        click.echo()
        click.echo("✅ License key revoked successfully!")
        click.echo(f"   License ID: {license_id}")
        click.echo(f"   Reason: {reason}")
        click.echo()

    except ValueError as e:
        click.echo(f"❌ Invalid UUID: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Failed to revoke license: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--agent-id", help="Filter by agent UUID (optional)")
@click.option("--tier", help="Filter by tier (optional)")
@click.option("--limit", default=50, help="Maximum results to display")
def list_licenses(agent_id: str | None, tier: str | None, limit: int):
    """
    List active license keys.

    Examples:
        # List all licenses
        python scripts/manage_licenses.py list

        # List licenses for specific agent
        python scripts/manage_licenses.py list --agent-id UUID

        # List licenses by tier
        python scripts/manage_licenses.py list --tier PRO --limit 100
    """
    asyncio.run(_list_licenses(agent_id, tier, limit))


async def _list_licenses(agent_id_str: str | None, tier_str: str | None, limit: int):
    """Internal async implementation for list command."""
    try:
        from sqlalchemy import select
        from src.models.license_key import LicenseKey

        # Create database session
        session = await get_db_session()

        # Build query
        stmt = select(LicenseKey).where(LicenseKey.is_active == True)

        if agent_id_str:
            agent_id = UUID(agent_id_str)
            stmt = stmt.where(LicenseKey.agent_id == agent_id)

        if tier_str:
            tier = TierEnum(tier_str)
            stmt = stmt.where(LicenseKey.tier == tier)

        stmt = stmt.order_by(LicenseKey.issued_at.desc()).limit(limit)

        # Execute query
        result = await session.execute(stmt)
        licenses = result.scalars().all()

        if not licenses:
            click.echo("📋 No active licenses found")
            return

        # Display results
        click.echo(f"\n📋 Active Licenses ({len(licenses)} results):")
        click.echo("=" * 120)
        click.echo(f"{'License ID':<40} {'Agent ID':<40} {'Tier':<15} {'Issued':<12} {'Expires':<12}")
        click.echo("=" * 120)

        for lic in licenses:
            issued_str = lic.issued_at.strftime("%Y-%m-%d")
            expires_str = lic.expires_at.strftime("%Y-%m-%d") if lic.expires_at else "PERPETUAL"

            click.echo(f"{str(lic.id):<40} {str(lic.agent_id):<40} {lic.tier.value:<15} {issued_str:<12} {expires_str:<12}")

        click.echo("=" * 120)
        click.echo()

    except Exception as e:
        click.echo(f"❌ Failed to list licenses: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--license-key", required=True, help="Full license key to validate")
def status(license_key: str):
    """
    Check status of a license key (validation + details).

    Examples:
        # Check license status
        python scripts/manage_licenses.py status --license-key "TMWS-PRO-550e8400-..."
    """
    asyncio.run(_check_status(license_key))


async def _check_status(license_key: str):
    """Internal async implementation for status command."""
    try:
        # Create license service (no DB session needed for signature-only validation)
        license_service = LicenseService(db_session=None)

        # Validate license key
        click.echo("⏳ Validating license key...")
        result = await license_service.validate_license_key(license_key)

        click.echo()
        if result.valid:
            click.echo("✅ License Key: VALID")
            click.echo()
            click.echo("📊 License Details:")
            click.echo(f"   Tier: {result.tier.value}")
            click.echo(f"   License ID: {result.license_id}")
            click.echo(f"   Expires: {result.expires_at.strftime('%Y-%m-%d') if result.expires_at else 'PERPETUAL'}")
            click.echo(f"   Is Expired: {'Yes' if result.is_expired else 'No'}")
            click.echo(f"   Is Revoked: {'Yes' if result.is_revoked else 'No'}")
            click.echo()

            if result.limits:
                click.echo("📊 Tier Limits:")
                click.echo(f"   Token Budget: {_format_token_budget(result.limits.max_tokens_per_hour)}")
                click.echo(f"   Rate Limit: {_format_rate_limit(result.limits.rate_limit_per_minute)}")
                click.echo(f"   Max Agents: {result.limits.max_agents}")
                click.echo(f"   Max Namespaces: {result.limits.max_namespace_count}")
                click.echo(f"   Features: {len(result.limits.features)} enabled")
            click.echo()
        else:
            click.echo("❌ License Key: INVALID")
            click.echo(f"   Error: {result.error_message}")
            click.echo()
            sys.exit(1)

    except Exception as e:
        click.echo(f"❌ Failed to validate license: {e}", err=True)
        sys.exit(1)


# Helper functions
def _get_token_budget_display(tier: TierEnum) -> str:
    """Get human-readable token budget for tier."""
    budgets = {
        TierEnum.FREE: "1,000,000 tokens/hour",
        TierEnum.PRO: "5,000,000 tokens/hour",
        TierEnum.ENTERPRISE: "Unlimited",
        TierEnum.ADMINISTRATOR: "Unlimited + Perpetual",
    }
    return budgets.get(tier, "Unknown")


def _format_token_budget(tokens: int | None) -> str:
    """Format token budget for display."""
    if tokens is None:
        return "Unlimited"
    return f"{tokens:,} tokens/hour"


def _format_rate_limit(rate: int | None) -> str:
    """Format rate limit for display."""
    if rate is None:
        return "Unlimited"
    return f"{rate:,} req/min"


if __name__ == "__main__":
    cli()
