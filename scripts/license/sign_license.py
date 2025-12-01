#!/usr/bin/env python3
"""
TMWS License Key Signing Tool

This script generates license keys signed with Ed25519.
REQUIRES the private key (trinitas_private.key).

Usage:
    python sign_license.py --tier PRO --expiry 365
    python sign_license.py --tier ENTERPRISE --perpetual
    python sign_license.py --tier ADMINISTRATOR --perpetual

License Key Format (Version 3 - Ed25519):
    TMWS-{TIER}-{UUID}-{EXPIRY}-{ED25519_SIGNATURE_B64}

    Example:
        TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-20261127-base64signature

Security:
    - Ed25519 signature (256-bit)
    - Base64 URL-safe encoding for signature
    - Only Trinitas can generate valid licenses

Author: Artemis (Technical Perfectionist)
Created: 2025-11-27
"""

import argparse
import base64
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("Error: cryptography package required")
    print("Install: pip install cryptography")
    sys.exit(1)


def load_private_key(key_path: Path) -> Ed25519PrivateKey:
    """Load Ed25519 private key from PEM file."""
    pem_data = key_path.read_bytes()
    return serialization.load_pem_private_key(pem_data, password=None)


def sign_license(
    private_key: Ed25519PrivateKey,
    tier: str,
    expires_days: int | None = None,
    license_id: str | None = None,
) -> str:
    """
    Generate a signed license key.

    Args:
        private_key: Ed25519 private key for signing
        tier: License tier (FREE, PRO, ENTERPRISE, ADMINISTRATOR)
        expires_days: Days until expiration (None = perpetual)
        license_id: Optional UUID (auto-generated if not provided)

    Returns:
        License key string
    """
    # Generate UUID if not provided
    if license_id is None:
        license_id = str(uuid4())

    # Calculate expiry
    if expires_days is None:
        expiry_str = "PERPETUAL"
    else:
        expiry_date = datetime.now(timezone.utc) + timedelta(days=expires_days)
        expiry_str = expiry_date.strftime("%Y%m%d")

    # Create data to sign
    signature_data = f"{tier}:{license_id}:{expiry_str}"

    # Sign with Ed25519
    signature = private_key.sign(signature_data.encode())

    # Encode signature as standard base64, then replace '+' and '/' with URL-safe chars
    # Standard base64 uses '+' and '/', which don't conflict with license key '-' separator
    # We replace: '+' -> '.' and '/' -> '~' and remove padding '='
    signature_b64 = base64.b64encode(signature).rstrip(b"=").decode()
    signature_b64 = signature_b64.replace("+", ".").replace("/", "~")

    # Assemble license key
    license_key = f"TMWS-{tier}-{license_id}-{expiry_str}-{signature_b64}"

    return license_key


def main():
    parser = argparse.ArgumentParser(description="Generate TMWS License Keys")
    parser.add_argument(
        "--tier",
        required=True,
        choices=["FREE", "PRO", "ENTERPRISE", "ADMINISTRATOR"],
        help="License tier",
    )
    parser.add_argument(
        "--expiry",
        type=int,
        default=None,
        help="Days until expiration (omit for perpetual)",
    )
    parser.add_argument(
        "--perpetual",
        action="store_true",
        help="Create perpetual license (no expiration)",
    )
    parser.add_argument(
        "--uuid",
        type=str,
        default=None,
        help="Specific UUID to use (auto-generated if not provided)",
    )
    parser.add_argument(
        "--key",
        type=str,
        default=None,
        help="Path to private key file (default: trinitas_private.key in same directory)",
    )

    args = parser.parse_args()

    # Determine key path
    if args.key:
        key_path = Path(args.key)
    else:
        key_path = Path(__file__).parent / "trinitas_private.key"

    if not key_path.exists():
        print(f"Error: Private key not found: {key_path}")
        print("Run generate_keys.py first to create key pair")
        sys.exit(1)

    # Load private key
    private_key = load_private_key(key_path)

    # Determine expiry
    expires_days = None if args.perpetual else args.expiry

    # Generate license
    license_key = sign_license(
        private_key=private_key,
        tier=args.tier,
        expires_days=expires_days,
        license_id=args.uuid,
    )

    print()
    print("=" * 70)
    print("TMWS License Key Generated")
    print("=" * 70)
    print()
    print(f"Tier:       {args.tier}")
    if expires_days:
        print(f"Expires:    {expires_days} days from now")
    else:
        print("Expires:    PERPETUAL (never)")
    print()
    print("License Key:")
    print("-" * 70)
    print(license_key)
    print("-" * 70)
    print()
    print("Add to .env file:")
    print(f'TMWS_LICENSE_KEY="{license_key}"')
    print()


if __name__ == "__main__":
    main()
