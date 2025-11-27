#!/usr/bin/env python3
"""
TMWS License Key Management - Ed25519 Key Generation

This script generates Ed25519 key pairs for license signing.
The PRIVATE KEY is kept by Trinitas (never distributed).
The PUBLIC KEY is embedded in Docker images for verification.

Usage:
    python generate_keys.py

Output:
    - trinitas_private.key (SECRET - never distribute)
    - trinitas_public.key (safe to distribute)

Security:
    - Ed25519 provides 128-bit security level
    - Private key compromise = ability to forge licenses
    - Public key exposure = no security impact

Author: Artemis (Technical Perfectionist) + Hestia (Security Guardian)
Created: 2025-11-27
"""

import base64
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("Error: cryptography package required")
    print("Install: pip install cryptography")
    sys.exit(1)


def generate_ed25519_keypair(output_dir: Path = Path(".")):
    """Generate Ed25519 key pair for license signing."""

    # Generate private key
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize private key (PEM format)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key (PEM format)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Also get raw bytes for embedding
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    public_b64 = base64.b64encode(public_raw).decode()

    # Save files
    private_path = output_dir / "trinitas_private.key"
    public_path = output_dir / "trinitas_public.key"
    public_b64_path = output_dir / "trinitas_public.b64"

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    public_b64_path.write_text(public_b64)

    # Set restrictive permissions on private key
    private_path.chmod(0o600)

    print("=" * 60)
    print("TMWS Ed25519 Key Pair Generated")
    print("=" * 60)
    print()
    print(f"Private Key: {private_path}")
    print(f"  - KEEP SECRET - Never distribute!")
    print(f"  - Used for: License key signing")
    print(f"  - Permissions: 600 (owner read/write only)")
    print()
    print(f"Public Key (PEM): {public_path}")
    print(f"  - Safe to distribute")
    print(f"  - Used for: License key verification")
    print()
    print(f"Public Key (Base64): {public_b64_path}")
    print(f"  - For embedding in Docker images")
    print(f"  - Value: {public_b64}")
    print()
    print("=" * 60)
    print("NEXT STEPS:")
    print("=" * 60)
    print("1. Store trinitas_private.key in a secure location")
    print("2. Add public key to GitHub Secrets: TMWS_LICENSE_PUBLIC_KEY")
    print("3. Update Dockerfile to embed public key")
    print("4. Generate license keys using sign_license.py")
    print()

    return private_key, public_key


if __name__ == "__main__":
    output_dir = Path(__file__).parent
    generate_ed25519_keypair(output_dir)
