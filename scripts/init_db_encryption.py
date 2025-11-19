#!/usr/bin/env python3
"""Initialize Database Encryption for TMWS v2.3.3

This script generates and saves an encryption key for SQLCipher database encryption.
Run this script once during initial setup or when rotating encryption keys.

Usage:
    python scripts/init_db_encryption.py [--force]

Options:
    --force    Overwrite existing encryption key (DANGEROUS: will make existing DB unreadable)

Security Warnings:
    - Backup existing encryption key before rotation
    - Encrypted databases cannot be read without the correct key
    - Lost keys = lost data (permanent)

Author: Artemis (Technical Perfectionist)
Created: 2025-11-19
Version: 2.3.3
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Direct import to avoid config dependency chain
import importlib.util
spec = importlib.util.spec_from_file_location(
    "db_encryption",
    Path(__file__).parent.parent / "src" / "security" / "db_encryption.py"
)
db_encryption_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(db_encryption_module)
DatabaseEncryptionService = db_encryption_module.DatabaseEncryptionService


def main():
    """Main entry point for encryption key initialization."""
    parser = argparse.ArgumentParser(
        description="Initialize TMWS database encryption key",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate new key (safe, won't overwrite existing):
  python scripts/init_db_encryption.py

  # Force overwrite existing key (DANGEROUS):
  python scripts/init_db_encryption.py --force

Security Notes:
  - Keys are stored in ~/.tmws/secrets/ with 0o600 permissions
  - Backup keys before rotation
  - Never commit keys to version control
  - Lost keys = lost data
        """,
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing encryption key (DANGEROUS)",
    )

    args = parser.parse_args()

    # Initialize encryption service
    service = DatabaseEncryptionService()

    # Check if key already exists
    if service.key_exists():
        key_path = service.secrets_dir / "db_encryption.key"

        if not args.force:
            print(f"❌ ERROR: Encryption key already exists: {key_path}")
            print()
            print("📋 Options:")
            print("  1. Use existing key (recommended)")
            print("  2. Backup existing key and run with --force to rotate")
            print()
            print("⚠️ WARNING: Rotating keys will make existing encrypted DB unreadable")
            print("            unless you decrypt and re-encrypt with new key.")
            print()
            sys.exit(1)
        else:
            print(f"⚠️ WARNING: Overwriting existing key: {key_path}")
            print()
            response = input("Type 'YES' to confirm: ")
            if response != "YES":
                print("❌ Aborted")
                sys.exit(1)

    # Generate new encryption key
    print("🔐 Generating 256-bit encryption key...")
    encryption_key = service.generate_encryption_key()

    # Save key to secure storage
    print("💾 Saving encryption key...")
    key_path = service.save_encryption_key(encryption_key)

    # Display success message
    print()
    print("✅ SUCCESS: Encryption key initialized")
    print()
    print(f"📁 Key location: {key_path}")
    print(f"🔒 Permissions: 0o600 (owner read/write only)")
    print(f"🔐 Cipher: AES-256-GCM")
    print()
    print("⚠️ CRITICAL NEXT STEPS:")
    print("  1. Backup this key to secure location (e.g., password manager)")
    print("  2. Add ~/.tmws/secrets/ to .gitignore (if not already)")
    print("  3. Never commit this key to version control")
    print("  4. Test database encryption with: pytest tests/unit/security/test_db_encryption.py")
    print()
    print("🎯 Ready to use encrypted database!")
    print()


if __name__ == "__main__":
    main()
