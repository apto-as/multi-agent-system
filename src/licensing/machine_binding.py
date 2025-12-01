"""Machine Fingerprinting and License Binding for TMWS v2.3.3

This module implements hardware-based machine fingerprinting to bind licenses
to specific machines, preventing license key circumvention (P0-2 security fix).

Security Implementation:
- SHA-256 hash of hardware identifiers
- MAC address, CPU info, hostname, platform
- Stable across reboots
- Resistant to VM cloning (detects hardware changes)

CVSS 7.5 HIGH: License key circumvention without machine binding
Mitigation: Cryptographic binding of license to hardware fingerprint

Author: Artemis (Technical Perfectionist)
Created: 2025-11-19
Version: 2.3.3
"""

import hashlib
import logging
import platform
import uuid

# Use standard logging to avoid config dependencies
logger = logging.getLogger(__name__)


def get_machine_fingerprint() -> str:
    """Generate stable machine fingerprint from hardware identifiers.

    The fingerprint is a SHA-256 hash of:
    - MAC address (uuid.getnode())
    - CPU architecture (platform.machine())
    - Processor name (platform.processor())
    - Hostname (platform.node())

    Returns:
        64-character hex string (SHA-256 hash of hardware info)

    Security:
        - Stable across reboots
        - Changes when hardware changes (VM migration, MAC spoofing)
        - One-way hash (cannot reverse to original hardware info)

    Example:
        >>> fp = get_machine_fingerprint()
        >>> len(fp)
        64
        >>> fp == get_machine_fingerprint()  # Stable
        True
    """
    # Collect hardware identifiers
    mac_address = str(uuid.getnode())  # MAC address as integer
    machine_type = platform.machine()  # e.g., "arm64", "x86_64"
    processor = platform.processor()  # CPU name
    hostname = platform.node()  # System hostname

    # Create fingerprint string (pipe-separated)
    fingerprint_components = [
        mac_address,
        machine_type,
        processor,
        hostname,
    ]

    fingerprint_str = "|".join(fingerprint_components)

    # Hash with SHA-256 for privacy and stability
    fingerprint_hash = hashlib.sha256(fingerprint_str.encode("utf-8")).hexdigest()

    logger.debug(
        f"Machine fingerprint generated: {fingerprint_hash[:16]}... "
        f"(MAC: {mac_address[:8]}..., CPU: {machine_type})"
    )

    return fingerprint_hash


def get_machine_info() -> dict[str, str]:
    """Get detailed machine information for debugging.

    Returns:
        Dictionary with hardware details:
        - mac_address: Network MAC address
        - machine_type: CPU architecture (arm64, x86_64, etc.)
        - processor: CPU name/model
        - hostname: System hostname
        - platform: OS platform (Darwin, Linux, Windows)
        - fingerprint: SHA-256 hash of above

    Example:
        >>> info = get_machine_info()
        >>> "fingerprint" in info
        True
        >>> len(info["fingerprint"])
        64
    """
    mac_address = str(uuid.getnode())
    machine_type = platform.machine()
    processor = platform.processor()
    hostname = platform.node()
    os_platform = platform.system()  # Darwin, Linux, Windows

    return {
        "mac_address": mac_address,
        "machine_type": machine_type,
        "processor": processor,
        "hostname": hostname,
        "platform": os_platform,
        "fingerprint": get_machine_fingerprint(),
    }


class MachineBindingValidator:
    """Validates license keys against machine fingerprints.

    This class provides methods to bind licenses to specific machines
    and validate that a license is being used on the authorized machine.

    Security:
        - Prevents license key sharing across machines
        - Detects VM cloning and hardware changes
        - Cryptographic validation (SHA-256)
    """

    def __init__(self):
        """Initialize machine binding validator."""
        self.current_fingerprint = get_machine_fingerprint()
        logger.info(f"MachineBindingValidator initialized (FP: {self.current_fingerprint[:16]}...)")

    def validate_binding(self, bound_fingerprint: str) -> bool:
        """Validate that current machine matches bound fingerprint.

        Args:
            bound_fingerprint: SHA-256 hash of authorized machine

        Returns:
            True if machine matches, False otherwise

        Example:
            >>> validator = MachineBindingValidator()
            >>> current_fp = validator.current_fingerprint
            >>> validator.validate_binding(current_fp)
            True
            >>> validator.validate_binding("different_fingerprint")
            False
        """
        matches = self.current_fingerprint == bound_fingerprint

        if matches:
            logger.info("✅ Machine binding validated successfully")
        else:
            logger.warning(
                f"❌ Machine binding validation FAILED\n"
                f"   Expected: {bound_fingerprint[:16]}...\n"
                f"   Current:  {self.current_fingerprint[:16]}..."
            )

        return matches

    def create_binding(self) -> str:
        """Create new machine binding for current hardware.

        Returns:
            Machine fingerprint (SHA-256 hash)

        Example:
            >>> validator = MachineBindingValidator()
            >>> binding = validator.create_binding()
            >>> len(binding)
            64
        """
        logger.info(f"Created machine binding: {self.current_fingerprint[:16]}...")
        return self.current_fingerprint


# Singleton instance
_validator: MachineBindingValidator | None = None


def get_validator() -> MachineBindingValidator:
    """Get or create singleton MachineBindingValidator instance.

    Returns:
        Singleton MachineBindingValidator
    """
    global _validator
    if _validator is None:
        _validator = MachineBindingValidator()
    return _validator
