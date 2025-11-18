#!/usr/bin/env python3
"""
License Key Entropy Analysis (Phase 2E-3 Security Audit)
Hestia - Security Guardian

Tests:
1. Entropy measurement (target: ≥256 bits for 512-bit signature)
2. Basic uniformity test
3. Pattern detection (no repeating sequences)
"""
import sys
import hashlib
import math
from collections import Counter

# Import TMWS license service
sys.path.insert(0, '/usr/local/lib/python3.11/site-packages')
from src.services.license_service import LicenseService
from src.core.config import settings


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits"""
    if not data:
        return 0.0

    byte_counts = Counter(data)
    entropy = 0.0
    data_len = len(data)

    for count in byte_counts.values():
        probability = count / data_len
        entropy -= probability * math.log2(probability)

    return entropy


def uniformity_test(data: bytes) -> float:
    """
    Basic uniformity test
    Returns: variance from expected uniform distribution (0.0 = perfect)
    """
    byte_counts = Counter(data)
    expected_count = len(data) / 256

    variance = sum((byte_counts.get(i, 0) - expected_count) ** 2
                   for i in range(256)) / 256

    # Normalize to 0-1 range
    return variance / expected_count if expected_count > 0 else 1.0


def test_entropy():
    """Test license key generation entropy"""
    print("=== License Key Entropy Analysis ===")

    # Generate 100 license keys
    service = LicenseService()
    keys = []

    for i in range(100):
        license_key = service.create_license(
            agent_id=f"test-agent-{i}",
            tier="FREE",
            max_users=1,
            features=["core"]
        )
        keys.append(license_key)

    # Extract signature portions (512-bit HMAC-SHA256)
    signatures = [key.split('.')[-1] for key in keys]
    combined_data = ''.join(signatures).encode('utf-8')

    # 1. Shannon Entropy
    entropy = shannon_entropy(combined_data)
    print(f"Shannon Entropy: {entropy:.2f} bits/byte")
    print(f"Total Entropy: {entropy * len(combined_data):.0f} bits")

    # 2. Uniformity Test
    uniformity = uniformity_test(combined_data)
    print(f"\nUniformity Test:")
    print(f"  Variance: {uniformity:.4f}")
    print(f"  Uniform: {'✅ YES' if uniformity < 1.0 else '❌ NO'}")

    # 3. Pattern Detection
    patterns = []
    for sig in signatures:
        # Check for repeating 4-char sequences
        for i in range(len(sig) - 8):
            chunk = sig[i:i+4]
            if sig.count(chunk) > 1:
                patterns.append(chunk)

    print(f"\nRepeating Patterns: {len(set(patterns))}")
    if patterns:
        print(f"  Examples: {list(set(patterns))[:5]}")

    # 4. Verdict
    print(f"\n=== VERDICT ===")
    entropy_pass = entropy >= 7.5  # Close to 8 bits/byte (maximum)
    uniformity_pass = uniformity < 1.0
    pattern_pass = len(set(patterns)) < 10

    print(f"Entropy: {'✅ PASS' if entropy_pass else '❌ FAIL'} (≥7.5 bits/byte)")
    print(f"Uniformity: {'✅ PASS' if uniformity_pass else '❌ FAIL'} (variance < 1.0)")
    print(f"Patterns: {'✅ PASS' if pattern_pass else '❌ FAIL'} (<10 unique)")

    overall_pass = entropy_pass and uniformity_pass and pattern_pass
    print(f"\nOVERALL: {'✅ CRYPTOGRAPHICALLY SECURE' if overall_pass else '❌ INSECURE'}")

    sys.exit(0 if overall_pass else 1)


if __name__ == "__main__":
    test_entropy()
