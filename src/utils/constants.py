"""Shared constants for QuantumSafe-IDS."""
from __future__ import annotations

from enum import IntEnum


class Label(IntEnum):
    """Canonical classification labels used throughout the project."""

    BENIGN_CLASSICAL = 0
    BENIGN_HYBRID_PQC = 1
    DOWNGRADE_VIOLATION = 2
    HANDSHAKE_EXHAUSTION = 3
    MALFORMED_HANDSHAKE = 4
    UNKNOWN_ANOMALY = 5


# Default expected key-share extension lengths (bytes) for well-known TLS 1.3
# key-exchange groups, used by R05 when a ServicePolicy does not define its
# own key_share_bounds override. These are protocol-level facts, not
# deployment policy, so they live in code rather than the YAML config.
#
# Verify against your actual PQC stack before relying on these beyond the
# lab MVP - hybrid KEM encodings can vary by implementation/draft version.
DEFAULT_KEY_SHARE_BOUNDS: dict[str, tuple[int, int]] = {
    "x25519": (32, 32),
    "secp256r1": (65, 65),
    "prime256v1": (65, 65),
    "x25519mlkem768": (1216, 1216),
}