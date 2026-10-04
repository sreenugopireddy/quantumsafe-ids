"""Pydantic models and loader for the PQC policy YAML configuration
(configs/pqc_policy.yaml). Consumed by src/rules/rule_engine.py.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator


class KeyShareBounds(BaseModel):
    """Expected key-share length bounds (bytes) for a single KEM/group.
    Used by R05. Falls back to DEFAULT_KEY_SHARE_BOUNDS in constants.py
    when a service doesn't define an override for a given group.
    """

    min_bytes: int = Field(..., ge=0)
    max_bytes: int = Field(..., ge=0)

    @field_validator("max_bytes")
    @classmethod
    def _max_at_least_min(cls, v: int, info) -> int:
        min_bytes = info.data.get("min_bytes")
        if min_bytes is not None and v < min_bytes:
            raise ValueError("max_bytes must be >= min_bytes")
        return v


class ServicePolicy(BaseModel):
    """PQC security policy for a single TLS service, keyed by service
    name in the YAML file (e.g. 'pqc_api')."""

    hostname: str
    minimum_tls_version: str = "TLSv1.3"
    pqc_required: bool = False
    allowed_key_exchange_groups: list[str] = Field(default_factory=list)
    allow_classical_fallback: bool = True
    max_handshake_duration_ms: int = Field(default=2000, gt=0)
    max_handshakes_per_source_per_minute: int = Field(default=120, gt=0)
    max_failed_handshakes_per_source_per_minute: int = Field(default=20, gt=0)
    key_share_bounds: dict[str, KeyShareBounds] = Field(default_factory=dict)


class PQCPolicyConfig(BaseModel):
    """Top-level policy document: services -> ServicePolicy."""

    services: dict[str, ServicePolicy]

    def get_service(self, hostname: str) -> Optional[ServicePolicy]:
        """Look up a service policy by hostname (destination_service on a
        TLSSessionRecord)."""
        for policy in self.services.values():
            if policy.hostname == hostname:
                return policy
        return None


def load_policy(path: str | Path) -> PQCPolicyConfig:
    """Load and validate a PQC policy YAML file.

    Raises:
        FileNotFoundError: if `path` does not exist.
        pydantic.ValidationError: if the YAML content fails schema validation.
        yaml.YAMLError: if the file is not valid YAML.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"PQC policy file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return PQCPolicyConfig.model_validate(raw)