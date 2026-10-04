"""Shared Pydantic schemas used across rules, features, and alerting.

NOTE: not part of the originally declared src/utils/ modules
(logger.py, config.py, constants.py, validators.py) - added in Phase 2
so rules, and later features/inference, share one definition of a TLS
session record and an alert instead of duplicating fields per module.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.utils.constants import Label


class TLSSessionRecord(BaseModel):
    """A single observed TLS handshake, as would eventually be produced by
    src/parsers/session_aggregator.py from Zeek ssl.log / conn.log rows.

    Phase 2 note: this is a synthetic stand-in until the real parser exists.
    Only fields needed by R01-R05 are required; everything else is optional
    so later phases can extend this record without breaking the rule engine.
    """

    session_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str
    destination_ip: str
    destination_service: str  # hostname, matched against ServicePolicy.hostname

    tls_version: str  # negotiated version, e.g. "TLSv1.3", "TLSv1.2"
    offered_groups: list[str] = Field(default_factory=list)  # client-offered groups
    selected_group: Optional[str] = None  # server-selected group
    key_share_length: Optional[int] = None  # bytes, negotiated key-share extension

    handshake_duration_ms: Optional[float] = None
    failed: bool = False

    extra: dict[str, Any] = Field(default_factory=dict)  # room for later parser fields


class RuleViolation(BaseModel):
    """A single triggered rule."""

    rule_id: str  # e.g. "R01"
    description: str
    severity: str  # "low" | "medium" | "high" | "critical"
    evidence: dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    """Matches the project's ALERT FORMAT spec exactly."""

    alert_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_service: str
    classification: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    rules_triggered: list[str] = Field(default_factory=list)
    model_scores: dict[str, float] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str


# --- Phase 3 additions: processed CSV row contract for baseline training ---

NUMERIC_FEATURE_COLUMNS: list[str] = [
    # cryptographic
    "key_share_length",
    "cert_size",
    "client_extension_count",
    "server_extension_count",
    # flow
    "flow_duration_ms",
    "total_packets",
    "client_packets",
    "server_packets",
    "total_bytes",
    "client_bytes",
    "server_bytes",
    "packet_size_mean",
    "packet_size_std",
    "packet_size_min",
    "packet_size_max",
    "retransmission_count",
    "tcp_reset_count",
    "handshake_packet_count",
    # timing
    "client_hello_to_server_hello_ms",
    "server_hello_to_completion_ms",
    "handshake_duration_ms",
    "mean_inter_arrival_ms",
    "inter_arrival_variance",
    "retry_count",
    "failure_rate",
    # Category D: optional endpoint/resource features
    "cpu_percent_mean",
    "cpu_percent_peak",
    "mem_percent_mean",
    "mem_percent_peak",
    "active_connection_count",
    "tls_error_count",
    "crypto_op_latency_ms",
]

CATEGORICAL_FEATURE_COLUMNS: list[str] = [
    "tls_version", "selected_group", "cipher_suite",
    "pqc_selected_flag", "classical_fallback_flag",
]
REQUIRED_ID_COLUMNS: list[str] = ["session_id", "experiment_id", "label"]
ALL_FEATURE_COLUMNS: list[str] = NUMERIC_FEATURE_COLUMNS + CATEGORICAL_FEATURE_COLUMNS


class SessionFeatureRow(BaseModel):
    """Row contract for data/processed/*.csv - one row per TLS handshake.
    Feature fields are Optional so missing values pass validation; the
    preprocessing pipeline in train_baseline.py handles imputation.
    """

    model_config = ConfigDict(extra="ignore")

    session_id: str
    experiment_id: str
    label: int = Field(ge=0, le=5)

    tls_version: Optional[str] = None
    selected_group: Optional[str] = None
    cipher_suite: Optional[str] = None

    key_share_length: Optional[float] = None
    cert_size: Optional[float] = None
    client_extension_count: Optional[float] = None
    server_extension_count: Optional[float] = None

    flow_duration_ms: Optional[float] = None
    total_packets: Optional[float] = None
    client_packets: Optional[float] = None
    server_packets: Optional[float] = None
    total_bytes: Optional[float] = None
    client_bytes: Optional[float] = None
    server_bytes: Optional[float] = None
    packet_size_mean: Optional[float] = None
    packet_size_std: Optional[float] = None
    packet_size_min: Optional[float] = None
    packet_size_max: Optional[float] = None
    retransmission_count: Optional[float] = None
    tcp_reset_count: Optional[float] = None
    handshake_packet_count: Optional[float] = None

    client_hello_to_server_hello_ms: Optional[float] = None
    server_hello_to_completion_ms: Optional[float] = None
    handshake_duration_ms: Optional[float] = None
    mean_inter_arrival_ms: Optional[float] = None
    inter_arrival_variance: Optional[float] = None
    retry_count: Optional[float] = None
    failure_rate: Optional[float] = None

    pqc_selected_flag: Optional[str] = None
    classical_fallback_flag: Optional[str] = None

    cpu_percent_mean: Optional[float] = None
    cpu_percent_peak: Optional[float] = None
    mem_percent_mean: Optional[float] = None
    mem_percent_peak: Optional[float] = None
    active_connection_count: Optional[float] = None
    tls_error_count: Optional[float] = None
    crypto_op_latency_ms: Optional[float] = None

    @field_validator("label")
    @classmethod
    def _label_is_known(cls, v: int) -> int:
        try:
            Label(v)
        except ValueError as exc:
            raise ValueError(f"label {v} is not one of the six defined project labels (0-5)") from exc
        return v
