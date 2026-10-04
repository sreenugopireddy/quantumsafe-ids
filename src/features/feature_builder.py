"""Bridges parsed TLSSessionRecord objects (from
src/parsers/session_aggregator.py, or synthetic test fixtures) into the
flat CSV schema consumed by src/training/train_baseline.py.

Design note (Phase 4): TLSSessionRecord (Phase 2) only carries the fields
R01-R05 need. Every Category A-D field this module produces beyond that
minimal set is read from TLSSessionRecord.extra, which exists precisely
as this extensibility point. label and experiment_id are NOT part of
TLSSessionRecord - they are supplied separately, since a live-captured
session has no label at all; only lab/experiment-generated sessions do.
"""
from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from pydantic import ValidationError

from src.utils.schemas import (
    ALL_FEATURE_COLUMNS,
    CATEGORICAL_FEATURE_COLUMNS,
    NUMERIC_FEATURE_COLUMNS,
    SessionFeatureRow,
    TLSSessionRecord,
)

logger = logging.getLogger(__name__)

UNKNOWN = "UNKNOWN"

# Fixed vocabularies for categorical normalization. Any observed value not
# in the vocab collapses to UNKNOWN rather than passing through arbitrary
# strings into the trained model's one-hot encoder.
_TLS_VERSION_VOCAB = {"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
_GROUP_VOCAB = {"x25519", "secp256r1", "prime256v1", "X25519MLKEM768"}
_CIPHER_VOCAB = {
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
}
_BOOL_FLAG_VOCAB = {"true", "false"}


class FeatureBuildError(Exception):
    """Raised when session/label/experiment_id inputs are inconsistent, or
    when the built DataFrame fails schema validation. Carries all
    violations found, not just the first."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        preview = "\n".join(errors[:20])
        more = f"\n... and {len(errors) - 20} more" if len(errors) > 20 else ""
        super().__init__(f"{len(errors)} issue(s) building features:\n{preview}{more}")


def _normalize_categorical(value: Any, vocab: set[str]) -> str:
    """Return value if it's a known member of vocab, else UNKNOWN.
    None/NaN also map to UNKNOWN."""
    if value is None:
        return UNKNOWN
    text = str(value)
    return text if text in vocab else UNKNOWN


def _numeric_or_nan(value: Any) -> float:
    """Coerce to float, mapping None/missing/non-numeric to np.nan."""
    if value is None:
        return np.nan
    try:
        return float(value)
    except (TypeError, ValueError):
        return np.nan


class FeatureBuilder:
    """Builds the training CSV schema from a list of TLSSessionRecord
    objects plus externally supplied labels and experiment IDs.

    Args:
        sessions: parsed TLS sessions.
        labels: session_id -> label (0-5), one entry per session.
        experiment_ids: session_id -> experiment_id, one entry per session.
    """

    def __init__(
        self,
        sessions: list[TLSSessionRecord],
        labels: dict[str, int],
        experiment_ids: dict[str, str],
    ):
        self._validate_inputs(sessions, labels, experiment_ids)
        self.sessions = sessions
        self.labels = labels
        self.experiment_ids = experiment_ids

    @staticmethod
    def _validate_inputs(
        sessions: list[TLSSessionRecord],
        labels: dict[str, int],
        experiment_ids: dict[str, str],
    ) -> None:
        errors: list[str] = []
        seen_ids: set[str] = set()
        for session in sessions:
            if session.session_id in seen_ids:
                errors.append(f"duplicate session_id: {session.session_id!r}")
            seen_ids.add(session.session_id)
            if session.session_id not in labels:
                errors.append(f"session_id {session.session_id!r} has no entry in `labels`")
            if session.session_id not in experiment_ids:
                errors.append(f"session_id {session.session_id!r} has no entry in `experiment_ids`")
        if errors:
            raise FeatureBuildError(errors)

    # --- Category A: cryptographic features ---

    def _build_crypto_features(self, session: TLSSessionRecord) -> dict[str, Any]:
        extra = session.extra
        pqc_selected = session.selected_group in {"X25519MLKEM768"} if session.selected_group else None
        classical_fallback = extra.get("classical_fallback_flag")
        if classical_fallback is None and session.selected_group is not None:
            classical_fallback = session.selected_group not in {"X25519MLKEM768"}

        return {
            "tls_version": _normalize_categorical(session.tls_version, _TLS_VERSION_VOCAB),
            "selected_group": _normalize_categorical(session.selected_group, _GROUP_VOCAB),
            "cipher_suite": _normalize_categorical(extra.get("cipher_suite"), _CIPHER_VOCAB),
            "pqc_selected_flag": _normalize_categorical(
                str(pqc_selected).lower() if pqc_selected is not None else None, _BOOL_FLAG_VOCAB
            ),
            "classical_fallback_flag": _normalize_categorical(
                str(classical_fallback).lower() if classical_fallback is not None else None, _BOOL_FLAG_VOCAB
            ),
            "key_share_length": _numeric_or_nan(session.key_share_length),
            "cert_size": _numeric_or_nan(extra.get("cert_size")),
            "client_extension_count": _numeric_or_nan(extra.get("client_extension_count")),
            "server_extension_count": _numeric_or_nan(extra.get("server_extension_count")),
        }

    # --- Category B: flow features ---

    def _build_flow_features(self, session: TLSSessionRecord) -> dict[str, Any]:
        extra = session.extra
        return {
            "flow_duration_ms": _numeric_or_nan(extra.get("flow_duration_ms")),
            "total_packets": _numeric_or_nan(extra.get("total_packets")),
            "client_packets": _numeric_or_nan(extra.get("client_packets")),
            "server_packets": _numeric_or_nan(extra.get("server_packets")),
            "total_bytes": _numeric_or_nan(extra.get("total_bytes")),
            "client_bytes": _numeric_or_nan(extra.get("client_bytes")),
            "server_bytes": _numeric_or_nan(extra.get("server_bytes")),
            "packet_size_mean": _numeric_or_nan(extra.get("packet_size_mean")),
            "packet_size_std": _numeric_or_nan(extra.get("packet_size_std")),
            "packet_size_min": _numeric_or_nan(extra.get("packet_size_min")),
            "packet_size_max": _numeric_or_nan(extra.get("packet_size_max")),
            "retransmission_count": _numeric_or_nan(extra.get("retransmission_count")),
            "tcp_reset_count": _numeric_or_nan(extra.get("tcp_reset_count")),
            "handshake_packet_count": _numeric_or_nan(extra.get("handshake_packet_count")),
        }

    # --- Category C: timing features ---

    def _build_timing_features(self, session: TLSSessionRecord) -> dict[str, Any]:
        extra = session.extra
        return {
            "client_hello_to_server_hello_ms": _numeric_or_nan(extra.get("client_hello_to_server_hello_ms")),
            "server_hello_to_completion_ms": _numeric_or_nan(extra.get("server_hello_to_completion_ms")),
            "handshake_duration_ms": _numeric_or_nan(session.handshake_duration_ms),
            "mean_inter_arrival_ms": _numeric_or_nan(extra.get("mean_inter_arrival_ms")),
            "inter_arrival_variance": _numeric_or_nan(extra.get("inter_arrival_variance")),
            "retry_count": _numeric_or_nan(extra.get("retry_count")),
            "failure_rate": _numeric_or_nan(
                extra.get("failure_rate", 1.0 if session.failed else 0.0)
            ),
        }

    # --- Category D: optional endpoint/resource features ---

    def _build_endpoint_features(self, session: TLSSessionRecord) -> dict[str, Any]:
        extra = session.extra
        return {
            "cpu_percent_mean": _numeric_or_nan(extra.get("cpu_percent_mean")),
            "cpu_percent_peak": _numeric_or_nan(extra.get("cpu_percent_peak")),
            "mem_percent_mean": _numeric_or_nan(extra.get("mem_percent_mean")),
            "mem_percent_peak": _numeric_or_nan(extra.get("mem_percent_peak")),
            "active_connection_count": _numeric_or_nan(extra.get("active_connection_count")),
            "tls_error_count": _numeric_or_nan(extra.get("tls_error_count")),
            "crypto_op_latency_ms": _numeric_or_nan(extra.get("crypto_op_latency_ms")),
        }

    def _build_row(self, session: TLSSessionRecord) -> dict[str, Any]:
        row: dict[str, Any] = {
            "session_id": session.session_id,
            "experiment_id": self.experiment_ids[session.session_id],
            "label": self.labels[session.session_id],
        }
        row.update(self._build_crypto_features(session))
        row.update(self._build_flow_features(session))
        row.update(self._build_timing_features(session))
        row.update(self._build_endpoint_features(session))
        return row

    def build(self) -> pd.DataFrame:
        """Build the full feature DataFrame, one row per session, and
        validate every row against SessionFeatureRow before returning."""
        logger.info("Building features for %d session(s)", len(self.sessions))

        rows = [self._build_row(session) for session in self.sessions]
        df = pd.DataFrame(rows, columns=["session_id", "experiment_id", "label"] + ALL_FEATURE_COLUMNS)

        self._validate_output_schema(df)

        missing_counts = df[ALL_FEATURE_COLUMNS].isna().sum()
        for column, count in missing_counts.items():
            if count > 0:
                logger.info("Column %r: %d/%d missing values", column, count, len(df))

        logger.info("Feature build complete: shape=%s", df.shape)
        return df

    @staticmethod
    def _validate_output_schema(df: pd.DataFrame) -> None:
        errors: list[str] = []

        critical_columns = ["session_id", "experiment_id", "label"]
        for column in critical_columns:
            if df[column].isna().any():
                errors.append(f"unexpected NaN in critical column {column!r}")

        records = df.to_dict(orient="records")
        for i, row in enumerate(records):
            cleaned = {key: (None if pd.isna(value) else value) for key, value in row.items()}
            try:
                SessionFeatureRow(**cleaned)
            except ValidationError as exc:
                errors.append(f"row {i} (session_id={cleaned.get('session_id')!r}) failed schema validation: {exc}")

        if errors:
            raise FeatureBuildError(errors)

    @staticmethod
    def _git_commit_hash() -> str:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=5, check=True,
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"

    def save(self, df: pd.DataFrame, csv_path: str | Path, manifest_path: str | Path) -> None:
        """Write the feature DataFrame to CSV and a reproducibility
        manifest (feature names/types, label distribution, experiment
        IDs, timestamp, git commit hash) to JSON."""
        csv_path = Path(csv_path)
        manifest_path = Path(manifest_path)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)

        df.to_csv(csv_path, index=False)

        label_distribution = df["label"].value_counts().sort_index().to_dict()
        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": self._git_commit_hash(),
            "row_count": len(df),
            "feature_names_and_types": {col: str(df[col].dtype) for col in df.columns},
            "label_distribution": {int(k): int(v) for k, v in label_distribution.items()},
            "experiment_ids": sorted(df["experiment_id"].unique().tolist()),
            "csv_path": str(csv_path),
        }
        with manifest_path.open("w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        logger.info("Saved %d rows to %s; manifest at %s", len(df), csv_path, manifest_path)
