"""Unit tests for Phase 4: FeatureBuilder (src/features/feature_builder.py).
Uses synthetic TLSSessionRecord fixtures - no lab or Zeek data required.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.features.feature_builder import FeatureBuildError, FeatureBuilder
from src.utils.schemas import ALL_FEATURE_COLUMNS, TLSSessionRecord


def _session(session_id: str = "s1", **overrides) -> TLSSessionRecord:
    base = dict(
        session_id=session_id,
        source_ip="10.0.0.5",
        destination_ip="10.0.0.100",
        destination_service="pqc-api.lab.local",
        tls_version="TLSv1.3",
        offered_groups=["X25519MLKEM768", "x25519"],
        selected_group="X25519MLKEM768",
        key_share_length=1216,
        handshake_duration_ms=45.0,
        failed=False,
        extra={},
    )
    base.update(overrides)
    return TLSSessionRecord(**base)


def _full_extra() -> dict:
    return {
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cert_size": 1200,
        "client_extension_count": 12,
        "server_extension_count": 6,
        "flow_duration_ms": 150.0,
        "total_packets": 12,
        "client_packets": 6,
        "server_packets": 6,
        "total_bytes": 4000,
        "client_bytes": 2000,
        "server_bytes": 2000,
        "packet_size_mean": 320.0,
        "packet_size_std": 50.0,
        "packet_size_min": 60.0,
        "packet_size_max": 1400.0,
        "retransmission_count": 0,
        "tcp_reset_count": 0,
        "handshake_packet_count": 8,
        "client_hello_to_server_hello_ms": 12.0,
        "server_hello_to_completion_ms": 20.0,
        "mean_inter_arrival_ms": 4.0,
        "inter_arrival_variance": 0.8,
        "retry_count": 0,
        "failure_rate": 0.0,
        "cpu_percent_mean": 15.0,
        "cpu_percent_peak": 40.0,
        "mem_percent_mean": 22.0,
        "mem_percent_peak": 30.0,
        "active_connection_count": 5,
        "tls_error_count": 0,
        "crypto_op_latency_ms": 3.5,
    }


# --- input validation ---

def test_missing_label_raises_feature_build_error():
    sessions = [_session("s1")]
    with pytest.raises(FeatureBuildError):
        FeatureBuilder(sessions, labels={}, experiment_ids={"s1": "e1"})


def test_missing_experiment_id_raises_feature_build_error():
    sessions = [_session("s1")]
    with pytest.raises(FeatureBuildError):
        FeatureBuilder(sessions, labels={"s1": 0}, experiment_ids={})


def test_duplicate_session_id_raises_feature_build_error():
    sessions = [_session("s1"), _session("s1")]
    with pytest.raises(FeatureBuildError):
        FeatureBuilder(sessions, labels={"s1": 0}, experiment_ids={"s1": "e1"})


# --- feature extraction correctness ---

def test_crypto_features_extracted_correctly():
    session = _session(extra=_full_extra())
    builder = FeatureBuilder([session], labels={"s1": 1}, experiment_ids={"s1": "e1"})
    df = builder.build()
    row = df.iloc[0]

    assert row["tls_version"] == "TLSv1.3"
    assert row["selected_group"] == "X25519MLKEM768"
    assert row["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert row["pqc_selected_flag"] == "true"
    assert row["classical_fallback_flag"] == "false"
    assert row["key_share_length"] == 1216
    assert row["cert_size"] == 1200


def test_flow_features_extracted_correctly():
    session = _session(extra=_full_extra())
    builder = FeatureBuilder([session], labels={"s1": 1}, experiment_ids={"s1": "e1"})
    df = builder.build()
    row = df.iloc[0]

    assert row["total_packets"] == 12
    assert row["total_bytes"] == 4000
    assert row["packet_size_mean"] == 320.0


def test_timing_features_extracted_correctly():
    session = _session(extra=_full_extra())
    builder = FeatureBuilder([session], labels={"s1": 1}, experiment_ids={"s1": "e1"})
    df = builder.build()
    row = df.iloc[0]

    assert row["handshake_duration_ms"] == 45.0
    assert row["client_hello_to_server_hello_ms"] == 12.0
    assert row["failure_rate"] == 0.0


def test_endpoint_features_extracted_correctly():
    session = _session(extra=_full_extra())
    builder = FeatureBuilder([session], labels={"s1": 1}, experiment_ids={"s1": "e1"})
    df = builder.build()
    row = df.iloc[0]

    assert row["cpu_percent_mean"] == 15.0
    assert row["active_connection_count"] == 5


# --- missing-value handling ---

def test_missing_extra_fields_fill_numeric_nan():
    session = _session(extra={})  # no flow/timing/endpoint data at all
    builder = FeatureBuilder([session], labels={"s1": 1}, experiment_ids={"s1": "e1"})
    df = builder.build()
    row = df.iloc[0]

    assert np.isnan(row["cert_size"])
    assert np.isnan(row["total_bytes"])
    assert np.isnan(row["cpu_percent_mean"])


def test_missing_extra_fields_fill_categorical_unknown():
    session = _session(extra={})  # no cipher_suite in extra
    builder = FeatureBuilder([session], labels={"s1": 1}, experiment_ids={"s1": "e1"})
    df = builder.build()
    row = df.iloc[0]

    assert row["cipher_suite"] == "UNKNOWN"


def test_failed_session_derives_failure_rate_when_absent():
    session = _session(failed=True, extra={})
    builder = FeatureBuilder([session], labels={"s1": 3}, experiment_ids={"s1": "e1"})
    df = builder.build()
    assert df.iloc[0]["failure_rate"] == 1.0


# --- categorical normalization ---

def test_unrecognized_tls_version_normalizes_to_unknown():
    session = _session(tls_version="SSLv3")
    builder = FeatureBuilder([session], labels={"s1": 5}, experiment_ids={"s1": "e1"})
    df = builder.build()
    assert df.iloc[0]["tls_version"] == "UNKNOWN"


def test_unrecognized_group_normalizes_to_unknown():
    session = _session(selected_group="some-future-kem")
    builder = FeatureBuilder([session], labels={"s1": 5}, experiment_ids={"s1": "e1"})
    df = builder.build()
    assert df.iloc[0]["selected_group"] == "UNKNOWN"


def test_none_selected_group_normalizes_to_unknown():
    session = _session(selected_group=None)
    builder = FeatureBuilder([session], labels={"s1": 5}, experiment_ids={"s1": "e1"})
    df = builder.build()
    assert df.iloc[0]["selected_group"] == "UNKNOWN"
    assert df.iloc[0]["pqc_selected_flag"] == "UNKNOWN"


# --- output schema validation ---

def test_output_dataframe_has_all_expected_columns():
    session = _session(extra=_full_extra())
    builder = FeatureBuilder([session], labels={"s1": 1}, experiment_ids={"s1": "e1"})
    df = builder.build()

    expected = {"session_id", "experiment_id", "label"} | set(ALL_FEATURE_COLUMNS)
    assert expected.issubset(set(df.columns))


def test_no_unexpected_nan_in_critical_fields():
    sessions = [_session("s1"), _session("s2")]
    builder = FeatureBuilder(sessions, labels={"s1": 0, "s2": 1}, experiment_ids={"s1": "e1", "s2": "e1"})
    df = builder.build()

    assert df["session_id"].isna().sum() == 0
    assert df["experiment_id"].isna().sum() == 0
    assert df["label"].isna().sum() == 0


def test_multiple_sessions_produce_one_row_each():
    sessions = [_session(f"s{i}") for i in range(5)]
    labels = {f"s{i}": i % 6 for i in range(5)}
    experiment_ids = {f"s{i}": "e1" for i in range(5)}
    builder = FeatureBuilder(sessions, labels, experiment_ids)
    df = builder.build()
    assert len(df) == 5


# --- save() / manifest ---

def test_save_writes_csv_and_manifest(tmp_path):
    session = _session(extra=_full_extra())
    builder = FeatureBuilder([session], labels={"s1": 1}, experiment_ids={"s1": "e1"})
    df = builder.build()

    csv_path = tmp_path / "features.csv"
    manifest_path = tmp_path / "manifest.json"
    builder.save(df, csv_path, manifest_path)

    assert csv_path.exists()
    assert manifest_path.exists()

    reloaded = pd.read_csv(csv_path)
    assert len(reloaded) == 1

    import json
    manifest = json.loads(manifest_path.read_text())
    assert manifest["row_count"] == 1
    assert manifest["label_distribution"] == {"1": 1}
    assert manifest["experiment_ids"] == ["e1"]
    assert "git_commit" in manifest
    assert "generated_at" in manifest
