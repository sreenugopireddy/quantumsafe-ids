"""Unit tests for Task 3: scripts/label_sessions.py. Uses fully synthetic
Zeek TSV fixtures and manifest JSON files - no lab or Docker required.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from scripts.label_sessions import label_sessions, match_session_to_manifest
from src.utils.schemas import TLSSessionRecord

BASE_TIME = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)


def _session(session_id: str, timestamp: datetime, destination_port: int | None = 8443) -> TLSSessionRecord:
    extra = {}
    if destination_port is not None:
        extra["destination_port"] = destination_port
    return TLSSessionRecord(
        session_id=session_id,
        timestamp=timestamp,
        source_ip="10.0.0.5",
        destination_ip="10.0.0.100",
        destination_service="classical-api.lab.local",
        tls_version="TLSv1.3",
        offered_groups=[],
        selected_group="x25519",
        key_share_length=None,
        handshake_duration_ms=40.0,
        failed=False,
        extra=extra,
    )


def _manifest(experiment_id: str, label: int, label_name: str, start: datetime, end: datetime, ports: list[int]) -> dict:
    return {
        "experiment_id": experiment_id,
        "expected_label": label,
        "label_name": label_name,
        "target_ports": ports,
        "start_time": start.isoformat().replace("+00:00", "Z"),
        "end_time": end.isoformat().replace("+00:00", "Z"),
    }


# --- match_session_to_manifest ---

def test_session_within_window_and_matching_port_matches():
    manifest = _manifest("exp-001", 0, "benign_classical", BASE_TIME, BASE_TIME + timedelta(seconds=60), [8443])
    session = _session("s1", BASE_TIME + timedelta(seconds=10), destination_port=8443)
    result = match_session_to_manifest(session, [manifest])
    assert result is not None
    assert result["experiment_id"] == "exp-001"


def test_session_outside_window_does_not_match():
    manifest = _manifest("exp-001", 0, "benign_classical", BASE_TIME, BASE_TIME + timedelta(seconds=60), [8443])
    session = _session("s1", BASE_TIME + timedelta(seconds=120), destination_port=8443)
    assert match_session_to_manifest(session, [manifest]) is None


def test_session_wrong_port_does_not_match():
    manifest = _manifest("exp-001", 0, "benign_classical", BASE_TIME, BASE_TIME + timedelta(seconds=60), [8443])
    session = _session("s1", BASE_TIME + timedelta(seconds=10), destination_port=8444)
    assert match_session_to_manifest(session, [manifest]) is None


def test_session_with_unknown_port_falls_back_to_time_only_match():
    manifest = _manifest("exp-001", 0, "benign_classical", BASE_TIME, BASE_TIME + timedelta(seconds=60), [8443])
    session = _session("s1", BASE_TIME + timedelta(seconds=10), destination_port=None)
    result = match_session_to_manifest(session, [manifest])
    assert result is not None


def test_no_manifests_returns_none():
    session = _session("s1", BASE_TIME)
    assert match_session_to_manifest(session, []) is None


# --- label_sessions end-to-end ---

SSL_LOG_TEMPLATE = (
    "#separator \\x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\tresumed\testablished\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\tbool\n"
    "{ts}\t{uid}\t10.0.0.5\t54321\t10.0.0.100\t{port}\tTLSv1.3\tTLS_AES_256_GCM_SHA384\tx25519\tclassical-api.lab.local\tF\tT\n"
)

CONN_LOG_TEMPLATE = (
    "#separator \\x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tstring\tcount\tcount\n"
    "{ts}\t{uid}\t10.0.0.5\t54321\t10.0.0.100\t{port}\ttcp\t0.030\t800\t400\tSF\t4\t4\n"
)


@pytest.fixture
def synthetic_lab(tmp_path):
    """Builds a small zeek_log_dir with one processed-pcap subdirectory
    and one labels_dir with one manifest, matching in time."""
    zeek_log_dir = tmp_path / "zeek_logs"
    labels_dir = tmp_path / "labels"
    subdir = zeek_log_dir / "classical_20260905_120000"
    subdir.mkdir(parents=True)
    labels_dir.mkdir()

    session_ts = BASE_TIME.timestamp()
    (subdir / "ssl.log").write_text(
        SSL_LOG_TEMPLATE.format(ts=session_ts, uid="Cuid001", port=8443), encoding="utf-8"
    )
    (subdir / "conn.log").write_text(
        CONN_LOG_TEMPLATE.format(ts=session_ts, uid="Cuid001", port=8443), encoding="utf-8"
    )

    manifest = _manifest(
        "exp-001-benign-classical", 0, "benign_classical",
        BASE_TIME - timedelta(seconds=5), BASE_TIME + timedelta(seconds=60), [8443],
    )
    (labels_dir / "exp-001-benign-classical.json").write_text(json.dumps(manifest), encoding="utf-8")

    return zeek_log_dir, labels_dir


def test_label_sessions_matches_and_labels_correctly(synthetic_lab, tmp_path):
    zeek_log_dir, labels_dir = synthetic_lab
    fake_policy_path = tmp_path / "no_policy.yaml"  # does not exist -> cross-check skipped gracefully

    sessions, labels, experiment_ids = label_sessions(zeek_log_dir, labels_dir, fake_policy_path)

    assert len(sessions) == 1
    assert labels["Cuid001"] == 0
    assert experiment_ids["Cuid001"] == "exp-001-benign-classical"


def test_label_sessions_drops_unmatched_sessions(tmp_path):
    zeek_log_dir = tmp_path / "zeek_logs"
    labels_dir = tmp_path / "labels"
    subdir = zeek_log_dir / "classical_20260905_120000"
    subdir.mkdir(parents=True)
    labels_dir.mkdir()  # no manifests at all

    session_ts = BASE_TIME.timestamp()
    (subdir / "ssl.log").write_text(
        SSL_LOG_TEMPLATE.format(ts=session_ts, uid="Cuid001", port=8443), encoding="utf-8"
    )
    (subdir / "conn.log").write_text(
        CONN_LOG_TEMPLATE.format(ts=session_ts, uid="Cuid001", port=8443), encoding="utf-8"
    )

    sessions, labels, experiment_ids = label_sessions(zeek_log_dir, labels_dir, tmp_path / "no_policy.yaml")
    assert sessions == []
    assert labels == {}


def test_label_sessions_handles_missing_zeek_log_dir(tmp_path):
    sessions, labels, experiment_ids = label_sessions(
        tmp_path / "does_not_exist", tmp_path / "labels_missing", tmp_path / "no_policy.yaml"
    )
    assert sessions == []
