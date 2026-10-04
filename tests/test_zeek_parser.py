"""Unit tests for Phase 5 Task 1: src/parsers/zeek_parser.py.
Uses synthetic TSV fixture files that mimic Zeek's exact log format.
"""
from __future__ import annotations

import pytest

from src.parsers.zeek_parser import build_session_records, parse_zeek_tsv

SSL_LOG_CONTENT = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tssl\n"
    "#open\t2026-09-01-15-05-56\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\tresumed\testablished\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\tbool\n"
    "1756742156.123456\tCuidAAA1\t10.0.0.5\t54321\t10.0.0.100\t8443\tTLSv1.3\tTLS_AES_256_GCM_SHA384\tX25519MLKEM768\tpqc-api.lab.local\tF\tT\n"
    "1756742160.654321\tCuidAAA2\t10.0.0.6\t54322\t10.0.0.100\t8443\tTLSv1.2\tTLS_AES_128_GCM_SHA256\t-\tclassical-api.lab.local\tF\tF\n"
    "1756742170.000000\tCuidAAA3\t10.0.0.7\t54323\t10.0.0.100\t8443\tTLSv1.3\tTLS_AES_256_GCM_SHA384\tX25519MLKEM768\t-\tF\tT\n"
    "#close\t2026-09-01-15-06-56\n"
)

CONN_LOG_CONTENT = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tconn\n"
    "#open\t2026-09-01-15-05-56\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tstring\tcount\tcount\n"
    "1756742156.123456\tCuidAAA1\t10.0.0.5\t54321\t10.0.0.100\t8443\ttcp\t0.045\t1500\t2500\tSF\t6\t6\n"
    "1756742160.654321\tCuidAAA2\t10.0.0.6\t54322\t10.0.0.100\t8443\ttcp\t0.030\t800\t400\tSF\t4\t4\n"
    "#close\t2026-09-01-15-06-56\n"
)


@pytest.fixture
def ssl_log_path(tmp_path):
    path = tmp_path / "ssl.log"
    path.write_text(SSL_LOG_CONTENT, encoding="utf-8")
    return path


@pytest.fixture
def conn_log_path(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(CONN_LOG_CONTENT, encoding="utf-8")
    return path


# --- parse_zeek_tsv ---

def test_parse_zeek_tsv_reads_fields_and_header(ssl_log_path):
    log = parse_zeek_tsv(ssl_log_path)
    assert "uid" in log.fields
    assert "ts" in log.fields
    assert len(log.rows) == 3


def test_parse_zeek_tsv_type_coercion(ssl_log_path):
    log = parse_zeek_tsv(ssl_log_path)
    row = log.rows[0]
    assert isinstance(row["ts"], float)
    assert row["ts"] == pytest.approx(1756742156.123456)
    assert row["established"] is True
    assert row["resumed"] is False


def test_parse_zeek_tsv_handles_unset_field(ssl_log_path):
    log = parse_zeek_tsv(ssl_log_path)
    row = log.rows[1]  # curve is "-" (unset) for this row
    assert row["curve"] is None


def test_parse_zeek_tsv_handles_missing_optional_string(ssl_log_path):
    log = parse_zeek_tsv(ssl_log_path)
    row = log.rows[2]  # server_name is "-" for this row
    assert row["server_name"] is None


def test_parse_zeek_tsv_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_zeek_tsv(tmp_path / "does_not_exist.log")


def test_parse_zeek_tsv_conn_log_count_types(conn_log_path):
    log = parse_zeek_tsv(conn_log_path)
    row = log.rows[0]
    assert isinstance(row["orig_pkts"], int)
    assert row["orig_pkts"] == 6
    assert isinstance(row["duration"], float)


# --- build_session_records ---

def test_build_session_records_produces_one_record_per_ssl_row(ssl_log_path, conn_log_path):
    sessions = build_session_records(ssl_log_path, conn_log_path)
    assert len(sessions) == 3


def test_build_session_records_joins_flow_features_from_conn_log(ssl_log_path, conn_log_path):
    sessions = build_session_records(ssl_log_path, conn_log_path)
    session = next(s for s in sessions if s.session_id == "CuidAAA1")
    assert session.extra["total_bytes"] == 4000
    assert session.extra["client_packets"] == 6
    assert session.extra["server_packets"] == 6
    assert session.extra["cipher_suite"] == "TLS_AES_256_GCM_SHA384"


def test_build_session_records_handles_unmatched_conn_row(ssl_log_path, conn_log_path):
    sessions = build_session_records(ssl_log_path, conn_log_path)
    session = next(s for s in sessions if s.session_id == "CuidAAA3")  # no conn.log entry
    assert session.extra == {}
    assert session.handshake_duration_ms is None


def test_build_session_records_documents_offered_groups_and_key_share_limitation(ssl_log_path, conn_log_path):
    sessions = build_session_records(ssl_log_path, conn_log_path)
    for session in sessions:
        assert session.offered_groups == []
        assert session.key_share_length is None


def test_build_session_records_marks_failed_handshake_when_established_false(ssl_log_path, conn_log_path):
    sessions = build_session_records(ssl_log_path, conn_log_path)
    session = next(s for s in sessions if s.session_id == "CuidAAA2")
    assert session.failed is True


def test_build_session_records_not_failed_when_established_true(ssl_log_path, conn_log_path):
    sessions = build_session_records(ssl_log_path, conn_log_path)
    session = next(s for s in sessions if s.session_id == "CuidAAA1")
    assert session.failed is False


def test_build_session_records_falls_back_to_dest_ip_when_no_sni(ssl_log_path, conn_log_path):
    sessions = build_session_records(ssl_log_path, conn_log_path)
    session = next(s for s in sessions if s.session_id == "CuidAAA3")  # server_name unset
    assert session.destination_service == "10.0.0.100"


def test_build_session_records_selected_group_from_curve(ssl_log_path, conn_log_path):
    sessions = build_session_records(ssl_log_path, conn_log_path)
    session = next(s for s in sessions if s.session_id == "CuidAAA1")
    assert session.selected_group == "X25519MLKEM768"
def test_build_session_records_includes_destination_port_from_conn_log(ssl_log_path, conn_log_path):
    sessions = build_session_records(ssl_log_path, conn_log_path)
    session = next(s for s in sessions if s.session_id == "CuidAAA1")
    assert session.extra["destination_port"] == 8443