"""Unit tests for Phase 5 Task 1: src/parsers/session_aggregator.py.
Uses synthetic TLSSessionRecord fixtures - no lab or Zeek data required.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.parsers.session_aggregator import SessionAggregator
from src.utils.schemas import TLSSessionRecord


def _session(session_id: str, source_ip: str, timestamp: datetime, failed: bool = False) -> TLSSessionRecord:
    return TLSSessionRecord(
        session_id=session_id,
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip="10.0.0.100",
        destination_service="pqc-api.lab.local",
        tls_version="TLSv1.3",
        offered_groups=[],
        selected_group="X25519MLKEM768",
        key_share_length=None,
        handshake_duration_ms=50.0,
        failed=failed,
        extra={},
    )


BASE_TIME = datetime(2026, 9, 1, 15, 0, 0, tzinfo=timezone.utc)


def test_sessions_grouped_by_source_ip_and_window():
    sessions = [
        _session("s1", "10.0.0.5", BASE_TIME),
        _session("s2", "10.0.0.5", BASE_TIME + timedelta(seconds=10)),
        _session("s3", "10.0.0.6", BASE_TIME),
    ]
    aggregator = SessionAggregator(sessions, window_seconds=60)
    stats = aggregator.compute_window_stats()

    source_ips = {s.source_ip for s in stats}
    assert source_ips == {"10.0.0.5", "10.0.0.6"}

    ip5_stats = next(s for s in stats if s.source_ip == "10.0.0.5")
    assert ip5_stats.handshake_count == 2


def test_sessions_in_different_windows_not_merged():
    sessions = [
        _session("s1", "10.0.0.5", BASE_TIME),
        _session("s2", "10.0.0.5", BASE_TIME + timedelta(seconds=120)),  # 2 windows later
    ]
    aggregator = SessionAggregator(sessions, window_seconds=60)
    stats = aggregator.compute_window_stats()

    ip5_stats = [s for s in stats if s.source_ip == "10.0.0.5"]
    assert len(ip5_stats) == 2
    assert all(s.handshake_count == 1 for s in ip5_stats)


def test_failed_handshake_ratio_computed_correctly():
    sessions = [
        _session("s1", "10.0.0.5", BASE_TIME, failed=True),
        _session("s2", "10.0.0.5", BASE_TIME + timedelta(seconds=5), failed=True),
        _session("s3", "10.0.0.5", BASE_TIME + timedelta(seconds=10), failed=False),
        _session("s4", "10.0.0.5", BASE_TIME + timedelta(seconds=15), failed=False),
    ]
    aggregator = SessionAggregator(sessions, window_seconds=60)
    stats = aggregator.compute_window_stats()[0]
    assert stats.failed_handshake_count == 2
    assert stats.handshake_count == 4
    assert stats.failed_handshake_ratio == pytest.approx(0.5)


def test_handshakes_per_minute_computed_correctly():
    sessions = [_session(f"s{i}", "10.0.0.5", BASE_TIME + timedelta(seconds=i)) for i in range(30)]
    aggregator = SessionAggregator(sessions, window_seconds=60)
    stats = aggregator.compute_window_stats()[0]
    # 30 handshakes in a 60s window -> 30 per minute
    assert stats.handshakes_per_minute == pytest.approx(30.0)


def test_stats_for_source_filters_correctly():
    sessions = [
        _session("s1", "10.0.0.5", BASE_TIME),
        _session("s2", "10.0.0.6", BASE_TIME),
    ]
    aggregator = SessionAggregator(sessions, window_seconds=60)
    stats = aggregator.stats_for_source("10.0.0.5")
    assert len(stats) == 1
    assert stats[0].source_ip == "10.0.0.5"


def test_window_seconds_must_be_positive():
    with pytest.raises(ValueError):
        SessionAggregator([], window_seconds=0)


def test_empty_sessions_produces_no_stats():
    aggregator = SessionAggregator([], window_seconds=60)
    assert aggregator.compute_window_stats() == []


def test_session_ids_tracked_per_window():
    sessions = [
        _session("s1", "10.0.0.5", BASE_TIME),
        _session("s2", "10.0.0.5", BASE_TIME + timedelta(seconds=5)),
    ]
    aggregator = SessionAggregator(sessions, window_seconds=60)
    stats = aggregator.compute_window_stats()[0]
    assert set(stats.session_ids) == {"s1", "s2"}


def test_window_start_end_are_60s_apart_for_60s_window():
    sessions = [_session("s1", "10.0.0.5", BASE_TIME)]
    aggregator = SessionAggregator(sessions, window_seconds=60)
    stats = aggregator.compute_window_stats()[0]
    assert (stats.window_end - stats.window_start).total_seconds() == 60
def test_mean_handshake_duration_ms_computed_correctly():
    sessions = [
        _session("s1", "10.0.0.5", BASE_TIME),
        _session("s2", "10.0.0.5", BASE_TIME + timedelta(seconds=5)),
    ]
    sessions[0].handshake_duration_ms = 100.0
    sessions[1].handshake_duration_ms = 200.0
    aggregator = SessionAggregator(sessions, window_seconds=60)
    stats = aggregator.compute_window_stats()[0]
    assert stats.mean_handshake_duration_ms == pytest.approx(150.0)


def test_mean_handshake_duration_ms_is_none_when_all_sessions_lack_it():
    sessions = [_session("s1", "10.0.0.5", BASE_TIME)]
    sessions[0].handshake_duration_ms = None
    aggregator = SessionAggregator(sessions, window_seconds=60)
    stats = aggregator.compute_window_stats()[0]
    assert stats.mean_handshake_duration_ms is None


def test_mean_handshake_duration_ms_ignores_none_values_in_mix():
    sessions = [
        _session("s1", "10.0.0.5", BASE_TIME),
        _session("s2", "10.0.0.5", BASE_TIME + timedelta(seconds=5)),
    ]
    sessions[0].handshake_duration_ms = 100.0
    sessions[1].handshake_duration_ms = None
    aggregator = SessionAggregator(sessions, window_seconds=60)
    stats = aggregator.compute_window_stats()[0]
    assert stats.mean_handshake_duration_ms == pytest.approx(100.0)