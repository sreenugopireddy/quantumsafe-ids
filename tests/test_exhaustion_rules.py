"""Unit tests for R06-R08 (src/rules/exhaustion_rules.py),
evaluate_window() (src/rules/rule_engine.py), and build_window_alert()
(src/rules/alert_builder.py)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.parsers.session_aggregator import SourceWindowStats
from src.rules.alert_builder import build_window_alert
from src.rules.exhaustion_rules import (
    check_r06_handshake_rate_exceeded,
    check_r07_failed_handshake_ratio_exceeded,
    check_r08_rate_correlates_with_latency,
)
from src.rules.policy_loader import ServicePolicy
from src.rules.rule_engine import evaluate_window
from src.utils.constants import Label

BASE_TIME = datetime(2026, 9, 1, 15, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def policy() -> ServicePolicy:
    return ServicePolicy(
        hostname="pqc-api.lab.local",
        max_handshakes_per_source_per_minute=10,
        max_failed_handshakes_per_source_per_minute=3,
        max_handshake_duration_ms=100,
    )


def _stats(**overrides) -> SourceWindowStats:
    base = dict(
        source_ip="10.0.0.5",
        window_start=BASE_TIME,
        window_end=BASE_TIME + timedelta(seconds=60),
        handshake_count=5,
        failed_handshake_count=1,
        session_ids=["s1", "s2", "s3", "s4", "s5"],
        mean_handshake_duration_ms=50.0,
    )
    base.update(overrides)
    return SourceWindowStats(**base)


# --- R06 ---

def test_r06_triggers_when_rate_exceeds_threshold(policy):
    stats = _stats(handshake_count=11)
    violation = check_r06_handshake_rate_exceeded(stats, policy)
    assert violation is not None
    assert violation.rule_id == "R06"


def test_r06_does_not_trigger_at_or_below_threshold(policy):
    stats = _stats(handshake_count=10)
    assert check_r06_handshake_rate_exceeded(stats, policy) is None


# --- R07 ---

def test_r07_triggers_when_failed_count_exceeds_threshold(policy):
    stats = _stats(failed_handshake_count=4)
    violation = check_r07_failed_handshake_ratio_exceeded(stats, policy)
    assert violation is not None
    assert violation.rule_id == "R07"


def test_r07_does_not_trigger_at_or_below_threshold(policy):
    stats = _stats(failed_handshake_count=3)
    assert check_r07_failed_handshake_ratio_exceeded(stats, policy) is None


# --- R08 ---

def test_r08_triggers_when_rate_and_latency_both_high(policy):
    stats = _stats(handshake_count=15, mean_handshake_duration_ms=250.0)
    violation = check_r08_rate_correlates_with_latency(stats, policy)
    assert violation is not None
    assert violation.rule_id == "R08"


def test_r08_does_not_trigger_when_only_rate_high(policy):
    stats = _stats(handshake_count=15, mean_handshake_duration_ms=50.0)  # latency fine
    assert check_r08_rate_correlates_with_latency(stats, policy) is None


def test_r08_does_not_trigger_when_only_latency_high(policy):
    stats = _stats(handshake_count=5, mean_handshake_duration_ms=250.0)  # rate fine
    assert check_r08_rate_correlates_with_latency(stats, policy) is None


def test_r08_does_not_trigger_when_latency_is_none(policy):
    stats = _stats(handshake_count=15, mean_handshake_duration_ms=None)
    assert check_r08_rate_correlates_with_latency(stats, policy) is None


# --- evaluate_window ---

def test_evaluate_window_returns_all_triggered_rules(policy):
    stats = _stats(handshake_count=15, failed_handshake_count=5, mean_handshake_duration_ms=250.0)
    violations = evaluate_window(stats, policy)
    triggered = {v.rule_id for v in violations}
    assert triggered == {"R06", "R07", "R08"}


def test_evaluate_window_returns_empty_when_clean(policy):
    stats = _stats(handshake_count=5, failed_handshake_count=1, mean_handshake_duration_ms=50.0)
    violations = evaluate_window(stats, policy)
    assert violations == []


# --- build_window_alert ---

def test_build_window_alert_classifies_as_handshake_exhaustion_when_triggered(policy):
    stats = _stats(handshake_count=15, failed_handshake_count=5, mean_handshake_duration_ms=250.0)
    violations = evaluate_window(stats, policy)
    alert = build_window_alert(stats, violations, policy)

    assert alert.classification == Label.HANDSHAKE_EXHAUSTION.name.lower()
    assert alert.source_ip == "10.0.0.5"
    assert alert.destination_service == "pqc-api.lab.local"
    assert set(alert.rules_triggered) == {"R06", "R07", "R08"}
    assert alert.confidence == 1.0


def test_build_window_alert_classifies_as_benign_when_clean(policy):
    stats = _stats(handshake_count=5, failed_handshake_count=1, mean_handshake_duration_ms=50.0)
    violations = evaluate_window(stats, policy)
    alert = build_window_alert(stats, violations, policy)

    assert alert.classification == Label.BENIGN_CLASSICAL.name.lower()
    assert alert.rules_triggered == []
    assert alert.confidence == 0.0


def test_build_window_alert_produces_valid_alert_schema_fields(policy):
    stats = _stats(handshake_count=15, mean_handshake_duration_ms=250.0)
    violations = evaluate_window(stats, policy)
    alert = build_window_alert(stats, violations, policy)
    payload = alert.model_dump(mode="json")

    for field in (
        "alert_id", "timestamp", "source_ip", "destination_ip", "destination_service",
        "classification", "severity", "confidence", "rules_triggered", "model_scores",
        "evidence", "recommendation",
    ):
        assert field in payload
