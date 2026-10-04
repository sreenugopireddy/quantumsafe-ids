"""Stateful rate/exhaustion rules: R06, R07, R08. Unlike R01-R05 (which
evaluate a single TLSSessionRecord), these evaluate a SourceWindowStats
aggregate produced by src/parsers/session_aggregator.py, since detecting
a handshake-rate attack requires visibility across many sessions from the
same source IP within a time window - a single session has no such
visibility.

KNOWN LIMITATION (R08): the project spec describes R08 as "high handshake
rate correlates with high server CPU or handshake latency." Only the
latency half is implemented here. The CPU half requires joining against
data/raw/telemetry/endpoint_telemetry.csv, which has no reliable
per-session or per-window key (only an approximate nearest-timestamp
match) - that join does not exist yet. See KNOWN_LIMITATIONS.md.
"""
from __future__ import annotations

from src.parsers.session_aggregator import SourceWindowStats
from src.rules.policy_loader import ServicePolicy
from src.utils.schemas import RuleViolation


def check_r06_handshake_rate_exceeded(
    stats: SourceWindowStats, policy: ServicePolicy
) -> RuleViolation | None:
    """R06: source exceeds the configured handshake-rate threshold within
    the window."""
    if stats.handshake_count <= policy.max_handshakes_per_source_per_minute:
        return None
    return RuleViolation(
        rule_id="R06",
        description=(
            f"Source {stats.source_ip!r} made {stats.handshake_count} handshakes in "
            f"the window, exceeding the configured limit of "
            f"{policy.max_handshakes_per_source_per_minute} per source per minute."
        ),
        severity="high",
        evidence={
            "source_ip": stats.source_ip,
            "window_start": stats.window_start.isoformat(),
            "window_end": stats.window_end.isoformat(),
            "handshake_count": stats.handshake_count,
            "threshold": policy.max_handshakes_per_source_per_minute,
        },
    )


def check_r07_failed_handshake_ratio_exceeded(
    stats: SourceWindowStats, policy: ServicePolicy
) -> RuleViolation | None:
    """R07: source has an excessive number of failed handshakes within
    the window.

    NOTE: despite the project spec's wording ("excessive failed-handshake
    ratio"), this checks failed_handshake_count against
    policy.max_failed_handshakes_per_source_per_minute, which is an
    absolute per-window count, not a ratio - matching the field's actual
    name and units in configs/pqc_policy.yaml. ServicePolicy has no
    ratio-based threshold field today; add one if a true ratio check is
    wanted instead.
    """
    if stats.failed_handshake_count <= policy.max_failed_handshakes_per_source_per_minute:
        return None
    return RuleViolation(
        rule_id="R07",
        description=(
            f"Source {stats.source_ip!r} had {stats.failed_handshake_count} failed "
            f"handshakes in the window, exceeding the configured limit of "
            f"{policy.max_failed_handshakes_per_source_per_minute} per source per minute."
        ),
        severity="high",
        evidence={
            "source_ip": stats.source_ip,
            "window_start": stats.window_start.isoformat(),
            "window_end": stats.window_end.isoformat(),
            "failed_handshake_count": stats.failed_handshake_count,
            "handshake_count": stats.handshake_count,
            "threshold": policy.max_failed_handshakes_per_source_per_minute,
        },
    )


def check_r08_rate_correlates_with_latency(
    stats: SourceWindowStats, policy: ServicePolicy
) -> RuleViolation | None:
    """R08 (latency-only, see module docstring): flags a window where the
    handshake rate exceeds the same R06 threshold AND the mean handshake
    latency in that window exceeds policy.max_handshake_duration_ms - a
    high-rate window that is also visibly slow, consistent with a
    handshake-exhaustion attack degrading server responsiveness.

    A window with no recorded latencies (mean_handshake_duration_ms is
    None) cannot be evaluated and never triggers this rule.
    """
    if stats.mean_handshake_duration_ms is None:
        return None
    rate_exceeded = stats.handshake_count > policy.max_handshakes_per_source_per_minute
    latency_exceeded = stats.mean_handshake_duration_ms > policy.max_handshake_duration_ms
    if not (rate_exceeded and latency_exceeded):
        return None

    return RuleViolation(
        rule_id="R08",
        description=(
            f"Source {stats.source_ip!r} triggered a high handshake rate "
            f"({stats.handshake_count} > {policy.max_handshakes_per_source_per_minute}) "
            f"correlated with elevated mean handshake latency "
            f"({stats.mean_handshake_duration_ms:.1f}ms > {policy.max_handshake_duration_ms}ms), "
            f"consistent with handshake-exhaustion degrading server responsiveness."
        ),
        severity="critical",
        evidence={
            "source_ip": stats.source_ip,
            "window_start": stats.window_start.isoformat(),
            "window_end": stats.window_end.isoformat(),
            "handshake_count": stats.handshake_count,
            "rate_threshold": policy.max_handshakes_per_source_per_minute,
            "mean_handshake_duration_ms": stats.mean_handshake_duration_ms,
            "latency_threshold_ms": policy.max_handshake_duration_ms,
            "note": "CPU correlation deferred - latency-only heuristic, see KNOWN_LIMITATIONS.md",
        },
    )
