"""Groups TLSSessionRecord objects by source IP and fixed time windows,
computing per-window handshake-rate statistics needed by the deferred
stateful rules R06-R08 (not yet implemented in src/rules/).

A single TLSSessionRecord has no visibility into other sessions from the
same source IP, so R06 (handshake-rate threshold), R07 (failed-handshake
ratio), and R08 (rate correlated with CPU/latency) cannot be evaluated
per-session. This module produces the SourceWindowStats those rules will
consume once implemented.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.utils.schemas import TLSSessionRecord

logger = logging.getLogger(__name__)


@dataclass
class SourceWindowStats:
    """Aggregated handshake statistics for one source IP within one
    fixed-size, tumbling time window."""

    source_ip: str
    window_start: datetime
    window_end: datetime
    handshake_count: int
    failed_handshake_count: int
    session_ids: list[str] = field(default_factory=list)
    mean_handshake_duration_ms: Optional[float] = None

    @property
    def failed_handshake_ratio(self) -> float:
        if self.handshake_count == 0:
            return 0.0
        return self.failed_handshake_count / self.handshake_count

    @property
    def handshakes_per_minute(self) -> float:
        window_seconds = (self.window_end - self.window_start).total_seconds()
        if window_seconds <= 0:
            return 0.0
        return self.handshake_count / (window_seconds / 60.0)


class SessionAggregator:
    """Buckets sessions into fixed-size tumbling windows per source IP.

    Windows are aligned to epoch time (floor(timestamp / window_seconds)),
    not to each source's first session, so window boundaries are
    consistent and comparable across different source IPs.
    """

    def __init__(self, sessions: list[TLSSessionRecord], window_seconds: int = 60):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.sessions = sessions
        self.window_seconds = window_seconds

    def _window_bounds(self, timestamp: datetime) -> tuple[datetime, datetime]:
        epoch_seconds = timestamp.timestamp()
        window_index = int(epoch_seconds // self.window_seconds)
        window_start = datetime.fromtimestamp(window_index * self.window_seconds, tz=timezone.utc)
        window_end = window_start + timedelta(seconds=self.window_seconds)
        return window_start, window_end

    def compute_window_stats(self) -> list[SourceWindowStats]:
        """Group all sessions by (source_ip, window) and compute
        handshake counts / failure counts / mean handshake latency per
        group. mean_handshake_duration_ms is computed only over sessions
        with a non-None handshake_duration_ms; a window where every
        session lacks that field yields None, not 0.0."""
        buckets: dict[tuple[str, datetime], SourceWindowStats] = {}
        durations_by_key: dict[tuple[str, datetime], list[float]] = {}

        for session in self.sessions:
            window_start, window_end = self._window_bounds(session.timestamp)
            key = (session.source_ip, window_start)

            if key not in buckets:
                buckets[key] = SourceWindowStats(
                    source_ip=session.source_ip,
                    window_start=window_start,
                    window_end=window_end,
                    handshake_count=0,
                    failed_handshake_count=0,
                    session_ids=[],
                )
                durations_by_key[key] = []

            stats = buckets[key]
            stats.handshake_count += 1
            if session.failed:
                stats.failed_handshake_count += 1
            stats.session_ids.append(session.session_id)

            if session.handshake_duration_ms is not None:
                durations_by_key[key].append(session.handshake_duration_ms)

        for key, stats in buckets.items():
            durations = durations_by_key[key]
            stats.mean_handshake_duration_ms = (
                sum(durations) / len(durations) if durations else None
            )

        results = sorted(buckets.values(), key=lambda s: (s.source_ip, s.window_start))
        logger.info(
            "Aggregated %d session(s) into %d (source_ip, window) bucket(s) at %ds resolution",
            len(self.sessions), len(results), self.window_seconds,
        )
        return results
    def stats_for_source(self, source_ip: str) -> list[SourceWindowStats]:
        """Convenience: window stats for a single source IP, in time order."""
        return [s for s in self.compute_window_stats() if s.source_ip == source_ip]
