"""Demo: parses all Zeek log subdirectories under data/raw/zeek_logs/
(one subdirectory per processed pcap, per watch_and_process.sh),
builds TLSSessionRecord objects, aggregates them via SessionAggregator,
and prints a summary.

Usage:
    python -m scripts.demo_parse_zeek [--zeek-log-dir data/raw/zeek_logs] [--window-seconds 60]
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.parsers.session_aggregator import SessionAggregator
from src.parsers.zeek_parser import build_session_records, find_zeek_log_pairs
from src.utils.schemas import TLSSessionRecord
from scripts.label_sessions import label_sessions

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

def main() -> None:
    parser = argparse.ArgumentParser(description="Demo: parse Zeek logs into TLSSessionRecords and aggregate.")
    parser.add_argument("--zeek-log-dir", type=Path, default=Path("data/raw/zeek_logs"))
    parser.add_argument("--window-seconds", type=int, default=60)
    args = parser.parse_args()

    if not args.zeek_log_dir.exists():
        print(f"No such directory: {args.zeek_log_dir}")
        return

    pairs = find_zeek_log_pairs(args.zeek_log_dir)
    if not pairs:
        print(f"No (ssl.log, conn.log) pairs found under {args.zeek_log_dir}")
        return

    all_sessions: list[TLSSessionRecord] = []
    for ssl_log, conn_log in pairs:
        all_sessions.extend(build_session_records(ssl_log, conn_log))

    print(f"\nParsed {len(all_sessions)} session(s) from {len(pairs)} log directory pair(s)")
    if not all_sessions:
        return

    missing_group = sum(1 for s in all_sessions if s.selected_group is None)
    missing_key_share = sum(1 for s in all_sessions if s.key_share_length is None)
    print(f"  Missing selected_group:   {missing_group}/{len(all_sessions)}")
    print(f"  Missing key_share_length: {missing_key_share}/{len(all_sessions)} "
          f"(expected - see zeek_parser.py module docstring)")

    aggregator = SessionAggregator(all_sessions, window_seconds=args.window_seconds)
    window_stats = aggregator.compute_window_stats()

    print(f"\nAggregated into {len(window_stats)} (source_ip, {args.window_seconds}s window) bucket(s)")
    for stats in window_stats[:10]:
        print(
            f"  {stats.source_ip:<15} window={stats.window_start.isoformat()} "
            f"handshakes={stats.handshake_count} failed={stats.failed_handshake_count} "
            f"rate/min={stats.handshakes_per_minute:.1f}"
        )
    if len(window_stats) > 10:
        print(f"  ... and {len(window_stats) - 10} more bucket(s)")
        if len(window_stats) > 10:
            print(f"  ... and {len(window_stats) - 10} more bucket(s)")

    print("\n--- Labeling against data/labels/ manifests ---")
    labeled_sessions, labels, experiment_ids = label_sessions(
        args.zeek_log_dir, Path("data/labels"), Path("configs/pqc_policy.yaml")
    )
    if labeled_sessions:
        from collections import Counter
        distribution = Counter(labels.values())
        print(f"Labeled {len(labeled_sessions)}/{len(all_sessions)} session(s)")
        for label_value in sorted(distribution):
            print(f"  label {label_value}: {distribution[label_value]}")
    else:
        print("No sessions matched any manifest in data/labels/")

if __name__ == "__main__":
    main()
