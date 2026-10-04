"""Reads generator-script manifests from data/labels/, matches parsed
TLSSessionRecord objects (from src/parsers/zeek_parser.py) against the
manifest whose experiment time window contains each session's timestamp,
and produces a labeled training CSV via FeatureBuilder.

Matching strategy: each manifest declares a [start_time, end_time] window
(UTC, with a small buffer already applied by the generator scripts) and a
set of target_ports. A session matches a manifest if its timestamp falls
within the window AND, when the parser recorded a destination port
(extra["destination_port"]), that port is one of the manifest's
target_ports. Sessions matching no manifest are dropped, with a count
logged - this is expected for some malformed-handshake traffic (see
KNOWN_LIMITATIONS.md: Zeek may never log these in ssl.log at all).

As a light cross-check (not an override), each matched session is also
evaluated against the rule engine's evaluate_session(); if the rule
engine's own view of the session disagrees with the manifest's declared
label (e.g. downgrade rules fire for a session manifest-labeled
benign_hybrid_pqc - likely because the PQC server fell back to classical),
a warning is logged for human review. The manifest label is still what
gets used, since it reflects known experimental intent.
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.features.feature_builder import FeatureBuilder
from src.parsers.zeek_parser import build_session_records, find_zeek_log_pairs
from src.rules.policy_loader import PQCPolicyConfig, load_policy
from src.rules.rule_engine import UnknownServiceError, evaluate_session
from src.utils.schemas import TLSSessionRecord

logger = logging.getLogger(__name__)


def load_manifests(labels_dir: Path) -> list[dict[str, Any]]:
    manifests = []
    for path in sorted(labels_dir.glob("*.json")):
        with path.open("r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifests.append(manifest)
    return manifests


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def match_session_to_manifest(
    session: TLSSessionRecord, manifests: list[dict[str, Any]]
) -> Optional[dict[str, Any]]:
    """Return the manifest whose time window contains session.timestamp
    (and whose target_ports include the session's destination port, if
    known), or None if no manifest matches."""
    destination_port = session.extra.get("destination_port")
    for manifest in manifests:
        start = _parse_iso(manifest["start_time"])
        end = _parse_iso(manifest["end_time"])
        if not (start <= session.timestamp <= end):
            continue
        target_ports = manifest.get("target_ports")
        if target_ports and destination_port is not None and destination_port not in target_ports:
            continue
        return manifest
    return None


def cross_check_against_rules(
    session: TLSSessionRecord, manifest: dict[str, Any], policy_config: PQCPolicyConfig
) -> None:
    """Log a warning (never raises, never changes the label) if the rule
    engine's view of this session disagrees with the manifest's declared
    label. Silently skipped if no policy matches the session's
    destination_service (common when SNI wasn't sent/recognized)."""
    try:
        violations = evaluate_session(session, policy_config)
    except UnknownServiceError:
        return

    triggered = {v.rule_id for v in violations}
    label_name = manifest.get("label_name")

    if label_name in ("benign_hybrid_pqc", "benign_classical") and triggered:
        logger.warning(
            "session %s manifest-labeled %r but rule engine flagged %s "
            "(if label_name is benign_hybrid_pqc, this often means the PQC "
            "server fell back to a classical group - see KNOWN_LIMITATIONS.md)",
            session.session_id, label_name, sorted(triggered),
        )


def label_sessions(
    zeek_log_dir: Path, labels_dir: Path, policy_path: Path
) -> tuple[list[TLSSessionRecord], dict[str, int], dict[str, str]]:
    """Parse all Zeek logs under zeek_log_dir, match each session against
    the manifests in labels_dir, and return the matched sessions plus
    their label/experiment_id dicts (ready for FeatureBuilder)."""
    manifests = load_manifests(labels_dir)
    if not manifests:
        logger.warning("No manifests found in %s - nothing to label", labels_dir)

    pairs = find_zeek_log_pairs(zeek_log_dir)
    all_sessions: list[TLSSessionRecord] = []
    for ssl_log, conn_log in pairs:
        all_sessions.extend(build_session_records(ssl_log, conn_log))

    policy_config: Optional[PQCPolicyConfig] = load_policy(policy_path) if policy_path.exists() else None

    matched_sessions: list[TLSSessionRecord] = []
    labels: dict[str, int] = {}
    experiment_ids: dict[str, str] = {}
    matched_manifest_ids: set[str] = set()

    for session in all_sessions:
        manifest = match_session_to_manifest(session, manifests)
        if manifest is None:
            continue

        matched_sessions.append(session)
        labels[session.session_id] = int(manifest["expected_label"])
        experiment_ids[session.session_id] = manifest["experiment_id"]
        matched_manifest_ids.add(manifest["experiment_id"])

        if policy_config is not None:
            corrected_label = cross_check_against_rules(session, manifest, policy_config)
        if corrected_label is not None:
            labels[session.session_id] = corrected_label

    unmatched_count = len(all_sessions) - len(matched_sessions)
    logger.info(
        "Matched %d/%d parsed session(s) to a manifest (%d unmatched)",
        len(matched_sessions), len(all_sessions), unmatched_count,
    )

    for manifest in manifests:
        if manifest["experiment_id"] not in matched_manifest_ids:
            logger.warning(
                "manifest %s (%s) matched ZERO parsed sessions - expected for "
                "exp-005-malformed-handshake, see KNOWN_LIMITATIONS.md; "
                "otherwise check the manifest's time window and target_ports",
                manifest["experiment_id"], manifest.get("label_name"),
            )

    return matched_sessions, labels, experiment_ids


def main() -> None:
    parser = argparse.ArgumentParser(description="Label parsed Zeek sessions using generator-script manifests.")
    parser.add_argument("--zeek-log-dir", type=Path, default=Path("data/raw/zeek_logs"))
    parser.add_argument("--labels-dir", type=Path, default=Path("data/labels"))
    parser.add_argument("--policy", type=Path, default=Path("configs/pqc_policy.yaml"))
    parser.add_argument("--out-csv", type=Path, default=Path("data/processed/real_lab_sessions.csv"))
    parser.add_argument("--out-manifest", type=Path, default=Path("data/dataset_cards/real_lab_sessions_manifest.json"))
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    sessions, labels, experiment_ids = label_sessions(args.zeek_log_dir, args.labels_dir, args.policy)

    if not sessions:
        print("No labeled sessions produced - nothing to write.")
        return

    builder = FeatureBuilder(sessions, labels, experiment_ids)
    df = builder.build()
    builder.save(df, args.out_csv, args.out_manifest)

    print(f"\nLabeling summary")
    print(f"  Labeled sessions: {len(df)}")
    print(f"  Label distribution:")
    for label_value, count in df["label"].value_counts().sort_index().items():
        print(f"    {label_value}: {count}")
    print(f"  CSV:      {args.out_csv}")
    print(f"  Manifest: {args.out_manifest}")


if __name__ == "__main__":
    main()
