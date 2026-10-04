"""Demo: builds a small synthetic set of TLSSessionRecord objects, runs
FeatureBuilder end-to-end, saves the CSV + manifest, and prints a summary.

Usage:
    python -m scripts.demo_build_features
"""
from __future__ import annotations

import logging
import random
from pathlib import Path

from src.features.feature_builder import FeatureBuilder
from src.utils.constants import Label
from src.utils.schemas import TLSSessionRecord

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

OUT_CSV = Path("data/processed/feature_builder_demo.csv")
OUT_MANIFEST = Path("data/dataset_cards/feature_builder_demo_manifest.json")
N_SESSIONS = 30
RANDOM_SEED = 42


def _synthetic_sessions() -> tuple[list[TLSSessionRecord], dict[str, int], dict[str, str]]:
    rng = random.Random(RANDOM_SEED)
    sessions: list[TLSSessionRecord] = []
    labels: dict[str, int] = {}
    experiment_ids: dict[str, str] = {}

    labels_pool = list(Label)
    for i in range(N_SESSIONS):
        session_id = f"demo-sess-{i:04d}"
        label = rng.choice(labels_pool)
        experiment_id = f"demo-exp-{i % 5:02d}"

        session = TLSSessionRecord(
            session_id=session_id,
            source_ip=f"10.0.0.{rng.randint(2, 250)}",
            destination_ip="10.0.0.100",
            destination_service="pqc-api.lab.local",
            tls_version=rng.choice(["TLSv1.3", "TLSv1.2"]),
            offered_groups=["X25519MLKEM768", "x25519"],
            selected_group=rng.choice(["X25519MLKEM768", "x25519", None]),
            key_share_length=rng.choice([1216, 32, None]),
            handshake_duration_ms=rng.uniform(20, 300),
            failed=rng.random() < 0.1,
            extra={
                "cipher_suite": rng.choice(
                    ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", None]
                ),
                "total_bytes": rng.randint(2000, 6000) if rng.random() > 0.15 else None,
                "cpu_percent_mean": rng.uniform(5, 60) if rng.random() > 0.3 else None,
            },
        )
        sessions.append(session)
        labels[session_id] = int(label)
        experiment_ids[session_id] = experiment_id

    return sessions, labels, experiment_ids


def main() -> None:
    sessions, labels, experiment_ids = _synthetic_sessions()

    builder = FeatureBuilder(sessions, labels, experiment_ids)
    df = builder.build()
    builder.save(df, OUT_CSV, OUT_MANIFEST)

    print(f"\nFeature build summary")
    print(f"  Rows:            {len(df)}")
    print(f"  Feature columns: {len(df.columns) - 3}")  # minus session_id/experiment_id/label
    print(f"  Label distribution:")
    for label_value, count in df["label"].value_counts().sort_index().items():
        print(f"    {Label(label_value).name.lower():<25} {count}")
    print(f"  CSV:      {OUT_CSV}")
    print(f"  Manifest: {OUT_MANIFEST}")


if __name__ == "__main__":
    main()
