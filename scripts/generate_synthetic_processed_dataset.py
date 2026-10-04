"""Generates a small synthetic processed session-level CSV
(data/processed/synthetic_sessions.csv) so the XGBoost baseline pipeline
can be run and tested end-to-end before real feature-engineered lab data
exists. NOT representative of real traffic - pipeline testing only.
"""
from __future__ import annotations

import csv
import random
from pathlib import Path

from src.utils.constants import Label

OUT_PATH = Path("data/processed/synthetic_sessions.csv")
RANDOM_SEED = 42
N_EXPERIMENTS = 12
SESSIONS_PER_EXPERIMENT = 15

CIPHERS = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]

FIELDNAMES = [
    "session_id", "experiment_id", "label",
    "tls_version", "selected_group", "cipher_suite",
    "key_share_length", "cert_size", "client_extension_count", "server_extension_count",
    "flow_duration_ms", "total_packets", "client_packets", "server_packets",
    "total_bytes", "client_bytes", "server_bytes",
    "packet_size_mean", "packet_size_std", "packet_size_min", "packet_size_max",
    "retransmission_count", "tcp_reset_count", "handshake_packet_count",
    "client_hello_to_server_hello_ms", "server_hello_to_completion_ms", "handshake_duration_ms",
    "mean_inter_arrival_ms", "inter_arrival_variance", "retry_count", "failure_rate",
]


def _row_for_label(rng: random.Random, label: int) -> dict:
    base = {
        "tls_version": "TLSv1.3",
        "selected_group": "X25519MLKEM768",
        "cipher_suite": rng.choice(CIPHERS),
        "key_share_length": 1216,
        "cert_size": rng.randint(800, 1600),
        "client_extension_count": rng.randint(8, 14),
        "server_extension_count": rng.randint(4, 8),
        "flow_duration_ms": rng.uniform(50, 400),
        "total_packets": rng.randint(8, 20),
        "client_packets": rng.randint(4, 10),
        "server_packets": rng.randint(4, 10),
        "total_bytes": rng.randint(2000, 6000),
        "client_bytes": rng.randint(1000, 3000),
        "server_bytes": rng.randint(1000, 3000),
        "packet_size_mean": rng.uniform(200, 500),
        "packet_size_std": rng.uniform(20, 80),
        "packet_size_min": rng.uniform(60, 100),
        "packet_size_max": rng.uniform(800, 1500),
        "retransmission_count": 0,
        "tcp_reset_count": 0,
        "handshake_packet_count": rng.randint(6, 10),
        "client_hello_to_server_hello_ms": rng.uniform(5, 40),
        "server_hello_to_completion_ms": rng.uniform(10, 60),
        "handshake_duration_ms": rng.uniform(30, 200),
        "mean_inter_arrival_ms": rng.uniform(1, 20),
        "inter_arrival_variance": rng.uniform(0.1, 5),
        "retry_count": 0,
        "failure_rate": 0.0,
    }

    if label == Label.BENIGN_CLASSICAL:
        base["selected_group"] = rng.choice(["x25519", "secp256r1"])
        base["key_share_length"] = 32 if base["selected_group"] == "x25519" else 65
    elif label == Label.BENIGN_HYBRID_PQC:
        pass  # defaults already reflect a clean PQC handshake
    elif label == Label.DOWNGRADE_VIOLATION:
        base["tls_version"] = "TLSv1.2"
        base["selected_group"] = rng.choice(["x25519", "prime256v1"])
        base["key_share_length"] = 32 if base["selected_group"] == "x25519" else 65
    elif label == Label.HANDSHAKE_EXHAUSTION:
        base["handshake_duration_ms"] = rng.uniform(1500, 4000)
        base["failure_rate"] = rng.uniform(0.3, 0.9)
        base["retry_count"] = rng.randint(3, 10)
        base["total_packets"] = rng.randint(30, 80)
    elif label == Label.MALFORMED_HANDSHAKE:
        base["key_share_length"] = rng.choice([0, 12, 4096])
        base["tcp_reset_count"] = rng.randint(1, 3)
    elif label == Label.UNKNOWN_ANOMALY:
        base["packet_size_std"] = rng.uniform(150, 400)
        base["inter_arrival_variance"] = rng.uniform(10, 50)

    return base


def generate(seed: int = RANDOM_SEED) -> None:
    rng = random.Random(seed)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    labels = list(Label)
    rows = []
    counter = 0
    for exp_i in range(N_EXPERIMENTS):
        experiment_id = f"exp-{exp_i:03d}"
        for _ in range(SESSIONS_PER_EXPERIMENT):
            label = rng.choice(labels)
            row = _row_for_label(rng, label)
            row["session_id"] = f"sess-{counter:05d}"
            row["experiment_id"] = experiment_id
            row["label"] = int(label)
            counter += 1
            rows.append(row)

    # Inject a handful of missing values to exercise imputation downstream.
    for row in rng.sample(rows, k=max(1, len(rows) // 10)):
        field = rng.choice(["cert_size", "packet_size_std", "selected_group"])
        row[field] = ""

    with OUT_PATH.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} synthetic sessions across {N_EXPERIMENTS} experiments to {OUT_PATH}")


if __name__ == "__main__":
    generate()