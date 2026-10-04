#!/usr/bin/env bash
set -euo pipefail

DATA_PATH="${1:-data/processed/synthetic_sessions.csv}"
CONFIG_PATH="${2:-configs/model_config.yaml}"
OUT_DIR="${3:-models/baselines}"

if [[ ! -f "$DATA_PATH" ]]; then
  echo "[train_models] $DATA_PATH not found - generating synthetic dataset first"
  python scripts/generate_synthetic_processed_dataset.py
fi

python -m src.training.train_baseline --data "$DATA_PATH" --config "$CONFIG_PATH" --out-dir "$OUT_DIR"