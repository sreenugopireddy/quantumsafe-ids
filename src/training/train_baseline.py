"""Reproducible XGBoost baseline training entrypoint for QuantumSafe-IDS.

Usage:
    python -m src.training.train_baseline \
        --data data/processed/synthetic_sessions.csv \
        --config configs/model_config.yaml \
        --out-dir models/baselines
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import yaml
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from src.models.xgboost_model import build_xgboost_classifier, save_model_bundle
from src.training.dataset import SplitConfig, feature_columns_present, group_aware_split, load_processed_csv
from src.training.evaluate import compute_metrics, save_confusion_matrix, save_feature_importance, save_metrics_json
from src.utils.schemas import CATEGORICAL_FEATURE_COLUMNS, NUMERIC_FEATURE_COLUMNS


def build_preprocessing_pipeline(numeric_cols: list[str], categorical_cols: list[str]) -> ColumnTransformer:
    numeric_pipeline = Pipeline([("imputer", SimpleImputer(strategy="median"))])
    categorical_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("onehot", OneHotEncoder(handle_unknown="ignore")),
    ])
    return ColumnTransformer(
        transformers=[
            ("numeric", numeric_pipeline, numeric_cols),
            ("categorical", categorical_pipeline, categorical_cols),
        ],
        remainder="drop",
    )


def _pip_freeze_versions(packages: tuple[str, ...] = ("xgboost", "scikit-learn", "pandas", "numpy")) -> dict[str, str]:
    try:
        installed = subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True)
    except Exception:
        return {}
    versions: dict[str, str] = {}
    for line in installed.splitlines():
        if "==" not in line:
            continue
        name, _, version = line.partition("==")
        if name.lower() in packages:
            versions[name.lower()] = version
    return versions


def write_reproducibility_readme(run_dir: Path, config: dict, data_path: Path, seed: int) -> None:
    versions = _pip_freeze_versions()
    lines = [
        "# Baseline run reproducibility notes", "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        f"- Data file: `{data_path}`",
        f"- Random seed: `{seed}`", "",
        "## Config", "```json", json.dumps(config, indent=2), "```", "",
        "## Package versions", "",
        *(f"- {name}=={version}" for name, version in sorted(versions.items())), "",
        "## Reproduce this run", "",
        "```bash",
        f"python -m src.training.train_baseline --data {data_path} "
        f"--config configs/model_config.yaml --out-dir models/baselines",
        "```",
    ]
    (run_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def run_training(
    data_path: Path,
    config_path: Path,
    out_root: Path,
    reports_root: Path = Path("reports"),
) -> Path:
    with config_path.open("r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh)

    seed = int(config["random_seed"])
    split_config = SplitConfig(
        val_size=float(config["split"]["val_size"]),
        test_size=float(config["split"]["test_size"]),
        random_seed=seed,
    )

    df = load_processed_csv(data_path)
    splits = group_aware_split(df, split_config)

    present = feature_columns_present(df)
    numeric_cols = [c for c in NUMERIC_FEATURE_COLUMNS if c in present]
    categorical_cols = [c for c in CATEGORICAL_FEATURE_COLUMNS if c in present]

    preprocessor = build_preprocessing_pipeline(numeric_cols, categorical_cols)
    model = build_xgboost_classifier(config.get("xgboost", {}), random_seed=seed)
    pipeline = Pipeline([("preprocessor", preprocessor), ("model", model)])

    feature_cols = numeric_cols + categorical_cols
    x_train = splits.train[feature_cols]
    y_train = splits.train["label"].astype(int).to_numpy()

    # Class-imbalance handling via sample_weight (inverse-frequency), since
    # rare attack classes would otherwise be dominated by benign traffic.
    class_counts = pd.Series(y_train).value_counts()
    weight_map = {label: len(y_train) / (6 * count) for label, count in class_counts.items()}
    sample_weight = pd.Series(y_train).map(weight_map).to_numpy()

    pipeline.fit(x_train, y_train, model__sample_weight=sample_weight)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    save_model_bundle(pipeline, run_dir / "model_bundle.joblib")

    for split_name, split_df in (("val", splits.val), ("test", splits.test)):
        x_split = split_df[feature_cols]
        y_split = split_df["label"].astype(int).to_numpy()
        y_pred = pipeline.predict(x_split)
        y_proba = pipeline.predict_proba(x_split)

        metrics = compute_metrics(y_split, y_pred, y_proba)
        save_metrics_json(metrics, reports_root / "metrics" / f"xgboost_baseline_{split_name}_{run_id}.json")
        save_confusion_matrix(y_split, y_pred, reports_root / "confusion_matrices",
                               f"xgboost_baseline_{split_name}_{run_id}")

    feature_names = list(pipeline.named_steps["preprocessor"].get_feature_names_out())
    importances = pipeline.named_steps["model"].feature_importances_
    save_feature_importance(feature_names, importances, reports_root / "figures" / f"xgboost_baseline_{run_id}")

    write_reproducibility_readme(run_dir, config, data_path, seed)
    return run_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the QuantumSafe-IDS XGBoost baseline.")
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("configs/model_config.yaml"))
    parser.add_argument("--out-dir", type=Path, default=Path("models/baselines"))
    parser.add_argument("--reports-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()

    run_dir = run_training(args.data, args.config, args.out_dir, args.reports_dir)
    print(f"Training complete. Artifacts saved to: {run_dir}")


if __name__ == "__main__":
    main()