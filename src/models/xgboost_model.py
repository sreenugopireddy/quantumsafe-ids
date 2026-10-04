"""Thin wrapper around XGBClassifier: construction from config, and
save/load helpers that keep the fitted preprocessing pipeline and the
model bundled together as one artifact.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
from xgboost import XGBClassifier


def build_xgboost_classifier(params: dict[str, Any], random_seed: int) -> XGBClassifier:
    return XGBClassifier(
        objective="multi:softprob",
        num_class=6,
        eval_metric=params.get("eval_metric", "mlogloss"),
        max_depth=params.get("max_depth", 6),
        n_estimators=params.get("n_estimators", 300),
        learning_rate=params.get("learning_rate", 0.1),
        subsample=params.get("subsample", 0.9),
        colsample_bytree=params.get("colsample_bytree", 0.9),
        min_child_weight=params.get("min_child_weight", 1),
        reg_lambda=params.get("reg_lambda", 1.0),
        tree_method=params.get("tree_method", "hist"),
        random_state=random_seed,
        n_jobs=params.get("n_jobs", -1),
    )


def save_model_bundle(pipeline: Any, path: str | Path) -> None:
    """Save the full fitted sklearn Pipeline (preprocessor + XGBClassifier)
    as a single joblib artifact."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)


def load_model_bundle(path: str | Path) -> Any:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Model bundle not found: {path}")
    return joblib.load(path)