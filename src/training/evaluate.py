"""Metrics computation for baseline model evaluation: macro-F1, per-class
precision/recall/F1, PR-AUC (one-vs-rest), confusion matrix, and the
false-positive rate for benign_hybrid_pqc (label 1) specifically requested
for this task.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import average_precision_score, classification_report, confusion_matrix

from src.utils.constants import Label

LABEL_NAMES: list[str] = [label.name.lower() for label in sorted(Label)]


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> dict[str, Any]:
    """y_proba must be shape (n_samples, 6), columns ordered by label value 0-5."""
    report = classification_report(
        y_true, y_pred, labels=list(range(6)), target_names=LABEL_NAMES,
        output_dict=True, zero_division=0,
    )

    pr_auc: dict[str, float] = {}
    for label_value, label_name in enumerate(LABEL_NAMES):
        y_true_binary = (y_true == label_value).astype(int)
        if y_true_binary.sum() == 0:
            pr_auc[label_name] = float("nan")  # class absent from this split; can't score
            continue
        pr_auc[label_name] = float(average_precision_score(y_true_binary, y_proba[:, label_value]))

    fpr_benign_hybrid_pqc = _false_positive_rate(y_true, y_pred, positive_label=Label.BENIGN_HYBRID_PQC.value)

    return {
        "macro_f1": report["macro avg"]["f1-score"],
        "weighted_f1": report["weighted avg"]["f1-score"],
        "per_class": {
            name: {
                "precision": report[name]["precision"],
                "recall": report[name]["recall"],
                "f1": report[name]["f1-score"],
                "support": report[name]["support"],
            }
            for name in LABEL_NAMES
        },
        "pr_auc_ovr": pr_auc,
        "false_positive_rate_benign_hybrid_pqc": fpr_benign_hybrid_pqc,
    }


def _false_positive_rate(y_true: np.ndarray, y_pred: np.ndarray, positive_label: int) -> float:
    """One-vs-rest FPR: of all sessions that are NOT actually this class,
    what fraction did the model incorrectly predict as this class?"""
    negatives_mask = y_true != positive_label
    n_negatives = int(negatives_mask.sum())
    if n_negatives == 0:
        return float("nan")
    false_positives = int(((y_pred == positive_label) & negatives_mask).sum())
    return false_positives / n_negatives


def save_confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray, out_dir: str | Path, split_name: str) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cm = confusion_matrix(y_true, y_pred, labels=list(range(6)))
    np.save(out_dir / f"confusion_matrix_{split_name}.npy", cm)

    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(6)); ax.set_yticks(range(6))
    ax.set_xticklabels(LABEL_NAMES, rotation=45, ha="right")
    ax.set_yticklabels(LABEL_NAMES)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    ax.set_title(f"Confusion Matrix - {split_name}")
    for i in range(6):
        for j in range(6):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black")
    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    fig.savefig(out_dir / f"confusion_matrix_{split_name}.png", dpi=150)
    plt.close(fig)


def save_feature_importance(feature_names: list[str], importances: np.ndarray, out_dir: str | Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    order = np.argsort(importances)[::-1]
    sorted_names = [feature_names[i] for i in order]
    sorted_values = importances[order]

    with (out_dir / "feature_importance.csv").open("w", encoding="utf-8") as fh:
        fh.write("feature,importance\n")
        for name, value in zip(sorted_names, sorted_values):
            fh.write(f"{name},{value}\n")

    top_n = min(25, len(sorted_names))
    fig, ax = plt.subplots(figsize=(8, max(4, top_n * 0.3)))
    ax.barh(sorted_names[:top_n][::-1], sorted_values[:top_n][::-1])
    ax.set_xlabel("Gain-based importance")
    ax.set_title(f"Top {top_n} feature importances")
    fig.tight_layout()
    fig.savefig(out_dir / "feature_importance.png", dpi=150)
    plt.close(fig)


def save_metrics_json(metrics: dict[str, Any], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)