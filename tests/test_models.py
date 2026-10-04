"""Unit tests for Phase 3: dataset validation, group-aware splitting,
label mapping, metrics, and an end-to-end smoke test of the XGBoost
baseline on a small synthetic dataset. Also covers the stratified split
strategy added for datasets with too few experiment_ids per class (see
data/processed/real_lab_sessions.csv and KNOWN_LIMITATIONS.md).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from pydantic import ValidationError

from src.training.dataset import DatasetValidationError, SplitConfig, group_aware_split, load_processed_csv
from src.training.evaluate import compute_metrics
from src.utils.constants import Label
from src.utils.schemas import SessionFeatureRow


def _minimal_row(**overrides) -> dict:
    base = dict(
        session_id="s1", experiment_id="e1", label=0,
        tls_version="TLSv1.3", selected_group="x25519", cipher_suite="TLS_AES_128_GCM_SHA256",
        key_share_length=32, cert_size=1000, client_extension_count=10, server_extension_count=6,
        flow_duration_ms=100.0, total_packets=10, client_packets=5, server_packets=5,
        total_bytes=3000, client_bytes=1500, server_bytes=1500,
        packet_size_mean=300.0, packet_size_std=40.0, packet_size_min=60.0, packet_size_max=1200.0,
        retransmission_count=0, tcp_reset_count=0, handshake_packet_count=8,
        client_hello_to_server_hello_ms=10.0, server_hello_to_completion_ms=20.0, handshake_duration_ms=50.0,
        mean_inter_arrival_ms=5.0, inter_arrival_variance=1.0, retry_count=0, failure_rate=0.0,
    )
    base.update(overrides)
    return base


# --- label mapping ---

def test_all_six_labels_are_accepted():
    for label in Label:
        row = SessionFeatureRow(**_minimal_row(label=int(label)))
        assert row.label == int(label)


def test_out_of_range_label_rejected():
    with pytest.raises(ValidationError):
        SessionFeatureRow(**_minimal_row(label=6))


def test_negative_label_rejected():
    with pytest.raises(ValidationError):
        SessionFeatureRow(**_minimal_row(label=-1))


def test_missing_optional_feature_is_allowed():
    row = SessionFeatureRow(**{**_minimal_row(), "cert_size": None})
    assert row.cert_size is None


# --- dataset loading / schema validation ---

def test_load_processed_csv_rejects_missing_required_column(tmp_path):
    path = tmp_path / "bad.csv"
    pd.DataFrame([{"session_id": "s1", "label": 0}]).to_csv(path, index=False)  # missing experiment_id
    with pytest.raises(DatasetValidationError):
        load_processed_csv(path)


def test_load_processed_csv_rejects_invalid_label(tmp_path):
    path = tmp_path / "bad.csv"
    pd.DataFrame([_minimal_row(label=99)]).to_csv(path, index=False)
    with pytest.raises(DatasetValidationError):
        load_processed_csv(path)


def test_load_processed_csv_accepts_valid_rows(tmp_path):
    path = tmp_path / "good.csv"
    rows = [_minimal_row(session_id=f"s{i}", experiment_id=f"e{i % 3}", label=i % 6) for i in range(12)]
    pd.DataFrame(rows).to_csv(path, index=False)
    df = load_processed_csv(path)
    assert len(df) == 12


# --- group-aware split ---

def _synthetic_df(n_experiments: int = 10, sessions_per_experiment: int = 6) -> pd.DataFrame:
    rows = []
    counter = 0
    for e in range(n_experiments):
        for _ in range(sessions_per_experiment):
            rows.append(_minimal_row(session_id=f"s{counter}", experiment_id=f"e{e}", label=counter % 6))
            counter += 1
    return pd.DataFrame(rows)


def test_group_split_has_no_experiment_id_leakage():
    df = _synthetic_df()
    splits = group_aware_split(df, SplitConfig(val_size=0.2, test_size=0.2, random_seed=42))
    train_ids, val_ids, test_ids = (set(s["experiment_id"]) for s in (splits.train, splits.val, splits.test))
    assert not (train_ids & val_ids)
    assert not (train_ids & test_ids)
    assert not (val_ids & test_ids)


def test_group_split_covers_all_rows():
    df = _synthetic_df()
    splits = group_aware_split(df, SplitConfig(val_size=0.2, test_size=0.2, random_seed=42))
    assert len(splits.train) + len(splits.val) + len(splits.test) == len(df)


def test_group_split_is_deterministic_for_fixed_seed():
    df = _synthetic_df()
    splits_a = group_aware_split(df, SplitConfig(val_size=0.2, test_size=0.2, random_seed=7))
    splits_b = group_aware_split(df, SplitConfig(val_size=0.2, test_size=0.2, random_seed=7))
    assert list(splits_a.train["session_id"]) == list(splits_b.train["session_id"])


# --- evaluate.py metrics ---

def test_compute_metrics_reports_all_six_classes():
    y_true = np.array([0, 1, 2, 3, 4, 5, 0, 1])
    y_pred = np.array([0, 1, 2, 3, 4, 5, 1, 1])
    y_proba = np.eye(6)[np.array([0, 1, 2, 3, 4, 5, 1, 1])]
    metrics = compute_metrics(y_true, y_pred, y_proba)
    assert set(metrics["per_class"].keys()) == {label.name.lower() for label in Label}
    assert 0.0 <= metrics["macro_f1"] <= 1.0


def test_false_positive_rate_for_benign_hybrid_pqc_is_computed_correctly():
    # 4 negatives (not label 1); 1 incorrectly predicted as label 1 -> FPR = 0.25
    y_true = np.array([0, 2, 3, 4, 1])
    y_pred = np.array([1, 2, 3, 4, 1])
    y_proba = np.eye(6)[y_pred]
    metrics = compute_metrics(y_true, y_pred, y_proba)
    assert metrics["false_positive_rate_benign_hybrid_pqc"] == pytest.approx(0.25)


# --- end-to-end smoke test ---

def test_train_baseline_end_to_end_on_synthetic_csv(tmp_path):
    """Fast smoke test: pipeline runs start-to-finish on a small synthetic
    dataset and produces all artifacts, without asserting on quality."""
    from src.training.train_baseline import run_training

    df = _synthetic_df(n_experiments=15, sessions_per_experiment=8)
    data_path = tmp_path / "synthetic.csv"
    df.to_csv(data_path, index=False)

    config_path = tmp_path / "model_config.yaml"
    config_path.write_text(
        "random_seed: 42\n"
        "split:\n  val_size: 0.2\n  test_size: 0.2\n"
        "xgboost:\n  n_estimators: 20\n  max_depth: 3\n",
        encoding="utf-8",
    )

    out_dir = tmp_path / "models"
    reports_dir = tmp_path / "reports"
    run_dir = run_training(data_path, config_path, out_dir, reports_root=reports_dir)

    assert (run_dir / "model_bundle.joblib").exists()
    assert (run_dir / "README.md").exists()
    assert (reports_dir / "metrics").exists()
    assert (reports_dir / "confusion_matrices").exists()


# --- stratified split (added for datasets with too few experiment_ids per class) ---

def test_stratified_split_preserves_all_classes():
    from src.training.dataset import stratified_split

    rows = []
    for label in range(6):
        for i in range(20):
            rows.append(_minimal_row(session_id=f"s{label}_{i}", experiment_id=f"e{label}", label=label))
    df = pd.DataFrame(rows)

    splits = stratified_split(df, SplitConfig(val_size=0.2, test_size=0.2, random_seed=42))
    for split_df in (splits.train, splits.val, splits.test):
        assert set(split_df["label"].unique()) == set(range(6))


def test_stratified_split_raises_if_a_class_would_be_missing():
    from src.training.dataset import stratified_split

    # Only 1 row total for label 5 - too few to survive a 3-way stratified split
    rows = [_minimal_row(session_id=f"s{i}", experiment_id=f"e{i}", label=0) for i in range(20)]
    rows += [_minimal_row(session_id="s_rare1", experiment_id="e_rare", label=5)]
    df = pd.DataFrame(rows)

    with pytest.raises((ValueError, AssertionError)):
        stratified_split(df, SplitConfig(val_size=0.2, test_size=0.2, random_seed=42))


def test_split_dataset_dispatches_to_group_by_default():
    from src.training.dataset import split_dataset

    df = _synthetic_df()
    splits = split_dataset(df, SplitConfig(val_size=0.2, test_size=0.2, random_seed=42))
    train_ids, test_ids = set(splits.train["experiment_id"]), set(splits.test["experiment_id"])
    assert not (train_ids & test_ids)


def test_split_dataset_dispatches_to_stratified():
    from src.training.dataset import split_dataset

    rows = []
    for label in range(6):
        for i in range(20):
            rows.append(_minimal_row(session_id=f"s{label}_{i}", experiment_id=f"e{label}", label=label))
    df = pd.DataFrame(rows)

    splits = split_dataset(df, SplitConfig(val_size=0.2, test_size=0.2, random_seed=42, split_strategy="stratified"))
    for split_df in (splits.train, splits.val, splits.test):
        assert set(split_df["label"].unique()) == set(range(6))


def test_split_dataset_rejects_unknown_strategy():
    from src.training.dataset import split_dataset

    df = _synthetic_df()
    with pytest.raises(ValueError):
        split_dataset(df, SplitConfig(split_strategy="bogus"))    df = load_processed_csv(data_path)
    splits = split_dataset(df, split_config)