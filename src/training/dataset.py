"""Load, validate, and group-aware split processed session-level CSV data
for baseline model training (src/training/train_baseline.py).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd
from pydantic import ValidationError
from sklearn.model_selection import GroupShuffleSplit

from src.utils.schemas import ALL_FEATURE_COLUMNS, REQUIRED_ID_COLUMNS, SessionFeatureRow


class DatasetValidationError(Exception):
    """Raised when a processed CSV fails schema validation. Carries all
    row-level errors found, not just the first, so a CSV can be fixed in
    one pass instead of one error at a time."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        preview = "\n".join(errors[:20])
        more = f"\n... and {len(errors) - 20} more" if len(errors) > 20 else ""
        super().__init__(f"{len(errors)} row(s)/issue(s) failed schema validation:\n{preview}{more}")


@dataclass(frozen=True)
class SplitConfig:
    val_size: float = 0.15
    test_size: float = 0.15
    random_seed: int = 42


@dataclass(frozen=True)
class DatasetSplits:
    train: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame


def load_processed_csv(path: str | Path) -> pd.DataFrame:
    """Load a processed session-level CSV and validate it against
    SessionFeatureRow. Raises DatasetValidationError with all violations
    aggregated if the file does not conform.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Processed dataset not found: {path}")

    df = pd.read_csv(path)

    missing_columns = set(REQUIRED_ID_COLUMNS) - set(df.columns)
    if missing_columns:
        raise DatasetValidationError([f"CSV is missing required column(s): {sorted(missing_columns)}"])

    errors: list[str] = []
    records = df.to_dict(orient="records")
    for i, row in enumerate(records):
        cleaned = {key: (None if pd.isna(value) else value) for key, value in row.items()}
        try:
            SessionFeatureRow(**cleaned)
        except ValidationError as exc:
            errors.append(f"row {i} (session_id={cleaned.get('session_id')!r}): {exc}")

    if errors:
        raise DatasetValidationError(errors)

    return df


def group_aware_split(df: pd.DataFrame, config: SplitConfig | None = None) -> DatasetSplits:
    """Split into train/val/test with no experiment_id appearing in more
    than one split (GroupShuffleSplit keyed on experiment_id)."""
    config = config or SplitConfig()

    gss_test = GroupShuffleSplit(n_splits=1, test_size=config.test_size, random_state=config.random_seed)
    train_val_idx, test_idx = next(gss_test.split(df, groups=df["experiment_id"]))
    train_val_df = df.iloc[train_val_idx]
    test_df = df.iloc[test_idx]

    # val_size is expressed relative to the *original* dataset; convert to a
    # fraction of the remaining train_val_df before the second split.
    relative_val_size = config.val_size / (1.0 - config.test_size)
    gss_val = GroupShuffleSplit(n_splits=1, test_size=relative_val_size, random_state=config.random_seed)
    train_idx, val_idx = next(gss_val.split(train_val_df, groups=train_val_df["experiment_id"]))
    train_df = train_val_df.iloc[train_idx]
    val_df = train_val_df.iloc[val_idx]

    _assert_no_group_leakage(train_df, val_df, test_df)
    return DatasetSplits(train=train_df, val=val_df, test=test_df)


def _assert_no_group_leakage(train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame) -> None:
    train_ids = set(train_df["experiment_id"])
    val_ids = set(val_df["experiment_id"])
    test_ids = set(test_df["experiment_id"])
    overlap = (train_ids & val_ids) | (train_ids & test_ids) | (val_ids & test_ids)
    if overlap:
        raise AssertionError(f"experiment_id leakage detected across splits: {overlap}")


def feature_columns_present(df: pd.DataFrame) -> list[str]:
    """Subset of ALL_FEATURE_COLUMNS actually present in df, fixed order,
    so training tolerates a CSV missing some optional feature columns."""
    return [c for c in ALL_FEATURE_COLUMNS if c in df.columns]