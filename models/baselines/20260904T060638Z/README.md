# Baseline run reproducibility notes

- Generated: 2026-09-04T06:06:48.222637+00:00
- Data file: `data/processed/synthetic_sessions.csv`
- Random seed: `42`

## Config
```json
{
  "random_seed": 42,
  "split": {
    "val_size": 0.15,
    "test_size": 0.15
  },
  "xgboost": {
    "max_depth": 6,
    "n_estimators": 300,
    "learning_rate": 0.1,
    "subsample": 0.9,
    "colsample_bytree": 0.9,
    "min_child_weight": 1,
    "reg_lambda": 1.0,
    "tree_method": "hist",
    "eval_metric": "mlogloss",
    "n_jobs": -1
  }
}
```

## Package versions

- numpy==2.5.2
- pandas==3.0.5
- scikit-learn==1.9.0
- xgboost==3.4.1

## Reproduce this run

```bash
python -m src.training.train_baseline --data data/processed/synthetic_sessions.csv --config configs/model_config.yaml --out-dir models/baselines
```