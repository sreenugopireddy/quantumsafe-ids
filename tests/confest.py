"""Adds the repo root to sys.path so tests can `import src....` without
requiring a full `pip install -e .` package setup."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))