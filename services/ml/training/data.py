"""Загрузка датасета, выгруженного Go (cmd/export)."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

CLASS_NONE, CLASS_SERVICE, CLASS_ALLOWLISTED, CLASS_EMERGENCY = 0, 1, 2, 3


class DatasetError(Exception):
    pass


def load_meta(directory: str | Path) -> dict:
    p = Path(directory) / "meta.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise DatasetError(f"не удалось прочитать {p}: {e}") from e


def load_split(directory: str | Path, name: str, features: list[str]) -> pd.DataFrame:
    """Читает {name}.csv, проверяет колонки признаков. Экстренные вызовы остаются (для отчёта)."""
    p = Path(directory) / f"{name}.csv"
    try:
        df = pd.read_csv(p, dtype={"caller": "string", "kind": "string"})
    except (OSError, pd.errors.ParserError) as e:
        raise DatasetError(f"не удалось прочитать {p}: {e}") from e
    need = ["label", "kind", "class", "signals", "emergency", "caller", "ts", "s1"] + [f"r_{f}" for f in features]
    missing = [c for c in need if c not in df.columns]
    if missing:
        raise DatasetError(f"в {p} нет колонок: {missing[:5]}")
    return df


def trainable(df: pd.DataFrame) -> pd.DataFrame:
    """Строки, проходящие через модель: без экстренных вызовов (защитный слой стоит выше модели)."""
    return df[df["emergency"] == 0].reset_index(drop=True)


def raw_matrix(df: pd.DataFrame, features: list[str]):
    return df[[f"r_{f}" for f in features]].to_numpy(dtype="float64")
