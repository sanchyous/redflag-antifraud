"""Загрузка и применение модели: CatBoost + калибровка Платта + точный TreeSHAP."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from catboost import CatBoostClassifier, Pool

META_FILE = "meta.json"
MODEL_FILE = "model.cbm"


class ModelError(Exception):
    """Ошибка загрузки модели или контракта признаков."""


class FeatureError(ValueError):
    """Во входе нет обязательных признаков или значения некорректны."""


@dataclass(frozen=True)
class Thresholds:
    review: float
    block: float
    gate: float  # порог стадии 1, с которого вызов уходит в ML (справочно для ядра)
    min_signals: int = 2


@dataclass
class Contribution:
    feature: str
    value: float
    contribution: float  # вклад в лог-шансы относительно среднего, >0 повышает риск


@dataclass
class ScoreResult:
    score: float
    logit: float
    base_logit: float
    contributions: list[Contribution] = field(default_factory=list)


def _sigmoid(x: np.ndarray) -> np.ndarray:
    # устойчивая сигмоида
    out = np.empty_like(x, dtype=np.float64)
    pos = x >= 0
    out[pos] = 1.0 / (1.0 + np.exp(-x[pos]))
    e = np.exp(x[~pos])
    out[~pos] = e / (1.0 + e)
    return out


class ModelBundle:
    """Модель со всем необходимым для инференса. Потокобезопасна для чтения: CatBoost
    predict/SHAP не изменяют состояние модели."""

    def __init__(self, model: CatBoostClassifier, meta: dict):
        self.model = model
        self.meta = meta
        self.features: list[str] = list(meta["features"])
        self.version: str = str(meta["version"])
        self.platt_a = float(meta.get("platt_a", 1.0))
        self.platt_b = float(meta.get("platt_b", 0.0))
        if not (self.platt_a > 0 and math.isfinite(self.platt_a) and math.isfinite(self.platt_b)):
            raise ModelError("некорректная калибровка (platt_a должен быть > 0)")
        th = meta["thresholds"]
        self.thresholds = Thresholds(
            review=float(th["review"]), block=float(th["block"]), gate=float(th.get("gate", 0.0)),
            min_signals=int(th.get("min_signals", 2)),
        )
        if not (0 < self.thresholds.review <= self.thresholds.block <= 1):
            raise ModelError("пороги должны удовлетворять 0 < review <= block <= 1")
        if list(model.feature_names_) != self.features:
            raise ModelError("порядок признаков модели не совпадает с meta.json")
        self.warmup()

    def warmup(self) -> None:
        """Прогрев: первый вызов predict и SHAP заметно медленнее последующих (инициализация
        внутренних структур CatBoost) и мог бы упереться в таймаут ядра."""
        row = {f: 0.0 for f in self.features}
        self.score([row], explain=True)

    @classmethod
    def load(cls, directory: str | Path) -> "ModelBundle":
        d = Path(directory)
        try:
            meta = json.loads((d / META_FILE).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise ModelError(f"не удалось прочитать {d / META_FILE}: {e}") from e
        model = CatBoostClassifier()
        try:
            model.load_model(str(d / MODEL_FILE))
        except Exception as e:  # catboost бросает общий CatBoostError
            raise ModelError(f"не удалось загрузить {d / MODEL_FILE}: {e}") from e
        return cls(model, meta)

    def matrix(self, rows: list[dict[str, float]]) -> np.ndarray:
        """Строит матрицу признаков в порядке модели. Отсутствующий признак — ошибка контракта
        (молчаливая подстановка нуля скрыла бы рассинхрон Go и Python)."""
        X = np.empty((len(rows), len(self.features)), dtype=np.float64)
        for i, row in enumerate(rows):
            for j, name in enumerate(self.features):
                if name not in row:
                    raise FeatureError(f"нет признака {name!r} в строке {i}")
                v = float(row[name])
                if not math.isfinite(v):
                    raise FeatureError(f"признак {name!r} не число: {row[name]!r}")
                X[i, j] = v
        return X

    def score(self, rows: list[dict[str, float]], explain: bool = False, top_k: int = 6, neg_k: int = 2) -> list[ScoreResult]:
        if not rows:
            return []
        X = self.matrix(rows)
        raw = np.asarray(self.model.predict(X, prediction_type="RawFormulaVal"), dtype=np.float64)
        logit = self.platt_a * raw + self.platt_b
        prob = _sigmoid(logit)
        shap = None
        if explain:
            shap = self.model.get_feature_importance(Pool(X, feature_names=self.features), type="ShapValues")
        out: list[ScoreResult] = []
        for i in range(len(rows)):
            res = ScoreResult(score=float(prob[i]), logit=float(logit[i]), base_logit=0.0)
            if shap is not None:
                phi = self.platt_a * shap[i, :-1]  # калибровка линейна по logit → вклады масштабируются
                res.base_logit = float(self.platt_a * shap[i, -1] + self.platt_b)
                res.contributions = self._top(phi, X[i], top_k, neg_k)
            out.append(res)
        return out

    def _top(self, phi: np.ndarray, x: np.ndarray, k: int, neg_k: int) -> list[Contribution]:
        order = np.argsort(-np.abs(phi))
        contribs = [
            Contribution(self.features[j], float(x[j]), float(phi[j]))
            for j in order if abs(phi[j]) > 1e-6
        ]
        pos = [c for c in contribs if c.contribution > 0][:k]
        neg = [c for c in contribs if c.contribution < 0][:neg_k]
        return pos + neg
