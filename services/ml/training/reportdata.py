"""Машиночитаемый отчёт об обучении (report.json) для раздела «ML» панели мониторинга.

Лежит рядом с моделью (каталог модели ML-сервиса) и отдаётся через GET /v1/report: панель показывает
не только итоговые числа, но и кривые, распределения, калибровку и разбор по типам абонентов.
Все кривые считаются на независимой проверке (test), не участвовавшей ни в обучении, ни в подборе порогов.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve, roc_auc_score, roc_curve

from . import evaluate as E
from .data import CLASS_EMERGENCY

REPORT_FILE = "report.json"
SCHEMA = 1


def _round(a, n: int = 6) -> list[float]:
    return [round(float(x), n) for x in a]


def roc_points(y: np.ndarray, s: np.ndarray, n: int = 90) -> dict:
    """Кривая «доля пойманных мошеннических (recall) при доле ложных срабатываний (FPR)». По оси FPR — логарифмическая
    сетка от 1e-5 до 1: именно область малых FPR важна для кейса."""
    fpr, tpr, _ = roc_curve(y, s)
    grid = np.geomspace(1e-5, 1.0, n)
    idx = np.clip(np.searchsorted(fpr, grid, side="right") - 1, 0, len(tpr) - 1)
    return {"fpr": _round(grid, 7), "recall": _round(tpr[idx], 5)}


def pr_points(y: np.ndarray, s: np.ndarray, n: int = 80) -> dict:
    prec, rec, _ = precision_recall_curve(y, s)
    # recall убывает вдоль массива; берём точки на равномерной сетке recall
    grid = np.linspace(0.0, 1.0, n)
    order = np.argsort(rec)
    p = np.interp(grid, rec[order], prec[order])
    return {"recall": _round(grid, 4), "precision": _round(p, 5)}


def score_hist(y: np.ndarray, s: np.ndarray, bins: int = 36) -> dict:
    """Распределение score легитимных и мошеннических вызовов (лог-шкала: основная масса легитимных — около нуля)."""
    edges = np.geomspace(1e-5, 1.0, bins + 1)
    clipped = np.clip(s, 1e-5, 1.0)
    legit, _ = np.histogram(clipped[y == 0], bins=edges)
    fraud, _ = np.histogram(clipped[y == 1], bins=edges)
    return {"edges": _round(edges, 7), "legit": [int(x) for x in legit], "fraud": [int(x) for x in fraud]}


def calibration(y: np.ndarray, s: np.ndarray, prevalence: float, bins: int = 12) -> list[dict]:
    """Надёжность калибровки: средний прогноз против фактической доли мошенничества. Тестовый набор содержит
    больше мошенничества, чем боевой поток, поэтому легитимные вызовы перевешиваются до ожидаемой доли (prevalence)."""
    n_pos, n_neg = max(int((y == 1).sum()), 1), max(int((y == 0).sum()), 1)
    w = np.where(y == 1, prevalence / n_pos, (1 - prevalence) / n_neg)
    edges = np.geomspace(1e-5, 1.0, bins + 1)
    idx = np.clip(np.digitize(s, edges) - 1, 0, bins - 1)
    out = []
    for b in range(bins):
        m = idx == b
        if not m.any():
            continue
        wt = w[m].sum()
        out.append(
            {
                "predicted": round(float((s[m] * w[m]).sum() / wt), 6),
                "observed": round(float((y[m] * w[m]).sum() / wt), 6),
                "n": int(m.sum()),
            }
        )
    return out


def threshold_sweep(y: np.ndarray, s: np.ndarray, n: int = 48) -> dict:
    """Что даёт каждый порог score: доля пойманных мошеннических и доля ложных срабатываний."""
    th = np.geomspace(1e-4, 1.0, n)
    legit, fraud = max(int((y == 0).sum()), 1), max(int((y == 1).sum()), 1)
    fpr = [float(((s >= t) & (y == 0)).sum() / legit) for t in th]
    rec = [float(((s >= t) & (y == 1)).sum() / fraud) for t in th]
    return {"threshold": _round(th, 6), "fpr": _round(fpr, 6), "recall": _round(rec, 5)}


def learning_curve(evals_result: dict | None, n: int = 120) -> dict | None:
    """Кривая обучения CatBoost: метрика на train и на отложенной выборке по итерациям бустинга —
    видно переобучение (расхождение кривых) и момент ранней остановки, не только финальный результат.
    evals_result — вывод `model.get_evals_result()`; downsample до n точек, итераций обычно больше."""
    if not evals_result:
        return None
    learn = evals_result.get("learn", {})
    valid = evals_result.get("validation", {})
    metric = next((m for m in ("AUC", "Logloss") if m in learn), None)
    if metric is None or metric not in valid:
        return None
    tr, va = np.asarray(learn[metric], dtype=np.float64), np.asarray(valid[metric], dtype=np.float64)
    total = len(tr)
    if total == 0:
        return None
    idx = np.unique(np.linspace(0, total - 1, min(n, total)).astype(int))
    return {
        "metric": metric,
        "iteration": [int(i) for i in idx],
        "train": _round(tr[idx], 6),
        "validation": _round(va[idx], 6),
        "best_iteration": int(np.argmax(va)) if metric == "AUC" else int(np.argmin(va)),
    }


def recall_at_fpr(y: np.ndarray, s: np.ndarray, fpr_target: float) -> float:
    legit = np.sort(s[y == 0])
    allowed = int(len(legit) * fpr_target)
    thr = E.quantile_above(legit, allowed)
    return float(((s >= thr) & (y == 1)).sum() / max(int((y == 1).sum()), 1))


def build(
    *,
    meta: dict,
    meta_in: dict,
    scores: np.ndarray,
    test_full: pd.DataFrame,
    m_test: dict,
    m_test_flat: dict,
    targets,
    n_train: int,
    n_calib: int,
    importances: dict[str, float],
    stage1_review: float,
    graph: dict | None = None,
    evals_result: dict | None = None,
) -> dict:
    body_mask = test_full["class"].to_numpy() != CLASS_EMERGENCY
    body = test_full[body_mask].reset_index(drop=True)
    s = scores[body_mask].astype(np.float64)
    y = body["label"].to_numpy()
    s1 = body["s1"].to_numpy(dtype=np.float64)
    th = meta["thresholds"]
    prevalence = float(meta["prevalence"])

    stage1_auc = float(roc_auc_score(y, s1))
    return {
        "schema": SCHEMA,
        "model": {
            "version": meta["version"],
            "trained_at": meta["trained_at"],
            "algorithm": "CatBoost (монотонные ограничения) + калибровка Платта + TreeSHAP",
            "features": meta["features"],
            "thresholds": th,
            "prevalence": prevalence,
            "legit_weight": meta["legit_weight"],
            "platt": {"a": meta["platt_a"], "b": meta["platt_b"]},
        },
        "data": {
            "source": "размеченный файл организаторов"
            if meta_in.get("input")
            else "синтетика (генератор internal/lab/synth)",
            "synthetic": not bool(meta_in.get("input")),
            "seed": meta_in.get("seed"),
            "days": meta_in.get("days"),
            "numplan_version": meta_in.get("numplan_version"),
            "train": n_train,
            "calib": n_calib,
            "test": int(m_test["n"] + m_test["emergency"]["n"]),
            "test_legit": m_test["legit"],
            "test_fraud": m_test["fraud"],
            "test_fraud_share": m_test["fraud"] / max(m_test["n"], 1),
        },
        "targets": {
            "review_fpr": targets.review_fpr,
            "block_fpr": targets.block_fpr,
            "min_signals": targets.min_signals,
            "max_ml_share": targets.max_ml_share,
            "gate_recall": targets.gate_recall,
        },
        "quality": {
            "auc": m_test["auc"],
            "pr_auc": m_test["pr_auc"],
            "review": m_test["review"],
            "block": m_test["block"],
            "flat_review": m_test_flat["review"],
            "flat_block": m_test_flat["block"],
            "ml_traffic_share": m_test["ml_traffic_share"],
            "ml_traffic_share_legit": m_test["ml_traffic_share_legit"],
            "rule_floor": m_test["rule_floor"],
            "emergency": m_test["emergency"],
            "callers": m_test["callers"],
            "precision_by_prevalence": [
                {
                    "prevalence": p,
                    "review": E.precision_at(m_test["review"]["recall"], m_test["review"]["fpr"], p),
                    "block": E.precision_at(m_test["block"]["recall"], m_test["block"]["fpr"], p),
                }
                for p in (0.001, 0.01, 0.05, 0.15)
            ],
        },
        "curves": {
            "roc_ml": roc_points(y, s),
            "roc_stage1": roc_points(y, s1),
            "pr_ml": pr_points(y, s),
            "score_hist": score_hist(y, s),
            "calibration": calibration(y, s, prevalence),
            "sweep": threshold_sweep(y, s),
            "learning": learning_curve(evals_result),
        },
        "uplift": {
            "auc_stage1": stage1_auc,
            "auc_ml": m_test["auc"],
            "recall_at_review_fpr": {
                "fpr": targets.review_fpr,
                "stage1": recall_at_fpr(y, s1, targets.review_fpr),
                "ml": recall_at_fpr(y, s, targets.review_fpr),
            },
            "recall_at_block_fpr": {
                "fpr": targets.block_fpr,
                "stage1": recall_at_fpr(y, s1, targets.block_fpr),
                "ml": recall_at_fpr(y, s, targets.block_fpr),
            },
            "stage1_review": stage1_review,
        },
        "by_kind": m_test["by_kind"],
        "importances": {k: round(float(v), 4) for k, v in sorted(importances.items(), key=lambda kv: -kv[1])},
        "graph": graph or {"available": False, "reason": "не посчитан"},
    }
