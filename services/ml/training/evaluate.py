"""Метрики, пороги по целевому FPR и симуляция итоговой политики каскада."""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from .data import CLASS_EMERGENCY

# Жёсткие сигналы-свидетельства (подмена номера и нераспределённый CLI): пол вердикта review независимо
# от модели. Биты — контракт с Go (decide.HardSignals = SigSpoof|SigUnallocated = 1|2); Go проверяет
# значения тестом TestSignalBitsAreStableContract.
HARD_SIGNALS_MASK = 3


def hard_mask(df: pd.DataFrame) -> np.ndarray:
    return (df["signals"].to_numpy().astype(np.int64) & HARD_SIGNALS_MASK) > 0


def popcount(x: np.ndarray) -> np.ndarray:
    x = x.astype(np.uint64).copy()
    c = np.zeros_like(x)
    while x.any():
        c += x & np.uint64(1)
        x >>= np.uint64(1)
    return c.astype(np.int64)


def _above(v: float) -> float:
    """Наименьшее float32 строго больше v (порог хранится и сравнивается как float32)."""
    return float(np.nextafter(np.float32(v), np.float32(2)))


def quantile_above(vals: np.ndarray, allowed: int) -> float:
    """Порог, при котором не более `allowed` значений его достигают; 0 — ограничений нет."""
    if len(vals) <= allowed:
        return 0.0
    v = np.sort(vals)[len(vals) - 1 - allowed]
    return _above(v)


@dataclass
class Targets:
    review_fpr: float = 0.01
    block_fpr: float = 0.0001
    min_signals: int = 2
    gate_recall: float = 0.995
    max_ml_share: float = 0.30  # верхний предел доли трафика, уходящей в ML (нагрузка на Python-сервис)


def fit_thresholds(scores: np.ndarray, df: pd.DataFrame, t: Targets) -> tuple[float, float]:
    """Пороги review и block по целевому FPR на калибровочном наборе (без экстренных вызовов).
    Block считается по полной политике: сильные сигналы и защитные классы."""
    scores = scores.astype(np.float32)
    legit = df["label"].to_numpy() == 0
    n_legit = int(legit.sum())
    # Жёсткое правило само отмечает часть легитимных вызовов; они расходуют бюджет FPR, поэтому для порога
    # модели остаётся меньше. Считаем их по всем таким вызовам (консервативно).
    hard = hard_mask(df)
    budget = max(math.floor(t.review_fpr * n_legit) - int((legit & hard).sum()), 0)
    review = quantile_above(scores[legit & ~hard], budget)
    review = max(review, 0.001)
    blockable = legit & (popcount(df["signals"].to_numpy()) >= t.min_signals) & (df["class"].to_numpy() == 0)
    block = quantile_above(scores[blockable], math.floor(t.block_fpr * n_legit))
    block = min(max(block, review, 0.5), 1.0)
    return review, block


def fit_gate(df: pd.DataFrame, stage1_review: float, t: Targets) -> float:
    """Порог «серой зоны»: вызов уходит в ML, если s1 >= gate или есть сильный сигнал.

    Сначала ворота подбираются по полноте: среди мошеннических вызовов без сильных сигналов не менее
    gate_recall достигают ML. Если при этом в ML уходит больше max_ml_share трафика, ворота
    поднимаются до предела нагрузки (потеря полноты честно видна в отчёте). Порог не выше review
    стадии 1: иначе вызовы, отмеченные стадией 1, не дошли бы до ML."""
    fraud_no_sig = df[(df["label"] == 1) & (df["signals"] == 0)]["s1"].to_numpy(dtype=np.float32)
    if len(fraud_no_sig) == 0:
        gate = float(stage1_review)
    else:
        gate = float(min(max(np.quantile(fraud_no_sig, 1 - t.gate_recall), 1e-6), stage1_review))
    if reachable(df, gate).mean() <= t.max_ml_share:
        return gate
    lo, hi = gate, float(stage1_review)  # share(g) убывает с ростом g
    if reachable(df, hi).mean() > t.max_ml_share:
        return hi  # даже на верхней границе сильные сигналы дают больше предела — выше нельзя
    for _ in range(40):
        mid = (lo + hi) / 2
        if reachable(df, mid).mean() > t.max_ml_share:
            lo = mid
        else:
            hi = mid
    return float(hi)


def verdicts(scores: np.ndarray, df: pd.DataFrame, review: float, block: float, min_signals: int = 2) -> np.ndarray:
    """0 allow / 1 review / 2 block — та же политика, что decide.Decide в Go."""
    scores = scores.astype(np.float32)
    v = np.zeros(len(df), dtype=np.int8)
    v[scores >= np.float32(review)] = 1
    cls = df["class"].to_numpy()
    strong = popcount(df["signals"].to_numpy()) >= min_signals
    blk = (scores >= np.float32(block)) & strong
    v[blk] = 2
    v[(v == 2) & (cls != 0)] = 1  # защищённые классы не блокируются
    v[(v == 0) & hard_mask(df)] = 1  # пол: модель не может «отменить» свидетельство подмены
    v[cls == CLASS_EMERGENCY] = 0
    return v


def reachable(df: pd.DataFrame, gate: float) -> np.ndarray:
    """Вызовы, которые каскад отправит в ML."""
    return (df["s1"].to_numpy(dtype=np.float32) >= np.float32(gate)) | (df["signals"].to_numpy() > 0)


def confusion(y: np.ndarray, flagged: np.ndarray) -> dict:
    tp = int(((y == 1) & flagged).sum())
    fn = int(((y == 1) & ~flagged).sum())
    fp = int(((y == 0) & flagged).sum())
    tn = int(((y == 0) & ~flagged).sum())
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
    }


def precision_at(recall: float, fpr: float, prevalence: float) -> float:
    den = recall * prevalence + fpr * (1 - prevalence)
    return recall * prevalence / den if den else 0.0


def evaluate(
    scores: np.ndarray,
    df: pd.DataFrame,
    review: float,
    block: float,
    gate: float,
    min_signals: int = 2,
    cascade: bool = True,
) -> dict:
    """Метрики итоговой политики. Не дошедшие до ML вызовы (cascade=True) получают allow:
    их s1 ниже порога review стадии 1, то есть стадия 1 их не отмечает."""
    emergency = df["class"].to_numpy() == CLASS_EMERGENCY
    body = df[~emergency].reset_index(drop=True)
    sc = scores[~emergency]
    y = body["label"].to_numpy()
    v = verdicts(sc, body, review, block, min_signals)
    reach = reachable(body, gate)
    if cascade:
        v = np.where(reach, v, 0)
    flagged, blocked = v >= 1, v == 2
    m = {
        "n": len(body),
        "legit": int((y == 0).sum()),
        "fraud": int((y == 1).sum()),
        "auc": float(roc_auc_score(y, sc)),
        "pr_auc": float(average_precision_score(y, sc)),
        "review": confusion(y, flagged),
        "block": confusion(y, blocked),
        "ml_traffic_share": float(reach.mean()),
        "rule_floor": {
            "legit": int(
                (
                    hard_mask(body)
                    & (sc < np.float32(review))
                    & (y == 0)
                    & (body["class"].to_numpy() != CLASS_EMERGENCY)
                ).sum()
            ),
            "fraud": int((hard_mask(body) & (sc < np.float32(review)) & (y == 1)).sum()),
        },
        "ml_traffic_share_legit": float(reach[y == 0].mean()) if (y == 0).any() else 0.0,
        "emergency": {"n": int(emergency.sum())},
    }
    # экстренные: вердикт всегда allow по построению verdicts(); проверяем на данных
    em = df[emergency]
    if len(em):
        ev = verdicts(scores[emergency], em, review, block, min_signals)
        m["emergency"].update(allowed=int((ev == 0).sum()), blocked=int((ev == 2).sum()))
    else:
        m["emergency"].update(allowed=0, blocked=0)

    by_kind = {}
    for kind, g in body.assign(_f=flagged, _b=blocked, _r=reach).groupby("kind"):
        by_kind[str(kind)] = {
            "n": len(g),
            "review": int(g["_f"].sum()),
            "block": int(g["_b"].sum()),
            "ml": int(g["_r"].sum()),
            "fraud": bool(g["label"].iloc[0] == 1),
        }
    m["by_kind"] = by_kind

    # скорость реакции на номер-нарушитель (в порядке времени)
    order = np.argsort(body["ts"].to_numpy(), kind="stable")
    seen: dict[str, dict] = {}
    callers = body["caller"].to_numpy()
    for idx in order:
        if y[idx] != 1:
            continue
        s = seen.setdefault(callers[idx], {"n": 0, "review": None, "block": None})
        if flagged[idx] and s["review"] is None:
            s["review"] = s["n"]
        if blocked[idx] and s["block"] is None:
            s["block"] = s["n"]
        s["n"] += 1
    rev = [s["review"] for s in seen.values() if s["review"] is not None]
    blk = [s["block"] for s in seen.values() if s["block"] is not None]
    m["callers"] = {
        "fraud_callers": len(seen),
        "reviewed": len(rev),
        "blocked": len(blk),
        "median_calls_to_review": float(np.median(rev)) if rev else None,
        "median_calls_to_block": float(np.median(blk)) if blk else None,
    }
    return m
