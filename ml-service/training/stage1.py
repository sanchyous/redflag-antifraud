"""Обучение линейной стадии 1: взвешенная логистическая регрессия с ограничениями знаков весов.

Стадия 1 решает почти весь трафик в Go-ядре за микросекунды и остаётся запасным решателем, если ML-сервис
недоступен, поэтому она должна быть объяснимой (рост признака не снижает риск — веса неотрицательны, кроме
длительности разговора) и с приемлемой долей ложных срабатываний. Результат — stage1.json в формате,
который читает Go (scoring.Load): вклад признака = вес × (значение − базовое значение эталонного абонента).

    python -m training.stage1 --data ../dataset --out models/stage1.json
"""
from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.optimize import minimize

from app.features import MONOTONE_DECREASING
from . import data as D
from . import evaluate as E


def x_matrix(df: pd.DataFrame, features: list[str]) -> np.ndarray:
    """Вход линейной модели (преобразованные признаки x_*, как их считает Go)."""
    return df[[f"x_{f}" for f in features]].to_numpy(dtype="float64")


def bounds_for(features: list[str]) -> list[tuple[float | None, float | None]]:
    """Ограничения весов: рост признака не снижает риск (w >= 0); у длительности разговора — наоборот."""
    b: list[tuple[float | None, float | None]] = []
    for f in features:
        b.append((None, 0.0) if f in MONOTONE_DECREASING else (0.0, None))
    return b


def fit_logistic(X: np.ndarray, y: np.ndarray, weights: np.ndarray, bounds, l2: float = 1e-3):
    """Взвешенная логистическая регрессия L-BFGS-B с границами на веса. Возвращает (w, bias)."""
    n, d = X.shape
    sw = weights / weights.sum()

    def loss_grad(theta: np.ndarray):
        w, b = theta[:d], theta[d]
        z = X @ w + b
        # log(1+e^z) - y*z, устойчиво
        log1pexp = np.where(z > 0, z + np.log1p(np.exp(-z)), np.log1p(np.exp(z)))
        loss = float(np.sum(sw * (log1pexp - y * z))) + 0.5 * l2 * float(w @ w)
        p = 1.0 / (1.0 + np.exp(-np.clip(z, -700, 700)))
        r = sw * (p - y)
        g = np.empty(d + 1)
        g[:d] = X.T @ r + l2 * w
        g[d] = r.sum()
        return loss, g

    prior = float((sw * y).sum())
    theta0 = np.zeros(d + 1)
    theta0[d] = math.log(prior / (1 - prior))
    res = minimize(loss_grad, theta0, jac=True, method="L-BFGS-B", bounds=list(bounds) + [(None, None)],
                   options={"maxiter": 500, "ftol": 1e-12})
    return res.x[:d], float(res.x[d])


def sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -700, 700)))


def train_stage1(data_dir: Path, out_path: Path, *, prevalence: float = 0.01, legit_weight: float = 3.0,
                 targets: E.Targets | None = None, l2: float = 1e-3) -> dict:
    targets = targets or E.Targets()
    meta_in = D.load_meta(data_dir)
    features: list[str] = list(meta_in["features"])
    train = D.trainable(D.load_split(data_dir, "train", features))
    calib = D.trainable(D.load_split(data_dir, "calib", features))
    test_full = D.load_split(data_dir, "test", features)

    Xtr, ytr = x_matrix(train, features), train["label"].to_numpy().astype(float)
    sw = np.where(ytr == 0, legit_weight, 1.0)
    w, bias = fit_logistic(Xtr, ytr, sw, bounds_for(features), l2)
    # Смещение под ожидаемую долю мошенничества в боевом потоке (пороги от неё не зависят — они по FPR).
    train_prior = float((sw * ytr).sum() / sw.sum())
    bias += math.log(prevalence / (1 - prevalence)) - math.log(train_prior / (1 - train_prior))

    # Эталонный абонент — среднее преобразованных признаков легитимных вызовов; вклад = w·(x − base).
    base = Xtr[ytr == 0].mean(axis=0)

    def score(df: pd.DataFrame) -> np.ndarray:
        return sigmoid(x_matrix(df, features) @ w + bias)

    review, block = E.fit_thresholds(score(calib), calib, targets)
    m = E.evaluate(score(test_full), test_full, review, block, gate=0.0, min_signals=targets.min_signals, cascade=False)
    version = "stage1-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    model = {
        "version": version,
        "bias": float(bias),
        "features": [{"name": f, "w": float(w[i]), "base": float(base[i])} for i, f in enumerate(features)],
        "thresholds": {"review": float(review), "block": float(block)},
        "metrics": {"auc": m["auc"], "review_recall": m["review"]["recall"], "review_fpr": m["review"]["fpr"],
                    "block_recall": m["block"]["recall"], "block_fpr": m["block"]["fpr"]},
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(model, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"model": model, "test": m}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--prevalence", type=float, default=0.01)
    ap.add_argument("--legit-weight", type=float, default=3.0)
    ap.add_argument("--review-fpr", type=float, default=0.01)
    ap.add_argument("--block-fpr", type=float, default=0.0001)
    ap.add_argument("--min-signals", type=int, default=2)
    ap.add_argument("--l2", type=float, default=1e-3)
    a = ap.parse_args()
    res = train_stage1(a.data, a.out, prevalence=a.prevalence, legit_weight=a.legit_weight, l2=a.l2,
                       targets=E.Targets(review_fpr=a.review_fpr, block_fpr=a.block_fpr, min_signals=a.min_signals))
    t = res["test"]
    print(f"{res['model']['version']}: AUC {t['auc']:.4f}, review recall {t['review']['recall']:.1%} FPR {t['review']['fpr']:.3%}, "
          f"block recall {t['block']['recall']:.1%} FPR {t['block']['fpr']:.4%} ({t['block']['fp']} из {t['legit']})")
    zero = [f["name"] for f in res["model"]["features"] if abs(f["w"]) < 1e-9]
    if zero:
        print("нулевые веса:", ", ".join(zero))


if __name__ == "__main__":
    main()
