"""Обучение ML-модели: CatBoost с монотонными ограничениями + калибровка Платта + пороги по FPR.

python -m training.train --data ../dataset --out models/current --report report.md
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier, Pool
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit

from app.features import monotone_constraints
from app.model import META_FILE, MODEL_FILE

from . import data as D
from . import evaluate as E
from . import graphfeat as GF
from .report import write_report
from .reportdata import REPORT_FILE
from .reportdata import build as build_report


def fit_catboost(
    train: pd.DataFrame,
    features: list[str],
    legit_weight: float,
    seed: int,
    iterations: int = 500,
    depth: int = 6,
    learning_rate: float = 0.08,
) -> CatBoostClassifier:
    """Обучает CatBoost. Ранняя остановка идёт по отложенной части train, разбитой ПО НОМЕРАМ
    (GroupShuffleSplit): вызовы одного номера не попадают одновременно в обучение и остановку —
    иначе оценка завышена утечкой."""
    X = D.raw_matrix(train, features)
    y = train["label"].to_numpy()
    groups = train["caller"].astype(str).to_numpy()
    gss = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=seed)
    tr, va = next(gss.split(X, y, groups))
    weights = np.where(y == 0, legit_weight, 1.0)  # ложное срабатывание дороже пропуска
    model = CatBoostClassifier(
        iterations=iterations,
        depth=depth,
        learning_rate=learning_rate,
        loss_function="Logloss",
        eval_metric="AUC",
        random_seed=seed,
        verbose=0,
        allow_writing_files=False,
        monotone_constraints=monotone_constraints(features),
        early_stopping_rounds=50,
        thread_count=-1,
    )
    model.fit(
        Pool(X[tr], y[tr], weight=weights[tr], feature_names=features),
        eval_set=Pool(X[va], y[va], weight=weights[va], feature_names=features),
    )
    return model


def fit_platt(raw_logit: np.ndarray, y: np.ndarray, prevalence: float) -> tuple[float, float]:
    """Калибровка Платта на калибровочном наборе с весами, приводящими долю мошенничества к
    ожидаемой в боевом потоке (prevalence). Возвращает (a, b): p = sigmoid(a*logit + b)."""
    n = len(y)
    n_pos = max(int((y == 1).sum()), 1)
    n_neg = max(int((y == 0).sum()), 1)
    w = np.where(y == 1, prevalence * n / n_pos, (1 - prevalence) * n / n_neg)
    lr = LogisticRegression(C=1e6, solver="lbfgs", max_iter=1000)
    lr.fit(raw_logit.reshape(-1, 1), y, sample_weight=w)
    a, b = float(lr.coef_[0, 0]), float(lr.intercept_[0])
    if a <= 0:  # монотонность калибровки обязательна: иначе порядок score перевернётся
        raise ValueError(f"калибровка дала неположительный наклон {a}")
    return a, b


def raw_logits(model: CatBoostClassifier, df: pd.DataFrame, features: list[str]) -> np.ndarray:
    return np.asarray(model.predict(D.raw_matrix(df, features), prediction_type="RawFormulaVal"), dtype=np.float64)


def sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -700, 700)))


def train(
    data_dir: Path,
    out_dir: Path,
    *,
    prevalence: float = 0.01,
    legit_weight: float = 3.0,
    targets: E.Targets | None = None,
    seed: int = 1,
    iterations: int = 500,
    stage1_review: float = 0.15,
    report_path: Path | None = None,
) -> dict:
    targets = targets or E.Targets()
    meta_in = D.load_meta(data_dir)
    features: list[str] = list(meta_in["features"])
    train_df = D.trainable(D.load_split(data_dir, "train", features))
    calib_full = D.load_split(data_dir, "calib", features)
    test_full = D.load_split(data_dir, "test", features)
    calib = D.trainable(calib_full)

    model = fit_catboost(train_df, features, legit_weight, seed, iterations)
    evals_result = model.get_evals_result()
    a, b = fit_platt(raw_logits(model, calib, features), calib["label"].to_numpy(), prevalence)

    def score(df: pd.DataFrame) -> np.ndarray:
        return sigmoid(a * raw_logits(model, df, features) + b)

    review, block = E.fit_thresholds(score(calib), calib, targets)
    gate = E.fit_gate(calib, stage1_review, targets)
    m_test = E.evaluate(score(test_full), test_full, review, block, gate, targets.min_signals)
    m_test_flat = E.evaluate(score(test_full), test_full, review, block, gate, targets.min_signals, cascade=False)
    # графовый анализ (NetworkX) — отдельно от каскада, считается один раз и идёт в оба отчёта
    graph = GF.analyze(test_full[test_full["emergency"] == 0] if "emergency" in test_full.columns else test_full)

    version = "catboost-" + datetime.now(UTC).strftime("%Y%m%d-%H%M")
    metrics = {
        "auc": m_test["auc"],
        "pr_auc": m_test["pr_auc"],
        "review_recall": m_test["review"]["recall"],
        "review_fpr": m_test["review"]["fpr"],
        "block_recall": m_test["block"]["recall"],
        "block_fpr": m_test["block"]["fpr"],
        "ml_traffic_share": m_test["ml_traffic_share"],
    }
    meta = {
        "version": version,
        "features": features,
        "platt_a": a,
        "platt_b": b,
        "thresholds": {"review": review, "block": block, "gate": gate, "min_signals": targets.min_signals},
        "metrics": metrics,
        "prevalence": prevalence,
        "legit_weight": legit_weight,
        "numplan_version": meta_in.get("numplan_version"),
        "dataset_seed": meta_in.get("seed"),
        "trained_at": datetime.now(UTC).isoformat(),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    model.save_model(str(out_dir / MODEL_FILE))
    (out_dir / META_FILE).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    importances = dict(zip(features, model.get_feature_importance(), strict=True))
    (out_dir / REPORT_FILE).write_text(
        json.dumps(
            build_report(
                meta=meta,
                meta_in=meta_in,
                scores=score(test_full),
                test_full=test_full,
                m_test=m_test,
                m_test_flat=m_test_flat,
                targets=targets,
                n_train=len(train_df),
                n_calib=len(calib),
                importances=importances,
                stage1_review=stage1_review,
                graph=graph,
                evals_result=evals_result,
            ),
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    if report_path:
        write_report(
            report_path,
            meta=meta,
            test=m_test,
            test_flat=m_test_flat,
            targets=targets,
            n_train=len(train_df),
            n_calib=len(calib),
            importances=importances,
            graph=graph,
        )
    return {"meta": meta, "test": m_test}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", required=True, type=Path, help="каталог с train.csv, calib.csv, test.csv, meta.json")
    ap.add_argument("--out", required=True, type=Path, help="куда записать model.cbm и meta.json")
    ap.add_argument("--report", type=Path, default=None)
    ap.add_argument("--prevalence", type=float, default=0.01)
    ap.add_argument("--legit-weight", type=float, default=3.0)
    ap.add_argument("--review-fpr", type=float, default=0.01)
    ap.add_argument("--block-fpr", type=float, default=0.0001)
    ap.add_argument("--min-signals", type=int, default=2)
    ap.add_argument("--max-ml-share", type=float, default=0.30, help="предел доли трафика, уходящей в ML")
    ap.add_argument("--iterations", type=int, default=500)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    res = train(
        args.data,
        args.out,
        prevalence=args.prevalence,
        legit_weight=args.legit_weight,
        seed=args.seed,
        iterations=args.iterations,
        report_path=args.report,
        targets=E.Targets(
            review_fpr=args.review_fpr,
            block_fpr=args.block_fpr,
            min_signals=args.min_signals,
            max_ml_share=args.max_ml_share,
        ),
    )
    t = res["test"]
    print(
        f"версия {res['meta']['version']}: AUC {t['auc']:.4f}, review recall {t['review']['recall']:.1%} "
        f"FPR {t['review']['fpr']:.3%}, block recall {t['block']['recall']:.1%} FPR {t['block']['fpr']:.4%} "
        f"(ложных блокировок {t['block']['fp']} из {t['legit']}), в ML уходит {t['ml_traffic_share']:.1%} трафика"
    )


if __name__ == "__main__":
    main()
