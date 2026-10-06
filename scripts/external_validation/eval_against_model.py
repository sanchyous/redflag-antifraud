#!/usr/bin/env python3
"""Оценивает уже обученную модель (services/ml, ModelBundle) на независимом наборе, которого она не
видела ни при обучении, ни при подборе порогов. Запускать из services/ml/ (нужны его зависимости).

    cd services/ml
    python ../../scripts/external_validation/eval_against_model.py <model_dir> <dataset_dir>

<dataset_dir> — вывод `go run ./cmd/export -input ... -out ...` (train/calib/test.csv + meta.json);
для внешней проверки они объединяются в один набор — деления на train/calib/test здесь не имеют
значения, модель их не видела ни в каком качестве. См. docs/external-validation.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, ".")
from app.model import ModelBundle
from training import data as D
from training import evaluate as E


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("model_dir", type=Path)
    ap.add_argument("dataset_dir", type=Path)
    args = ap.parse_args()

    meta = D.load_meta(args.dataset_dir)
    features = meta["features"]
    df = pd.concat(
        [
            D.load_split(args.dataset_dir, name, features)
            for name in ("train", "calib", "test")
        ],
        ignore_index=True,
    )
    df = D.trainable(df)  # без экстренных (здесь их и не будет)
    print(
        f"строк для оценки: {len(df)}, мошеннических: {int(df['label'].sum())}",
        file=sys.stderr,
    )

    bundle = ModelBundle.load(args.model_dir)
    rows = [
        dict(zip(features, vals, strict=True))
        for vals in df[[f"r_{f}" for f in features]].to_numpy()
    ]
    scores = np.array([r.score for r in bundle.score(rows)])
    y = df["label"].to_numpy()

    print(f"ROC-AUC: {roc_auc_score(y, scores):.4f}")
    print(
        f"PR-AUC: {average_precision_score(y, scores):.4f}  (базовая линия — доля фрода: {y.mean():.4f})"
    )

    for fpr_target in (0.01, 0.05):
        thr = E.quantile_above(
            np.sort(scores[y == 0]), int((y == 0).sum() * fpr_target)
        )
        recall = ((scores >= thr) & (y == 1)).sum() / max(1, (y == 1).sum())
        print(
            f"порог, подобранный НА ЭТОМ наборе под FPR<={fpr_target:.0%}: recall={recall:.1%}"
        )

    # пороги из своей модели (подобраны на СВОИХ данных) — честная проверка переноса, а не подгонка под чужие
    th = json.loads((args.model_dir / "meta.json").read_text())["thresholds"]
    review_recall = ((scores >= th["review"]) & (y == 1)).sum() / max(1, (y == 1).sum())
    review_fpr = ((scores >= th["review"]) & (y == 0)).sum() / max(1, (y == 0).sum())
    print(
        f"со своими порогами (review={th['review']:.4f}): recall={review_recall:.1%}, FPR={review_fpr:.1%}"
    )


if __name__ == "__main__":
    main()
