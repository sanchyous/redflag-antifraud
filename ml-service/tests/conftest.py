"""Общие фикстуры: небольшой синтетический датасет в формате Go-экспорта и обученная на нём модель."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Порядок и имена — копия internal/features (проверяется тестом против meta.json Go при наличии).
FEATURES = [
    "out_calls_1h", "out_calls_24h", "out_peers_1h", "out_peers_24h", "out_novelty",
    "out_regions_24h", "out_region_entropy", "out_short_share", "out_unanswered_share", "out_gap_robot",
    "in_calls_1h", "in_peers_24h",
    "call_short", "call_hangup_1s", "call_unanswered", "call_night", "call_duration",
    "foreign_ingress", "spoof", "caller_unallocated", "caller_invalid", "operator_mismatch", "conn_international",
    "fan_member", "fan_size", "subscriber_numbers",
]


def make_split(n: int, seed: int, fraud_share: float = 0.2, with_emergency: bool = True) -> pd.DataFrame:
    """Синтетические строки: мошенники — короткие/неотвеченные, много собеседников, часть со spoof;
    легитимные — обычные, плюс «трудные» (много уникальных адресатов, но длинные разговоры)."""
    r = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        fraud = r.random() < fraud_share
        f = dict.fromkeys(FEATURES, 0.0)
        kind = "regular"
        if fraud:
            kind = str(r.choice(["spoof_burst", "robocall", "one_ring"]))
            f["out_calls_1h"] = float(r.integers(20, 300))
            f["out_calls_24h"] = f["out_calls_1h"] + float(r.integers(0, 200))
            f["out_peers_1h"] = f["out_calls_1h"] * float(r.uniform(0.8, 1.0))
            f["out_peers_24h"] = f["out_calls_24h"] * float(r.uniform(0.8, 1.0))
            f["out_novelty"] = float(r.uniform(0.8, 1.0))
            f["out_regions_24h"] = float(r.integers(5, 60))
            f["out_region_entropy"] = float(r.uniform(2, 5))
            f["out_short_share"] = float(r.uniform(0.5, 1.0))
            f["out_unanswered_share"] = float(r.uniform(0.3, 0.9))
            f["call_short"] = float(r.random() < 0.6)
            f["call_duration"] = float(r.integers(0, 12))
            f["foreign_ingress"] = f["spoof"] = f["conn_international"] = float(kind == "spoof_burst")
            f["out_gap_robot"] = float(r.uniform(0.6, 1.0)) if kind == "robocall" else 0.0
        else:
            if r.random() < 0.15:
                kind = "call_center"
                f["out_calls_1h"] = float(r.integers(15, 45))
                f["out_calls_24h"] = f["out_calls_1h"] * 6
                f["out_peers_1h"] = f["out_calls_1h"] * float(r.uniform(0.6, 0.9))
                f["out_peers_24h"] = f["out_calls_24h"] * float(r.uniform(0.5, 0.8))
                f["out_novelty"] = float(r.uniform(0.5, 0.8))
                f["out_unanswered_share"] = float(r.uniform(0.3, 0.6))
                f["out_short_share"] = float(r.uniform(0.0, 0.15))
                f["call_duration"] = float(r.integers(20, 200))
            else:
                f["out_calls_1h"] = float(r.integers(0, 4))
                f["out_calls_24h"] = f["out_calls_1h"] + float(r.integers(0, 8))
                f["out_peers_1h"] = min(f["out_calls_1h"], float(r.integers(0, 3)))
                f["out_peers_24h"] = min(f["out_calls_24h"], float(r.integers(0, 6)))
                f["out_short_share"] = float(r.uniform(0, 0.1))
                f["out_unanswered_share"] = float(r.uniform(0, 0.25))
                f["call_duration"] = float(r.integers(20, 600))
        sig = 0
        if f["spoof"]:
            sig |= 1
        if f["out_calls_1h"] >= 60 and f["out_short_share"] >= 0.7:
            sig |= 8
        row = {
            "label": int(fraud), "kind": kind, "class": 0, "signals": sig, "emergency": 0,
            "caller": f"c{seed}-{i // 8}", "ts": 1_800_000_000 + i * 30,
            "s1": float(min(1.0, 0.002 + 0.9 * fraud * r.random() + 0.02 * r.random())),
        }
        row.update({f"r_{k}": v for k, v in f.items()})
        rows.append(row)
    df = pd.DataFrame(rows)
    if with_emergency:
        em = df.head(max(3, n // 100)).copy()
        em["emergency"], em["class"], em["kind"], em["label"], em["signals"] = 1, 3, "emergency", 0, 0
        for k in FEATURES:
            em[f"r_{k}"] = 0.0
        df = pd.concat([df, em], ignore_index=True)
    # часть легитимных — защищённые классы (allowlist/сервисные)
    legit_idx = df.index[(df["label"] == 0) & (df["emergency"] == 0)]
    df.loc[legit_idx[::17], "class"] = 2
    return df


@pytest.fixture(scope="session")
def dataset_dir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("dataset")
    for name, seed in (("train", 1), ("calib", 2), ("test", 3)):
        make_split(4000, seed).to_csv(d / f"{name}.csv", index=False)
    (d / "meta.json").write_text(json.dumps({"features": FEATURES, "numplan_version": "test", "seed": 1}), encoding="utf-8")
    return d


@pytest.fixture(scope="session")
def trained(dataset_dir, tmp_path_factory):
    from training.train import train
    out = tmp_path_factory.mktemp("model")
    res = train(dataset_dir, out, iterations=80, seed=1, report_path=out / "report.md")
    return out, res
