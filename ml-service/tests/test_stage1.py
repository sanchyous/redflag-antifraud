import json

import numpy as np
import pytest

from app.features import monotone_constraints
from training import stage1 as S
from training.evaluate import Targets
from tests.conftest import FEATURES, make_split


def with_x(df):
    """В тестовом датасете x_* = log1p для счётчиков (как в Go), остальные без изменений."""
    out = df.copy()
    logged = {"out_calls_1h", "out_calls_24h", "out_peers_1h", "out_peers_24h", "out_regions_24h",
              "in_calls_1h", "in_peers_24h", "call_duration", "fan_size", "subscriber_numbers"}
    for f in FEATURES:
        out[f"x_{f}"] = np.log1p(out[f"r_{f}"]) if f in logged else out[f"r_{f}"]
    return out


@pytest.fixture(scope="module")
def stage1_data(tmp_path_factory):
    d = tmp_path_factory.mktemp("s1data")
    for name, seed in (("train", 1), ("calib", 2), ("test", 3)):
        with_x(make_split(4000, seed)).to_csv(d / f"{name}.csv", index=False)
    (d / "meta.json").write_text(json.dumps({"features": FEATURES}), encoding="utf-8")
    return d


def test_bounds_follow_common_sense():
    b = S.bounds_for(FEATURES)
    assert b[FEATURES.index("call_duration")] == (None, 0.0)
    assert all(lo == 0.0 and hi is None for f, (lo, hi) in zip(FEATURES, b) if f != "call_duration")


def test_fit_respects_bounds_and_learns_signal():
    r = np.random.default_rng(0)
    n = 4000
    y = (r.random(n) < 0.3).astype(float)
    X = r.normal(size=(n, 3))
    X[:, 0] += 2.0 * y            # полезный признак
    X[:, 1] -= 1.5 * y            # признак «наоборот»: без границы вес был бы отрицательным
    w, b = S.fit_logistic(X, y, np.ones(n), [(0.0, None), (0.0, None), (None, 0.0)])
    assert w[0] > 0.5
    assert w[1] == pytest.approx(0.0, abs=1e-9), "нижняя граница должна удерживать вес на нуле"
    assert w[2] <= 0.0


def test_trains_and_writes_go_compatible_json(stage1_data, tmp_path):
    out = tmp_path / "stage1.json"
    res = S.train_stage1(stage1_data, out, targets=Targets(review_fpr=0.02))
    m = json.loads(out.read_text(encoding="utf-8"))
    assert set(m) == {"version", "bias", "features", "thresholds", "metrics"}
    assert [f["name"] for f in m["features"]] == FEATURES, "порядок и имена признаков — контракт с Go"
    assert all(set(f) == {"name", "w", "base"} for f in m["features"])
    th = m["thresholds"]
    assert 0 < th["review"] <= th["block"] <= 1
    for f in m["features"]:
        assert (f["w"] <= 1e-12) if f["name"] == "call_duration" else (f["w"] >= -1e-12), f"знак веса {f['name']}"
    assert res["test"]["auc"] > 0.9
    assert res["test"]["emergency"]["blocked"] == 0


def test_stage1_contribution_decomposition_matches_logit(stage1_data, tmp_path):
    """Вклад = w·(x − base); сумма вкладов и базового logit равна logit — точное разложение."""
    out = tmp_path / "s.json"
    S.train_stage1(stage1_data, out)
    m = json.loads(out.read_text(encoding="utf-8"))
    w = np.array([f["w"] for f in m["features"]])
    base = np.array([f["base"] for f in m["features"]])
    x = np.random.default_rng(1).random(len(w)) * 3
    logit = m["bias"] + w @ x
    base_logit = m["bias"] + w @ base
    assert logit == pytest.approx(base_logit + (w * (x - base)).sum())
