import json

import numpy as np
import pytest

from app.model import META_FILE, MODEL_FILE, ModelBundle, ModelError
from tests.conftest import FEATURES
from training import data as D
from training.train import fit_platt, sigmoid


def test_training_artifacts_and_quality(trained):
    out, res = trained
    assert (out / MODEL_FILE).exists() and (out / META_FILE).exists() and (out / "report.md").exists()
    meta = json.loads((out / META_FILE).read_text(encoding="utf-8"))
    assert meta["features"] == FEATURES
    th = meta["thresholds"]
    assert 0 < th["review"] <= th["block"] <= 1 and 0 < th["gate"] <= 0.15
    assert meta["platt_a"] > 0
    t = res["test"]
    assert t["auc"] > 0.95
    assert t["emergency"]["blocked"] == 0
    assert t["review"]["recall"] > 0.7


def test_report_content(trained):
    out, _ = trained
    text = (out / "report.md").read_text(encoding="utf-8")
    for want in (
        "Экстренные службы",
        "call_center",
        "spoof_burst",
        "Важность признаков",
        "ROC-AUC",
        "Графовый анализ связей",
    ):
        assert want in text
    meta = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert meta["graph"]["available"] is True
    assert meta["graph"]["summary"]["nodes"] > 0


def test_model_respects_monotone_constraints(trained):
    out, _ = trained
    b = ModelBundle.load(out)
    rng = np.random.default_rng(0)
    base = dict.fromkeys(FEATURES, 0.0)
    for name, sign in (("out_short_share", 1), ("spoof", 1), ("out_unanswered_share", 1), ("call_duration", -1)):
        for _ in range(15):
            row = dict(base)
            row.update({f: float(rng.random() * 5) for f in FEATURES if f != name})
            lo, hi = dict(row), dict(row)
            lo[name], hi[name] = 0.0, 1.0 if name != "call_duration" else 500.0
            s = b.score([lo, hi])
            assert sign * (s[1].logit - s[0].logit) >= -1e-9, f"{name} нарушает монотонность"


def test_shap_is_additive(trained):
    out, _ = trained
    b = ModelBundle.load(out)
    row = dict.fromkeys(FEATURES, 0.0)
    row.update(out_short_share=0.9, out_calls_1h=150.0, spoof=1.0, foreign_ingress=1.0)
    r = b.score([row], explain=True, top_k=100, neg_k=100)[0]
    total = r.base_logit + sum(c.contribution for c in r.contributions)
    assert abs(total - r.logit) < 1e-3, "сумма вкладов и базового значения должна давать logit"
    assert any(c.feature == "out_short_share" and c.contribution > 0 for c in r.contributions)


def test_platt_monotone_and_prevalence_shifts_scores():
    r = np.random.default_rng(3)
    y = (r.random(5000) < 0.3).astype(int)
    z = np.where(y == 1, r.normal(2, 1, 5000), r.normal(-2, 1, 5000))
    a, b = fit_platt(z, y, prevalence=0.01)
    a2, b2 = fit_platt(z, y, prevalence=0.3)
    assert a > 0 and a2 > 0
    assert b < b2, "меньшая ожидаемая доля мошенничества — ниже смещение"
    assert sigmoid(a * 0 + b) < sigmoid(a2 * 0 + b2)


def test_platt_rejects_inverted_ranking():
    r = np.random.default_rng(4)
    y = (r.random(2000) < 0.5).astype(int)
    z = np.where(y == 1, r.normal(-2, 1, 2000), r.normal(2, 1, 2000))  # инвертированная модель
    with pytest.raises(ValueError):
        fit_platt(z, y, prevalence=0.1)


def test_warmup_makes_first_request_fast(trained):
    import time

    b = ModelBundle.load(trained[0])  # прогрев выполняется при загрузке
    row = dict.fromkeys(FEATURES, 0.0)
    t = time.perf_counter()
    b.score([row], explain=True)
    assert (time.perf_counter() - t) < 0.05, "первый запрос после загрузки не должен быть «холодным»"


def test_load_errors(tmp_path):
    with pytest.raises(ModelError):
        ModelBundle.load(tmp_path)
    (tmp_path / META_FILE).write_text("{", encoding="utf-8")
    with pytest.raises(ModelError):
        ModelBundle.load(tmp_path)


def test_dataset_loader_checks_columns(tmp_path, dataset_dir):
    (tmp_path / "meta.json").write_text(json.dumps({"features": FEATURES}), encoding="utf-8")
    (tmp_path / "train.csv").write_text("label,kind\n1,x\n", encoding="utf-8")
    with pytest.raises(D.DatasetError):
        D.load_split(tmp_path, "train", FEATURES)
    with pytest.raises(D.DatasetError):
        D.load_split(tmp_path, "missing", FEATURES)
    assert D.trainable(D.load_split(dataset_dir, "train", FEATURES))["emergency"].eq(0).all()
