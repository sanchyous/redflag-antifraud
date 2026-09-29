import shutil

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import FEATURES

FRAUD = {f: 0.0 for f in FEATURES} | {"out_calls_1h": 200.0, "out_calls_24h": 300.0, "out_peers_1h": 190.0,
                                      "out_peers_24h": 280.0, "out_novelty": 0.95, "out_regions_24h": 40.0,
                                      "out_region_entropy": 4.5, "out_short_share": 0.9, "out_unanswered_share": 0.6,
                                      "call_short": 1.0, "call_duration": 4.0, "spoof": 1.0, "foreign_ingress": 1.0,
                                      "conn_international": 1.0}
NORMAL = {f: 0.0 for f in FEATURES} | {"out_calls_1h": 1.0, "out_calls_24h": 3.0, "out_peers_1h": 1.0,
                                       "out_peers_24h": 2.0, "call_duration": 120.0}


@pytest.fixture()
def client(trained):
    return TestClient(create_app(str(trained[0])))


def test_health_and_model_info(client):
    assert client.get("/health").json()["status"] == "ok"
    info = client.get("/v1/model").json()
    assert info["features"] == FEATURES and info["thresholds"]["review"] > 0 and "auc" in info["metrics"]


def test_score_separates_fraud_from_normal(client):
    hi = client.post("/v1/score", json={"features": FRAUD}).json()
    lo = client.post("/v1/score", json={"features": NORMAL}).json()
    assert hi["score"] > 0.5 > lo["score"]
    assert hi["model_version"] == lo["model_version"]
    assert hi["contributions"] == []  # без explain вклады не считаются


def test_score_with_explanations(client):
    r = client.post("/v1/score", json={"features": FRAUD, "explain": True}).json()
    assert r["contributions"], "ожидались вклады"
    top = r["contributions"][0]
    assert top["contribution"] > 0 and top["feature"] in FEATURES
    assert len([c for c in r["contributions"] if c["contribution"] > 0]) <= 6


def test_batch(client):
    r = client.post("/v1/score/batch", json={"items": [FRAUD, NORMAL, FRAUD], "explain": True}).json()
    assert len(r["results"]) == 3
    assert r["results"][0]["score"] == r["results"][2]["score"] > r["results"][1]["score"]


def test_batch_limits(client):
    assert client.post("/v1/score/batch", json={"items": []}).status_code == 422
    assert client.post("/v1/score/batch", json={"items": [NORMAL] * 501}).status_code == 422


def test_missing_feature_is_contract_error(client):
    bad = dict(NORMAL)
    del bad["spoof"]
    r = client.post("/v1/score", json={"features": bad})
    assert r.status_code == 422 and "spoof" in r.json()["detail"]


def test_extra_features_ignored_nan_rejected(client):
    ok = client.post("/v1/score", json={"features": NORMAL | {"новый_признак": 5.0}})
    assert ok.status_code == 200
    r = client.post("/v1/score", content='{"features": {"spoof": NaN}}', headers={"content-type": "application/json"})
    assert r.status_code == 422


def test_auth(trained):
    c = TestClient(create_app(str(trained[0]), api_key="secret"))
    assert c.get("/health").status_code == 200
    assert c.post("/v1/score", json={"features": NORMAL}).status_code == 401
    assert c.post("/v1/score", json={"features": NORMAL}, headers={"X-API-Key": "wrong"}).status_code == 401
    assert c.post("/v1/score", json={"features": NORMAL}, headers={"X-API-Key": "secret"}).status_code == 200


def test_no_model_returns_503():
    c = TestClient(create_app(None))
    assert c.get("/health").json()["status"] == "no_model"
    assert c.post("/v1/score", json={"features": NORMAL}).status_code == 503


def test_reload_keeps_old_model_on_failure(trained, tmp_path):
    d = tmp_path / "m"
    shutil.copytree(trained[0], d)
    c = TestClient(create_app(str(d)))
    v = c.get("/health").json()["model_version"]
    assert c.post("/v1/reload").json()["status"] == "reloaded"
    (d / "meta.json").write_text("{", encoding="utf-8")
    assert c.post("/v1/reload").status_code == 500
    assert c.get("/health").json()["model_version"] == v, "неудачная перезагрузка не должна ломать текущую модель"
    assert c.post("/v1/score", json={"features": NORMAL}).status_code == 200
