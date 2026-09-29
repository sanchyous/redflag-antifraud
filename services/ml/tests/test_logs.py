import json
import logging
import shutil

import pytest
from fastapi.testclient import TestClient

from app.logs import JsonFormatter, PrettyFormatter, event, setup_logging
from app.main import SLOW_MS, create_app
from tests.conftest import FEATURES


def _record(msg="evt", level=logging.INFO, **fields):
    r = logging.LogRecord("t", level, __file__, 1, msg, (), None)
    r.fields = fields
    return r


def test_json_formatter_is_one_parseable_line():
    line = JsonFormatter().format(_record("model_loaded", version="v1", gate=0.01, note="два слова"))
    d = json.loads(line)
    assert d["msg"] == "model_loaded" and d["component"] == "ml" and d["level"] == "INFO"
    assert d["version"] == "v1" and d["gate"] == 0.01 and d["note"] == "два слова"
    assert "\n" not in line and "T" in d["time"]


def test_pretty_formatter_layout_and_quoting():
    line = PrettyFormatter(color=False).format(_record("model_loaded", version="v1", note="два слова", n=3, ok=True))
    assert "INFO " in line and "ml         model_loaded" in line
    assert "version=v1" in line and 'note="два слова"' in line and "n=3" in line and "ok=true" in line
    assert "\x1b[" not in line
    assert "\x1b[" in PrettyFormatter(color=True).format(_record())


def test_pretty_includes_exception_text():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        r = _record()
        r.exc_info = sys.exc_info()
    assert "ValueError: boom" in PrettyFormatter(color=False).format(r)
    assert json.loads(JsonFormatter().format(r))["exc"].endswith("ValueError: boom")


def test_setup_logging_levels_and_format(capsys):
    log = setup_logging("warning", "json")
    log.info("hidden")
    log.warning("shown", extra={"fields": {"k": 1}})
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1 and json.loads(out[0])["k"] == 1
    setup_logging("info", "pretty")  # не падает и переключает формат
    logging.getLogger("ml-service").info("x")
    assert "x" in capsys.readouterr().out


def test_event_helper_skips_disabled_levels(caplog):
    lg = logging.getLogger("ml-service")
    with caplog.at_level(logging.WARNING, logger="ml-service"):
        event(lg, logging.DEBUG, "quiet", a=1)
        event(lg, logging.WARNING, "loud", a=2)
    assert [r.getMessage() for r in caplog.records] == ["loud"]
    assert caplog.records[0].fields == {"a": 2}


@pytest.fixture()
def client(trained):
    return TestClient(create_app(str(trained[0])))


def test_model_load_is_logged(trained, caplog):
    with caplog.at_level(logging.INFO, logger="ml-service"):
        create_app(str(trained[0]))
    rec = next(r for r in caplog.records if r.getMessage() == "model_loaded")
    assert rec.fields["features"] == len(FEATURES) and rec.fields["version"].startswith("catboost-")
    assert {"review", "block", "gate"} <= set(rec.fields)


def test_reload_is_logged_with_previous_version(trained, tmp_path, caplog):
    d = tmp_path / "m"
    shutil.copytree(trained[0], d)
    c = TestClient(create_app(str(d)))
    with caplog.at_level(logging.INFO, logger="ml-service"):
        assert c.post("/v1/reload").status_code == 200
    rec = next(r for r in caplog.records if r.getMessage() == "model_reloaded")
    assert rec.fields["previous"] == rec.fields["version"]


def test_errors_are_logged_as_warnings_and_ok_requests_as_debug(client, caplog):
    good = dict.fromkeys(FEATURES, 0.0)
    bad = {k: v for k, v in good.items() if k != "spoof"}
    with caplog.at_level(logging.DEBUG, logger="ml-service"):
        assert client.post("/v1/score", json={"features": good}).status_code == 200
        assert client.post("/v1/score", json={"features": bad}).status_code == 422
        client.get("/health")
    reqs = [r for r in caplog.records if r.getMessage() == "http_request"]
    ok = next(r for r in reqs if r.fields["status"] == 200)
    err = next(r for r in reqs if r.fields["status"] == 422)
    assert ok.levelno == logging.DEBUG and err.levelno == logging.WARNING
    assert ok.fields["path"] == "/v1/score" and ok.fields["method"] == "POST" and ok.fields["took_ms"] >= 0
    assert not any(r.fields.get("path") == "/health" for r in reqs), "health-пробы не засоряют лог"
    violation = next(r for r in caplog.records if r.getMessage() == "feature_contract_violation")
    assert "spoof" in violation.fields["detail"]


def test_ok_requests_are_silent_at_info(client, caplog):
    with caplog.at_level(logging.INFO, logger="ml-service"):
        client.post("/v1/score", json={"features": dict.fromkeys(FEATURES, 0.0)})
    assert not [r for r in caplog.records if r.getMessage() == "http_request"], (
        "успешные быстрые запросы — только debug"
    )
    assert SLOW_MS > 0
