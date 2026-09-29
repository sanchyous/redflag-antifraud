"""FastAPI-сервис инференса: принимает вектор признаков от Go-ядра, возвращает score и вклады SHAP."""

from __future__ import annotations

import hmac
import logging
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Annotated

import numpy as np
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .logs import event, setup_logging
from .model import FeatureError, ModelBundle, ModelError

log = logging.getLogger("ml-service")

MAX_BATCH = 500
REPORT_FILE = "report.json"  # отчёт об обучении рядом с моделью (см. training/reportdata.py)
LAT_WINDOW = 4096  # сколько последних замеров задержки хранить для перцентилей
SLOW_MS = 50.0  # запрос дольше этого порога пишется на уровне info: он рискует упереться в таймаут ядра


class ScoreRequest(BaseModel):
    features: dict[str, float]
    explain: bool = False


class BatchRequest(BaseModel):
    items: list[dict[str, float]] = Field(min_length=1, max_length=MAX_BATCH)
    explain: bool = False


class ContributionOut(BaseModel):
    feature: str
    value: float
    contribution: float


class ScoreOut(BaseModel):
    score: float
    logit: float
    base_logit: float
    contributions: list[ContributionOut] = []


class ScoreResponse(ScoreOut):
    model_version: str


class BatchResponse(BaseModel):
    model_version: str
    results: list[ScoreOut]


class ModelInfo(BaseModel):
    version: str
    features: list[str]
    thresholds: dict[str, float]
    metrics: dict[str, float] = {}


class Stats:
    """Счётчики самого сервиса для панели: запросы скоринга, ошибки и задержка инференса (последние LAT_WINDOW замеров)."""

    def __init__(self) -> None:
        self.started = time.time()
        self._lock = threading.Lock()
        self.requests = 0
        self.errors = 0
        self.rows = 0
        self._lat: deque[float] = deque(maxlen=LAT_WINDOW)

    def observe(self, took_ms: float, ok: bool, rows: int = 1) -> None:
        with self._lock:
            self.requests += 1
            self.rows += rows
            if not ok:
                self.errors += 1
            self._lat.append(took_ms)

    def snapshot(self) -> dict:
        with self._lock:
            lat = np.array(self._lat, dtype=np.float64)
            out = {
                "uptime_sec": round(time.time() - self.started, 1),
                "requests": self.requests,
                "errors": self.errors,
                "rows": self.rows,
            }
        if len(lat):
            p50, p95, p99 = np.percentile(lat, [50, 95, 99])
            out["latency_ms"] = {
                "p50": round(float(p50), 3),
                "p95": round(float(p95), 3),
                "p99": round(float(p99), 3),
                "max": round(float(lat.max()), 3),
                "samples": len(lat),
            }
        else:
            out["latency_ms"] = None
        return out


class State:
    """Держатель текущей модели с потокобезопасной подменой (перезагрузка без остановки)."""

    def __init__(self, model_dir: str | None):
        self.model_dir = model_dir
        self._lock = threading.Lock()
        self.bundle: ModelBundle | None = None
        if model_dir:
            self.bundle = ModelBundle.load(model_dir)
            _log_loaded("model_loaded", self.bundle)

    def reload(self) -> ModelBundle:
        if not self.model_dir:
            raise ModelError("MODEL_DIR не задан")
        nb = ModelBundle.load(self.model_dir)  # ошибка не портит текущую модель
        with self._lock:
            prev, self.bundle = self.bundle, nb
        _log_loaded("model_reloaded", nb, previous=prev.version if prev else None)
        return nb

    def get(self) -> ModelBundle:
        b = self.bundle
        if b is None:
            raise HTTPException(status_code=503, detail="model_not_loaded")
        return b


def _log_loaded(name: str, b: ModelBundle, **extra) -> None:
    th = b.thresholds
    event(
        log,
        logging.INFO,
        name,
        version=b.version,
        features=len(b.features),
        review=round(th.review, 5),
        block=round(th.block, 5),
        gate=round(th.gate, 5),
        **extra,
    )


def create_app(model_dir: str | None = None, api_key: str | None = None) -> FastAPI:
    model_dir = model_dir if model_dir is not None else os.environ.get("MODEL_DIR")
    api_key = api_key if api_key is not None else os.environ.get("API_KEY", "")
    state = State(model_dir)
    app = FastAPI(title="RedFlag ML service", version="1.0.0")
    app.state.model_state = state
    stats = Stats()

    @app.middleware("http")
    async def access_log(request: Request, call_next):
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            event(log, logging.ERROR, "http_exception", method=request.method, path=request.url.path)
            log.exception("unhandled error", extra={"fields": {"path": request.url.path}})
            raise
        took_ms = (time.perf_counter() - start) * 1000
        # Успешные быстрые запросы — debug (поток ядра велик); ошибки и медленные — info/warning.
        level = logging.DEBUG
        if response.status_code >= 500:
            level = logging.ERROR
        elif response.status_code >= 400:
            level = logging.WARNING
        elif took_ms > SLOW_MS:
            level = logging.INFO
        if request.url.path.startswith("/v1/score"):
            stats.observe(took_ms, response.status_code < 400)
        if request.url.path != "/health":
            event(
                log,
                level,
                "http_request",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                took_ms=round(took_ms, 2),
                slow=took_ms > SLOW_MS,
            )
        return response

    def auth(x_api_key: Annotated[str | None, Header()] = None) -> None:
        if api_key and not hmac.compare_digest((x_api_key or "").encode(), api_key.encode()):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/health")
    def health():
        b = state.bundle
        return {"status": "ok" if b else "no_model", "model_version": b.version if b else None}

    @app.get("/v1/model", response_model=ModelInfo, dependencies=[Depends(auth)])
    def model_info():
        b = state.get()
        th = b.thresholds
        return ModelInfo(
            version=b.version,
            features=b.features,
            thresholds={"review": th.review, "block": th.block, "gate": th.gate, "min_signals": th.min_signals},
            metrics={k: float(v) for k, v in b.meta.get("metrics", {}).items() if isinstance(v, (int, float))},
        )

    @app.get("/v1/report", dependencies=[Depends(auth)])
    def report():
        """Отчёт об обучении текущей модели (кривые, распределения, разбор по типам): для раздела «ML» панели."""
        state.get()
        if not state.model_dir:
            raise HTTPException(status_code=404, detail="report_not_found")
        try:
            data = (Path(state.model_dir) / REPORT_FILE).read_bytes()
        except OSError:
            raise HTTPException(status_code=404, detail="report_not_found") from None
        return Response(content=data, media_type="application/json")

    @app.get("/v1/stats", dependencies=[Depends(auth)])
    def service_stats():
        b = state.get()
        return {"model_version": b.version, **stats.snapshot()}

    @app.post("/v1/score", response_model=ScoreResponse, dependencies=[Depends(auth)])
    def score(req: ScoreRequest):
        b = state.get()
        try:
            r = b.score([req.features], explain=req.explain)[0]
        except FeatureError as e:
            event(log, logging.WARNING, "feature_contract_violation", detail=str(e))
            raise HTTPException(status_code=422, detail=str(e)) from e
        return ScoreResponse(model_version=b.version, **_out(r).model_dump())

    @app.post("/v1/score/batch", response_model=BatchResponse, dependencies=[Depends(auth)])
    def score_batch(req: BatchRequest):
        b = state.get()
        try:
            rs = b.score(req.items, explain=req.explain)
        except FeatureError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e
        return BatchResponse(model_version=b.version, results=[_out(r) for r in rs])

    @app.post("/v1/reload", dependencies=[Depends(auth)])
    def reload():
        try:
            b = state.reload()
        except ModelError as e:
            log.error("reload failed: %s", e)
            raise HTTPException(status_code=500, detail=f"reload_failed: {e}") from e
        return {"status": "reloaded", "model_version": b.version}

    return app


def _out(r) -> ScoreOut:
    return ScoreOut(
        score=r.score,
        logit=r.logit,
        base_logit=r.base_logit,
        contributions=[
            ContributionOut(feature=c.feature, value=c.value, contribution=c.contribution) for c in r.contributions
        ],
    )


def app_factory() -> FastAPI:
    """Точка входа для uvicorn: `uvicorn app.main:app_factory --factory`."""
    setup_logging()
    return create_app()
