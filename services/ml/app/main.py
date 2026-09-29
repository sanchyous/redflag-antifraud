"""FastAPI-сервис инференса: принимает вектор признаков от Go-ядра, возвращает score и вклады SHAP."""

from __future__ import annotations

import hmac
import logging
import os
import threading
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .model import FeatureError, ModelBundle, ModelError

log = logging.getLogger("ml-service")

MAX_BATCH = 500


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


class State:
    """Держатель текущей модели с потокобезопасной подменой (перезагрузка без остановки)."""

    def __init__(self, model_dir: str | None):
        self.model_dir = model_dir
        self._lock = threading.Lock()
        self.bundle: ModelBundle | None = None
        if model_dir:
            self.bundle = ModelBundle.load(model_dir)

    def reload(self) -> ModelBundle:
        if not self.model_dir:
            raise ModelError("MODEL_DIR не задан")
        nb = ModelBundle.load(self.model_dir)  # ошибка не портит текущую модель
        with self._lock:
            self.bundle = nb
        return nb

    def get(self) -> ModelBundle:
        b = self.bundle
        if b is None:
            raise HTTPException(status_code=503, detail="model_not_loaded")
        return b


def create_app(model_dir: str | None = None, api_key: str | None = None) -> FastAPI:
    model_dir = model_dir if model_dir is not None else os.environ.get("MODEL_DIR")
    api_key = api_key if api_key is not None else os.environ.get("API_KEY", "")
    state = State(model_dir)
    app = FastAPI(title="RedFlag ML service", version="1.0.0")
    app.state.model_state = state

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

    @app.post("/v1/score", response_model=ScoreResponse, dependencies=[Depends(auth)])
    def score(req: ScoreRequest):
        b = state.get()
        try:
            r = b.score([req.features], explain=req.explain)[0]
        except FeatureError as e:
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
    return create_app()
