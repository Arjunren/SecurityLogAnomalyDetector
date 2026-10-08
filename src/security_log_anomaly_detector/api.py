"""Authenticated, bounded anomaly scoring over log windows."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field

from security_log_anomaly_detector import __version__
from security_log_anomaly_detector.artifact import Model, load_model
from security_log_anomaly_detector.config import Settings
from security_log_anomaly_detector.features import LogWindow

REQUESTS = Counter("requests_total", "HTTP requests", ["endpoint", "status"])
PREDICTIONS = Counter("predictions_total", "Predictions", ["classification"])
ERRORS = Counter("prediction_errors_total", "Inference failures")
LATENCY = Histogram("prediction_latency_seconds", "Inference latency")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {"level": record.levelname, "event": record.getMessage(), "logger": record.name}
        )


class PredictRequest(BaseModel):
    observation: LogWindow


class BatchRequest(BaseModel):
    observations: list[LogWindow] = Field(min_length=1)


class FeatureDeviation(BaseModel):
    feature: str
    squared_error: float


class PredictResponse(BaseModel):
    anomaly_score: float
    anomaly_flag: bool
    threshold: float
    baseline_percentile: float
    risk_score: int
    model_version: str
    top_feature_deviations: list[FeatureDeviation]


class BatchResponse(BaseModel):
    predictions: list[PredictResponse]


def create_app(settings: Settings | None = None, model: Model | None = None) -> FastAPI:
    settings = settings or Settings()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=settings.log_level, handlers=[handler], force=True)
    logger = logging.getLogger(__name__)
    app = FastAPI(
        title="SecurityLogAnomalyDetector", version=__version__, docs_url=None, redoc_url=None
    )
    try:
        active_model = model or load_model(settings.model_path)
    except ValueError:
        active_model = None
        logger.warning("model_unavailable")
    executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_inference)
    capacity = asyncio.Semaphore(settings.max_concurrent_inference)

    async def authenticate(x_api_key: str | None = Header(default=None)) -> None:
        if settings.api_key and (
            x_api_key is None or not hmac.compare_digest(x_api_key, settings.api_key)
        ):
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.middleware("http")
    async def limit_body(request: Request, call_next: Any) -> Response:
        started = time.perf_counter()
        route = (
            request.url.path
            if request.url.path
            in {
                "/health",
                "/ready",
                "/version",
                "/metrics",
                "/api/v1/predict",
                "/api/v1/batch-predict",
            }
            else "unmatched"
        )
        status = 500
        try:
            if request.method == "POST":
                media_type = request.headers.get("content-type", "").split(";")[0].lower()
                if media_type != "application/json":
                    status = 415
                    return JSONResponse(
                        {"detail": "Content-Type must be application/json"}, status_code=415
                    )
                try:
                    advertised = int(request.headers.get("content-length", "0"))
                except ValueError:
                    status = 400
                    return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
                if (
                    advertised > settings.max_request_bytes
                    or len(await request.body()) > settings.max_request_bytes
                ):
                    status = 413
                    return JSONResponse({"detail": "Request body too large"}, status_code=413)
            response: Response = await call_next(request)
            status = response.status_code
            return response
        finally:
            REQUESTS.labels(route, str(status)).inc()
            logger.info(
                "request_complete path=%s status=%s duration_ms=%d",
                route,
                status,
                round((time.perf_counter() - started) * 1000),
            )

    async def infer(observations: list[LogWindow]) -> list[dict[str, Any]]:
        if active_model is None:
            raise HTTPException(status_code=503, detail="Model unavailable")
        if len(observations) > settings.max_batch_size:
            raise HTTPException(status_code=413, detail="Batch too large")
        try:
            await asyncio.wait_for(capacity.acquire(), timeout=settings.inference_timeout_seconds)
        except TimeoutError as exc:
            ERRORS.inc()
            raise HTTPException(status_code=503, detail="Inference capacity exhausted") from exc
        loop = asyncio.get_running_loop()
        started = time.perf_counter()
        try:
            future = loop.run_in_executor(
                executor,
                lambda: [active_model.predict(observation) for observation in observations],
            )
            future.add_done_callback(lambda _: capacity.release())
            result = await asyncio.wait_for(
                asyncio.shield(future), timeout=settings.inference_timeout_seconds
            )
            for item in result:
                PREDICTIONS.labels("anomalous" if item["anomaly_flag"] else "baseline").inc()
            LATENCY.observe(time.perf_counter() - started)
            return result
        except TimeoutError as exc:
            ERRORS.inc()
            raise HTTPException(status_code=504, detail="Inference timeout") from exc
        except Exception:
            ERRORS.inc()
            logger.exception("inference_failed")
            raise HTTPException(status_code=500, detail="Inference failed") from None

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready() -> dict[str, str]:
        if active_model is None:
            raise HTTPException(status_code=503, detail="Model unavailable")
        return {"status": "ready"}

    @app.get("/version")
    def version() -> dict[str, str]:
        return {
            "application": __version__,
            "model": active_model.version if active_model else "unavailable",
        }

    @app.get("/metrics", dependencies=[Depends(authenticate)])
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.post(
        "/api/v1/predict", response_model=PredictResponse, dependencies=[Depends(authenticate)]
    )
    async def predict(body: PredictRequest) -> dict[str, Any]:
        return (await infer([body.observation]))[0]

    @app.post(
        "/api/v1/batch-predict", response_model=BatchResponse, dependencies=[Depends(authenticate)]
    )
    async def batch_predict(body: BatchRequest) -> dict[str, Any]:
        return {"predictions": await infer(body.observations)}

    return app


app = create_app()
