"""Non-executable PCA anomaly model with strict JSON validation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from security_log_anomaly_detector.features import FEATURE_NAMES, LogWindow, extract_features

FORMAT = "security-log-pca-anomaly-v1"
MAX_ARTIFACT_BYTES = 65536


@dataclass(frozen=True)
class Model:
    version: str
    threshold: float
    means: np.ndarray
    scales: np.ndarray
    pca_mean: np.ndarray
    components: np.ndarray
    score_quantiles: np.ndarray

    def score(self, observation: LogWindow) -> float:
        vector = (extract_features(observation) - self.means) / self.scales
        centered = vector - self.pca_mean
        reconstructed = (centered @ self.components.T) @ self.components
        return float(np.mean(np.square(centered - reconstructed)))

    def predict(self, observation: LogWindow) -> dict[str, Any]:
        vector = (extract_features(observation) - self.means) / self.scales
        centered = vector - self.pca_mean
        reconstructed = (centered @ self.components.T) @ self.components
        residual = np.square(centered - reconstructed)
        score = float(np.mean(residual))
        percentile = float(np.interp(score, self.score_quantiles, np.linspace(0, 1, 101)))
        important = np.argsort(residual)[::-1][:5]
        return {
            "anomaly_score": round(score, 6),
            "anomaly_flag": score > self.threshold,
            "threshold": round(self.threshold, 6),
            "baseline_percentile": round(percentile, 4),
            "risk_score": round(percentile * 100),
            "model_version": self.version,
            "top_feature_deviations": [
                {"feature": FEATURE_NAMES[i], "squared_error": round(float(residual[i]), 6)}
                for i in important
            ],
        }


def _vector(value: object, length: int) -> np.ndarray:
    if not isinstance(value, list) or len(value) != length:
        raise ValueError("Invalid model vector length")
    if any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in value):
        raise ValueError("Model contains a non-numeric value")
    result = np.asarray(value, dtype=np.float64)
    if not np.all(np.isfinite(result)):
        raise ValueError("Model contains a non-finite value")
    return result


def load_model(path: Path) -> Model:
    if not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("Model artifact missing or oversized")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if document["format"] != FORMAT:
            raise ValueError("Unsupported model format")
        payload = document["model"]
        if payload["features"] != list(FEATURE_NAMES):
            raise ValueError("Feature schema mismatch")
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if digest != document["sha256"]:
            raise ValueError("Model checksum mismatch")
        size = len(FEATURE_NAMES)
        means = _vector(payload["means"], size)
        scales = _vector(payload["scales"], size)
        pca_mean = _vector(payload["pca_mean"], size)
        rows = payload["components"]
        if not isinstance(rows, list) or not 1 <= len(rows) < size:
            raise ValueError("Invalid PCA component count")
        components = np.vstack([_vector(row, size) for row in rows])
        quantiles = _vector(payload["score_quantiles"], 101)
        threshold = float(payload["threshold"])
        if not np.all(scales > 0) or not np.all(np.diff(quantiles) >= 0):
            raise ValueError("Invalid scaling or quantiles")
        if not np.isfinite(threshold) or threshold < 0:
            raise ValueError("Invalid threshold")
        version = payload["version"]
        if not isinstance(version, str) or not 1 <= len(version) <= 64:
            raise ValueError("Invalid model version")
        return Model(version, threshold, means, scales, pca_mean, components, quantiles)
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError) as exc:
        raise ValueError("Invalid model artifact") from exc


def save_model(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    candidate = path.with_suffix(path.suffix + ".tmp")
    candidate.write_text(
        json.dumps(
            {"format": FORMAT, "sha256": digest, "model": payload}, sort_keys=True, indent=2
        ),
        encoding="utf-8",
    )
    candidate.replace(path)
