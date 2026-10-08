from pathlib import Path

import numpy as np
import pytest

from security_log_anomaly_detector.artifact import Model, load_model, save_model
from security_log_anomaly_detector.features import FEATURE_NAMES, LogWindow


@pytest.fixture
def observation() -> LogWindow:
    return LogWindow.model_validate_json(Path("examples/observation.json").read_text())


@pytest.fixture
def model(tmp_path: Path) -> Model:
    size = len(FEATURE_NAMES)
    payload = {
        "features": list(FEATURE_NAMES),
        "means": [0.0] * size,
        "scales": [1.0] * size,
        "pca_mean": [0.0] * size,
        "components": np.eye(size)[:4].tolist(),
        "score_quantiles": np.linspace(0, 10000, 101).tolist(),
        "threshold": 1000.0,
        "version": "test-1",
    }
    artifact = tmp_path / "model.json"
    save_model(artifact, payload)
    return load_model(artifact)
