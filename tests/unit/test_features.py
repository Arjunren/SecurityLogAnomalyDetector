import numpy as np
import pytest
from pydantic import ValidationError

from security_log_anomaly_detector.features import FEATURE_NAMES, LogWindow, extract_features


def test_log_features(observation: LogWindow) -> None:
    vector = extract_features(observation)
    assert len(vector) == len(FEATURE_NAMES)
    assert vector[FEATURE_NAMES.index("activity_vs_baseline")] == pytest.approx(4 / 4.5)
    assert np.all(np.isfinite(vector))


def test_malformed_window_rejected(observation: LogWindow) -> None:
    with pytest.raises(ValidationError):
        LogWindow.model_validate({**observation.model_dump(), "source_type_code": 5})
    with pytest.raises(ValidationError):
        LogWindow.model_validate({**observation.model_dump(), "events_per_minute": float("inf")})
