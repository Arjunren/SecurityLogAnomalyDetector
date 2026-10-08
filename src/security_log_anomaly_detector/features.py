"""Validated aggregate log windows and deterministic anomaly features."""

from __future__ import annotations

import math

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, field_validator

RAW_FIELDS = (
    "source_type_code",
    "events_per_minute",
    "error_ratio",
    "auth_failure_ratio",
    "access_denied_ratio",
    "distinct_event_codes",
    "distinct_principals",
    "distinct_hosts",
    "off_hours_ratio",
    "rare_template_ratio",
    "mean_severity",
    "burstiness",
    "mean_interarrival_seconds",
    "privileged_action_count",
    "baseline_expected_events_per_minute",
)
FEATURE_NAMES = RAW_FIELDS[1:] + (
    "source_linux",
    "source_windows",
    "source_cloud",
    "source_application",
    "source_authentication",
    "activity_vs_baseline",
    "failure_volume",
    "privileged_rate",
)
LABELS = ("benign", "anomalous")


class LogWindow(BaseModel):
    """One source and five-minute interval, without raw messages or identifiers."""

    model_config = ConfigDict(extra="forbid")

    source_type_code: int = Field(ge=0, le=4)
    events_per_minute: float = Field(ge=0, le=1_000_000)
    error_ratio: float = Field(ge=0, le=1)
    auth_failure_ratio: float = Field(ge=0, le=1)
    access_denied_ratio: float = Field(ge=0, le=1)
    distinct_event_codes: int = Field(ge=0, le=100_000)
    distinct_principals: int = Field(ge=0, le=100_000)
    distinct_hosts: int = Field(ge=0, le=100_000)
    off_hours_ratio: float = Field(ge=0, le=1)
    rare_template_ratio: float = Field(ge=0, le=1)
    mean_severity: float = Field(ge=0, le=10)
    burstiness: float = Field(ge=0, le=1000)
    mean_interarrival_seconds: float = Field(ge=0, le=300)
    privileged_action_count: int = Field(ge=0, le=1_000_000)
    baseline_expected_events_per_minute: float = Field(gt=0, le=1_000_000)

    @field_validator(
        "events_per_minute",
        "error_ratio",
        "auth_failure_ratio",
        "access_denied_ratio",
        "off_hours_ratio",
        "rare_template_ratio",
        "mean_severity",
        "burstiness",
        "mean_interarrival_seconds",
        "baseline_expected_events_per_minute",
    )
    @classmethod
    def finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("Log feature must be finite")
        return value


def extract_features(observation: LogWindow) -> np.ndarray:
    values = observation.model_dump()
    event_count = max(observation.events_per_minute * 5, 1)
    indicators = tuple(float(observation.source_type_code == i) for i in range(5))
    engineered = (
        observation.events_per_minute / observation.baseline_expected_events_per_minute,
        observation.auth_failure_ratio * event_count,
        observation.privileged_action_count / event_count,
    )
    return np.asarray(
        [values[name] for name in RAW_FIELDS[1:]] + list(indicators) + list(engineered),
        dtype=np.float64,
    )


def feature_matrix(observations: list[LogWindow]) -> np.ndarray:
    if not observations:
        raise ValueError("At least one observation is required")
    return np.vstack([extract_features(item) for item in observations])
