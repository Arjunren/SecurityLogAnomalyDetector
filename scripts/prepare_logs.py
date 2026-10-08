"""Source-specific JSON log parsers and private five-minute aggregation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import secrets
import statistics
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from security_log_anomaly_detector.features import RAW_FIELDS, LogWindow

SOURCE_TYPES = {"linux": 0, "windows": 1, "cloud": 2, "application": 3, "authentication": 4}
MAX_INPUT_BYTES = 134217728
MAX_EVENTS = 100000
WINDOW_SECONDS = 300


class LogEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type_code: int = Field(ge=0, le=4)
    source_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    event_code: str = Field(min_length=1, max_length=128)
    principal: str = Field(min_length=1, max_length=256)
    host: str = Field(min_length=1, max_length=256)
    severity: int = Field(ge=0, le=10)
    is_error: bool = False
    auth_failed: bool = False
    access_denied: bool = False
    off_hours: bool = False
    rare_template: bool = False
    privileged_action: bool = False
    baseline_expected_events_per_minute: float = Field(gt=0, le=1000000)
    reviewed_label: str

    @model_validator(mode="after")
    def valid_event(self) -> LogEvent:
        if self.timestamp.tzinfo is None or self.reviewed_label not in {"benign", "anomalous"}:
            raise ValueError("Timestamp needs timezone and label must be reviewed")
        return self


def parse_event(raw: dict[str, Any], source_format: str) -> LogEvent:
    """Map one known source schema without retaining free-form message bodies."""
    if source_format not in SOURCE_TYPES:
        raise ValueError("Unsupported log format")
    field_map = {
        "linux": ("host", "timestamp", "event_code", "principal", "host", "severity"),
        "windows": ("Computer", "TimeCreated", "EventID", "TargetUserName", "Computer", "Level"),
        "cloud": (
            "sourceIPAddress",
            "eventTime",
            "eventName",
            "userIdentity",
            "eventSource",
            "severity",
        ),
        "application": ("service", "timestamp", "event_code", "principal", "host", "severity"),
        "authentication": ("provider", "timestamp", "event_code", "principal", "host", "severity"),
    }
    source, stamp, code, principal, host, severity = field_map[source_format]
    identity = raw.get(principal)
    if source_format == "cloud" and isinstance(identity, dict):
        identity = identity.get("principalId")
    document = {
        "source_type_code": SOURCE_TYPES[source_format],
        "source_id": raw.get(source),
        "timestamp": raw.get(stamp),
        "event_code": str(raw[code]) if code in raw else None,
        "principal": identity,
        "host": raw.get(host),
        "severity": raw.get(severity),
        "is_error": raw.get("is_error", False),
        "auth_failed": raw.get("auth_failed", False),
        "access_denied": raw.get("access_denied", False),
        "off_hours": raw.get("off_hours", False),
        "rare_template": raw.get("rare_template", False),
        "privileged_action": raw.get("privileged_action", False),
        "baseline_expected_events_per_minute": raw.get("baseline_expected_events_per_minute"),
        "reviewed_label": raw.get("reviewed_label"),
    }
    return LogEvent.model_validate(document)


def _summarize(events: list[LogEvent]) -> LogWindow:
    n = len(events)
    stamps = sorted(e.timestamp.astimezone(UTC).timestamp() for e in events)
    intervals = [b - a for a, b in zip(stamps, stamps[1:], strict=False)]
    mean_interval = statistics.mean(intervals) if intervals else 0.0
    cv = (
        statistics.pstdev(intervals) / mean_interval
        if len(intervals) >= 2 and mean_interval
        else 0.0
    )
    baselines = {e.baseline_expected_events_per_minute for e in events}
    if len(baselines) != 1:
        raise ValueError("Inconsistent historical baseline in window")
    return LogWindow(
        source_type_code=events[0].source_type_code,
        events_per_minute=n / 5,
        error_ratio=sum(e.is_error for e in events) / n,
        auth_failure_ratio=sum(e.auth_failed for e in events) / n,
        access_denied_ratio=sum(e.access_denied for e in events) / n,
        distinct_event_codes=len({e.event_code for e in events}),
        distinct_principals=len({e.principal for e in events}),
        distinct_hosts=len({e.host for e in events}),
        off_hours_ratio=sum(e.off_hours for e in events) / n,
        rare_template_ratio=sum(e.rare_template for e in events) / n,
        mean_severity=sum(e.severity for e in events) / n,
        burstiness=min(cv, 1000),
        mean_interarrival_seconds=mean_interval,
        privileged_action_count=sum(e.privileged_action for e in events),
        baseline_expected_events_per_minute=baselines.pop(),
    )


def prepare(source: Path, output: Path, source_format: str) -> dict[str, int]:
    if (
        source_format not in SOURCE_TYPES
        or not source.is_file()
        or source.stat().st_size > MAX_INPUT_BYTES
    ):
        raise ValueError("Unsupported source or input exceeds byte limit")
    windows: dict[tuple[str, int], list[LogEvent]] = defaultdict(list)
    count = 0
    with source.open(encoding="utf-8") as handle:
        for line in handle:
            count += 1
            if count > MAX_EVENTS or len(line) > 16384:
                raise ValueError("Input exceeds event or line limit")
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError("Log line must be a JSON object")
            event = parse_event(raw, source_format)
            bucket = int(event.timestamp.astimezone(UTC).timestamp()) // WINDOW_SECONDS
            windows[(event.source_id, bucket)].append(event)
    salt = secrets.token_bytes(32)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*RAW_FIELDS, "group_id", "label"])
        writer.writeheader()
        for (source_id, _), events in sorted(windows.items()):
            row = _summarize(events).model_dump()
            row["group_id"] = hmac.new(salt, source_id.encode(), hashlib.sha256).hexdigest()
            row["label"] = (
                "anomalous" if any(e.reviewed_label == "anomalous" for e in events) else "benign"
            )
            writer.writerow(row)
    return {"events": count, "windows": len(windows)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--format", choices=list(SOURCE_TYPES), required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.input, args.output, args.format)))


if __name__ == "__main__":
    main()
