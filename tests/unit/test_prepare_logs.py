import csv
import json
from pathlib import Path

import pytest

from scripts.prepare_logs import parse_event, prepare


@pytest.mark.parametrize(
    ("source_format", "fields"),
    [
        (
            "linux",
            {
                "host": "host-a",
                "timestamp": "2026-01-01T12:00:00+00:00",
                "event_code": "sshd",
                "principal": "alice",
                "severity": 3,
            },
        ),
        (
            "windows",
            {
                "Computer": "host-a",
                "TimeCreated": "2026-01-01T12:00:00+00:00",
                "EventID": 4625,
                "TargetUserName": "alice",
                "Level": 3,
            },
        ),
        (
            "cloud",
            {
                "sourceIPAddress": "192.0.2.1",
                "eventTime": "2026-01-01T12:00:00+00:00",
                "eventName": "Login",
                "userIdentity": {"principalId": "alice"},
                "eventSource": "iam.example",
                "severity": 3,
            },
        ),
        (
            "application",
            {
                "service": "app-a",
                "timestamp": "2026-01-01T12:00:00+00:00",
                "event_code": "AUTH",
                "principal": "alice",
                "host": "host-a",
                "severity": 3,
            },
        ),
        (
            "authentication",
            {
                "provider": "idp-a",
                "timestamp": "2026-01-01T12:00:00+00:00",
                "event_code": "LOGIN",
                "principal": "alice",
                "host": "host-a",
                "severity": 3,
            },
        ),
    ],
)
def test_source_parsers(source_format: str, fields: dict[str, object]) -> None:
    event = parse_event(
        {**fields, "baseline_expected_events_per_minute": 2, "reviewed_label": "benign"},
        source_format,
    )
    assert event.event_code
    assert event.principal == "alice"


def test_aggregation_omits_identifiers(tmp_path: Path) -> None:
    source = tmp_path / "logs.jsonl"
    item = {
        "host": "private-host",
        "timestamp": "2026-01-01T12:00:00+00:00",
        "event_code": "sshd",
        "principal": "private-user",
        "severity": 3,
        "baseline_expected_events_per_minute": 2,
        "reviewed_label": "benign",
    }
    source.write_text(json.dumps(item) + "\n", encoding="utf-8")
    output = tmp_path / "windows.csv"
    assert prepare(source, output, "linux") == {"events": 1, "windows": 1}
    with output.open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert float(row["events_per_minute"]) == 0.2
    assert "private-host" not in output.read_text(encoding="utf-8")
    assert "private-user" not in output.read_text(encoding="utf-8")
