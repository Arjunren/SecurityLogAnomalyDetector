"""Generate synthetic log windows for smoke tests, never a benchmark."""

import argparse
import csv
import random
from pathlib import Path

from security_log_anomaly_detector.features import RAW_FIELDS


def generate(output: Path) -> None:
    rng = random.Random(42)  # noqa: S311  # nosec B311
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*RAW_FIELDS, "group_id", "label"])
        writer.writeheader()
        for label in ("benign", "anomalous"):
            for source_type in range(5):
                for group in range(40 if label == "benign" else 20):
                    unusual = label == "anomalous"
                    for _repeat in range(2):
                        writer.writerow(
                            {
                                "source_type_code": source_type,
                                "events_per_minute": (28 if unusual else 4) + rng.uniform(0, 2),
                                "error_ratio": rng.uniform(0.5, 0.8)
                                if unusual
                                else rng.uniform(0, 0.1),
                                "auth_failure_ratio": rng.uniform(0.4, 0.7)
                                if unusual
                                else rng.uniform(0, 0.05),
                                "access_denied_ratio": rng.uniform(0.3, 0.6)
                                if unusual
                                else rng.uniform(0, 0.05),
                                "distinct_event_codes": (20 if unusual else 5) + group % 3,
                                "distinct_principals": (18 if unusual else 2) + group % 3,
                                "distinct_hosts": (10 if unusual else 1) + group % 2,
                                "off_hours_ratio": rng.uniform(0.6, 0.9)
                                if unusual
                                else rng.uniform(0, 0.2),
                                "rare_template_ratio": rng.uniform(0.5, 0.8)
                                if unusual
                                else rng.uniform(0, 0.1),
                                "mean_severity": (7 if unusual else 2) + rng.uniform(0, 1),
                                "burstiness": (5 if unusual else 0.8) + rng.uniform(0, 0.2),
                                "mean_interarrival_seconds": (2 if unusual else 15)
                                + rng.uniform(0, 1),
                                "privileged_action_count": 20 if unusual else group % 2,
                                "baseline_expected_events_per_minute": 4 + group % 3,
                                "group_id": f"{label}-{source_type}-{group}",
                                "label": label,
                            }
                        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("data/processed/synthetic.csv"))
    args = parser.parse_args()
    generate(args.output)
    print(args.output)


if __name__ == "__main__":
    main()
