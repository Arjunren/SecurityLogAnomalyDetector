from pathlib import Path

import numpy as np

from scripts.generate_test_data import generate
from security_log_anomaly_detector.artifact import load_model
from security_log_anomaly_detector.training import (
    TrainingConfig,
    calculate_metrics,
    split_indices,
    train,
)


def test_group_split_disjoint() -> None:
    labels = np.asarray([i % 2 for i in range(100)])
    groups = np.asarray([f"group-{i}" for i in range(100)])
    partitions = split_indices(labels, groups, TrainingConfig())
    sets = [set(groups[part]) for part in partitions]
    assert not sets[0] & sets[1]
    assert not sets[0] & sets[2]
    assert not sets[1] & sets[2]


def test_metrics_include_false_rates() -> None:
    result = calculate_metrics(np.asarray([0, 0, 1, 1]), np.asarray([0.1, 0.9, 0.2, 0.8]), 0.5)
    assert result["false_positive_rate"] == 0.5
    assert result["false_negative_rate"] == 0.5


def test_training_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "windows.csv"
    generate(source)
    config = tmp_path / "training.json"
    config.write_text(Path("configs/training.json").read_text(encoding="utf-8"), encoding="utf-8")
    artifact = tmp_path / "model.json"
    report = train(source, artifact, config)
    assert report["test_metrics"]["pr_auc"] >= 0
    assert load_model(artifact).version == "1.0.0"
