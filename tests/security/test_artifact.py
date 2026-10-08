from pathlib import Path

import pytest

from security_log_anomaly_detector.artifact import load_model


def test_rejects_pickle_artifact(tmp_path: Path) -> None:
    path = tmp_path / "model.json"
    path.write_bytes(b"\x80\x04pickle")
    with pytest.raises(ValueError):
        load_model(path)


def test_rejects_oversized_artifact(tmp_path: Path) -> None:
    path = tmp_path / "model.json"
    path.write_bytes(b" " * 65537)
    with pytest.raises(ValueError):
        load_model(path)
