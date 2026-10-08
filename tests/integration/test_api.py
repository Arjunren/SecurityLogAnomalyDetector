from fastapi.testclient import TestClient

from security_log_anomaly_detector.api import create_app
from security_log_anomaly_detector.artifact import Model
from security_log_anomaly_detector.config import Settings
from security_log_anomaly_detector.features import LogWindow


def test_anomaly_api_and_rejections(observation: LogWindow, model: Model) -> None:
    api = TestClient(
        create_app(
            Settings(
                app_env="test", api_key="test-secret", max_batch_size=2, max_request_bytes=1024
            ),
            model,
        )
    )
    assert api.get("/health").status_code == 200
    assert api.get("/ready").status_code == 200
    assert api.get("/version").json()["model"] == "test-1"
    headers = {"X-API-Key": "test-secret"}
    body = {"observation": observation.model_dump()}
    assert api.post("/api/v1/predict", json=body).status_code == 401
    result = api.post("/api/v1/predict", headers=headers, json=body)
    assert result.status_code == 200
    assert result.json()["anomaly_score"] >= 0
    assert "top_feature_deviations" in result.json()
    assert api.post("/api/v1/predict", headers=headers, json={"observation": {}}).status_code == 422
    assert (
        api.post(
            "/api/v1/batch-predict",
            headers=headers,
            json={"observations": [observation.model_dump()] * 3},
        ).status_code
        == 413
    )
    assert (
        api.post(
            "/api/v1/predict", headers={**headers, "Content-Type": "text/plain"}, content="bad"
        ).status_code
        == 415
    )
    assert (
        api.post(
            "/api/v1/predict",
            headers={**headers, "Content-Type": "application/json"},
            content=b"x" * 1025,
        ).status_code
        == 413
    )
