"""Validated runtime settings."""

from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    model_path: Path = Path("models/model.json")
    api_host: str = "127.0.0.1"
    api_port: int = Field(8000, ge=1, le=65535)
    api_key: str = ""
    max_batch_size: int = Field(100, ge=1, le=1000)
    max_request_bytes: int = Field(1048576, ge=1024, le=10485760)
    max_concurrent_inference: int = Field(4, ge=1, le=32)
    inference_timeout_seconds: float = Field(2.0, gt=0, le=30)

    @model_validator(mode="after")
    def require_production_key(self) -> "Settings":
        if self.app_env == "production" and len(self.api_key) < 24:
            raise ValueError("Production API_KEY must contain at least 24 characters")
        return self
