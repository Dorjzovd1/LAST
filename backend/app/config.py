"""Application configuration loaded from environment / .env file."""
from __future__ import annotations

import shutil
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime тохиргоо. REA_ prefix-тэй орчны хувьсагчаар дарж болно."""

    model_config = SettingsConfigDict(
        env_prefix="REA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "sqlite:///./data/rea.db"

    data_dir: Path = Path("./data")
    recovered_dir: Path = Path("./data/recovered")
    export_dir: Path = Path("./data/exports")

    # Forensic CLI олдохгүй үед mock өгөгдөл ашиглах эсэх.
    allow_mock: bool = True

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @field_validator("data_dir", "recovered_dir", "export_dir", mode="before")
    @classmethod
    def _as_path(cls, value: str | Path) -> Path:
        return Path(value)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.recovered_dir, self.export_dir):
            d.mkdir(parents=True, exist_ok=True)

    def tool_available(self, name: str) -> bool:
        """Forensic CLI хэрэгсэл системд байгаа эсэхийг шалгана."""
        return shutil.which(name) is not None


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_dirs()
    return settings
