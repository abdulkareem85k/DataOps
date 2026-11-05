"""Validated application settings loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Network, ip_network
from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings; secret values are excluded from normal representations."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    llm_provider: str = "openai_compatible"
    llm_model: str = ""
    llm_api_key: SecretStr = SecretStr("")
    zap_api_key: SecretStr = SecretStr("")
    zap_url: str = "http://zap:8090"
    runner_url: str = "http://scanner-runner:9000"
    runner_token: SecretStr = SecretStr("")
    db_url: str = "sqlite:///./data/vapt.db"
    data_dir: Path = Path("./data")
    lab_cidr: str = "172.30.0.0/24"
    allow_public_targets: bool = False
    enable_zap_active_scan: bool = False
    enable_active_validation: bool = False

    @field_validator("db_url")
    @classmethod
    def require_sqlite(cls, value: str) -> str:
        """Keep this milestone on its specified local SQLite persistence layer."""
        if not value.startswith("sqlite:"):
            raise ValueError("DB_URL must use SQLite for this project milestone")
        return value

    @field_validator("lab_cidr")
    @classmethod
    def require_private_ipv4_lab(cls, value: str) -> str:
        """Reject non-private or non-IPv4 lab networks at configuration load time."""
        network = ip_network(value, strict=True)
        if not isinstance(network, IPv4Network) or not network.is_private:
            raise ValueError("LAB_CIDR must be a private IPv4 network")
        return str(network)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached, validated process settings."""
    return Settings()
