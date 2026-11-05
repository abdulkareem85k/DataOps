"""Validated settings for the isolated scanner-runner."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_network
from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RunnerSettings(BaseSettings):
    """Runner settings; executable paths are deliberately not configurable."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    runner_token: SecretStr = SecretStr("")
    lab_cidr: str = "172.30.0.0/24"
    runner_backend_ip: IPv4Address = IPv4Address("172.30.0.50")
    enable_active_validation: bool = False
    audit_path: Path = Path("/var/lib/scanner-runner/audit.jsonl")

    @field_validator("lab_cidr")
    @classmethod
    def require_private_ipv4_lab(cls, value: str) -> str:
        network = ip_network(value, strict=True)
        if not isinstance(network, IPv4Network) or not network.is_private:
            raise ValueError("LAB_CIDR must be a private IPv4 network")
        return str(network)
