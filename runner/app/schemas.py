"""Validated scanner request/response payloads; callers cannot submit raw CLI flags."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class NmapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=7, max_length=39)
    top_ports: Literal[100, 1000] = 100
    timeout_seconds: int = Field(default=60, ge=5, le=120)


class NiktoRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=7, max_length=39)
    port: Literal[80, 443, 3000, 4280, 8080, 8090, 8181, 8443] = 80
    use_https: bool = False
    timeout_seconds: int = Field(default=90, ge=5, le=120)
    approval_id: str = Field(min_length=8, max_length=128)


class ScanResponse(BaseModel):
    tool: Literal["nmap", "nikto"]
    target: str
    status: Literal["completed", "failed"]
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool
