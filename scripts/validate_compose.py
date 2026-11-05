"""Static Compose policy checks; this does not replace Docker runtime verification."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "docker-compose.yml"
EXPECTED_NETWORKS = {"lab_net", "app_net", "egress_net"}
EXPECTED_SERVICES = {"frontend", "backend", "scanner-runner", "zap", "juice-shop", "dvwa"}
EXPECTED_MEMBERS = {
    "lab_net": {"backend", "scanner-runner", "zap", "juice-shop", "dvwa"},
    "app_net": {"backend", "frontend"},
    "egress_net": {"backend"},
}


def load_compose() -> dict[str, Any]:
    with COMPOSE_PATH.open(encoding="utf-8") as handle:
        parsed = yaml.safe_load(handle)
    if not isinstance(parsed, dict):
        raise AssertionError("Compose document must be a YAML mapping")
    return parsed


def main() -> None:
    config = load_compose()
    services = config.get("services", {})
    networks = config.get("networks", {})
    assert set(services) == EXPECTED_SERVICES, f"unexpected services: {set(services) ^ EXPECTED_SERVICES}"
    assert set(networks) == EXPECTED_NETWORKS, f"unexpected networks: {set(networks) ^ EXPECTED_NETWORKS}"

    members = {network: set() for network in networks}
    for service_name, service in services.items():
        assert "env_file" not in service, f"{service_name} must not receive the entire .env file"
        for network in service.get("networks", {}):
            members[network].add(service_name)
        ports = service.get("ports", [])
        if service_name == "frontend":
            assert ports == ["3000:3000"], "only frontend may publish host port 3000"
        else:
            assert not ports, f"{service_name} must not publish a host port"
        assert not service.get("privileged", False), f"{service_name} must not be privileged"
        assert service.get("network_mode") != "host", f"{service_name} must not use host networking"
        for volume in service.get("volumes", []):
            assert "/var/run/docker.sock" not in str(volume), "Docker socket mounts are forbidden"
        image = service.get("image", "")
        assert not image.endswith(":latest"), f"moving latest image tag is forbidden: {service_name}"
        if service_name in {"zap", "juice-shop", "dvwa"}:
            assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"{service_name} image must be digest-pinned"
        if service_name in {"frontend", "backend", "scanner-runner"}:
            assert re.search(r":0\.1\.0$", image), f"local image tag must be pinned: {service_name}"

    for network_name, expected_members in EXPECTED_MEMBERS.items():
        assert members[network_name] == expected_members, (
            f"{network_name} members differ: {members[network_name] ^ expected_members}"
        )
    assert networks["lab_net"].get("internal") is True, "lab_net must be internal"
    assert networks["app_net"].get("internal") is True, "app_net must be internal"
    assert services["backend"].get("healthcheck"), "backend must have a healthcheck"
    assert services["scanner-runner"].get("read_only") is True, "runner filesystem must be read-only"
    assert services["scanner-runner"].get("cap_drop") == ["ALL"], "runner must drop all capabilities"
    backend_ip = services["backend"]["networks"]["lab_net"]["ipv4_address"]
    runner_ip = services["scanner-runner"]["environment"].get("RUNNER_BACKEND_IP")
    assert runner_ip == backend_ip, "runner caller allowlist must match the backend lab address"
    expected_backend_env = {
        "LLM_PROVIDER",
        "LLM_MODEL",
        "LLM_API_KEY",
        "ZAP_API_KEY",
        "RUNNER_TOKEN",
        "ZAP_URL",
        "RUNNER_URL",
        "DB_URL",
        "DATA_DIR",
        "LAB_CIDR",
        "ALLOW_PUBLIC_TARGETS",
        "ENABLE_ZAP_ACTIVE_SCAN",
        "ENABLE_ACTIVE_VALIDATION",
    }
    assert set(services["backend"]["environment"]) == expected_backend_env
    assert set(services["scanner-runner"]["environment"]) == {
        "RUNNER_TOKEN",
        "LAB_CIDR",
        "RUNNER_BACKEND_IP",
        "ENABLE_ACTIVE_VALIDATION",
        "AUDIT_PATH",
    }
    assert set(services["zap"]["environment"]) == {"ZAP_API_KEY"}
    assert services["zap"].get("command"), "ZAP must start in daemon mode"
    assert "-daemon" in services["zap"]["command"], "ZAP must run in daemon mode"

    print("Compose static policy checks passed; Docker runtime isolation remains unverified here.")


if __name__ == "__main__":
    main()
