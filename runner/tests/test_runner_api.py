from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.audit import HashChainedAuditLog
from app.main import create_app
from app.settings import RunnerSettings

TOKEN = "a" * 64


def make_client(
    tmp_path: Path,
    active_validation: bool = False,
    source_ip: str = "172.30.0.50",
) -> TestClient:
    settings = RunnerSettings(
        _env_file=None,
        runner_token=TOKEN,
        lab_cidr="172.30.0.0/24",
        enable_active_validation=active_validation,
        audit_path=tmp_path / "audit.jsonl",
    )
    return TestClient(
        create_app(settings, HashChainedAuditLog(settings.audit_path)),
        client=(source_ip, 50000),
    )


def test_health_is_plain_ok_and_documentation_is_disabled(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    assert client.get("/health").text == "OK"
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    paths = {route.path for route in client.app.routes}
    assert paths == {"/health", "/run/nmap", "/run/nikto"}


def test_scan_endpoint_requires_bearer_token(tmp_path: Path) -> None:
    response = make_client(tmp_path).post("/run/nmap", json={"target": "172.30.0.10"})
    assert response.status_code == 401


def test_scan_endpoint_rejects_target_network_caller(tmp_path: Path) -> None:
    client = make_client(tmp_path, source_ip="172.30.0.10")
    response = client.post(
        "/run/nmap",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"target": "172.30.0.10"},
    )
    assert response.status_code == 403
    assert "backend-only" in response.text
    assert "runner.source_rejected" in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_health_endpoint_rejects_target_network_caller(tmp_path: Path) -> None:
    response = make_client(tmp_path, source_ip="172.30.0.10").get("/health")
    assert response.status_code == 403


def test_nmap_rejects_out_of_scope_target_before_execution(
    tmp_path: Path, monkeypatch: object
) -> None:
    def fail_if_called(_command: object) -> None:
        raise AssertionError("scanner must not execute for an out-of-scope target")

    monkeypatch.setattr("app.main.execute_command", fail_if_called)  # type: ignore[attr-defined]
    client = make_client(tmp_path)
    response = client.post(
        "/run/nmap",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"target": "8.8.8.8"},
    )
    assert response.status_code == 403
    assert not response.json().get("target")


def test_nmap_builds_only_allowlisted_argv_and_audits_result(
    tmp_path: Path, monkeypatch: object
) -> None:
    seen: list[tuple[str, ...]] = []

    def fake_execute(command: object) -> tuple[int, str, str, bool]:
        argv = tuple(command.argv)  # type: ignore[attr-defined]
        seen.append(argv)
        return 0, "<nmaprun />", "", False

    monkeypatch.setattr("app.main.execute_command", fake_execute)  # type: ignore[attr-defined]
    client = make_client(tmp_path)
    response = client.post(
        "/run/nmap",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"target": "172.30.0.10", "top_ports": 100},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert seen[0][0] == "/usr/bin/nmap"
    assert "--script" not in seen[0]
    assert seen[0][-1] == "172.30.0.10"
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "scan.started" in audit_text and "scan.completed" in audit_text


def test_nikto_is_disabled_by_default(tmp_path: Path, monkeypatch: object) -> None:
    def fail_if_called(_command: object) -> None:
        raise AssertionError("Nikto must remain disabled without active-validation opt-in")

    monkeypatch.setattr("app.main.execute_command", fail_if_called)  # type: ignore[attr-defined]
    client = make_client(tmp_path, active_validation=False)
    response = client.post(
        "/run/nikto",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "target": "172.30.0.10",
            "port": 3000,
            "approval_id": "approval-0001",
        },
    )
    assert response.status_code == 403
    assert "active validation is disabled" in response.text


def test_nikto_stays_blocked_until_recorded_approval_workflow_exists(
    tmp_path: Path, monkeypatch: object
) -> None:
    def fail_if_called(_command: object) -> None:
        raise AssertionError("a caller-provided approval ID is not recorded approval")

    monkeypatch.setattr("app.main.execute_command", fail_if_called)  # type: ignore[attr-defined]
    client = make_client(tmp_path, active_validation=True)
    response = client.post(
        "/run/nikto",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "target": "172.30.0.10",
            "port": 3000,
            "approval_id": "approval-0001",
        },
    )
    assert response.status_code == 409
    assert "recorded human approvals" in response.text
