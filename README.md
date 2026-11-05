# AI Unified VAPT Agent — Foundation

This repository contains the Prompt 1 monorepo/lab scaffold and the Prompt 2 assessment data layer. Prompt 1's Docker runtime network checks remain unverified in this sandbox because Docker is unavailable. Approval workflows, scan orchestration, LLM analysis, risk scoring, and PDF report generation are not implemented yet. No real findings or scanner results are fabricated.

## Prerequisites

For the Compose lab, install Docker Engine or Docker Desktop with Docker Compose v2. For local Preview and checks, install Python 3.11, `uv`, Node.js 22, and npm 10. The selected Compose target CIDR is `172.30.0.0/24`; ensure it does not overlap a network already used by your Docker host.

## Configure secrets

Copy the safe template and generate unique secrets locally:

```sh
cp .env.example .env
openssl rand -hex 32
```

Use one generated value for `ZAP_API_KEY` and a different value for `RUNNER_TOKEN`. Keep `LLM_API_KEY` empty until an LLM integration is implemented and approved. Compose passes only each service's required values: the backend receives its provider/ZAP/runner settings, the runner receives only `RUNNER_TOKEN` and lab controls, and ZAP receives only `ZAP_API_KEY`. Never commit `.env`; it is ignored by Git and excluded from Docker build contexts.

## Start and stop the lab

```sh
make up
make down
```

`make up` builds the backend, frontend, and scanner-runner images and starts the pinned Juice Shop, DVWA, and ZAP images. Only the frontend is published to the host at `http://localhost:3000`. The backend, scanner-runner, ZAP, Juice Shop, and DVWA ports are not published. The frontend proxies `/health` to the backend. `GET /health` returns the plain text `OK` when the SQLite-backed API is ready.

In the intended assessment workflow, the backend coordinates target access through the approved scanner runner and ZAP; analysts do not connect to targets through host-published ports. No manual target-browsing override is included.

The target services are reachable only inside `lab_net`. That network is marked `internal: true`; neither target, ZAP, nor scanner-runner is connected to `egress_net`. The frontend and backend communicate over internal `app_net`. Only the backend is attached to `egress_net`, which is reserved for the LLM provider when that integration is implemented. Docker's bridge does not itself restrict that network to specific destination domains. The current backend has no outbound LLM client; before one is added, enforce an approved provider-domain egress allowlist at the host/network boundary. Do not treat `egress_net` membership alone as a domain-level firewall.

Targets are deliberately not exposed to the host. No manual browsing override is included. If a later approved workflow requires browser access, add a separate development-only Compose override and keep it out of the default lab topology.

## Local development

In one terminal, install and run the backend from the repository root:

```sh
uv sync --project backend
uv run --project backend uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

In another terminal, install and run the frontend:

```sh
npm --prefix frontend ci
npm --prefix frontend run dev -- --host 0.0.0.0 --port 3000
```

Vite proxies `/health` to `http://127.0.0.1:8000` by default. The Webdev Preview uses port 3000. The frontend contains no scan trigger and does not access the runner directly.

## Prompt 2 data model

The backend uses SQLAlchemy 2 ORM models and SQLite/WAL `create_all` initialization. It declares `Assessment`, `ScopeRule`, `Plan`, `PlanStep`, `ToolRun`, `Asset`, `Service`, `Finding`, `Evidence`, `Approval`, `AuditEvent`, `Decision`, `Report`, and `ChatMessage`, plus a normalized `FindingSource` relation for per-tool raw references. A repository/service boundary currently supports creating and reading assessments, ToolRuns, findings, and raw-output metadata; no scan, approval, report, or LLM execution endpoint is exposed by this milestone.

Findings receive sequential `FND-0001`-style IDs from a transactionally updated SQLite counter. Pydantic v2 schemas constrain the category, status, validation status, confidence, port, CVSS range, and evidence type. `source_tools` is derived from the linked ToolRuns; each contributing run retains its own raw locator. Observed evidence and inference are separate rows. CVE/CWE values and CVSS/severity fields are copied only when source references are supplied; the code does not generate identifiers, scores, proof, or scanner output.

Raw output is stored below `<DATA_DIR>/raw/<assessment_id>/<tool_run_id>/raw-output.bin` (by default, `data/raw/...`). IDs are restricted to safe path characters, directories use mode `0700`, files use mode `0400` after fsync, and exclusive creation prevents overwriting. SHA-256 and the relative path are attached to a ToolRun once. Raw output is not served by HTTP or included in logs/reports. The JSON fixture in `backend/tests/fixtures/` is prominently labeled synthetic and exists only for isolated round-trip tests; production `make seed` never inserts it.

## Runner safety

The runner has only `/health`, `POST /run/nmap`, and `POST /run/nikto`; FastAPI docs and OpenAPI routes are disabled. Scan endpoints require both a bearer token and a caller IP matching the fixed backend address; the frontend is not on `lab_net`. Targets must be literal IPv4 addresses within `LAB_CIDR`; hostnames, loopback, link-local, multicast, reserved, and out-of-range addresses are rejected. Scanner commands use fixed executable paths, validated arguments, and `shell=False`. The runner has no Docker socket, no host-published port, and no egress network. Backend structured logs redact common bearer tokens and secret assignments; request bodies and settings are not logged.

The runner audit file is appended under a file lock, hash-linked, checked before each append, and fsynced. This detects broken links and ordinary tampering, but the chain is not externally anchored; a privileged actor able to rewrite the entire volume could recompute it. External anchoring remains a later hardening task.

Nmap is constrained to non-script top-port/service discovery. Nikto is treated as active web validation: `ENABLE_ACTIVE_VALIDATION` is false by default, and it remains non-executable even if toggled on until a later prompt implements recorded human approval. A caller-provided approval reference alone is not accepted. The backend does not yet expose scan orchestration; later prompts must implement and verify recorded approval and scope checks before calling Nikto or ZAP. ZAP active scanning is disabled by default. Approval must never override `LAB_CIDR`.

## Checks and database initialization

```sh
make test
make lint
make seed
```

`make seed` creates the declared model tables using `create_all`, verifies SQLite WAL mode, and intentionally adds no synthetic targets or findings. Static Compose checks verify pinned image references and network/port membership. A Docker-capable host must still run the Compose lab and verify that an egress attempt from a lab target fails; these runtime checks cannot be performed in the current sandbox because it has no Docker CLI or daemon.
