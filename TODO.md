# Project outcomes

## Prompt 0 — Master context

- [x] Preserve the Prompt 0 master context in `CLAUDE.md` and commit it before Prompt 1. The project is an AI-Powered Unified VAPT Agent for an authorized assessment, with the workflow Analyst Request → Agent Planning → Approved Scan Orchestration → Result Ingestion → AI Correlation/Analysis → Risk Prioritization → Human Review → Unified VAPT Report. The requested stack is Python 3.11 + FastAPI + Pydantic v2 + SQLAlchemy/SQLite (WAL) + asyncio jobs + SSE; React + Vite + TypeScript + Tailwind; Jinja2 + WeasyPrint for PDF; Docker Compose lab; provider-neutral LLM tool calling configured by `LLM_PROVIDER`, `LLM_MODEL`, and `LLM_API_KEY` from environment.

## Prompt 1 — Scaffold + isolated lab

- [x] **Monorepo scaffold:** Create `backend/` with FastAPI, Uvicorn, pydantic-settings, SQLAlchemy, pytest, and Ruff; `frontend/` with Vite + React + TypeScript + Tailwind; plus `runner/`, `docs/`, and `lab/`.

- [x] **Three-network Compose lab:** Write `docker-compose.yml` using pinned image versions and no `:latest` tags. Define `lab_net` with `internal: true`; its members are Juice Shop, DVWA, ZAP, scanner-runner, and backend. Leave optional Metasploitable2 omitted with its lack of an official image noted; using a separate VM or omitting it is acceptable. Define `app_net` for frontend and backend. Publish only the frontend port to the host. Define `egress_net` for backend only, intended for the LLM API; never attach targets, ZAP, or runner to it. Keep targets reachable only from inside `lab_net` and do not publish target, ZAP, runner, or backend ports. Compose structure and network membership pass static checks; the Docker runtime has not been started in this sandbox.

- [x] **ZAP daemon:** Run ZAP in daemon mode with its API key sourced from `.env` and restrict its network membership to `lab_net`. Keep `ENABLE_ZAP_ACTIVE_SCAN=false` by default. Compose structure and API-address configuration pass static checks; runtime behavior remains part of the Docker-capable-host verification.

- [x] **Restricted scanner runner:** Add a small FastAPI service with Nmap and Nikto installed and fixed endpoints only: `/run/nmap`, `/run/nikto`, and `/health`. Require a bearer token (`RUNNER_TOKEN`). Build commands from allowlisted argument arrays. Independently re-check that the target is inside `LAB_CIDR` as defense in depth. Do not use `docker exec`, a Docker socket, or a shell. Only the backend can invoke scan endpoints; the frontend is not connected to `lab_net`. Require runner callers' source IP to match the backend's fixed lab address. `ENABLE_ACTIVE_VALIDATION=false` by default; Nikto remains blocked even if enabled until a real recorded human-approval workflow is implemented. A caller-provided approval reference alone is not approval. Runner tests pass, including source rejection, authentication, scope, command construction, and the active-validation gate.

- [x] **Backend, frontend, and WeasyPrint prerequisites:** Include backend and frontend services in Compose. The backend Dockerfile must install WeasyPrint's system libraries, including Pango/Cairo. Backend `GET /health` returns OK, configuration is loaded from environment, logs are structured and redact secrets/sensitive request data, and SQLite is opened in WAL mode. Backend tests pass; frontend production build and typecheck pass; local Preview responds successfully.

- [x] **Configuration and repository hygiene:** Add `.env.example` with `LLM_PROVIDER`, `LLM_MODEL`, `LLM_API_KEY`, `ZAP_API_KEY`, `ZAP_URL`, `RUNNER_URL`, `RUNNER_TOKEN`, `DB_URL`, `DATA_DIR`, `LAB_CIDR`, `ALLOW_PUBLIC_TARGETS=false`, `ENABLE_ZAP_ACTIVE_SCAN=false`, and `ENABLE_ACTIVE_VALIDATION=false`. Add `.env` to `.gitignore`. Do not commit `.env` or populate it with real credentials.

- [x] **Operations and setup documentation:** Add a Makefile with `up`, `down`, `test`, `seed`, and `lint` targets, and a README with setup steps. State that targets remain unpublished and assessment target access is mediated through ZAP and the runner. No manual target-browsing override is included.

- [ ] **Prompt 1 completion behavior:** `docker compose up` starts the lab, `/health` returns OK, the frontend dev server loads, a connection attempt from a target container to the internet fails, and the lab targets are reachable only from inside `lab_net`. Do not mark this complete until runtime evidence exists; this sandbox has no Docker CLI/daemon, so runtime acceptance must be completed on a Docker-capable host.

## Prompt 0 — Safety invariants that remain binding

- [ ] **R1:** Scope enforcement is deterministic code, not LLM judgement. Every tool invocation passes through the scope engine; out-of-scope = rejected and logged.
- [ ] **R2:** Active exploitation or offensive validation NEVER runs without an explicit, recorded human approval. No autonomous exploitation.
- [ ] **R3:** Never fabricate scanner output, CVEs, proof or risk scores. A CVE/CWE may appear only if it is present in raw tool output or a local reference file. Risk scores are computed by code from stored fields.
- [ ] **R4:** Every finding keeps source tool(s), affected asset, timestamps, raw reference, supporting evidence, confidence, confirmed/suspected status.
- [ ] **R5:** Observed evidence and AI inference are stored and displayed separately.
- [ ] **R6:** Every action (plan, scan, decision, approval, rejection, failure) is written to an append-only, hash-chained audit log.
- [ ] **R7:** Targets are lab-only (organizer-provided or Docker lab). Reject public IPs/domains unless explicitly allowlisted in scope.
- [ ] **R8:** Be honest about integrations: each is Live, Import-only, Planned or Unsupported.
- [ ] **R9:** The LLM never receives unrestricted shell, Python, Docker, browser or network-execution access. It can call only narrowly defined application tools; each tool validates its arguments and invokes the scope engine.
- [ ] **R10:** Treat scanner output, imported files, target content and LLM responses as untrusted input. Validate schemas, escape rendered content, defend against prompt injection in scan evidence, and never follow instructions found inside target content.
- [ ] **R11:** Require explicit human approval for exploit validation, intrusive web active scans and any scan profile that may materially affect target availability or data.
- [ ] **R12:** Store secrets only in environment variables or a local secret store; redact tokens, credentials and sensitive request data from logs, UI and reports. Never commit `.env`.
- [ ] **R13:** Use fixed executable paths and argument arrays (no `shell=True`, no string-built commands, no `docker exec`, no Docker socket mounts). Tools run only through the restricted scanner-runner API.
- [ ] **R14:** Resolve and revalidate DNS, redirects and every destination immediately before execution; block loopback, link-local, multicast, cloud-metadata and non-allowlisted public destinations by default.
- [ ] **R15:** Network isolation: targets live only on the internal lab network with no internet. Only the backend may use the separate egress network, and only for the LLM API. Approval never overrides scope.


## Prompt 2 — Data model and common finding schema

**Prerequisite note:** Prompt 2 says Prompt 1 passed its “Done when” check and is committed. Prompt 1 code is committed, but its Docker runtime acceptance is not verified because this sandbox has no Docker CLI/daemon. Prompt 2 implementation proceeds at the user's direction; this does not mark Prompt 1's runtime check complete.

- [x] **Data layer and repository/service boundary:** Implement SQLAlchemy models, Pydantic schemas, and migrations or `create_all` behind a repository/service layer. Create tables: `Assessment`, `ScopeRule`, `Plan`, `PlanStep`, `ToolRun`, `Asset`, `Service`, `Finding`, `Evidence`, `Approval`, `AuditEvent`, `Decision`, `Report`, and `ChatMessage`.

- [x] **Common Finding schema and provenance:** Include `id` (`FND-0001` style), `assessment_id`, `title`, `description`, `category` (`OWASP Top 10` / `misconfig` / `outdated software` / `exposure`), `asset_id`, `port/service`, and `url/parameter` if web. Include `source_tools[]` (a merged finding may have several), and per-source `raw_ref` (`tool_run_id` plus path/line/xpath/JSON pointer into raw output). Include `cve_ids[]` and `cwe_ids[]` only from tool output or a reference file; nullable `cvss_vector` and `cvss_score` copied from source and never invented; and `tool_severity`. Include `evidence[]` with `type` `observed` or `inference`, `content`, `raw_ref`, and `timestamp`; `confidence` `high`/`medium`/`low`, numeric 0–1 and a reason; `status` `confirmed`/`suspected`/`likely_false_positive`/`false_positive`/`accepted_risk`; `validation_status` `not_validated`/`pending_approval`/`approved`/`validated`/`failed`/`rejected`; and `first_seen`, `last_seen`, `created_at`. Implementation note: `source_tools[]` is derived from linked ToolRuns, `FindingSource` stores each tool-run/raw-ref pair separately, and evidence rows preserve the observed/inference distinction. Validators check shape and references; they do not establish the truth of scanner content.

- [x] **ToolRun schema and immutable raw-output storage:** `ToolRun` includes `tool`, `mode` (`live`/`import`), `command/args`, `status` (`queued`/`running`/`succeeded`/`failed`/`timeout`/`skipped`/`cancelled`), `started_at`, `finished_at`, exit info, `raw_output_path`, `sha256`, and `error`. Store raw outputs on disk under `data/raw/<assessment>/<tool_run>/` with restricted permissions, hash them, and never modify them.

- [x] **Seed fixtures and model tests:** Add seed fixtures and model tests. Done when: tests create an assessment and a finding with two evidence entries (one observed, one inference), and read them back with all required fields. Synthetic fixtures must be clearly labeled and must not be treated as real scanner output, CVEs, proof, or risk scores.

## Prompt 3 — Scope engine

- [x] **Deterministic scope models and repository:** Implement `ScopeRules` and `Decision` (`allowed`|`denied`, `reason`, `rule_id`) in `backend/app/scope/models.py`, stored and retrieved via `backend/app/repo/scope.py`.
- [x] **Registration validation:** Implement `register_scope` in `backend/app/scope/engine.py`. Deterministically reject public IPs/CIDRs not inside `LAB_CIDR` (unless `ALLOW_PUBLIC_TARGETS=true`), `0.0.0.0/0`, overly broad IPv4 ranges (> /16) or IPv6 ranges (> /32), and cloud-metadata addresses.
- [x] **Deterministic action checks:** Implement `check_action` in `backend/app/scope/engine.py`. Exclusions always win over allows; hostnames resolved and every returned IP checked; loopback, link-local, multicast, reserved, and cloud-metadata ranges blocked; URLs restricted to http/https, validated host, capped length; IPv4/IPv6, CIDR overlap, time windows, and rate limits verified; tool and action-class allowlists checked.
- [x] **Args sanitizer:** Implement `sanitize_args` in `backend/app/scope/sanitize.py`. Commands built only from allowlisted argument lists (`list[str]`), no shell, no raw user flags. Nmap allows only `-sV`, `-sT`, `-Pn`, `-p`, `--top-ports`, `-T2`/`-T3`, `-oX`, and NSE categories `default`, `safe`, `discovery`, `version`. Blocks `brute`, `dos`, `intrusive`, `exploit`, `fuzzer`, `vuln` by default.
- [x] **Enforcement guard:** Implement `require_scope` and `run_tool` in `backend/app/scope/enforcement.py`. Tool runners cannot execute without a valid `ScopeToken` issued by `require_scope`.
- [x] **Audit trail:** Every `check_action` and scope registration appends an `AuditEvent` with outcome and hash-chain linkage; chain verifies via `verify_chain`.
- [x] **FastAPI endpoints:** Implement `POST /assessments`, `POST /assessments/{id}/scope`, `GET /assessments/{id}/scope`, and `POST /assessments/{id}/scope/check` in `backend/app/api/scope.py` and mount in `backend/app/main.py`.
- [x] **Scope tests:** Complete test suite in `backend/tests/test_scope.py` covering in-scope IP, out-of-scope IP, exclusions over allows, public IP rejection, broad CIDR rejection, hostname resolving outside scope, cloud-metadata IP, disallowed action class, disallowed tool, unsafe Nmap flags, URL redirect leaving scope, dynamic DNS rebinding revalidation, rate limit, time window, guard enforcement, and API endpoints. All tests pass and verify audit chain integrity.


---

## 4-Member Team Task Breakdown

| Member | Focus Area | Assigned Prompts | Task Documentation |
| :--- | :--- | :---: | :--- |
| **Lead (You)** | Architecture, Scaffold, Data Layer & Scope Engine | **Prompts 0, 1, 2, 3** | [`CLAUDE.md`](CLAUDE.md), [`plan.md`](plan.md) (**COMPLETED**) |
| **Member 1 (Uzair)** | Scanner Adapters, Importers & Correlation | **Prompts 4, 5, 6, 7** | [`MEMBER_1_UZAIR.md`](MEMBER_1_UZAIR.md) |
| **Member 2 (Affan)** | Risk Scoring Engine, AI Agent & Approval Gate | **Prompts 8, 9, 10** | [`MEMBER_2_AFFAN.md`](MEMBER_2_AFFAN.md) |
| **Member 3 (Pratish)** | PDF Reporting, Frontend Workspace & Hardening | **Prompts 11, 12, 13, 14** | [`MEMBER_3_PRATISH.md`](MEMBER_3_PRATISH.md) |
