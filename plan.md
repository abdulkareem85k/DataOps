# Implementation Plan — AI Unified VAPT Agent

**Status: Prompt 1 code and local Preview complete; Docker runtime acceptance remains pending. Prompt 2 data-layer implementation in progress.**

## Scope and source constraints

Prompt 0 of 14 defines the product, stack, and hard safety rules R1–R15. Its master context is saved in `CLAUDE.md` and was committed to the canonical `main` branch as `c460c956b097d359d389bd93644e328465072627` (“prompt 0 done”). Prompt 1 code is committed as `a9b5884`, but its Docker runtime acceptance was not verified because this sandbox has no Docker CLI/daemon. Prompt 2 has now been supplied and is the current implementation scope. Prompts 3–13 are not supplied; no requirements belonging to them will be invented.

Prompt 1 requires `backend/` (FastAPI, Uvicorn, pydantic-settings, SQLAlchemy, pytest, Ruff), `frontend/` (Vite, React, TypeScript, Tailwind), `runner/`, `docs/`, and `lab/`. It requires Compose services for Juice Shop, DVWA, ZAP, the scanner runner, backend, and frontend, with pinned non-`latest` image versions and exactly three networks: internal `lab_net`, `app_net`, and backend-only `egress_net`. Targets, ZAP, and runner must never be attached to egress. Only the frontend publishes a host port. The scanner runner exposes only `/run/nmap`, `/run/nikto`, and `/health`, requires a bearer token, builds commands from allowlisted argument arrays, independently validates targets against `LAB_CIDR`, and must not use `docker exec`, a Docker socket, or a shell. Backend requirements include `GET /health`, environment-based settings, structured logging, SQLite WAL, and a Dockerfile with WeasyPrint's Pango/Cairo system libraries. `.env.example`, `.gitignore`, Makefile targets, and setup README are required.

The managed Webdev project is at `/home/ubuntu/vaptagent`, uses Preview port 3000, and has the server capability enabled but no managed database. The application will use the requested local SQLite/WAL store. The cloud sandbox has no Docker CLI or daemon; therefore Compose can be authored and statically checked here, but `docker compose up` and runtime network-isolation acceptance cannot be claimed as run in this environment.

## Implementation approach

1. **Scaffold:** Create backend, frontend, runner, docs, and lab folders. Pin the JavaScript package manager and lockfile; lock Python dependencies. Keep all secrets out of tracked files.
2. **Network boundary:** Use an internal `lab_net` with a fixed private CIDR matching `LAB_CIDR`; attach Juice Shop, DVWA, ZAP, scanner-runner, and backend only as specified. Use an internal `app_net` for frontend/backend communication, preventing direct frontend Internet egress. Attach only backend to a separate egress-capable `egress_net`, intended only for future LLM API calls. Publish only frontend port 3000. No target, ZAP, or runner port is published. No Docker socket is mounted.
3. **Pinned lab images:** Pin Juice Shop, DVWA, and ZAP with fixed upstream tags and registry digests. Pin Python and Node base images to exact patch tags. Document upstream references in `docs/upstream-images.md`. Do not use `:latest` or moving tags such as `stable` alone.
4. **Scanner runner:** Implement a small FastAPI app with only the three specified HTTP paths; disable docs/openapi routes. Protect scan endpoints with constant-time bearer-token comparison and require the caller IP to equal the backend's fixed lab address. Accept only literal IPv4 targets inside `LAB_CIDR`, reject special addresses, validate bounded port/profile fields, and recheck scope immediately before invoking a scanner. Use fixed executable paths and arrays with `shell=False`; no caller-supplied switches, shell commands, Docker API, or Docker socket. Nmap will be limited to non-script top-port/service discovery. Nikto is gated by default-off `ENABLE_ACTIVE_VALIDATION` and remains non-executable until a real recorded-approval workflow exists; a supplied approval reference alone is not approval. ZAP active scanning remains disabled by default.
5. **Backend:** Load configuration from environment variables using pydantic-settings; represent secret values as `SecretStr`; initialize SQLite with SQLAlchemy and WAL pragmas; return unauthenticated plain-text `OK` from `GET /health`; emit JSON structured logs without credentials or sensitive request data. Add WeasyPrint's system libraries in the backend Dockerfile without inventing report schemas.
6. **Frontend and Preview:** Use React/Vite/TypeScript/Tailwind on port 3000 with a relative API proxy to FastAPI. Show a truthful scaffold state: lab-only, no findings or scans fabricated, and scanner/ZAP integrations are not claimed as operational. Keep `public/manus-routes.json` synchronized with the current `/` page route. For the sandbox Preview, run the frontend on port 3000 and backend on port 8000 as separate services.
7. **Operations and docs:** Add `.env.example` with every requested variable and safe disabled defaults, ignore `.env`, add Makefile targets `up`, `down`, `test`, `seed`, and `lint`, and document setup, topology, secret generation, expected URLs, and the distinction between static checks and Docker runtime checks. `seed` initializes the SQLite file only; it will not create fake findings or targets.
8. **Verification and delivery:** Register Python and TypeScript diagnostics before source edits. Add focused backend/runner tests and frontend type/build checks. Statically validate Compose structure and image pinning, confirm no host ports except the frontend, and scan source for forbidden shell/Docker usage. Because Docker is absent, leave Docker execution and the live egress-denial check clearly marked pending for a Docker-capable host. Commit and push the Prompt 1 result to canonical `main` after checks; do not publish it.

## Prompt 2 data-layer approach

Use the existing SQLAlchemy 2, Pydantic v2, SQLite/WAL stack without adding a database service or inventing later assessment workflows. Add ORM models for `Assessment`, `ScopeRule`, `Plan`, `PlanStep`, `ToolRun`, `Asset`, `Service`, `Finding`, `Evidence`, `Approval`, `AuditEvent`, `Decision`, `Report`, and `ChatMessage`; include a normalized finding-source reference record so each contributing tool run has its own raw-output locator. Initialize the schema with `Base.metadata.create_all` and a small repository/service layer for assessment, finding, tool-run and raw-output operations.

Pydantic schemas will represent the Prompt 2 finding fields and strict enum/value constraints. Source tools and their raw references remain distinct per finding source; evidence preserves `observed` and `inference` as separate typed rows. CVE/CWE IDs and CVSS values are nullable/copied fields only: no code synthesizes identifiers, scores, or evidence. The finding ID service allocates `FND-0001`-style identifiers transactionally.

Raw output is stored under `<DATA_DIR>/raw/<assessment_id>/<tool_run_id>/` with path-safe IDs, owner-only directories, exclusive create/no overwrite semantics, SHA-256, and read-only file permissions after fsync. The raw store does not parse, transform, serve, or log raw contents. Synthetic seed fixtures are test-only and explicitly labeled as synthetic; the production `make seed` path continues to initialize schema without adding fake scanner results.

Prompt 2 states Prompt 1 passed its Done-when check; this conflicts with the actual environment evidence, because Compose startup, target egress denial, and network isolation were not tested. Implement Prompt 2 as explicitly requested while retaining Prompt 1's runtime acceptance as pending in `TODO.md`.

## Project structure

```text
.
├── CLAUDE.md
├── plan.md
├── TODO.md
├── docker-compose.yml
├── Makefile
├── .env.example
├── .gitignore
├── backend/
│   ├── app/                  # FastAPI, config, SQLite/WAL, ORM models, Pydantic schemas, repositories/services, raw output store
│   ├── tests/                # Backend, data-model, schema, repository, raw-output, and fixture tests
│   ├── Dockerfile            # Python runtime and WeasyPrint system libraries
│   └── pyproject.toml        # FastAPI/Uvicorn/settings/SQLAlchemy/pytest/Ruff
├── frontend/                 # Vite + React + TypeScript + Tailwind
├── runner/
│   ├── app/                  # Fixed, authenticated scanner API and scope checks
│   ├── tests/                # Auth, scope, and argument allowlist tests
│   └── Dockerfile            # Pinned Python base plus Nmap/Nikto packages
├── docs/                     # Setup, network model, and pinned image sources
├── lab/                      # Lab documentation and lab-only assets
└── frontend/public/manus-routes.json  # Webdev page route manifest
```

## Design proposal

Three low-probability directions considered (style choice is an implementation proposal, not a user-selected preference):

- Precision Ops Console — **0.07**: a compact, audit-forward security operations workspace.
- Forensic Ledger — **0.04**: a document-like evidence register with restrained status color.
- Quiet Observatory — **0.08**: a dark, instrument-panel aesthetic with subtle telemetry motifs.

**Selected proposal: Precision Ops Console.**

- **Design movement:** Contemporary technical editorial, borrowing the hierarchy and legibility of incident-response runbooks rather than a generic neon “hacker” dashboard.
- **Core principles:** Evidence first; scope and approval state always visible; dense information with clear hierarchy; intrusive actions visually distinct and gated.
- **Color philosophy:** Warm near-white and ink provide calm reading surfaces; deep navy anchors navigation; a restrained copper accent identifies review/approval; red and amber are reserved for explicit severity and blocked/pending states, not decoration.
- **Layout paradigm:** A left-aligned persistent navigation rail, compact context header, and vertically stacked work panels that prioritize assessment state over decorative dashboard grids.
- **Signature elements:** Hash-chain/audit markers beside consequential events; scope boundary chips on targets; source/evidence badges distinct from AI-inference labels.
- **Interaction philosophy:** Clear state transitions, explicit confirmation for gated actions, no hidden execution; show why an action is blocked and the policy condition it failed.
- **Animation:** Minimal 120–180 ms transitions for navigation and status changes; no looping or flashing indicators; respect reduced-motion preference.
- **Typography system:** Inter for interface text and IBM Plex Mono for identifiers, hashes, addresses, and evidence excerpts; restrained hierarchy with readable body copy.
- **Brand essence:** A controlled assessment workspace for security analysts, distinguished by verifiable scope, evidence provenance, and approval gates; **precise, candid, accountable**.
- **Brand voice:** Direct and evidence-oriented. Example lines: “Assessment is scoped to approved lab assets.” “This action needs recorded approval before it can run.”
- **Wordmark & logo:** A proposed compact boundary/ledger glyph formed from a framed bracket and three linked audit ticks beside a custom wordmark; no decorative target reticle or skull imagery.
- **Signature brand color:** Deep ink-navy with a narrow copper line used for scope and approval emphasis.

## Safety constraints carried forward

Prompt 0's R1–R15 remain binding. In particular, approval never overrides scope; the backend alone may use the separate egress network; public destinations remain blocked by default; the runner can only receive validated targets and allowlisted argument values; secrets must never enter logs, reports, or source control; and untrusted tool output must never be treated as instructions. Prompt 1 builds scanner components but does not authorize running scans during implementation or exposing the runner to the frontend.
