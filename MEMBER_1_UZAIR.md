# AI VAPT Agent — Member 1: Uzair
## Scanner Adapters, Importers & Correlation Pipeline

> **Assigned Member:** Uzair  
> **Prerequisites Completed by Lead:** Prompts 0 (Rules & Architecture), 1 (Monorepo & Lab Scaffold), 2 (Data Layer & Finding Schemas), and 3 (Deterministic Scope Engine).  
> **Your Prompts:** **Prompt 4**, **Prompt 5**, **Prompt 6**, and **Prompt 7**  
> **Primary Responsibility:** Data ingestion from all sources (live scanners, runner API, ZAP daemon, and commercial XML reports) into the unified finding schema, with deduplication and cross-tool correlation.

---

### Master Rules & Safety Contracts (Binding)

1. **Deterministic Scope Check First:** Never invoke a scanner or runner endpoint without passing through `require_scope()` or `check_action()`. Out-of-scope targets must be rejected and logged.
2. **Restricted Scanner API Only:** Never use `shell=True`, string-built commands, or `docker exec`. Call the scanner-runner API with structured argument arrays.
3. **Honest Integration Labels:** Nmap, Nikto, and ZAP are **Live** (via runner/API). Nessus, OpenVAS, and Burp are **Import-only**. Never present an imported file as a live scan.
4. **Provenance & Evidence Integrity:** Every finding and raw observation must preserve `tool`, `tool_run_id`, locator/raw_ref, timestamp, and whether evidence is `observed` or `inference`. Never fabricate CVEs, CWEs, or scanner outputs.
5. **Untrusted Input Protection:** All XML parsing must use `defusedxml` to prevent XXE. Validate schemas and sanitize inputs before saving.

---

## 1. Prompt 4: Adapter Framework + Nmap (Live)

### Objectives
- Create the abstract base adapter class `ToolAdapter` in `backend/app/adapters/base.py`.
- Implement `NmapAdapter` in `backend/app/adapters/nmap.py` communicating with the scanner-runner service (never `docker exec`).
- Provide live Nmap execution against lab targets (Juice Shop / DVWA), parse XML results using `defusedxml` into Assets, Services, and Observations.
- Expose tool run status and streaming progress over Server-Sent Events (SSE).

### Key Files to Create / Modify
- `backend/app/adapters/__init__.py`
- `backend/app/adapters/base.py`:
  - Abstract class `ToolAdapter`: `name`, `mode` (`live` | `import`), `capabilities`, `check_availability()`.
  - `async run(request) -> ToolRun`: enforces scope check first via `require_scope()`, rate limiting, raw output persistence via `RawOutputStore`, audit logging, and error handling (failures become `ToolRun` with `status="failed"`, never unhandled crashes).
  - `parse(raw_output: bytes) -> list[RawObservation]`: pure function, testable offline with fixture XMLs.
- `backend/app/adapters/nmap.py`:
  - Call scanner-runner HTTP API (`POST /run/nmap`) using `RUNNER_TOKEN`.
  - Scan profiles: `host_discovery`, `service_scan` (`-sV -sT -Pn`), `targeted_scripts` (`--script default,safe`).
  - NSE category allowlist: only `default`, `safe`, `discovery`, `version`. Reject `brute`, `dos`, `intrusive`, `exploit`, `vuln` by default.
  - Parse `-oX` XML into `Asset`, `Service` (port, protocol, service name, version, banner), and observations.
- `backend/app/api/tool_runs.py`:
  - `GET /assessments/{id}/tool-runs`: list tool runs with status and duration.
  - `GET /assessments/{id}/events`: SSE stream emitting real-time status transitions (`queued`, `running`, `succeeded`, `failed`, `timeout`).
- `backend/tests/test_nmap_adapter.py`:
  - Unit tests with recorded Nmap XML fixtures in `backend/tests/fixtures/nmap_sample.xml`.
  - Test scope rejection, rate-limit check, XML parsing into assets/services, and timeout handling.

### Done When
1. A live Nmap run against a lab target creates `Asset` and `Service` rows in SQLite.
2. The run appears in `GET /assessments/{id}/tool-runs` with stored and hashed raw XML in `data/raw/`.
3. A forced timeout is recorded as `ToolRun(status="timeout")` without crashing the service.
4. Run: `cd backend && pytest -q tests/test_nmap_adapter.py` passes.

---

## 2. Prompt 5: Nikto (Live) and OWASP ZAP (Live)

### Objectives
- Implement `NiktoAdapter` in `backend/app/adapters/nikto.py` calling scanner-runner API for web server misconfigurations.
- Implement `ZapAdapter` in `backend/app/adapters/zap.py` calling the OWASP ZAP REST API for web application vulnerabilities.
- Default to **Passive Scanning**. Keep Active Scan gated (`ENABLE_ZAP_ACTIVE_SCAN=false`) until human approval.

### Key Files to Create / Modify
- `backend/app/adapters/nikto.py`:
  - Call runner `POST /run/nikto` against in-scope URLs with time limit.
  - Parse JSON/XML output into `RawObservation` with file + item locator.
  - Map OSVDB and CVE references only when present in scanner output.
- `backend/app/adapters/zap.py`:
  - Communicate with `ZAP_URL` using `ZAP_API_KEY`.
  - Create ZAP context restricted to authorized target URL scope.
  - Trigger ZAP spider (or AJAX spider for single-page apps like Juice Shop).
  - Wait for passive scan queue to drain (`/JSON/pscan/view/recordsToScan/`).
  - Query alerts via `/JSON/core/view/alerts/` and map to `RawObservation` (`name`, `risk`, `confidence`, `cweid`, `wascid`, `url`, `param`, `evidence`, `solution`, `reference`).
  - Carry forward ZAP's confidence ratings (`High`, `Medium`, `Low`, `Informational`).
- `backend/tests/test_nikto_adapter.py` and `backend/tests/test_zap_adapter.py`:
  - Offline parser tests using recorded fixtures in `backend/tests/fixtures/`.
  - Scope rejection and active-scan gate verification tests.

### Done When
1. Nikto and ZAP passive scans complete against lab targets (Juice Shop or DVWA).
2. Statuses stream live to `/assessments/{id}/events`.
3. Raw JSON/XML responses are saved to `RawOutputStore`, hashed, and linked to observations.
4. Active scan remains disabled if attempted without explicit approval.
5. Run: `cd backend && pytest -q tests/test_nikto_adapter.py tests/test_zap_adapter.py` passes.

---

## 3. Prompt 6: Importers (Nessus, OpenVAS, Burp — Import-Only)

### Objectives
- Implement secure XML import parsers for `.nessus`, OpenVAS/Greenbone XML, and Burp Suite XML issues export.
- Label all imported findings and tool runs strictly as **Import-only** across models, API, and audit trail.
- Enforce strict size limits, XXE protection via `defusedxml`, and scope check on imported target IPs/hosts.

### Key Files to Create / Modify
- `backend/app/importers/__init__.py`
- `backend/app/importers/base.py`:
  - Base importer verifying file extension, max file size (e.g. 50 MB), and recording a `ToolRun(mode="import", source_filename=..., sha256=...)`.
- `backend/app/importers/nessus.py`:
  - Parse `.nessus` XML v2: extract `ReportHost` and `ReportItem` (`pluginID`, `pluginName`, `severity`, `port`, `protocol`, `svc_name`, `cve`, `cvss_base_score`, `cvss3_vector`, `plugin_output`, `solution`).
- `backend/app/importers/openvas.py`:
  - Parse Greenbone/OpenVAS XML report: extract `result` (`nvt oid`, `name`, `threat`, `severity`, `qod`, `host`, `port`, `cve`, `description`, `solution`).
- `backend/app/importers/burp.py`:
  - Parse Burp Suite XML issues export: `issue type`, `name`, `severity`, `confidence`, `host`, `path`, `location`, `issueDetail`, `remediationDetail`, request/response snippets.
- `backend/app/api/imports.py`:
  - `POST /assessments/{id}/imports`: multipart file upload endpoint accepting `.nessus`, `.xml`.
  - Validate that imported hosts fall inside the registered assessment scope.
  - Out-of-scope hosts must be skipped and logged in `AuditEvent` (never silently dropped).
- `lab/samples/`:
  - Provide safe, synthetic sample files: `sample.nessus`, `sample_openvas.xml`, `sample_burp.xml`.
- `backend/tests/test_importers.py`:
  - Test all 3 importers with fixtures; test XXE rejection; test out-of-scope host skipping and audit logging.

### Done When
1. Uploading all three sample files produces valid raw observations tied to stored raw files.
2. Hosts outside the assessment scope are skipped, and the skipped host count is recorded in the audit log.
3. Every imported record has `mode="import"` clearly marked.
4. Run: `cd backend && pytest -q tests/test_importers.py` passes.

---

## 4. Prompt 7: Normalization, De-duplication & Correlation

### Objectives
- Build `backend/app/pipeline/normalize.py` to map raw observations into the common `Finding` schema.
- Build `backend/app/pipeline/correlate.py` to deduplicate and correlate findings across multiple scanners.
- Corroborate multi-tool findings (e.g., Nmap + Nessus finding the same vulnerability increases confidence).
- Implement rule-based, explainable false-positive heuristics (never delete findings; mark as `likely_false_positive`).

### Key Files to Create / Modify
- `backend/app/pipeline/__init__.py`
- `backend/app/pipeline/normalize.py`:
  - Convert `RawObservation` to `FindingCreate`.
  - Map scanner severities to canonical scale: `info`, `low`, `medium`, `high`, `critical`.
  - Validate CVE (`CVE-\d{4}-\d{4,7}`) and CWE (`CWE-\d+`) regex patterns. Only extract CVE/CWE if explicitly present in source raw data.
- `backend/app/pipeline/correlate.py`:
  - **Deduplication Key:** Same asset AND same port/endpoint AND (same CVE OR same CWE with same URL/parameter OR title similarity threshold on same service).
  - Merged findings keep **ALL** source tools in `source_tools[]`, all `raw_refs[]`, and all `evidence[]` entries.
  - Never merge across different assets or endpoints; link related issues using `related_to[]`.
  - **Corroboration Logic:** Findings seen by 2+ independent tools gain higher confidence score and confidence reason citing multi-tool corroboration.
  - **Version & Banner Consistency:** Correlate Nmap service versions with vulnerability findings. If banners contradict scanner claims, flag with lower confidence.
  - **Explainable False-Positive Heuristics:** E.g., missing security header on purely static asset, or banner mismatch on backported Linux distribution. Set status to `likely_false_positive` with an explainable reason.
- `backend/tests/test_pipeline.py`:
  - Test normalizing raw observations into common findings.
  - Test merging findings from Nmap + Nessus + OpenVAS on the same host: produces 1 finding with 3 sources and 3 evidence entries.
  - Test that the same vulnerability on 2 different hosts remains 2 separate findings.

### Done When
1. A test demonstrates 3 independent scanner outputs merging into 1 unified finding with complete provenance.
2. Same-named vulnerabilities on separate targets remain separate records with `related_to` links.
3. False-positive candidates are marked without data loss.
4. Run: `cd backend && pytest -q tests/test_pipeline.py` passes.

---

### Verification Commands for Uzair
```powershell
cd backend
# Run all your adapter, importer, and pipeline tests
.\.venv\Scripts\pytest -q tests/test_nmap_adapter.py tests/test_nikto_adapter.py tests/test_zap_adapter.py tests/test_importers.py tests/test_pipeline.py

# Format and lint your code
.\.venv\Scripts\ruff.exe check app tests
.\.venv\Scripts\ruff.exe format app tests
```
