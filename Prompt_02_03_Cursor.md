# AI VAPT Agent: Prompts 2 and 3 (for Cursor)

Use Cursor **Agent mode**. Save Prompt 0 as `.cursor/rules/vapt.mdc` (Always apply) or `CLAUDE.md` first, and finish Prompt 1 before starting here. Run one prompt per chat and commit after each.

---

## Prompt 2: Data model and Finding schema

```text
Read the project rules first (CLAUDE.md / .cursor/rules). Then implement the data layer in backend/. Work in the steps below and stop after step 6 to show me the results.

FILES TO CREATE
- backend/app/db.py: SQLAlchemy 2.0 engine/session, SQLite in WAL mode (PRAGMA journal_mode=WAL, foreign_keys=ON), get_session dependency.
- backend/app/models/orm.py: SQLAlchemy models.
- backend/app/models/schemas.py: Pydantic v2 schemas (separate Create/Read models).
- backend/app/repo/: repository functions (one module per entity group). Routers must never touch the ORM directly.
- backend/tests/test_models.py

STEP 1: ORM tables
Assessment, ScopeRule, Plan, PlanStep, ToolRun, Asset, Service, Finding, Evidence, Approval, AuditEvent, Decision, Report, ChatMessage. Use UUID or prefixed string primary keys, created_at on everything, and foreign keys to assessment_id.

STEP 2: Finding fields (most important)
- id (FND-0001 style, unique per assessment), assessment_id
- title, description, category (owasp_top10 | misconfig | outdated_software | exposure | other)
- asset_id, port, protocol, service, url, parameter (nullable)
- source_tools (list), raw_refs (list of {tool_run_id, locator})
- cve_ids, cwe_ids (lists; only from tool output or a reference file)
- cvss_vector, cvss_score (nullable; copied from a source, never invented), tool_severity
- confidence (high|medium|low) + confidence_score (0 to 1) + confidence_reason
- status: confirmed | suspected | likely_false_positive | false_positive | accepted_risk
- validation_status: not_validated | pending_approval | approved | validated | failed | rejected
- risk_score (nullable), risk_band (nullable), risk_breakdown (JSON), risk_rationale (text)
- first_seen, last_seen, related_to (list of finding ids)

STEP 3: Evidence
Evidence(id, finding_id, type: observed | inference, content, raw_ref, timestamp). A finding can have many. Observed and inference must never be merged into one field.

STEP 4: ToolRun
tool, mode (live|import), args (JSON array, never a shell string), status (queued|running|succeeded|failed|timeout|skipped|cancelled), started_at, finished_at, error, raw_output_path, sha256, source_filename (for imports).

STEP 5: AuditEvent
id, assessment_id, seq (auto-increment per assessment), timestamp, actor (user|agent|scope-engine|system), event_type, detail (JSON), outcome, prev_hash, hash. Add a repo function append_audit_event() that computes hash = sha256(prev_hash + canonical JSON of the event) and a verify_chain(assessment_id) function. No update or delete functions for audit events.

STEP 6: Tests (pytest)
- Create an assessment and a finding with two evidence rows (one observed, one inference), read them back, check every field.
- A finding with no CVSS source keeps cvss_score = None.
- Audit chain verifies; altering one row makes verify_chain fail.
- Seed fixture in backend/tests/fixtures.py.

RULES: type hints everywhere, docstrings on public functions, no business logic in models, do not add an LLM or any scanning code.

Run: cd backend && pytest -q
When done, list the files you created and the exact commands to verify.
```

**Done when:** `pytest -q` passes, and the audit-chain tamper test fails verification as expected.

---

## Prompt 3: Scope engine

```text
Read the project rules first. Prompt 2 (data model) is done. Build the deterministic scope engine in backend/app/scope/. No LLM. Work in the steps below and stop after step 7 to show me the test results.

FILES
- backend/app/scope/models.py: ScopeRules, Decision (allowed|denied, reason, rule_id)
- backend/app/scope/engine.py: register_scope, check_action
- backend/app/scope/sanitize.py: args sanitiser
- backend/app/api/scope.py: FastAPI router
- backend/tests/test_scope.py

STEP 1: Scope rules per assessment
allowed targets (IPs, CIDRs, hostnames, URLs), exclusions, allowed tools, allowed action classes (discovery | vuln_scan | web_scan | active_validation), rate limit, time window, notes. Store via the repo layer.

STEP 2: register_scope(assessment_id, rules)
Validate and REJECT: public IPs/CIDRs not inside LAB_CIDR (unless ALLOW_PUBLIC_TARGETS=true), 0.0.0.0/0 and overly broad ranges (e.g. larger than /16), invalid input. Return clear error reasons.

STEP 3: check_action(assessment_id, tool, target, action_class, args) -> Decision
- Exclusions always win over allows.
- Resolve hostnames to IPs and check the resolved IP too. Check every IP returned.
- Block by default: loopback, link-local, multicast, reserved, and cloud-metadata ranges (e.g. 169.254.169.254).
- For URLs: allow only http/https; re-check the host; cap URL length.
- Support IPv4 and IPv6, CIDR overlap, and the time window and rate limit.
- Check tool allowlist and action-class allowlist.
- Provide a revalidate_at_execution() helper that re-resolves DNS and re-checks, to defend against DNS rebinding and redirects.

STEP 4: Args sanitiser
Build commands only from an allowlist of flags as argument lists (list[str]). No shell=True, no string-built commands, no user-supplied raw flags. For Nmap allow only: -sV, -sT, -Pn, -p <ports>, --top-ports <n>, -T2/-T3, -oX, and the NSE categories default, safe, discovery, version. Reject brute, dos, intrusive, exploit, fuzzer and the vuln category by default.

STEP 5: Audit
Every check_action call appends an AuditEvent (allowed or denied) through the repo function from Prompt 2.

STEP 6: Enforcement
Add a base guard function require_scope(...) that any tool runner MUST call before running. Write a test that proves a tool cannot run without it.

STEP 7: API
POST /assessments, POST /assessments/{id}/scope, GET /assessments/{id}/scope, POST /assessments/{id}/scope/check (for the UI and tests).

TESTS (pytest, no network needed; mock DNS)
in-scope IP, out-of-scope IP, excluded host inside an allowed CIDR, public IP rejected at registration, hostname resolving outside scope, metadata IP 169.254.169.254, disallowed action class, disallowed tool, unsafe Nmap flag rejected, URL redirect leaving scope, and every case writes an audit row.

RULES: deterministic code only, type hints, no LLM, no scanning code.

Run: cd backend && pytest -q tests/test_scope.py
When done, show the test output and the list of endpoints.
```

**Done when:** all the scope tests pass and every allow or deny shows up in the audit table.

---

## Cursor tips

- Run one prompt per chat and commit after each (`git commit -m "prompt 2 done"`).
- If Cursor produces too much at once, send: "Do only steps 1 to 3 first, then stop and show me how to verify."
- Do not connect the LLM until `test_scope.py` is fully green.
