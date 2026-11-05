# AI VAPT Agent — Member 2: Affan
## Risk Prioritization, AI Agent Orchestration & Human Approval Gate

> **Assigned Member:** Affan  
> **Prerequisites Completed by Lead:** Prompts 0 (Rules & Architecture), 1 (Monorepo & Lab Scaffold), 2 (Data Layer & Finding Schemas), and 3 (Deterministic Scope Engine).  
> **Depends On Member 1 (Uzair):** Ingested findings from Prompts 4–7.  
> **Your Prompts:** **Prompt 8**, **Prompt 9**, and **Prompt 10**  
> **Primary Responsibility:** The intelligence, reasoning, and offensive safety core of the VAPT Agent (worth 35 hackathon judge points).

---

### Master Rules & Safety Contracts (Binding)

1. **Deterministic Risk Scoring:** The LLM may explain risk scores in natural language, but code must compute them mathematically from stored fields. Never let the LLM generate or override numbers.
2. **Narrow LLM Tool Calling:** The LLM must **NEVER** have unrestricted shell access, Python execution, Docker control, or raw socket capabilities. It can only call predefined, typed application tools. Every tool checks scope and writes an audit event.
3. **No Autonomous Exploitation:** Active exploitation, intrusive validation, and destructive scans **NEVER** run automatically. They must enter `pending_approval` state and require recorded human approval.
4. **Grounding & Provenance:** Every claim the AI makes must cite finding/evidence IDs. Observed facts and AI inference must be kept visibly separate.
5. **Untrusted Input Defense:** Wrap target content and scanner output as untrusted; never execute instructions or prompts found inside target data.

---

## 1. Prompt 8: Risk Prioritization (Requirement 5.6)

### Objectives
- Build a deterministic, explainable risk calculation engine in `backend/app/pipeline/risk.py`.
- Calculate composite risk scores (0–100) and priority bands (`P1 Critical`, `P2 High`, `P3 Medium`, `P4 Low`, `P5 Info`).
- Store the breakdown breakdown JSON (`risk_breakdown`) and a plain-English explanation (`risk_rationale`).
- Support analyst asset criticality adjustment and re-ranking.

### Mathematical Formula & Inputs
```text
Risk Score (0-100) = weighted_combination(
    CVSS base score (if present; otherwise default based on tool severity),
    Exposure factor (internet-facing, open port, unauthenticated service),
    Exploitability factor (known public exploit / POC, trivially reachable),
    Asset criticality (set by analyst: Critical=1.5, High=1.2, Medium=1.0, Low=0.7),
    Confidence score (0.0 to 1.0 from correlation step)
)
```
- If no CVSS was provided by scanner/reference file, keep `cvss_score = None` and label as `"not scored by source"`.
- Lower the ranking of unverified/suspected findings, but flag them for human review instead of hiding them.

### Key Files to Create / Modify
- `backend/app/pipeline/risk.py`:
  - `calculate_risk(finding: FindingRead, asset: AssetRead) -> RiskAssessment`: returns `score`, `band`, `breakdown: dict`, and `rationale: str`.
  - `recalculate_assessment_risks(session: Session, assessment_id: str)`: updates all findings in batch when asset criticality changes.
- `backend/app/api/findings.py`:
  - `GET /assessments/{id}/findings`: query findings with sorting (`sort=risk`, `sort=severity`, `sort=first_seen`) and filters (`severity`, `status`, `asset_id`, `tool`).
  - `GET /assessments/{id}/findings/summary`: returns severity distribution counts and risk band aggregations.
- `backend/tests/test_risk_engine.py`:
  - Prove finding without CVSS keeps `cvss_score = None`.
  - Prove same vulnerability on a Critical asset ranks higher than on a Low asset.
  - Prove score is 100% reproducible from its stored JSON breakdown.

### Done When
1. Every finding in the database has a calculated `risk_score`, `risk_band`, `risk_breakdown`, and `risk_rationale`.
2. Changing an asset's criticality dynamically re-ranks the findings list deterministically.
3. Run: `cd backend && pytest -q tests/test_risk_engine.py` passes.

---

## 2. Prompt 9: The AI Agent: Planner, Orchestrator & Reasoning (Core)

### Objectives
- Build the core AI reasoning and planning loop in `backend/app/agent/`.
- Implement a provider-neutral `LLMClient` with a mock provider for tests, supporting OpenAI-compatible APIs, Anthropic, or Ollama via `LLM_PROVIDER`, `LLM_MODEL`, and `LLM_API_KEY`.
- Provide typed agent tools (narrow wrappers that enforce scope and log audit rows).
- Execute the reasoning loop: **Plan → Human Approve → Execute → Observe → Reason → Re-plan**.
- Defend against prompt injection in scanner output and hallucinations.

### Agent Architecture
1. **Provider-Neutral Interface (`backend/app/agent/client.py`)**:
   - `LLMClient.complete(messages: list[ChatMessage], tools: list[ToolDefinition]) -> AgentResponse`
   - Implementations: `OpenAICompatibleClient`, `MockLLMClient` (replays canned responses for deterministic offline pytest runs).
2. **Narrow Agent Tools (`backend/app/agent/tools.py`)**:
   - `list_scope(assessment_id)`
   - `get_assets(assessment_id)`
   - `get_services(assessment_id, asset_id)`
   - `get_findings(assessment_id, filter)`
   - `get_tool_status(assessment_id)`
   - `propose_plan(assessment_id, steps: list[PlanStep])`
   - `run_nmap(assessment_id, target, profile)`
   - `run_nikto(assessment_id, url)`
   - `run_zap(assessment_id, url, mode)`
   - `request_validation(assessment_id, finding_id, method, justification)`
   - `update_finding(assessment_id, finding_id, status, confidence, inference_text)`
   - `generate_report(assessment_id)`
   - *Rule:* The LLM never touches the shell or network directly.
3. **Reasoning & State Management (`backend/app/agent/orchestrator.py`)**:
   - Maintain `AssessmentState`: completed steps, active targets, technologies detected, open questions, hypotheses.
   - Dedup Guard: reject running the identical `(tool, target, params)` twice unless a new technical justification is provided. Track avoided repeats.
   - Stop Conditions: budget reached, scope exhausted, or no new information gained.
4. **Grounding & Guardrails**:
   - System prompt instructs model: only cite facts from retrieved evidence IDs; label assertions as **OBSERVED** (with raw locator) or **INFERENCE** (with reasoning).
   - Post-validator: strip any CVE or CWE mentioned by the model that does not exist in the database for that finding.
   - Wrap scanner output in `<untrusted_scanner_output>` tags to mitigate prompt injection.
5. **SSE Event Streaming (`backend/app/api/agent.py`)**:
   - Stream events: `plan_created`, `step_started`, `step_progress`, `step_finished`, `step_failed`, `reasoning_note`, `awaiting_approval`, `stopped`.

### Key Files to Create / Modify
- `backend/app/agent/__init__.py`
- `backend/app/agent/client.py`: provider-neutral interface & mock provider.
- `backend/app/agent/prompts.py`: system prompt, security personas, few-shot examples.
- `backend/app/agent/tools.py`: tool definitions and execution dispatchers.
- `backend/app/agent/orchestrator.py`: plan-execute-observe-replan state machine.
- `backend/app/agent/validation.py`: anti-hallucination and prompt-injection validators.
- `backend/app/api/agent.py`: `POST /assessments/{id}/chat`, `POST /assessments/{id}/plan/approve`, `GET /assessments/{id}/agent/stream`.
- `backend/tests/test_agent.py`: offline unit and integration tests using `MockLLMClient`.

### Done When
1. Given a user goal, the agent outputs a structured plan with rationales for each step.
2. Steps execute only after approval; agent observes Nmap output and dynamically proposes a tailored next step (e.g. ZAP for HTTP).
3. The duplicate step guard prevents redundant scans and increments `avoided_repeats`.
4. Run: `cd backend && pytest -q tests/test_agent.py` passes.

---

## 3. Prompt 10: Human-in-the-Loop Approval Gate + Metasploit (Requirement 5.7)

### Objectives
- Implement the human-in-the-loop approval workflow in `backend/app/approvals/`.
- Ensure any intrusive action (`active_validation`, Metasploit, intrusive ZAP active scans) cannot run without a single-use, time-bounded approval token.
- Build a controlled, lab-only Metasploit check module adapter or safe POC verification fallback.
- Enforce the approval gate in code (in the adapter), not merely in the frontend UI.

### Approval Security Rules
1. **Mandatory Approval Gate:** Any action with `action_class="active_validation"` is stored as `pending_approval`. The orchestrator cannot run it until an authorized human approval record exists.
2. **Single-Use & Time-Bounded:** Approvals expire (e.g. 15 minutes) and are single-use. Any change to target, tool, or parameters invalidates the approval token.
3. **Approval Never Overrides Scope:** Scope is revalidated immediately at execution time; an approved action on an out-of-scope target is still rejected.
4. **Outcome Tracking:** If validation succeeds → finding marked `confirmed` with evidence. If validation fails → finding remains `suspected` (never mark false-positive solely because validation failed).

### Key Files to Create / Modify
- `backend/app/approvals/__init__.py`
- `backend/app/approvals/service.py`:
  - `create_approval_request(assessment_id, finding_id, tool, params, justification, risk)`
  - `decide_approval(approval_id, decision: "approve" | "reject", reason, approver_user)`
  - `verify_approval_token(token_id, expected_tool, expected_target, expected_params)`
- `backend/app/adapters/metasploit.py`:
  - Controlled RPC connection to `msfrpcd` in the isolated lab network.
  - Require `ENABLE_ACTIVE_VALIDATION=true` and valid human approval token.
  - Use `check` command where available rather than exploit payloads.
  - If Metasploit is not deployed in your local test environment, provide a safe verification fallback (e.g. banner verification or specific HTTP payload test) and keep Metasploit as "Planned" in the integration matrix.
- `backend/app/api/approvals.py`:
  - `GET /assessments/{id}/approvals`: list pending and decided approval requests.
  - `POST /approvals/{id}/decision`: record human decision (approve/reject) with reason.
- `backend/tests/test_approvals.py`:
  - Test that an unapproved validation is rejected.
  - Test that modifying parameters invalidates an approval.
  - Test that an expired approval is rejected.
  - Test that an out-of-scope target is blocked even if approved.

### Done When
1. When the agent proposes active validation, it enters `pending_approval` state.
2. Nothing executes until `POST /approvals/{id}/decision` records an approval.
3. The approval record and scan outcome are permanently recorded in the hash-chained audit log.
4. Run: `cd backend && pytest -q tests/test_approvals.py` passes.

---

### Verification Commands for Affan
```powershell
cd backend
# Run your risk engine, agent reasoning, and approval gate tests
.\.venv\Scripts\pytest -q tests/test_risk_engine.py tests/test_agent.py tests/test_approvals.py

# Format and lint your code
.\.venv\Scripts\ruff.exe check app tests
.\.venv\Scripts\ruff.exe format app tests
```
