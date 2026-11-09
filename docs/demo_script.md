# Hackathon Presentation Demo Script (5-Minute Walkthrough)

## Overview & Demo Goal
Showcase the **AI Unified VAPT Agent** as an autonomous, safety-first security assessment platform that eliminates scanner hallucinations, strictly respects network boundaries, correlates multi-tool evidence, enforces human-in-the-loop authorization, and generates client-ready PDF reports.

---

## 5-Minute Presentation Schedule

| Time | Segment | Key Talking Points & Actions |
|---|---|---|
| **0:00 - 0:45** | **Introduction & Scoping Setup** | Explain the challenge of AI in offensive security (uncontrolled scanning, hallucinations). Show assessment creation and strict CIDR boundary (`172.30.0.0/24`). |
| **0:45 - 1:30** | **WOW MOMENT 1: Out-of-Scope Rejection** | Attempt to scan an unauthorized target (`8.8.8.8` or out-of-scope IP). Show instant rejection by the deterministic scope engine with zero LLM bypass. |
| **1:30 - 2:30** | **WOW MOMENT 2: Agent Reasoning & Planning** | Prompt the agent: *"Assess web targets in the lab"*. Show structured plan proposal, tool badges, and reasoning notes. Demonstrate the **Dedup Guard** avoiding repeated scans. |
| **2:30 - 3:30** | **WOW MOMENT 3: Multi-Tool Correlation** | Ingest sample findings from Nmap and Nessus. Show automatic merging into a single correlated finding with distinct **OBSERVED EVIDENCE** vs **AI INFERENCE**. |
| **3:30 - 4:15** | **WOW MOMENT 4: Human-in-the-Loop Approval Gate** | Agent identifies an unconfirmed RCE and requests active verification with Metasploit. Show the system blocked in `pending_approval` state until analyst explicitly approves with 15-min single-use token. |
| **4:15 - 5:00** | **WOW MOMENT 5: Client-Ready PDF Report & Audit Integrity** | Click **"Generate Report"**. Show live HTML preview and download PDF. Highlight evidence locators and click **"Verify Cryptographic Chain"** showing 100% SHA-256 integrity. |

---

## Step-by-Step Execution Guide

### Step 1: Pre-Demo Setup
Run the demo seeding script to have realistic sample data ready if presenting offline:
```bash
python -m app.seed_demo
```
Or start the web workspace:
```bash
# Terminal 1: Backend
cd backend && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Frontend
cd frontend && npm run dev
```
Navigate to `http://localhost:5173`.

---

### Step 2: Live Action 1 — Out-of-Scope Defense
1. Open the **Scope Rules** view.
2. Demonstrate that the authorized target is `172.30.0.0/24`.
3. In the chat or API console, input:
   ```text
   Scan target 8.8.8.8 for open ports
   ```
4. **Point to Screen:** The agent's tool execution is intercepted and blocked:
   > *"Action rejected: resolved address is a public IP outside LAB_CIDR."*
5. Highlight to judges: *Safety is enforced mathematically at the code level, not left to LLM prompting.*

---

### Step 3: Live Action 2 — Agent Planning & Dedup Guard
1. In the chat, prompt:
   ```text
   Discover services on 172.30.0.10 and recommend next steps
   ```
2. Observe the center panel:
   - Step 1: Nmap service discovery proposed with technical rationale.
   - Step 2: Web DAST scan queued conditionally upon port 80/3000 detection.
3. Prompt again with the identical instruction:
   - Notice the **Avoided Repeats** counter increments. The duplicate scan is bypassed, saving bandwidth and avoiding target stress.

---

### Step 4: Live Action 3 — Multi-Tool Correlation & Distinct Evidence
1. Open the **Findings** tab.
2. Select finding **`[FND-0001] Apache Path Traversal and RCE`**.
3. Point out the evidence drawer:
   - **OBSERVED EVIDENCE:** Raw scanner snippet from `nmap_output.txt` at line 42 with cryptographic SHA-256 hash.
   - **AI INFERENCE:** Grounded impact assessment and remediation steps.
4. Explain to judges: *Every finding traces to raw tool bytes. Fabricated CVEs are filtered out by the anti-hallucination guardrail.*

---

### Step 5: Live Action 4 — Offensive Human Approval Gate
1. Point to the **Pending Approvals Queue**.
2. Show an active validation request for **`exploit/multi/http/apache_normalize_path_rce`** against `172.30.0.10`.
3. Explain to judges:
   - *Active exploitation is disabled by default.*
   - *Requires analyst sign-off with a 15-minute single-use cryptographic token.*
4. Click **Approve** and provide reason: *"Authorized lab validation test"*.
5. Show the controlled check module verify the finding safely without destructive payloads.

---

### Step 6: Live Action 5 — PDF Report & Cryptographic Audit Verification
1. Click **"Download PDF Report"** (or view HTML preview).
2. Showcase the 6 mandatory sections:
   - Executive Summary with risk score breakdown.
   - Severity Distribution table.
   - Detailed Findings with raw evidence locators and CVSS vectors.
   - Appendices with the truthful integration status matrix.
3. Open the **Audit Trail** tab:
   - Click **"Verify Cryptographic Chain"**.
   - Show the green verification banner: **"Cryptographic SHA-256 hash chain is verified intact from genesis."**
