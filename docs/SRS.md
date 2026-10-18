# AVPA — Software Requirements Specification (SRS)

**Full title:** CVE → LLM Exploit Pipeline: Software Requirements Specification
**Context:** Capstone Project for Bachelor of Science (B.Sc.) Degree, Faculty of Sciences, HIT — Holon Institute of Technology
**Authors:** Afik Haviv, Shir Molakandove, Kristina Asner

> This document specifies the **functional and non-functional requirements** of the system **as built**. Requirement codes (`FR-...`, `NFR-...`) are used throughout the codebase and in the Development Plan to cross-reference decisions back to this source. Refer to `INITIATION_DOCUMENT.md` for rationale and architectural context.

---

## 1. System Overview

The system accepts a CVE ID as input and produces a structured proof-of-concept (PoC) artifact set as output. The pipeline runs five sequential stages: CVE data fetch, vulnerability classification, LLM-based PoC generation, structural mock validation, and artifact persistence. An optional live-execution stage runs the PoC against an authorized lab target for two hand-verified CVEs.

---

## 2. Definitions

| Term | Definition |
|---|---|
| **CVE** | Common Vulnerabilities and Exposures — a standardized public vulnerability identifier and description. |
| **NVD** | National Vulnerability Database — the authoritative source of CVE metadata (CVSS scores, CWE IDs, CPEs). |
| **PoC** | Proof of Concept — a minimal script or page demonstrating that a vulnerability can be triggered. |
| **Classification** | The pipeline's categorization of a CVE into a vulnerability class (e.g. browser, network service) used to tailor the LLM prompt and mock runner. |
| **Mock Execution** | Structural validation of the generated PoC without executing code or touching a live target. |
| **Live Execution** | Real exploitation of a named lab target the operator explicitly owns or is authorized to test. |
| **Fernet Encryption** | Symmetric-key encryption scheme used to protect the plaintext `.env` secrets file at rest. |

---

## 3. Data Model

### 3.1 `CveInfo` (in-memory, from NVD)

| Field | Type | Source |
|---|---|---|
| `cve_id` | `str` | NVD `cve.id` |
| `description` | `str` | NVD English description |
| `cvss_score` | `float \| None` | Best available CVSS metric (v3.1 → v3.0 → v2) |
| `cvss_vector` | `str \| None` | CVSS vector string |
| `severity` | `str \| None` | Base severity label |
| `cwe_ids` | `list[str]` | All CWE IDs from the `weaknesses` block |
| `affected_products` | `list[str]` | CPE 2.3 strings from `configurations` |
| `references` | `list[str]` | Reference URLs |

### 3.2 `CveClassification` (in-memory, from classifier)

| Field | Type | Values |
|---|---|---|
| `category` | `str` | `"server-side"` \| `"client-side"` |
| `subtype` | `str` | `"network_service"` \| `"web_application"` \| `"browser"` \| `"document_or_file"` \| `"desktop_application"` \| `"unknown"` |
| `requires_user_interaction` | `bool` | From CVSS `UI` flag |
| `memory_corruption` | `bool` | CWE set or description keywords |
| `confidence` | `str` | `"high"` \| `"medium"` \| `"low"` |
| `rationale` | `list[str]` | Human-readable decision reasons |
| `product_hint` | `str \| None` | First human-readable CPE product name |

### 3.3 `LlmArtifacts` (in-memory, from LLM)

| Field | Type | Description |
|---|---|---|
| `prompt` | `str` | The user-facing portion of the generation prompt (saved to `prompt.txt`) |
| `filetype` | `str` | `"python"` \| `"msf_rc"` \| `"html"` — extracted from the `# FILETYPE:` prefix |
| `code` | `str` | The generated PoC code (saved to `exploit.<ext>`) |
| `breakdown_markdown` | `str` | Payload breakdown section from the explanation prompt |
| `execution_guide_markdown` | `str` | Execution guide section from the explanation prompt |

### 3.4 `MockExecutionResult` (in-memory + persisted)

| Field | Type | Description |
|---|---|---|
| `cve_id` | `str` | CVE identifier |
| `success` | `bool` | True when a threshold of structural checks pass |
| `checks` | `list[dict]` | Per-criterion `{label, passed}` entries |
| `transcript` | `list[str]` | Narrated simulation log lines |
| `mode` | `str` | Runner mode identifier (e.g. `"exact-match"`, `"generic-server-network"`) |
| `notes` | `str` | Explanation of simulation limitations or scope |

### 3.5 `RunResult` (live execution, persisted)

| Field | Type | Description |
|---|---|---|
| `cve_id` | `str` | CVE identifier |
| `target` | `str` | Resolved target IP address |
| `success` | `bool` | True when evidence of exploitation is observed |
| `transcript` | `list[str]` | Step-by-step execution log |
| `evidence` | `str` | Command output or error text confirming the result |

### 3.6 Persisted Artifacts (`output/<CVE-ID>/`)

| File | Content |
|---|---|
| `exploit.py` / `exploit.rc` / `exploit.html` | Generated PoC (extension from `filetype`) |
| `breakdown.md` | Payload breakdown Markdown |
| `execution_guide.md` | Execution guide Markdown |
| `prompt.txt` | The user-facing generation prompt |
| `classification.json` | `CveClassification` as JSON |
| `mock_execution_report.json` | `MockExecutionResult` as JSON |
| `live_execution_report.json` | `RunResult` as JSON (written only after a live run) |

---

## 4. Functional Requirements

### 4.1 CVE Data Fetching

- **FR-CVE-01.1 (NVD Fetch):** The system must query `https://services.nvd.nist.gov/rest/json/cves/2.0` with the provided CVE ID as the `cveId` parameter. The optional `NVD_API_KEY` setting must be sent as an `apiKey` header when present.
- **FR-CVE-01.2 (CVE Not Found):** When the NVD response contains an empty `vulnerabilities` array, the system must raise a `ValueError` with a message identifying the CVE ID. This must surface as a `502` response from the `/api/run` endpoint with an `{"error": "<message>"}` body.
- **FR-CVE-01.3 (CVSS Priority):** CVSS metrics must be selected in version priority order: v3.1 → v3.0 → v2. The `cvss_score`, `cvss_vector`, and `severity` fields must reflect the highest-priority available version.
- **FR-CVE-01.4 (Prompt Context):** `CveInfo.as_prompt_context()` must return a formatted multi-line string containing all seven fields (CVE ID, description, CVSS score/severity, CVSS vector, CWE IDs, up to 8 affected product CPEs, up to 5 reference URLs).

### 4.2 CVE Classification

- **FR-CLS-01.1 (Category Assignment):** The classifier must assign every CVE to either `"server-side"` or `"client-side"` based on the combined signal from: CVSS `AV`/`UI` flags, CWE membership in defined sets, description keyword matching, and CPE product name matching.
- **FR-CLS-01.2 (Subtype Assignment):** Within each category the classifier must assign one of the defined subtypes. The priority order must be: browser → document/file → web application → desktop application → network service → unknown.
- **FR-CLS-01.3 (Confidence Levels):** Confidence must be `"high"` when a recognized browser/document/web-app product or CWE is matched, `"medium"` when only the CVSS `AV` flag is used, and `"low"` otherwise.
- **FR-CLS-01.4 (Rationale):** The classifier must append at least one human-readable rationale string for every classification decision.
- **FR-CLS-01.5 (Memory Corruption Flag):** `memory_corruption` must be `True` when any of the defined memory-safety CWEs are present in the CVE or when any of the defined memory-safety description keywords appear in the description.

### 4.3 LLM Generation

- **FR-LLM-01.1 (Lab-Only System Instruction):** Every generation request must include the `LAB_ONLY_RULES` block as the system message. This block must instruct the model to target only lab placeholder values, avoid suggestions for scanning live systems, stay within the documented CVE capabilities, and stub out any real post-exploitation payload stage with a commented placeholder.
- **FR-LLM-01.2 (Classification-Specific Phase Guidance):** The generation system prompt must include phase guidance tailored to the assigned subtype. Each subtype (browser, document/file, web application, network service/unknown) must have a distinct guidance block specifying required phases, expected output structure, and `FILETYPE` declaration.
- **FR-LLM-01.3 (FILETYPE Marker):** The model must be instructed to begin its response with exactly one of the valid `# FILETYPE: <type>` lines. The parser must extract this marker from the first line of the response and use it to determine the artifact file extension.
- **FR-LLM-01.4 (Two-Prompt Chain):** Generation must use exactly two sequential chat requests: (1) a generate request producing the PoC code, (2) a breakdown request that receives the generated code and returns a Markdown document with a `## Payload Breakdown` section and a `## Execution Guide` section.
- **FR-LLM-01.5 (Breakdown Splitting):** The parser must split the explanation response at the `## Execution Guide` marker. Content before the marker becomes `breakdown_markdown`; content from the marker onward becomes `execution_guide_markdown`. When the marker is absent, the full response is assigned to `breakdown_markdown` and `execution_guide_markdown` is empty.
- **FR-LLM-01.6 (Code Block Extraction):** When the response contains triple-backtick fences, the parser must extract the content of the first fenced block. An optional language tag on the opening fence line must be stripped.
- **FR-LLM-01.7 (Temperature):** All LLM requests must use `temperature=0.2` to reduce response variance across runs.

### 4.4 Mock Execution

- **FR-MOCK-01.1 (Exact-Match Runners):** CVE-2011-2523 and CVE-2017-0144 must use hand-built exact-match runners that check for specific technical markers in the generated PoC and play back canned execution transcripts.
- **FR-MOCK-01.2 (Generic Dispatch):** All other CVEs must be routed to a generic simulation flow based on `classification.subtype`. Defined flows: browser, document/file, web application, network service. CVEs with `subtype == "unknown"` or an unrecognized subtype must fall back to a best-effort structural check.
- **FR-MOCK-01.3 (Success Threshold):** Each generic flow must define a minimum number of passed checks required to set `success=True`. A failed threshold must still produce a complete transcript and notes; it must not raise an exception.
- **FR-MOCK-01.4 (Mode Label):** Every `MockExecutionResult` must carry a `mode` string identifying which runner produced it.
- **FR-MOCK-01.5 (Notes):** Every generic flow must include a `notes` string explaining the limitations of the simulation and what a real execution attempt would require.
- **FR-MOCK-01.6 (No Code Execution):** The mock runner must never execute the generated PoC code or make any network connection. It must only inspect the PoC as a string.

### 4.5 Pipeline Orchestration

- **FR-PIPE-01.1 (Stage Sequence):** The pipeline must execute stages in this fixed order: Fetch CVE → Classify CVE → Generate & Explain Payload (LLM) → Mock Execute (Simulated Target) → Save Artifacts.
- **FR-PIPE-01.2 (Stage Timing):** Each stage must record its wall-clock execution time in seconds (rounded to two decimal places) in a `StageResult.seconds` field.
- **FR-PIPE-01.3 (Stage Data):** Each stage must attach a `data` dict to its `StageResult` containing the stage's primary output in a serializable form.
- **FR-PIPE-01.4 (Artifact Persistence):** The Save Artifacts stage must write all defined output files to `output/<CVE-ID>/`, creating the directory if it does not exist. A second run for the same CVE ID must overwrite existing files.

### 4.6 Live Execution

- **FR-LIVE-01.1 (Target Resolution):** Before any socket or RPC connection is opened, the target must be resolved to an IP address. Non-private, non-loopback IPs must raise `UnauthorizedTargetError` unless `allow_public_target=True` is explicitly passed.
- **FR-LIVE-01.2 (Authorization Confirmation):** `confirmed=False` must raise `UnauthorizedTargetError` with a message explaining the requirement. No live network action may precede this check.
- **FR-LIVE-01.3 (vsftpd Runner):** The CVE-2011-2523 runner must implement the three-phase trigger: (1) TCP connect to port 21, (2) send `USER test:)\r\n` + `PASS x\r\n`, (3) TCP connect to port 6200 and send `id;\n`. Success is confirmed by the presence of `"uid="` in the response.
- **FR-LIVE-01.4 (EternalBlue Runner):** The CVE-2017-0144 runner must drive a locally running `msfrpcd` instance via the `pymetasploit3` RPC client, execute `exploit/windows/smb/ms17_010_eternalblue`, wait up to 180 seconds for a new session, and confirm code execution with `sysinfo` on the resulting session.
- **FR-LIVE-01.5 (Live Report):** Every live execution attempt — successful or not — must produce a `RunResult` that is written to `output/<CVE-ID>/live_execution_report.json`.

### 4.7 Web UI

- **FR-UI-01.1 (Pipeline Trigger):** `POST /api/run` must accept `{"cve_id": "<id>"}`, run the full five-stage pipeline synchronously, and return the `PipelineResult` as JSON on success or `{"error": "<message>"}` with HTTP 502 on any pipeline exception.
- **FR-UI-01.2 (Stage Visualization):** The frontend must visually animate each stage as active → done in the order returned by the pipeline, displaying the stage timing.
- **FR-UI-01.3 (Result Display):** On completion, the UI must display: raw CVE metadata JSON, classification details (category, subtype, confidence, rationale), generated PoC code, breakdown Markdown, execution guide Markdown, and mock execution report (checks + transcript + notes).
- **FR-UI-01.4 (Live Execution Panel):** The live execution panel must only appear when the completed CVE ID is in the set of supported live CVEs (`["CVE-2011-2523", "CVE-2017-0144"]`). The LHOST field must only appear and be required when the CVE ID is `"CVE-2017-0144"`.
- **FR-UI-01.5 (Live Trigger):** `POST /api/execute` must accept `{"cve_id", "target", "lhost"?, "confirmed"}`. It must return `{"error": "<message>"}` with HTTP 403 for any `UnauthorizedTargetError` and HTTP 400 for an unsupported CVE ID or missing required fields.

### 4.8 Secret Management

- **FR-SEC-01.1 (Encrypted Env):** When `MASTER_KEY` is set and `.env.enc` exists, `config.py` must decrypt it using Fernet and inject the key/value pairs into the process environment via `os.environ.setdefault`.
- **FR-SEC-01.2 (Plaintext Fallback):** When `MASTER_KEY` is absent, `config.py` must fall back to loading `.env` with `python-dotenv`. When neither exists, it must rely on OS environment variables already present (for Docker/CI).
- **FR-SEC-01.3 (Generate Key CLI):** `crypto_env.py` must provide a `gen-key` subcommand that prints a new Fernet key to stdout. It must provide an `encrypt <src> <dst>` subcommand and a `decrypt <src>` subcommand.

---

## 5. Non-Functional Requirements

- **NFR-SEC-01.1 (No Secrets in VCS):** The plaintext `.env` and any Fernet master key file must be listed in `.gitignore`. Only `.env.enc` (the encrypted form) may be committed. This must be enforced in the gitignore before any repo push.
- **NFR-SEC-01.2 (No Live Code Auto-Execution):** The baseline pipeline must never execute the LLM-generated PoC code or make a network connection to a real target. Only the explicitly invoked live runner (CLI `--i-own-this-target` or UI authorization checkbox) may initiate real network connections.
- **NFR-SEC-01.3 (Private Target Enforcement):** The live runner must default to refusing non-private/non-loopback targets. The override (`allow_public_target`) must require an explicit opt-in at the call site and must not be the default value in any function signature.
- **NFR-PERF-01.1 (Pipeline Timeout):** The NVD fetch must use a 30-second request timeout. LLM generation requests must use `max_tokens=1500` for the generate call and `max_tokens=1200` for the breakdown call to bound response latency.
- **NFR-REP-01.1 (Artifact Reproducibility):** For the two graded baseline CVEs, running the demo scripts must always produce a `MockExecutionResult` with `success=True` as long as the LLM generates a structurally valid PoC, regardless of the exact code the LLM writes.
- **NFR-PORT-01.1 (Docker Support):** The application must be fully runnable inside the provided Docker image by setting `MASTER_KEY` as an environment variable and mounting `.env.enc`. No host-side Python installation must be required.
- **NFR-MAINT-01.1 (Model Configurability):** The LLM model ID must be configurable via the `HF_MODEL_ID` environment variable without any code changes. The default must be `Qwen/Qwen2.5-Coder-32B-Instruct`.

---

## 6. API Reference

| Method | Route | Purpose | Success | Error |
|---|---|---|---|---|
| `GET` | `/` | Serve the pipeline UI | `200 OK` + HTML | — |
| `POST` | `/api/run` | Run the five-stage baseline pipeline | `200 OK` + `PipelineResult` JSON | `400` (missing cve_id), `502` (pipeline error) |
| `POST` | `/api/execute` | Run the live exploit against a named lab target | `200 OK` + `RunResult` JSON | `400` (unsupported CVE / missing field), `403` (unauthorized target or unconfirmed) |

### 6.1 `POST /api/run` — Request
```json
{ "cve_id": "CVE-2011-2523" }
```

### 6.2 `POST /api/run` — Success Response (abbreviated)
```json
{
  "cve_id": "CVE-2011-2523",
  "stages": [
    { "name": "Fetch CVE",                        "seconds": 1.24, "data": { "cve": { ... } } },
    { "name": "Classify CVE",                     "seconds": 0.01, "data": { "classification": { ... } } },
    { "name": "Generate & Explain Payload (LLM)", "seconds": 18.4, "data": { "filetype": "python", "code": "...", "breakdown_markdown": "...", "execution_guide_markdown": "...", "model": "Qwen/Qwen2.5-Coder-32B-Instruct", "prompt": "..." } },
    { "name": "Mock Execute (Simulated Target)",  "seconds": 0.00, "data": { "report": { "success": true, "checks": [...], "transcript": [...], "mode": "exact-match", "notes": "" } } },
    { "name": "Save Artifacts",                   "seconds": 0.01, "data": { "output_dir": "output/CVE-2011-2523" } }
  ]
}
```

### 6.3 `POST /api/run` — Error Response
```json
{ "error": "NVD returned no results for CVE-2026-9999" }
```

### 6.4 `POST /api/execute` — Request
```json
{ "cve_id": "CVE-2011-2523", "target": "192.168.56.101", "confirmed": true }
```

### 6.5 `POST /api/execute` — Success Response
```json
{
  "cve_id": "CVE-2011-2523",
  "target": "192.168.56.101",
  "success": true,
  "transcript": ["connect 192.168.56.101:21", "recv: 220 ...", "..."],
  "evidence": "uid=0(root) gid=0(root) groups=0(root)"
}
```

### 6.6 `POST /api/execute` — Authorization Error Response (HTTP 403)
```json
{ "error": "Refusing to run a live exploit against 192.168.56.101 without explicit confirmation that you own or are authorized to test it." }
```

---

## 7. Configuration Reference

All configuration is loaded from environment variables (via `.env` or `.env.enc`). No setting has a required value except `HF_TOKEN` (the pipeline raises `RuntimeError` at LLM init time when it is empty).

| Variable | Default | Description |
|---|---|---|
| `HF_TOKEN` | `""` (required) | Hugging Face API token. Required for any LLM call. |
| `HF_MODEL_ID` | `Qwen/Qwen2.5-Coder-32B-Instruct` | Hugging Face model ID to use for generation. |
| `NVD_API_KEY` | `None` | Optional NVD API key; increases rate limit from 5 to 50 requests/30s. |
| `FLASK_SECRET_KEY` | `"dev-secret"` | Flask session secret. Must be changed for any non-local deployment. |
| `MSF_RPC_HOST` | `"127.0.0.1"` | Metasploit RPC daemon host (live EternalBlue runner only). |
| `MSF_RPC_PORT` | `55553` | Metasploit RPC daemon port. |
| `MSF_RPC_PASSWORD` | `""` | Metasploit RPC password. |
| `MSF_RPC_SSL` | `true` | Whether the RPC connection uses SSL. |
| `MASTER_KEY` | (OS env) | Fernet master key for decrypting `.env.enc`. Set in shell profile, not in `.env`. |

---

*This document reflects the system as of the current build. Update requirement statuses, add new FRs for features added, and record deviations from this spec here as the project evolves.*
