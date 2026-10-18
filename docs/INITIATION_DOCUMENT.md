# AVPA — Initiation Document for Implementation

**Full title:** CVE → LLM Exploit Pipeline: An Educational Automated Vulnerability Analysis and PoC Synthesis System
**Context:** Capstone Project for Bachelor of Science (B.Sc.) Degree, Faculty of Sciences, HIT — Holon Institute of Technology
**Authors:** Afik Haviv, Shir Molakandove, Kristina Asner

> This document records the **implementation decisions, architecture choices, and design rationale** made during the build. It complements the Software Requirements Specification (`SRS.md`) and reflects the system **as built**, not the original concept. Update it as further decisions are made.

---

## 1. Background & Rationale

### 1.1 Problem Domain

Security education requires hands-on exposure to how real vulnerabilities are structured, triggered, and mitigated. Today, students studying offensive security must read CVE documentation in isolation — the link between a public vulnerability description and a concrete, runnable proof-of-concept (PoC) exists only in the mind of an experienced practitioner.

This project automates that translation step within a closed academic setting: given a CVE ID, the system fetches the authoritative NVD description, classifies the vulnerability type, prompts an open-source LLM to draft a lab-only PoC, validates the PoC's structure, and (for two hand-verified CVEs) executes it against an isolated lab target to prove the technique works.

### 1.2 Why This Approach

Three design principles drove every decision:

- **Educational clarity over raw capability.** The system exists to teach, not to weaponize. The LLM is instructed to stub out real post-exploitation payloads and to keep the code readable and commented — the goal is a PoC that a student can read and understand, not one that silently lands a shell.
- **Classification before generation.** Not every CVE is a network-service exploit. A browser memory-corruption bug requires a fundamentally different PoC structure than an FTP backdoor trigger. The `cve_classifier` module resolves this before the LLM prompt is assembled, so the prompt guidance and the mock-execution validation are both tailored to the actual vulnerability class.
- **Reproducible baseline without a live lab.** The mock runner lets students, graders, and CI pipelines verify PoC structure without a vulnerable VM. The live runner is an explicit, gated opt-in that requires a named target and an authorization confirmation.

### 1.3 Scope

**In scope:**
- Fetching and parsing CVE metadata from the NVD API.
- Automated classification of CVEs into vulnerability categories (browser, document/file, web application, network service).
- LLM-driven PoC generation and explanation (breakdown + execution guide) via Hugging Face Inference API.
- Structural validation of generated PoCs against classification-specific completeness criteria (mock runner).
- Live execution against two hand-verified CVEs — vsftpd backdoor (CVE-2011-2523) and EternalBlue (CVE-2017-0144) — with explicit authorization guardrails.
- Persistent artifact output (code, breakdown, guide, classification, mock report) per CVE run.
- A Flask web UI and a CLI entry point exposing the same pipeline.

**Out of scope (per faculty guidelines and ethical design):**
- Model fine-tuning or parameter pre-training.
- Generating novel, weaponized exploits for CVEs not already extensively documented in public security research.
- Targeting any system the operator does not own or have written authorization to test.
- Shellcode generation or real post-exploitation payload delivery.

---

## 2. System Architecture

Single-service architecture; all components reside in one Python package deployed as a Flask app.

```
cve-exploit-llm-pipeline/
├── src/cve_pipeline/
│   ├── config.py          # encrypted-env loading + settings dataclass
│   ├── crypto_env.py      # Fernet encrypt/decrypt CLI for .env
│   ├── cve_client.py      # NVD API client → CveInfo dataclass
│   ├── cve_classifier.py  # server-side vs. client-side + subtype classification
│   ├── llm_client.py      # HuggingFace InferenceClient, two-prompt generate + explain
│   ├── mock_runner.py     # structural PoC validation (no live target required)
│   ├── net_guard.py       # private-IP + authorization guardrails for live runner
│   ├── exploit_runner.py  # live execution: sockets (vsftpd) / Metasploit RPC (EternalBlue)
│   ├── pipeline.py        # 5-stage orchestration + artifact persistence
│   ├── cli.py             # `cve-pipeline <CVE-ID>` entry point
│   ├── live_cli.py        # `cve-pipeline-live <CVE-ID> --target ...` entry point
│   ├── app.py             # Flask routes (/api/run, /api/execute)
│   ├── templates/         # Jinja2 HTML template
│   └── static/            # CSS + JS pipeline-visualization UI
├── demos/                 # two standalone baseline demonstration scripts
├── docs/LAB_SETUP.md      # lab VM setup + live-runner guardrails
└── output/                # generated artifacts (gitignored per-run)
```

### 2.1 Key Architectural Decisions

| Decision | Choice made | Rationale |
|---|---|---|
| Web framework | Flask | Lightweight; synchronous pipeline fit a request/response model without a task queue |
| LLM provider | Hugging Face Inference API | Open-source models, no fine-tuning required (faculty constraint), configurable via `HF_MODEL_ID` |
| Default model | `Qwen/Qwen2.5-Coder-32B-Instruct` | Strong code generation for a 32B instruction-tuned model; free tier available |
| Secret management | Fernet-encrypted `.env.enc` committed to repo; plaintext `.env` gitignored | Allows the encrypted config to travel with the repo without exposing secrets in version control |
| Execution model | Synchronous pipeline inside the request | CVE runs take 10–60s; acceptable for a lab/demo tool; avoids a background task queue |
| Artifact storage | `output/<CVE-ID>/` on the local filesystem | Simple, portable, grader-friendly; no database dependency |
| Live runner isolation | Raw sockets (vsftpd) / pymetasploit3 RPC (EternalBlue) | Hand-verified implementations against known CVEs; LLM-generated code is never auto-executed against a live target |

---

## 3. System Users

### 3.1 Student / Security Researcher
- Enters a CVE ID into the web UI or CLI.
- Observes the pipeline execute stage by stage (fetch → classify → generate → mock-execute → save).
- Reads the generated PoC, payload breakdown, and execution guide.
- For the two supported CVEs, optionally runs the live exploit against a personal lab VM they own.

### 3.2 Grader / Academic Evaluator
- Runs the two standalone demo scripts (`demo_vsftpd_cve_2011_2523.py`, `demo_eternalblue_cve_2017_0144.py`) to exercise the full pipeline with a reproducible output.
- Reviews artifacts in `output/<CVE-ID>/` without any live VM required.
- The mock runner produces a pass/fail report with per-check detail to aid evaluation.

### 3.3 Lab Instructor (Administrator)
- Configures the environment: sets `HF_TOKEN`, `HF_MODEL_ID`, `NVD_API_KEY`, Metasploit RPC settings in `.env`.
- Sets up lab VMs per `docs/LAB_SETUP.md` for students who want to exercise the live runner.
- Updates `net_guard.py` policy if the lab network topology requires it (e.g. allowing a specific non-private range).

---

## 4. Use Cases

### 4.1 Student: Analyze a CVE
1. Student opens the web UI (`http://127.0.0.1:5000`) or runs `cve-pipeline <CVE-ID>`.
2. Enters a CVE ID (e.g. `CVE-2021-44228`).
3. The pipeline runs: NVD fetch → classification → LLM generation → mock execution → artifact save.
4. Student reads the PoC code, breakdown, and execution guide in the UI or in `output/CVE-2021-44228/`.

### 4.2 Student: Live Lab Execution (Authorized CVEs)
1. Student has set up a Metasploitable2 VM per `docs/LAB_SETUP.md`.
2. Runs: `cve-pipeline-live CVE-2011-2523 --target 192.168.56.101 --i-own-this-target`
   or uses the "Live Execution" panel in the UI after a baseline run.
3. The live runner connects to the target, triggers the vulnerability, and reports a pass/fail with evidence.
4. A `live_execution_report.json` is written to `output/CVE-2011-2523/`.

### 4.3 Grader: Reproducible Baseline Demonstration
1. Grader runs: `uv run python demos/demo_vsftpd_cve_2011_2523.py`
2. The full pipeline executes against the vsftpd CVE with a canned mock-execution transcript.
3. All artifacts are written to `output/CVE-2011-2523/` and the terminal shows a structured pass/fail report.
4. No live VM or network connectivity required.

---

## 5. End-to-End Workflow

### 5.1 Baseline Pipeline (Web UI / CLI)

1. **Input** — User provides a CVE ID. No format validation is enforced server-side beyond the NVD API rejecting invalid IDs gracefully.
2. **Fetch** — `cve_client.fetch_cve()` queries `https://services.nvd.nist.gov/rest/json/cves/2.0`. Returns a `CveInfo` dataclass with description, CVSS score/vector, CWE IDs, affected product CPEs, and references. Raises `ValueError` on "no results" (NVD miss).
3. **Classify** — `cve_classifier.classify_cve()` inspects the description text, CVSS vector flags (`AV`, `UI`), CWE set, and CPE product names to assign a `category` (server-side / client-side) and a `subtype` (network_service / web_application / browser / document_or_file / desktop_application / unknown). Confidence (high/medium/low) and rationale strings are also returned.
4. **Generate** — `llm_client.LlmClient.generate_artifacts()` sends two sequential chat requests to the HF Inference API:
   - **Generate prompt**: system instruction (lab-only rules) + classification-specific phase guidance + CVE context. The model is asked to output exactly one fenced code block prefixed with `# FILETYPE: <type>`.
   - **Breakdown prompt**: asks the model to explain the generated PoC in Markdown with a "Payload Breakdown" section and an "Execution Guide" section.
5. **Mock Execute** — `mock_runner.run_mock_exploit()` validates the PoC structurally without running it. For vsftpd and EternalBlue: exact-marker checks + canned transcript. For all other CVEs: classification-aware generic simulation flow (4 subtypes + fallback) that checks phase structure and narrates what a real attempt would do.
6. **Save** — `pipeline._save_artifacts()` writes `exploit.<ext>`, `breakdown.md`, `execution_guide.md`, `prompt.txt`, `classification.json`, and `mock_execution_report.json` to `output/<CVE-ID>/`.
7. **Return** — `PipelineResult` (stage names, timings, per-stage data dicts) is returned as JSON to the Flask route and rendered by the UI.

### 5.2 Live Execution Flow

1. User has already run the baseline pipeline for a supported CVE.
2. User submits target IP + (for EternalBlue) LHOST + authorization confirmation.
3. `net_guard.resolve_and_check()` resolves the target hostname/IP and refuses non-private/non-loopback addresses unless `allow_public_target=True` is explicitly set.
4. `net_guard.require_confirmation()` enforces the `confirmed=True` flag; refuses without it.
5. `exploit_runner.run_vsftpd_backdoor()` or `run_eternalblue_via_msf_rpc()` executes the hand-verified implementation against the live target.
6. A `RunResult` (cve_id, target, success, transcript, evidence) is returned and written to `output/<CVE-ID>/live_execution_report.json`.

---

## 6. Security & Ethical Design Decisions

### 6.1 LLM Safety Constraints
The system prompt passed to the LLM (`LAB_ONLY_RULES` in `llm_client.py`) explicitly instructs the model to:
- Only target lab placeholder values (RHOST, file path, browser), never suggest scanning live systems.
- Not invent capabilities beyond what the CVE describes.
- Replace any real post-exploitation payload with a clearly commented stub — the PoC proves the *trigger*, not the weaponized delivery.

These constraints are intentional and must be preserved in any future prompt modifications.

### 6.2 Live Runner Guardrails
- Target must resolve to a private/loopback IP address. This check runs before any socket is opened.
- Caller must explicitly set `confirmed=True` (CLI: `--i-own-this-target`; UI: authorization checkbox). No implicit confirmation path exists.
- LLM-generated code is **never** automatically executed against a live target. The live runner uses hand-verified implementations only.

### 6.3 Secret Management
- Plaintext `.env` and the master Fernet key are gitignored.
- Only the encrypted `.env.enc` is committed. The `MASTER_KEY` environment variable is required at runtime to decrypt it.
- `config.py` prefers the encrypted path when `MASTER_KEY` is set; falls back to plaintext `.env`; falls back to OS environment variables (for Docker/CI).

---

## 7. Open Items

- **Additional CVE live-runner support**: the live runner only handles CVE-2011-2523 and CVE-2017-0144. Extending it to other CVEs requires hand-verified implementations and lab VM setup documentation.
- **CVE input validation**: the web UI currently accepts any non-empty string and relies on the NVD API to reject invalid IDs. A regex pre-check (e.g. `^CVE-\d{4}-\d{4,7}$`) would improve UX.
- **Caching**: every run re-fetches from NVD. A local cache keyed by CVE ID would reduce latency and NVD rate-limit exposure.
- **Model selection UI**: `HF_MODEL_ID` is environment-variable-only. A UI or CLI flag to select the model per run would be useful for comparing outputs.
- **Deployment**: currently local-only. Hosting on an institutional server would require rate limiting and a reverse proxy.

---

*Keep this document current as the authoritative implementation reference. Record architectural decisions and deviations from the original spec here as the project evolves.*
