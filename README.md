# CVE → LLM Exploit Pipeline

Educational/coursework project (Metasploit course). Given a CVE ID, the
pipeline:

1. **Fetch CVE** — pulls the description, CVSS score, CWE(s) and affected
   products from the NVD API.
2. **Classify CVE** — automatically classifies the CVE as server-side
   (network service, web application) or client-side (browser/JS engine,
   document/file parser, other desktop client) from its description, CVSS
   vector (attack vector / user interaction) and affected products/CWEs. See
   `cve_classifier.py`.
3. **Generate & Explain Payload (LLM)** — prompts an open-source Hugging Face
   model (no fine-tuning, called via the Inference API) to draft a PoC using
   phase guidance tailored to the classification (e.g. a browser HTML/JS
   deliver→trigger→report PoC for a client-side memory-corruption bug vs. a
   connect→trigger→interact script for a network service), then a second
   prompt asks it to break the payload down component-by-component and write
   a step-by-step execution guide.
4. **Mock Execute** — for the two CVEs with a hand-built simulated target
   (vsftpd backdoor, EternalBlue), validates the payload against exact
   CVE-specific markers and replays a canned transcript. For every other
   CVE, it dispatches to a generic simulation flow tailored to the
   classification (network service / web application / browser / document
   parser / best-effort fallback) — checking the PoC's structure and
   narrating what a real attempt would do, instead of a blind
   "unsupported CVE" failure. This is the always-available, reproducible
   baseline demonstration (no lab VM, browser, or vulnerable app required).
5. **Save Artifacts** — writes `exploit.py`/`exploit.rc`/`exploit.html`,
   `breakdown.md`, `execution_guide.md`, `classification.json` and
   `mock_execution_report.json` to `output/<CVE-ID>/`.

A small Flask UI visualizes each stage as it runs; a CLI and two standalone
demo scripts exercise the same pipeline for grading/demonstration.

**On top of that**, a separate **live execution runner** performs a real
exploitation attempt against a lab target you name and confirm authorization
for — see [Live execution](#live-execution-real-lab-target) below and
[docs/LAB_SETUP.md](docs/LAB_SETUP.md).

## Setup

```bash
uv sync
cp env.example .env          # fill in HF_TOKEN at minimum
uv run python -m cve_pipeline.crypto_env gen-key     # once — save the key
export MASTER_KEY=<the printed key>                  # or set it in your shell profile
uv run python -m cve_pipeline.crypto_env encrypt .env .env.enc
```

`.env` and the master key are gitignored; only the encrypted `.env.enc` is
committed. `src/cve_pipeline/config.py` decrypts it at startup whenever
`MASTER_KEY` is set.

## Run

```bash
# Web UI
uv run flask --app cve_pipeline.app run
# open http://127.0.0.1:5000

# CLI
uv run cve-pipeline CVE-2011-2523

# The two graded baseline (mock) demonstration test cases
uv run python demos/demo_vsftpd_cve_2011_2523.py
uv run python demos/demo_eternalblue_cve_2017_0144.py
```

## Live execution (real lab target)

Once `cve-pipeline` / the UI has generated artifacts for a CVE, run the same
exploit for real against a lab VM you own — see
[docs/LAB_SETUP.md](docs/LAB_SETUP.md) for setting up the targets:

```bash
uv run cve-pipeline-live CVE-2011-2523 --target 192.168.56.101 --i-own-this-target
uv run cve-pipeline-live CVE-2017-0144 --target 192.168.56.102 --lhost 192.168.56.1 --i-own-this-target
```

The Flask UI has the same capability: after a run, a "Live Execution" panel
appears for the two supported CVEs with a target field and a required
authorization checkbox (`POST /api/execute`).

Both paths refuse to run without an explicit target + authorization
confirmation, and refuse public IPs unless `--allow-public-target` is passed.
Every attempt (success or failure) is saved to
`output/<CVE-ID>/live_execution_report.json`.

## Docker

```bash
docker build -t cve-exploit-llm-pipeline .
docker run -e MASTER_KEY=... -v %cd%/.env.enc:/app/.env.enc -p 5000:5000 cve-exploit-llm-pipeline
```

## Project layout

```
src/cve_pipeline/
  config.py        # loads + decrypts .env.enc
  crypto_env.py     # Fernet encrypt/decrypt CLI for the .env file
  cve_client.py      # NVD API client
  cve_classifier.py   # server-side vs. client-side (+ subtype) CVE classification
  llm_client.py       # HF Inference API prompting (generate + breakdown + guide)
  mock_runner.py       # exact-match + classification-aware generic simulated transcripts
  net_guard.py           # private-target + authorization guardrails
  exploit_runner.py       # real execution: sockets (vsftpd) / Metasploit RPC (EternalBlue)
  pipeline.py               # orchestrates the 5 baseline stages, saves artifacts
  cli.py                     # `cve-pipeline <CVE-ID>` entry point
  live_cli.py                 # `cve-pipeline-live <CVE-ID> --target ...` entry point
  app.py                        # Flask routes (/api/run baseline, /api/execute live)
  templates/, static/            # pipeline-visualization UI
demos/                             # the two standalone graded baseline test-case scripts
docs/LAB_SETUP.md                    # lab VM setup + live-runner guardrails
output/                                # generated artifacts (gitignored)
```

## Ethical use

This project only generates PoCs for CVEs that are already public and
extensively documented. The baseline pipeline only "executes" against a
local mock target. The live runner performs real exploitation and is
guardrailed accordingly — see [docs/LAB_SETUP.md](docs/LAB_SETUP.md). Never
point it at a system you don't own or don't have explicit written
authorization to test.
