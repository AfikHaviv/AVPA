# Lab setup

The project has two execution tiers:

1. **Baseline (mock) stage** — runs automatically as part of `run_pipeline()`
   (the web UI and `cve-pipeline` CLI). It statically checks the LLM-generated
   payload for the CVE-specific markers a real exploit needs, then replays a
   simulated transcript. No target required — this is the reproducible,
   always-available demonstration.
2. **Live execution runner** (`exploit_runner.py`, `cve-pipeline-live` CLI,
   `/api/execute` in the UI) — performs a **real** exploitation attempt
   against a target you name explicitly and confirm authorization for. This
   is the required deliverable for verifying against your own lab.

The live runner uses hand-verified implementations for the two demo CVEs
rather than executing whatever the LLM generated in stage 2 — running
machine-written code unsupervised against a live target isn't something this
project does, lab or not. `output/<CVE-ID>/exploit.py`/`exploit.rc` (the LLM's
artifact) remains what you read, explain, and grade; the live runner is what
proves the technique works against a real host.

## Setting up the lab targets

### CVE-2011-2523 (vsftpd backdoor) — Metasploitable2

1. Download/import Metasploitable2 into VirtualBox/VMware, attach it to a
   **host-only or isolated NAT network** (not bridged to your LAN or the
   internet).
2. Boot it, note its IP (`ifconfig` inside the VM, default login
   `msfadmin`/`msfadmin`).
3. Run:
   ```bash
   uv run cve-pipeline-live CVE-2011-2523 --target <VM_IP> --i-own-this-target
   ```

### CVE-2017-0144 / MS17-010 (EternalBlue) — unpatched Windows 7/2008

1. Set up an unpatched Windows 7 or Server 2008 R2 VM with SMBv1 enabled, on
   the same isolated lab network.
2. On your Metasploit host, start the RPC daemon:
   ```bash
   msfrpcd -P <password> -S -a 127.0.0.1 -p 55553
   ```
3. Put the same password in `.env` as `MSF_RPC_PASSWORD` (see `env.example`),
   re-encrypt it, then run:
   ```bash
   uv run cve-pipeline-live CVE-2017-0144 --target <WIN_VM_IP> --lhost <YOUR_IP> --i-own-this-target
   ```

## Guardrails built into the live runner

- `resolve_and_check()` refuses any target that isn't a private (`10.x`,
  `172.16-31.x`, `192.168.x`) or loopback address, unless you pass
  `--allow-public-target` explicitly.
- `require_confirmation()` refuses to run at all unless `--i-own-this-target`
  (CLI) or the authorization checkbox (UI) is set.
- Every run — success or failure — writes `output/<CVE-ID>/live_execution_report.json`
  with the full transcript and captured evidence, so results are reproducible
  and reviewable after the fact.

Never point the live runner at a host you don't own or don't have explicit
written authorization to test.
