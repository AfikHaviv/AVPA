"""Prompts an open-source Hugging Face model (via the Inference API, no fine-tuning)
to draft a lab-only PoC exploit for a CVE and to explain/document it.
"""

from __future__ import annotations

from dataclasses import dataclass

from huggingface_hub import InferenceClient

from cve_pipeline.cve_client import CveInfo
from cve_pipeline.cve_classifier import (
    BROWSER,
    DOCUMENT_OR_FILE,
    WEB_APPLICATION,
    CveClassification,
)

LAB_ONLY_RULES = (
    "You are a security-training assistant helping students in an authorized, "
    "isolated lab replicate a *known, already-public* vulnerability against a "
    "deliberately vulnerable practice target in that lab (e.g. a Metasploitable2 VM "
    "for network services, or a specific vulnerable browser/reader build for "
    "client-side bugs). Only ever target RHOST/RHOSTS, file, or browser placeholders "
    "the operator supplies; never suggest scanning, targeting, or attacking systems "
    "outside the lab. Do not invent capabilities beyond what the CVE describes, and "
    "never implement real weaponized shellcode or a working sandbox-escape payload — "
    "any post-trigger payload stage must be a clearly commented stub/log statement "
    "instead."
)


def _phase_guidance(classification: CveClassification) -> str:
    subtype = classification.subtype
    if subtype == BROWSER:
        return (
            "This is a CLIENT-SIDE browser / JavaScript-engine vulnerability. Produce ONE HTML "
            "page (FILETYPE: html) containing inline <script> that:\n"
            "- Phase 1 (Deliver): sets up the DOM/JS state and any heap-grooming primitives "
            "(typed arrays, ArrayBuffer/WebAssembly, object allocation patterns) that this CVE's "
            "memory-corruption/logic flaw requires, based on your knowledge of how this bug class "
            "works even if the NVD description only states the *outcome* (e.g. 'execute arbitrary "
            "code inside a sandbox').\n"
            "- Phase 2 (Trigger): performs the exact sequence of JS operations that reaches and "
            "triggers the vulnerable code path in the affected engine/component.\n"
            "- Phase 3 (Report): since a real weaponized shellcode/sandbox-escape stage is out of "
            "scope for a lab demo, replace it with a clearly commented stub that logs "
            "'[PoC] vulnerable condition reached' (e.g. via console.log/document.title) instead of "
            "implementing real shellcode — the goal is to demonstrate the trigger, not deliver a "
            "working exploit.\n"
            "Comment each phase clearly. Assume the operator will open this page in an isolated lab "
            "VM running the exact vulnerable browser build named in the CVE."
        )
    if subtype == DOCUMENT_OR_FILE:
        return (
            "This is a CLIENT-SIDE document/file-parser vulnerability (e.g. a PDF/Office/media "
            "reader). Produce ONE standalone Python script (FILETYPE: python) that:\n"
            "- Phase 1 (Craft): builds a malicious file on disk in the exact format the CVE "
            "affects, embedding the structure/object that triggers the flaw, using your knowledge "
            "of this bug class to fill in what the NVD outcome-only description omits.\n"
            "- Phase 2 (Deliver): prints clear operator instructions for opening the crafted file "
            "with the exact vulnerable application/version in an isolated lab VM, and what to "
            "observe (crash, callback, log line) as evidence the flaw triggered.\n"
            "Comment each phase clearly."
        )
    if subtype == WEB_APPLICATION:
        return (
            "This is a SERVER-SIDE web-application vulnerability (injection/traversal/"
            "deserialization/etc.). Produce ONE standalone Python script (FILETYPE: python) using "
            "`requests` that:\n"
            "- Phase 1 (Trigger): sends the crafted HTTP request(s) against a TARGET base-URL "
            "placeholder, implementing the exact injection/traversal/bypass payload this CVE "
            "requires.\n"
            "- Phase 2 (Confirm): inspects the response (status, body, timing, or a side channel) "
            "to confirm the vulnerable condition was reached and prints a clear success/failure "
            "verdict.\n"
            "Comment each phase clearly."
        )
    # network_service and any other server-side/unknown subtype default to the
    # original network-service trigger/interact model.
    return (
        "Given this CVE, produce ONE proof-of-concept artifact for the lab:\n"
        "- If the CVE maps to a stable, well-known Metasploit module, output a Metasploit "
        "resource (.rc) script (FILETYPE: msf_rc) that sets the module, options (RHOSTS/LHOST "
        "as placeholders), payload, and runs it — intended for `msfconsole -r file.rc`.\n"
        "- Otherwise, output a small, well-commented, standalone Python script (FILETYPE: "
        "python) using the standard library (sockets/requests) that demonstrates the "
        "vulnerability.\n\n"
        "CRITICAL — the script must implement the FULL end-to-end trigger chain, not just "
        "its end state:\n"
        "- Start by connecting to the vulnerable service on its normal, documented port and "
        "performing whatever handshake, authentication, or crafted request/sequence is "
        "actually required to cause the vulnerable condition. Use your general knowledge of "
        "how this specific vulnerability works even if the CVE description only states the "
        "*outcome* (e.g. 'opens a shell on port 6200') — the outcome is not the trigger, and "
        "the outcome does not happen on its own.\n"
        "- NEVER assume a resulting shell, session, or secondary listener is already open. "
        "If the vulnerability's outcome is a shell/listener on another port, your script's "
        "first steps must be the exact action(s) against the primary service port that cause "
        "that shell/listener to come up — only then may it connect to and interact with it.\n"
        "- Structure the script in clearly commented phases, e.g. `# Phase 1: trigger the "
        "vulnerability on the primary service port` and `# Phase 2: interact with the "
        "resulting shell/session/response`, so both phases are unmistakably present."
    )


def _build_generate_system_prompt(classification: CveClassification) -> str:
    filetypes = {
        BROWSER: ["html"],
        DOCUMENT_OR_FILE: ["python"],
        WEB_APPLICATION: ["python"],
    }.get(classification.subtype, ["msf_rc", "python"])
    filetype_lines = "\n".join(f"# FILETYPE: {ft}" for ft in filetypes)
    return (
        LAB_ONLY_RULES
        + f"\n\nCVE classification for this task: category={classification.category}, "
        f"subtype={classification.subtype}, memory_corruption={classification.memory_corruption}, "
        f"requires_user_interaction={classification.requires_user_interaction}.\n\n"
        + _phase_guidance(classification)
        + "\n\nBefore finishing, re-check your own script against the phase list above; add any "
        "phase that's missing rather than jumping straight to the end state.\n\n"
        "Your FIRST line must be exactly one of:\n"
        + filetype_lines
        + "\nThen the full script in a single fenced code block. No prose outside the code block."
    )


def _build_breakdown_system_prompt(classification: CveClassification) -> str:
    success_hint = {
        BROWSER: (
            "for a browser/engine bug, success means the PoC's trigger phase is structurally "
            "complete and would reach the vulnerable code path on the exact vulnerable build "
            "named in the CVE — not that it achieves real code execution outside the lab."
        ),
        DOCUMENT_OR_FILE: (
            "success means the crafted file embeds the structure needed to reach the "
            "vulnerable parser path when opened by the exact vulnerable application version "
            "named in the CVE."
        ),
        WEB_APPLICATION: (
            "success means the HTTP request(s) reach and trigger the vulnerable endpoint/"
            "parameter and the response or side-effect confirms it."
        ),
    }.get(
        classification.subtype,
        "success means the primary-service trigger phase completes and the documented "
        "outcome (shell/session/response) is observed.",
    )
    return (
        LAB_ONLY_RULES
        + "\n\nYou will be shown a CVE and a PoC you previously wrote for it. Respond in "
        "Markdown with exactly two sections:\n\n"
        "## Payload Breakdown\n"
        "A bullet list explaining each meaningful component of the PoC (delivery/connection "
        "setup, the specific trigger that exploits the flaw, and how success is detected) and "
        "*why* it works against this CVE.\n\n"
        "## Execution Guide\n"
        "Numbered steps to run this in the lab: prerequisites (the exact vulnerable target/"
        "build needed), exact command(s) or manual steps, any placeholders to fill in, and "
        f"what to observe as evidence of success. For this CVE's classification, {success_hint}"
    )


@dataclass
class LlmArtifacts:
    prompt: str
    filetype: str
    code: str
    breakdown_markdown: str
    execution_guide_markdown: str


def _extract_code_block(text: str) -> tuple[str, str]:
    lines = text.strip().splitlines()
    filetype = "python"
    if lines and lines[0].strip().startswith("# FILETYPE:"):
        filetype = lines[0].split(":", 1)[1].strip()
        lines = lines[1:]

    body = "\n".join(lines)
    if "```" in body:
        parts = body.split("```")
        # parts[1] is the first fenced block; drop an optional language tag line.
        block = parts[1]
        block_lines = block.splitlines()
        if block_lines and block_lines[0].strip().isalpha():
            block_lines = block_lines[1:]
        body = "\n".join(block_lines).strip()

    return filetype, body


def _split_breakdown(text: str) -> tuple[str, str]:
    marker = "## Execution Guide"
    if marker in text:
        breakdown, guide = text.split(marker, 1)
        return breakdown.strip(), (marker + guide).strip()
    return text.strip(), ""


class LlmClient:
    def __init__(self, hf_token: str, model_id: str):
        if not hf_token:
            raise RuntimeError(
                "HF_TOKEN is not set. Fill in .env (see env.example) and encrypt it, "
                "or export HF_TOKEN directly."
            )
        self._client = InferenceClient(model=model_id, token=hf_token)
        self.model_id = model_id

    def _chat(self, system_prompt: str, user_prompt: str, max_tokens: int = 1500) -> str:
        response = self._client.chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        return response.choices[0].message.content

    def generate_artifacts(self, cve: CveInfo, classification: CveClassification) -> LlmArtifacts:
        generate_system_prompt = _build_generate_system_prompt(classification)
        user_prompt = (
            f"Write a lab-only PoC for this CVE:\n\n{cve.as_prompt_context()}\n\n"
            f"Classification: {classification.category} / {classification.subtype} "
            f"(confidence: {classification.confidence}). "
            f"Rationale: {'; '.join(classification.rationale) or 'n/a'}.\n\n"
            "Follow the phase structure for this classification exactly — do not default to "
            "a network-service trigger/listener model if this CVE is client-side, and do not "
            "assume a browser/HTML delivery model if this CVE is a server-side network service."
        )
        raw_code = self._chat(generate_system_prompt, user_prompt)
        filetype, code = _extract_code_block(raw_code)

        followup_prompt = (
            f"CVE context:\n{cve.as_prompt_context()}\n\n"
            f"Classification: {classification.category} / {classification.subtype}.\n\n"
            f"The PoC you wrote:\n```\n{code}\n```"
        )
        breakdown_system_prompt = _build_breakdown_system_prompt(classification)
        raw_explanation = self._chat(breakdown_system_prompt, followup_prompt, max_tokens=1200)
        breakdown_md, guide_md = _split_breakdown(raw_explanation)

        return LlmArtifacts(
            prompt=user_prompt,
            filetype=filetype,
            code=code,
            breakdown_markdown=breakdown_md,
            execution_guide_markdown=guide_md,
        )
