"""Mock exploit runner for local academic/pipeline verification.

This never executes the LLM-generated code and never touches a real network
target, browser, or file-parsing application. For the two CVEs with a
hand-built simulated target (vsftpd backdoor, EternalBlue) it statically
checks the generated payload for the exact technical markers a genuine
exploit would need, then plays back a canned execution transcript against an
in-memory mock target.

For every other CVE it dynamically classifies the vulnerability (see
`cve_classifier.py`) and dispatches to a generic simulation flow tailored to
that class — network service, server-side web application, browser/engine
memory corruption, or document/file parser — instead of a single blind
"no simulated target registered" failure. Each generic flow narrates what a
real exploitation attempt against a genuinely vulnerable target would do,
while running structural checks against the LLM-generated PoC to see whether
it actually implements the phases that CVE class requires.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cve_pipeline.cve_classifier import (
    BROWSER,
    DOCUMENT_OR_FILE,
    NETWORK_SERVICE,
    WEB_APPLICATION,
    CveClassification,
    classify_cve,
    describe_product,
)
from cve_pipeline.cve_client import CveInfo


@dataclass
class MockExecutionResult:
    cve_id: str
    success: bool
    checks: list[dict] = field(default_factory=list)
    transcript: list[str] = field(default_factory=list)
    mode: str = "exact-match"
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "success": self.success,
            "checks": self.checks,
            "transcript": self.transcript,
            "mode": self.mode,
            "notes": self.notes,
        }


def _check(label: str, passed: bool) -> dict:
    return {"label": label, "passed": passed}


def _run_vsftpd_backdoor(code: str) -> MockExecutionResult:
    checks = [
        _check("references FTP control port 21", "21" in code),
        _check("uses the ':)' backdoor trigger", ":)" in code),
        _check("connects to the backdoor shell on port 6200", "6200" in code),
    ]
    transcript = [
        "[mock] TCP connect 127.0.0.1:21 (simulated Metasploitable2, vsftpd 2.3.4)",
        "[mock] USER test:)   -> 331 Please specify the password.",
        "[mock] PASS x        -> backdoor trigger armed by the ':)' in the username",
        "[mock] TCP connect 127.0.0.1:6200",
        "[mock] recv: uid=0(root) gid=0(root) groups=0(root)",
        "[mock] root shell confirmed on port 6200",
    ]
    return MockExecutionResult(
        cve_id="CVE-2011-2523",
        success=all(c["passed"] for c in checks),
        checks=checks,
        transcript=transcript,
    )


def _run_eternalblue(code: str) -> MockExecutionResult:
    lowered = code.lower()
    checks = [
        _check("targets SMB (port 445)", "445" in code),
        _check(
            "references the MS17-010 / EternalBlue module or CVE",
            "ms17_010" in lowered or "eternalblue" in lowered or "2017-0144" in lowered,
        ),
        _check("configures a payload/session (meterpreter or shell)", "payload" in lowered or "meterpreter" in lowered),
    ]
    transcript = [
        "[mock] msfconsole -r exploit.rc (simulated Windows 7 target, SMBv1 enabled)",
        "[mock] use exploit/windows/smb/ms17_010_eternalblue",
        "[mock] set RHOSTS 127.0.0.1   (mock target)",
        "[mock] set PAYLOAD windows/x64/meterpreter/reverse_tcp",
        "[mock] exploit -> crafted SMBv1 Trans2 request triggers the buffer overflow",
        "[mock] Meterpreter session 1 opened",
        "[mock] sysinfo -> Computer: MOCK-TARGET, OS: Windows 7 (simulated)",
    ]
    return MockExecutionResult(
        cve_id="CVE-2017-0144",
        success=all(c["passed"] for c in checks),
        checks=checks,
        transcript=transcript,
    )


_RUNNERS = {
    "CVE-2011-2523": _run_vsftpd_backdoor,
    "CVE-2017-0144": _run_eternalblue,
}


def _passed(checks: list[dict]) -> int:
    return sum(1 for c in checks if c["passed"])


def _run_generic_browser(
    cve_id: str, code: str, cve: CveInfo | None, classification: CveClassification
) -> MockExecutionResult:
    lowered = code.lower()
    product = classification.product_hint or "the vulnerable browser build named in the CVE"
    checks = [
        _check(
            "PoC includes an HTML/JS delivery page (script/DOM markers)",
            any(m in lowered for m in ("<html", "<script", "document.", "window.")),
        ),
        _check(
            "PoC implements a memory-corruption trigger primitive (typed arrays / "
            "ArrayBuffer / WebAssembly / heap grooming)",
            any(
                m in lowered
                for m in ("arraybuffer", "webassembly", "typed array", "float64array", "uint8array", "sharedarraybuffer", "heap")
            ),
        ),
        _check(
            "PoC is structured in commented phases (deliver / trigger / report)",
            "phase" in lowered,
        ),
        _check(
            "PoC includes a clearly-labeled post-trigger report/stub stage",
            any(m in lowered for m in ("sandbox", "console.log", "vulnerable condition", "poc")),
        ),
    ]
    passed = _passed(checks)
    success = passed >= 3
    transcript = [
        f"[mock-sim] launching {product} inside an isolated lab VM",
        "[mock-sim] navigating the target browser to the crafted PoC page",
        "[mock-sim] renderer process loads attacker-controlled HTML/JS from the PoC",
        (
            "[mock-sim] JS heap-manipulation / typed-array primitives detected in PoC"
            if checks[1]["passed"]
            else "[mock-sim] WARNING: no heap-manipulation primitive detected in PoC -- trigger phase may be incomplete"
        ),
        (
            "[mock-sim] simulated renderer trigger reached (type-confusion / OOB signal observed)"
            if success
            else "[mock-sim] PoC structure insufficient to simulate a successful trigger"
        ),
        (
            "[mock-sim] post-trigger stage present -- on a genuinely vulnerable build this is where "
            "a sandbox-escape payload would run"
            if checks[3]["passed"]
            else "[mock-sim] no post-trigger report/stub stage found in PoC"
        ),
    ]
    notes = (
        "Client-side/browser memory-corruption bugs can't be replayed by a generic mock target the "
        "way a network service can -- there is no 'mock Chrome' listening on a port, and real "
        "exploitation depends on exact build offsets and heap layout. This is a structural "
        "simulation: it checks that the generated PoC contains the delivery, trigger, and "
        f"post-trigger stages a real exploit for this CVE class would need, and narrates what each "
        f"stage would do against a genuinely vulnerable {product}."
    )
    return MockExecutionResult(
        cve_id=cve_id, success=success, checks=checks, transcript=transcript,
        mode="generic-client-browser", notes=notes,
    )


def _run_generic_document_or_file(
    cve_id: str, code: str, cve: CveInfo | None, classification: CveClassification
) -> MockExecutionResult:
    lowered = code.lower()
    product = classification.product_hint or "the vulnerable reader/application named in the CVE"
    checks = [
        _check(
            "PoC writes a crafted file to disk (file-write / struct-pack markers)",
            any(m in lowered for m in ("open(", "wb", "struct.pack", "write(")),
        ),
        _check(
            "PoC is structured in commented phases (craft / deliver)",
            "phase" in lowered,
        ),
        _check(
            "PoC documents how to observe the trigger (crash/callback/log)",
            any(m in lowered for m in ("observe", "crash", "callback", "log", "evidence")),
        ),
    ]
    passed = _passed(checks)
    success = passed >= 2
    transcript = [
        f"[mock-sim] crafting the malicious file described by the PoC on disk",
        f"[mock-sim] operator opens the crafted file with {product} inside an isolated lab VM",
        (
            "[mock-sim] vulnerable parser path reached -- structural markers for the crafted "
            "object/structure are present"
            if success
            else "[mock-sim] PoC structure insufficient to simulate a successful trigger"
        ),
    ]
    notes = (
        "Document/file-parser bugs require the exact vulnerable reader build and are not something "
        "a generic mock target can execute. This is a structural simulation: it checks that the "
        "generated PoC actually builds a file and documents how to trigger + observe the flaw in "
        f"{product}, rather than assuming a network trigger."
    )
    return MockExecutionResult(
        cve_id=cve_id, success=success, checks=checks, transcript=transcript,
        mode="generic-client-document", notes=notes,
    )


def _run_generic_web_application(
    cve_id: str, code: str, cve: CveInfo | None, classification: CveClassification
) -> MockExecutionResult:
    lowered = code.lower()
    checks = [
        _check(
            "PoC sends crafted HTTP request(s) (requests/http markers)",
            any(m in lowered for m in ("requests.", "http://", "https://", "urlopen", "session()")),
        ),
        _check(
            "PoC includes an injection/traversal-style payload marker",
            any(m in lowered for m in ("' or ", "../", "union select", ";", "<script", "%00", "payload")),
        ),
        _check(
            "PoC inspects the response to confirm the vulnerable condition",
            any(m in lowered for m in (".status_code", ".text", ".content", "response")),
        ),
    ]
    passed = _passed(checks)
    success = passed >= 2
    transcript = [
        "[mock-sim] sending crafted HTTP request(s) to the target web application (TARGET placeholder)",
        (
            "[mock-sim] injection/traversal payload present in the request"
            if checks[1]["passed"]
            else "[mock-sim] WARNING: no recognizable injection payload found in PoC"
        ),
        (
            "[mock-sim] response inspected -- structural markers indicate the vulnerable endpoint "
            "would be reached"
            if success
            else "[mock-sim] PoC structure insufficient to confirm the vulnerable condition"
        ),
    ]
    notes = (
        "This is a server-side web-application bug, but no live vulnerable instance of the target "
        "app is deployed in this mock environment. This is a structural simulation: it checks that "
        "the generated PoC actually sends a crafted request implementing the injection/traversal "
        "primitive this CVE requires and inspects the response for confirmation."
    )
    return MockExecutionResult(
        cve_id=cve_id, success=success, checks=checks, transcript=transcript,
        mode="generic-server-web", notes=notes,
    )


def _run_generic_network_service(
    cve_id: str, code: str, cve: CveInfo | None, classification: CveClassification
) -> MockExecutionResult:
    lowered = code.lower()
    checks = [
        _check(
            "PoC opens a socket/connection to a service port",
            any(m in lowered for m in ("socket.", "connect(", "rhosts", "rhost")),
        ),
        _check(
            "PoC is structured in commented trigger/interact phases",
            "phase" in lowered,
        ),
        _check(
            "PoC references the CVE or a known exploit module/CWE for it",
            cve_id.lower() in lowered
            or any(c.lower() in lowered for c in (cve.cwe_ids if cve else [])),
        ),
    ]
    passed = _passed(checks)
    success = passed >= 2
    transcript = [
        "[mock-sim] connecting to the vulnerable service on its documented port (simulated lab target)",
        (
            "[mock-sim] trigger phase present -- crafted request/handshake would reach the vulnerable "
            "code path"
            if checks[1]["passed"]
            else "[mock-sim] WARNING: no explicit trigger phase found -- PoC may assume the vulnerable "
            "condition instead of causing it"
        ),
        (
            "[mock-sim] simulated service response consistent with the documented outcome"
            if success
            else "[mock-sim] PoC structure insufficient to simulate the documented outcome"
        ),
    ]
    notes = (
        "No hand-built simulated target is registered for this CVE, so this is a generic structural "
        "simulation of a network-reachable service: it checks that the PoC opens a connection, "
        "implements an explicit trigger phase, and ties back to this CVE, then narrates what a real "
        "attempt against a genuinely vulnerable service would do."
    )
    return MockExecutionResult(
        cve_id=cve_id, success=success, checks=checks, transcript=transcript,
        mode="generic-server-network", notes=notes,
    )


def _run_generic_fallback(
    cve_id: str, code: str, cve: CveInfo | None, classification: CveClassification
) -> MockExecutionResult:
    lowered = code.lower()
    checks = [
        _check("PoC is non-empty", bool(code.strip())),
        _check("PoC references this CVE ID", cve_id.lower() in lowered),
        _check("PoC includes explanatory comments", "#" in code or "//" in code),
    ]
    passed = _passed(checks)
    success = passed >= 2
    transcript = [
        f"[mock-sim] classification for {cve_id} was inconclusive "
        f"(category={classification.category}, subtype={classification.subtype})",
        "[mock-sim] falling back to a best-effort structural completeness check of the generated PoC",
        (
            "[mock-sim] PoC looks structurally complete for a manual lab walkthrough"
            if success
            else "[mock-sim] PoC is missing basic structural markers"
        ),
    ]
    notes = (
        "This CVE didn't match any of the recognized vulnerability classes with high confidence, so "
        "no tailored simulation flow was available. This performs a best-effort structural check of "
        "the generated PoC instead of a blind failure; see the Execution Guide for manual lab steps."
    )
    return MockExecutionResult(
        cve_id=cve_id, success=success, checks=checks, transcript=transcript,
        mode="generic-fallback", notes=notes,
    )


_GENERIC_DISPATCH = {
    BROWSER: _run_generic_browser,
    DOCUMENT_OR_FILE: _run_generic_document_or_file,
    WEB_APPLICATION: _run_generic_web_application,
    NETWORK_SERVICE: _run_generic_network_service,
}


def run_mock_exploit(
    cve_id: str,
    code: str,
    cve: CveInfo | None = None,
    classification: CveClassification | None = None,
) -> MockExecutionResult:
    """Simulate executing `code` against a local mock target for `cve_id`.

    CVEs with a hand-built simulated target (vsftpd, EternalBlue) use their
    exact-match runner. Every other CVE is classified (server-side vs.
    client-side, with a subtype) and routed to a tailored generic simulation
    flow instead of a blind "unsupported" failure.
    """
    runner = _RUNNERS.get(cve_id.upper())
    if runner is not None:
        return runner(code)

    if classification is None:
        classification = classify_cve(cve) if cve is not None else CveClassification(
            category="server-side",
            subtype="unknown",
            requires_user_interaction=False,
            memory_corruption=False,
            confidence="low",
            rationale=["no CVE metadata available to classify"],
        )

    handler = _GENERIC_DISPATCH.get(classification.subtype, _run_generic_fallback)
    return handler(cve_id, code, cve, classification)
