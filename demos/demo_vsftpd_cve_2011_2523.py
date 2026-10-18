"""Test case 1: run the full CVE -> LLM -> mock-execute pipeline for
CVE-2011-2523 (vsftpd 2.3.4 backdoor) and assert it succeeds.

    uv run python demos/demo_vsftpd_cve_2011_2523.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cve_pipeline.pipeline import run_pipeline  # noqa: E402


def main() -> None:
    result = run_pipeline("CVE-2011-2523")
    mock_stage = next(s for s in result.stages if s.name == "Mock Execute (Simulated Target)")
    report = mock_stage.data["report"]

    print(f"CVE: {result.cve_id}")
    for check in report["checks"]:
        mark = "PASS" if check["passed"] else "FAIL"
        print(f"  [{mark}] {check['label']}")
    print()
    print("\n".join(f"  {line}" for line in report["transcript"]))

    if not report["success"]:
        raise SystemExit("\nTest case 1 FAILED: generated payload missing expected markers.")
    print("\nTest case 1 PASSED: pipeline produced a working vsftpd backdoor PoC.")


if __name__ == "__main__":
    main()
