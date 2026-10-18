"""Command-line entry point: run the full pipeline for a CVE and print a summary.

    uv run cve-pipeline CVE-2011-2523
"""

from __future__ import annotations

import sys

from cve_pipeline.pipeline import run_pipeline


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: cve-pipeline <CVE-ID>")
        raise SystemExit(1)

    cve_id = sys.argv[1]
    result = run_pipeline(cve_id)

    print(f"\nPipeline complete for {result.cve_id}\n")
    for stage in result.stages:
        print(f"[{stage.seconds:>5.2f}s] {stage.name}")
    output_dir = result.stages[-1].data.get("output_dir")
    print(f"\nArtifacts written to: {output_dir}")


if __name__ == "__main__":
    main()
