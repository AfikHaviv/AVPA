"""Orchestrates the CVE -> LLM exploit-generation pipeline and records each stage's
output so both the CLI and the UI can show what happened at every step.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cve_pipeline.config import PROJECT_ROOT, get_settings
from cve_pipeline.cve_classifier import CveClassification, classify_cve
from cve_pipeline.cve_client import CveInfo, fetch_cve
from cve_pipeline.llm_client import LlmClient
from cve_pipeline.mock_runner import run_mock_exploit

OUTPUT_DIR = PROJECT_ROOT / "output"


@dataclass
class StageResult:
    name: str
    seconds: float
    data: dict = field(default_factory=dict)


@dataclass
class PipelineResult:
    cve_id: str
    stages: list[StageResult]

    def as_dict(self) -> dict:
        return {"cve_id": self.cve_id, "stages": [asdict(s) for s in self.stages]}


def _timed(name: str, fn):
    start = time.perf_counter()
    result = fn()
    return StageResult(name=name, seconds=round(time.perf_counter() - start, 2)), result


def run_pipeline(cve_id: str) -> PipelineResult:
    settings = get_settings()
    stages: list[StageResult] = []

    stage, cve = _timed("Fetch CVE", lambda: fetch_cve(cve_id, settings.nvd_api_key))
    stage.data = {"cve": asdict(cve)}
    stages.append(stage)

    stage, classification = _timed("Classify CVE", lambda: classify_cve(cve))
    stage.data = {"classification": classification.as_dict()}
    stages.append(stage)

    client = LlmClient(settings.hf_token, settings.hf_model_id)

    stage, artifacts = _timed(
        "Generate & Explain Payload (LLM)", lambda: client.generate_artifacts(cve, classification)
    )
    stage.data = {
        "prompt": artifacts.prompt,
        "filetype": artifacts.filetype,
        "code": artifacts.code,
        "breakdown_markdown": artifacts.breakdown_markdown,
        "execution_guide_markdown": artifacts.execution_guide_markdown,
        "model": client.model_id,
    }
    stages.append(stage)

    stage, report = _timed(
        "Mock Execute (Simulated Target)",
        lambda: run_mock_exploit(cve.cve_id, artifacts.code, cve, classification),
    )
    stage.data = {"report": report.as_dict()}
    stages.append(stage)

    stage, saved_dir = _timed(
        "Save Artifacts", lambda: _save_artifacts(cve, classification, artifacts, report)
    )
    stage.data = {"output_dir": str(saved_dir)}
    stages.append(stage)

    return PipelineResult(cve_id=cve.cve_id, stages=stages)


def _save_artifacts(
    cve: CveInfo, classification: CveClassification, artifacts, report
) -> Path:
    out_dir = OUTPUT_DIR / cve.cve_id
    out_dir.mkdir(parents=True, exist_ok=True)

    ext = {"msf_rc": "rc", "html": "html", "js": "js"}.get(artifacts.filetype, "py")
    (out_dir / f"exploit.{ext}").write_text(artifacts.code, encoding="utf-8")
    (out_dir / "breakdown.md").write_text(artifacts.breakdown_markdown, encoding="utf-8")
    (out_dir / "execution_guide.md").write_text(artifacts.execution_guide_markdown, encoding="utf-8")
    (out_dir / "prompt.txt").write_text(artifacts.prompt, encoding="utf-8")
    (out_dir / "classification.json").write_text(
        json.dumps(classification.as_dict(), indent=2), encoding="utf-8"
    )
    (out_dir / "mock_execution_report.json").write_text(
        json.dumps(report.as_dict(), indent=2), encoding="utf-8"
    )
    return out_dir
