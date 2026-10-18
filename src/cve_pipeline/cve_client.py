"""Fetches CVE details from the NVD (National Vulnerability Database) REST API."""

from __future__ import annotations

from dataclasses import dataclass

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CveInfo:
    cve_id: str
    description: str
    cvss_score: float | None
    cvss_vector: str | None
    severity: str | None
    cwe_ids: list[str]
    affected_products: list[str]
    references: list[str]

    def as_prompt_context(self) -> str:
        return (
            f"CVE ID: {self.cve_id}\n"
            f"Description: {self.description}\n"
            f"CVSS score/severity: {self.cvss_score} / {self.severity}\n"
            f"CVSS vector: {self.cvss_vector}\n"
            f"CWE(s): {', '.join(self.cwe_ids) or 'unknown'}\n"
            f"Affected products (CPE): {', '.join(self.affected_products[:8]) or 'unknown'}\n"
            f"References: {', '.join(self.references[:5])}"
        )


def fetch_cve(cve_id: str, api_key: str | None = None) -> CveInfo:
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(NVD_API_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
    resp.raise_for_status()
    payload = resp.json()

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        raise ValueError(f"NVD returned no results for {cve_id}")

    cve = vulnerabilities[0]["cve"]

    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "No description available.",
    )

    metrics = cve.get("metrics", {})
    cvss_score = cvss_vector = severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            entry = metrics[key][0]
            cvss_score = entry["cvssData"].get("baseScore")
            cvss_vector = entry["cvssData"].get("vectorString")
            severity = entry.get("baseSeverity") or entry["cvssData"].get("baseSeverity")
            break

    cwe_ids = [
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d["lang"] == "en"
    ]

    affected_products = [
        match["criteria"]
        for config in cve.get("configurations", [])
        for node in config.get("nodes", [])
        for match in node.get("cpeMatch", [])
        if match.get("vulnerable")
    ]

    references = [r["url"] for r in cve.get("references", [])]

    return CveInfo(
        cve_id=cve["id"],
        description=description,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        severity=severity,
        cwe_ids=cwe_ids,
        affected_products=affected_products,
        references=references,
    )
