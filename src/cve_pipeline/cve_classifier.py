"""Classifies a CVE as server-side or client-side (with a finer-grained subtype)
from its NVD description, CVSS vector, CWE IDs, and affected products.

Nothing downstream should assume every CVE is a network-service exploit that a
victim never has to interact with. This module gives the mock runner and the
LLM prompt builder a structured signal to branch on instead of guessing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cve_pipeline.cve_client import CveInfo

SERVER = "server-side"
CLIENT = "client-side"

NETWORK_SERVICE = "network_service"
WEB_APPLICATION = "web_application"
BROWSER = "browser"
DOCUMENT_OR_FILE = "document_or_file"
DESKTOP_APPLICATION = "desktop_application"
UNKNOWN = "unknown"


@dataclass
class CveClassification:
    category: str  # "server-side" | "client-side"
    subtype: str
    requires_user_interaction: bool
    memory_corruption: bool
    confidence: str  # "high" | "medium" | "low"
    rationale: list[str] = field(default_factory=list)
    product_hint: str | None = None

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "subtype": self.subtype,
            "requires_user_interaction": self.requires_user_interaction,
            "memory_corruption": self.memory_corruption,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "product_hint": self.product_hint,
        }


_BROWSER_PRODUCTS = {
    "chrome", "chromium", "firefox", "safari", "webkit", "edge", "edgehtml",
    "angle", "v8", "spidermonkey", "javascriptcore", "opera", "brave",
}
_DOCUMENT_PRODUCTS = {
    "acrobat", "acrobat_reader", "reader", "word", "excel", "powerpoint",
    "office", "libreoffice", "openoffice", "foxit", "outlook",
}
# Memory-safety CWEs: a strong signal for client-side/browser or document-parser
# bugs once paired with a matching product or "requires user interaction".
_MEMORY_CORRUPTION_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126",
    "CWE-127", "CWE-131", "CWE-190", "CWE-191", "CWE-369", "CWE-415", "CWE-416",
    "CWE-476", "CWE-590", "CWE-680", "CWE-704", "CWE-787", "CWE-843", "CWE-908",
    "CWE-1021",
}
_WEB_APP_CWES = {
    "CWE-89", "CWE-78", "CWE-77", "CWE-79", "CWE-352", "CWE-434", "CWE-22",
    "CWE-611", "CWE-918", "CWE-502", "CWE-943", "CWE-863", "CWE-284",
}
_MEMORY_CORRUPTION_WORDS = (
    "use-after-free", "use after free", "buffer overflow", "heap overflow",
    "heap-based buffer", "stack-based buffer", "out-of-bounds", "type confusion",
    "double free", "integer overflow", "memory corruption", "uninitialized",
    "null pointer dereference",
)
_BROWSER_WORDS = (
    "browser", "renderer", "sandbox", "crafted html page", "crafted web page",
    "malicious web page", "malicious website", "javascript engine", "webgl",
)
_DOCUMENT_WORDS = (
    "crafted pdf", "crafted document", "malicious document", "crafted file",
    "opening a specially crafted", "crafted office", "email attachment",
)
_NETWORK_SERVICE_WORDS = (
    "ftp", "smb", "ssh", "telnet", "rdp", "smtp", "daemon", "service allows", "protocol",
)


def _extract_cpe_product(cpe: str) -> tuple[str | None, str | None]:
    parts = cpe.split(":")
    if len(parts) >= 5:
        return parts[3] or None, parts[4] or None
    return None, None


def describe_product(cpe: str) -> str:
    """Best-effort human-readable name from a CPE 2.3 string, e.g.
    'cpe:2.3:a:google:chrome:*:*' -> 'Google Chrome'.
    """
    vendor, product = _extract_cpe_product(cpe)
    if not product:
        return cpe
    name = product.replace("_", " ").title()
    if vendor and vendor not in ("*", ""):
        return f"{vendor.replace('_', ' ').title()} {name}"
    return name


def _cvss_flags(vector: str | None) -> dict[str, str]:
    if not vector:
        return {}
    flags: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            key, value = part.split(":", 1)
            flags[key] = value
    return flags


def classify_cve(cve: CveInfo) -> CveClassification:
    description = (cve.description or "").lower()
    cwe_ids = {c.upper() for c in (cve.cwe_ids or [])}
    products = cve.affected_products or []
    product_names = [describe_product(p) for p in products]
    lowered_products = " ".join(p.lower() for p in products)

    flags = _cvss_flags(cve.cvss_vector)
    attack_vector = flags.get("AV")
    requires_ui = flags.get("UI") == "R"

    rationale: list[str] = []

    memory_corruption = bool(cwe_ids & _MEMORY_CORRUPTION_CWES) or any(
        w in description for w in _MEMORY_CORRUPTION_WORDS
    )
    if memory_corruption:
        rationale.append("memory-safety CWE or description keywords indicate a memory-corruption bug")

    is_browser_product = any(b in lowered_products for b in _BROWSER_PRODUCTS) or any(
        w in description for w in _BROWSER_WORDS
    )
    is_document_product = any(d in lowered_products for d in _DOCUMENT_PRODUCTS) or any(
        w in description for w in _DOCUMENT_WORDS
    )
    is_web_app_bug = bool(cwe_ids & _WEB_APP_CWES)
    is_network_service_bug = any(w in description for w in _NETWORK_SERVICE_WORDS) and not is_browser_product

    product_hint = product_names[0] if product_names else None

    if is_browser_product or (memory_corruption and requires_ui):
        category, subtype = CLIENT, BROWSER
        rationale.append(
            "affected product/description matches a browser or JS engine, or a memory-corruption "
            "bug that needs user interaction (a hallmark of client-side exploitation)"
        )
    elif is_document_product:
        category, subtype = CLIENT, DOCUMENT_OR_FILE
        rationale.append("affected product matches a document reader/office suite that a victim must open")
    elif is_web_app_bug and attack_vector == "N" and not requires_ui:
        category, subtype = SERVER, WEB_APPLICATION
        rationale.append(
            "CWE matches a classic server-side web-application weakness (injection/traversal/etc.) "
            "with no user interaction required"
        )
    elif requires_ui and attack_vector in ("N", "A"):
        category, subtype = CLIENT, DESKTOP_APPLICATION
        rationale.append(
            "CVSS requires user interaction over the network/adjacent network, suggesting the victim "
            "must open or run something (client-side), but no specific browser/document product was "
            "recognized"
        )
    elif is_network_service_bug or (attack_vector == "N" and not requires_ui):
        category, subtype = SERVER, NETWORK_SERVICE
        rationale.append(
            "description/CVSS indicate a directly network-reachable service with no victim interaction "
            "required (classic server-side exploitation)"
        )
    else:
        category, subtype = SERVER, UNKNOWN
        rationale.append("no strong client-side signal found; defaulting to generic server-side handling")

    confidence = "high" if (is_browser_product or is_document_product or is_web_app_bug) else (
        "medium" if attack_vector else "low"
    )

    return CveClassification(
        category=category,
        subtype=subtype,
        requires_user_interaction=requires_ui,
        memory_corruption=memory_corruption,
        confidence=confidence,
        rationale=rationale,
        product_hint=product_hint,
    )
