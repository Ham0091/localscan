"""Shared finding schema helpers for LocalScan modules and reporting."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

VALID_SEVERITIES = frozenset({"Critical", "High", "Medium", "Low", "Info"})
VALID_CONFIDENCE = frozenset({"High", "Medium", "Low"})
REQUIRED_KEYS = ("name", "severity", "description", "recommendation", "confidence")


def normalize_finding(finding: Any, module_name: str = "unknown") -> Dict[str, Any]:
    """Return a validated finding dict with a stable schema."""
    if not isinstance(finding, dict):
        return {
            "name": f"Malformed Finding ({module_name})",
            "severity": "Info",
            "description": (
                f"A non-dict finding was returned by '{module_name}': {repr(finding)[:200]}"
            ),
            "recommendation": "Check scanner.log for details.",
            "confidence": "Low",
        }

    out: Dict[str, Any] = dict(finding)

    if not out.get("name"):
        out["name"] = f"Unnamed Finding ({module_name})"
    if not out.get("severity"):
        out["severity"] = "Info"
    if not out.get("description"):
        out["description"] = "No description provided."
    if not out.get("recommendation"):
        out["recommendation"] = "No recommendation provided."
    if not out.get("confidence"):
        out["confidence"] = "Medium"

    if out["severity"] not in VALID_SEVERITIES:
        out["_original_severity"] = out["severity"]
        out["severity"] = "Info"

    if out["confidence"] not in VALID_CONFIDENCE:
        out["_original_confidence"] = out["confidence"]
        out["confidence"] = "Medium"

    normalized: Dict[str, Any] = {k: out[k] for k in REQUIRED_KEYS}
    for key, value in out.items():
        if key not in normalized:
            normalized[key] = value
    return normalized


def normalize_findings(findings: Iterable[Any], module_name: str) -> List[Dict[str, Any]]:
    """Normalize a module finding list into a stable list of dicts."""
    return [normalize_finding(f, module_name) for f in (findings or [])]
