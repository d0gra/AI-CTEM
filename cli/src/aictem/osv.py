"""Optional known-vulnerability lookup for pinned packages against OSV (https://osv.dev). Sends package names and versions only."""

from __future__ import annotations

import json
import urllib.request

from aictem import __version__
from aictem.model import Finding

QUERY_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/"
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "User-Agent": f"aictem/{__version__}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": f"aictem/{__version__}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def enrich(report: dict, *, max_details: int = 300) -> int:
    """Add a finding per known vulnerability in a pinned package. Returns the number added."""
    packages = [a for a in report["assets"] if a["type"] == "package" and a["attributes"].get("version")]
    hits: list[tuple[dict, str]] = []
    for start in range(0, len(packages), 500):
        chunk = packages[start:start + 500]
        queries = [{"package": {"name": p["attributes"]["package"], "ecosystem": p["attributes"]["ecosystem"]}, "version": p["attributes"]["version"]}
                   for p in chunk]
        results = _post(QUERY_URL, {"queries": queries}).get("results") or []
        for package, result in zip(chunk, results):
            for vuln in result.get("vulns") or []:
                hits.append((package, vuln["id"]))
    details: dict[str, dict] = {}
    added = 0
    for package, vuln_id in hits:
        if vuln_id not in details and len(details) < max_details:
            try:
                details[vuln_id] = _get(VULN_URL + vuln_id)
            except OSError:
                details[vuln_id] = {}
        doc = details.get(vuln_id, {})
        aliases = doc.get("aliases") or []
        cve = next((a for a in [vuln_id, *aliases] if a.startswith("CVE-")), None)
        sev = SEVERITY.get(str((doc.get("database_specific") or {}).get("severity", "")).upper(), "medium")
        fixed = sorted({e["fixed"] for a in doc.get("affected") or [] for r in a.get("ranges") or [] for e in r.get("events") or [] if "fixed" in e})
        attrs = package["attributes"]
        finding = Finding(
            rule_id=f"osv.{vuln_id}", title=f"{attrs['package']} {attrs['version']}: {doc.get('summary') or vuln_id}"[:300], severity=sev,
            domain="supply_chain", asset=package["ref"], description=(doc.get("details") or "")[:2000], confidence="confirmed",
            remediation=f"Upgrade to {', '.join(fixed[:3])} or later." if fixed else "No fixed version is published; consider an alternative package.",
            file=(attrs.get("declared_in") or [None])[0], discriminator=vuln_id,
            evidence={"vulnerability": vuln_id, "cve": cve, "aliases": aliases[:10], "fixed_versions": fixed[:10]})
        report["findings"].append({k: v for k, v in finding.__dict__.items() if v not in (None, "", {})})
        added += 1
    report["summary"]["vulnerabilities_checked"] = len(packages)
    by_sev: dict[str, int] = {}
    for f in report["findings"]:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    report["summary"]["findings_by_severity"] = by_sev
    return added
