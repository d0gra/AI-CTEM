"""Threat-intelligence and vulnerability-data sources.

Every record keeps its source, original identifier, source URL and timestamps. Nothing here
is synthesised: if a source is unreachable the sync fails and the failure is recorded in
`intel_sync_state`.
"""

from collections.abc import Iterable
from datetime import UTC, datetime

import httpx
import yaml
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import utcnow
from app.integrations.base import ApiError, ConnectorSpec, HttpApi, register_connector
from app.models import IntelSyncState, ThreatIntelligence, Vulnerability

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1"
ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

TRANSPORT: httpx.BaseTransport | None = None  # replaced in tests with a mock transport


def _api(base_url: str, **kw) -> HttpApi:
    return HttpApi(base_url, transport=TRANSPORT, **kw)


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _state(db: Session, source: str) -> IntelSyncState:
    state = db.get(IntelSyncState, source)
    if state is None:
        state = IntelSyncState(source=source)
        db.add(state)
        db.flush()
    return state


def _upsert_intel(db: Session, rows: list[dict]) -> None:
    now = utcnow()
    for start in range(0, len(rows), 500):
        chunk = [{**r, "fetched_at": now} for r in rows[start:start + 500]]
        stmt = insert(ThreatIntelligence).values(chunk)
        db.execute(stmt.on_conflict_do_update(
            index_elements=["source", "external_id"],
            set_={c: stmt.excluded[c] for c in ("kind", "title", "description", "data", "references", "source_url",
                                                 "published_at", "source_modified_at", "fetched_at", "confidence")},
        ))


def _upsert_vulns(db: Session, rows: list[dict], update_columns: Iterable[str]) -> None:
    columns = list(update_columns)
    for start in range(0, len(rows), 500):
        stmt = insert(Vulnerability).values(rows[start:start + 500])
        db.execute(stmt.on_conflict_do_update(index_elements=["external_id"], set_={c: stmt.excluded[c] for c in columns}))


def sync_kev(db: Session) -> dict:
    state = _state(db, "cisa_kev")
    doc = _api(KEV_URL).request("GET", KEV_URL, max_bytes=30 * 1024 * 1024).json()
    version = doc.get("catalogVersion")
    entries = doc.get("vulnerabilities") or []
    if not entries:
        raise ApiError("CISA KEV catalogue returned no entries", "upstream")
    if version and state.cursor.get("catalog_version") == version:
        return {"source": "cisa_kev", "records": len(entries), "changed": False, "catalog_version": version}
    vulns, intel = [], []
    for e in entries:
        cve = e["cveID"].upper()
        added, due = _dt(e.get("dateAdded")), _dt(e.get("dueDate"))
        ransomware = str(e.get("knownRansomwareCampaignUse", "")).lower() == "known"
        title = f"{e.get('vendorProject', '')} {e.get('product', '')}: {e.get('vulnerabilityName', '')}".strip()
        vulns.append({"external_id": cve, "source": "cisa_kev", "title": title[:512],
                      "description": e.get("shortDescription", ""), "kev": True, "kev_date_added": added,
                      "kev_due_date": due, "kev_ransomware_use": ransomware, "exploit_available": True,
                      "remediation": e.get("requiredAction", "")})
        intel.append({"source": "cisa_kev", "external_id": cve, "kind": "exploited_vulnerability", "title": title[:600],
                      "description": e.get("shortDescription", ""), "confidence": "high", "source_url": KEV_URL,
                      "published_at": added, "source_modified_at": added,
                      "references": [u for u in str(e.get("notes", "")).replace(";", " ").split() if u.startswith("http")][:10],
                      "data": {"vendor": e.get("vendorProject"), "product": e.get("product"), "due_date": e.get("dueDate"),
                               "ransomware_use": ransomware, "required_action": e.get("requiredAction"), "cwes": e.get("cwes")}})
    # Preserve richer descriptions already loaded from NVD/OSV: only KEV-owned columns are overwritten.
    _upsert_vulns(db, vulns, ("kev", "kev_date_added", "kev_due_date", "kev_ransomware_use", "exploit_available"))
    _upsert_intel(db, intel)
    state.cursor = {"catalog_version": version, "date_released": doc.get("dateReleased")}
    return {"source": "cisa_kev", "records": len(entries), "changed": True, "catalog_version": version}


def tracked_cves(db: Session, *, missing: str | None = None, limit: int = 5000) -> list[str]:
    stmt = select(Vulnerability.external_id).where(Vulnerability.external_id.like("CVE-%"))
    if missing == "cvss":
        stmt = stmt.where(Vulnerability.cvss_score.is_(None))
    return list(db.execute(stmt.order_by(Vulnerability.updated_at.desc()).limit(limit)).scalars())


def sync_epss(db: Session, cve_ids: list[str] | None = None) -> dict:
    """Refresh EPSS for CVEs in the catalogue (the full EPSS set is ~250k rows and is not mirrored)."""
    cve_ids = cve_ids if cve_ids is not None else tracked_cves(db)
    api, updated, date = _api(EPSS_API, min_interval=0.2), 0, None
    for start in range(0, len(cve_ids), 100):
        batch = cve_ids[start:start + 100]
        doc = api.get_json("/epss?cve=" + ",".join(batch))
        for row in doc.get("data") or []:
            vuln = db.execute(select(Vulnerability).where(Vulnerability.external_id == row["cve"].upper())).scalar_one_or_none()
            if vuln is not None:
                vuln.epss_score, vuln.epss_percentile = float(row["epss"]), float(row["percentile"])
                vuln.epss_date = _dt(row.get("date"))
                date = row.get("date") or date
                updated += 1
    return {"source": "epss", "requested": len(cve_ids), "records": updated, "score_date": date}


def _nvd_metrics(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        primary = next((m for m in entries if m.get("type") == "Primary"), entries[0] if entries else None)
        if primary:
            data = primary.get("cvssData") or {}
            return data.get("baseScore"), data.get("vectorString"), version
    return None, None, None


def apply_nvd_record(vuln: Vulnerability, cve: dict) -> None:
    descriptions = cve.get("descriptions") or []
    vuln.description = next((d["value"] for d in descriptions if d.get("lang") == "en"), vuln.description)
    vuln.cvss_score, vuln.cvss_vector, vuln.cvss_version = _nvd_metrics(cve.get("metrics") or {})
    cwes = {d["value"] for w in cve.get("weaknesses") or [] for d in w.get("description") or [] if d.get("value", "").startswith("CWE-")}
    vuln.cwe_ids = sorted(cwes)
    vuln.references = [{"url": r.get("url"), "tags": r.get("tags") or []} for r in (cve.get("references") or [])[:25]]
    if any("Exploit" in (r.get("tags") or []) for r in cve.get("references") or []):
        vuln.exploit_available = True
    vuln.published_at, vuln.modified_at = _dt(cve.get("published")), _dt(cve.get("lastModified"))
    affected = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable"):
                    affected.append({"cpe": match.get("criteria"), "version_end_excluding": match.get("versionEndExcluding"),
                                     "version_end_including": match.get("versionEndIncluding")})
    vuln.affected = affected[:50]
    vuln.fixed_versions = sorted({a["version_end_excluding"] for a in affected if a.get("version_end_excluding")})[:20]
    if vuln.source in ("scanner", "cisa_kev"):
        vuln.source = "nvd"
    if not vuln.title:
        vuln.title = vuln.description[:200]


def sync_nvd(db: Session, cve_ids: list[str] | None = None, *, limit: int = 40) -> dict:
    """Enrich catalogue CVEs that lack CVSS data from the NVD API (rate limited by NVD)."""
    settings = get_settings()
    cve_ids = (cve_ids if cve_ids is not None else tracked_cves(db, missing="cvss"))[:limit]
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    api = _api(NVD_API, headers=headers, min_interval=0.7 if settings.nvd_api_key else 6.5)
    updated, missing = 0, []
    for cve_id in cve_ids:
        doc = api.get_json(f"?cveId={cve_id}")
        items = doc.get("vulnerabilities") or []
        vuln = db.execute(select(Vulnerability).where(Vulnerability.external_id == cve_id)).scalar_one_or_none()
        if not items or vuln is None:
            missing.append(cve_id)
            continue
        apply_nvd_record(vuln, items[0]["cve"])
        updated += 1
        db.flush()
    return {"source": "nvd", "requested": len(cve_ids), "records": updated, "not_found": missing[:20]}


def _osv_severity(vuln: dict) -> tuple[float | None, str | None]:
    for sev in vuln.get("severity") or []:
        if sev.get("type", "").startswith("CVSS") and sev.get("score"):
            return None, sev["score"]
    return None, None


def osv_to_vulnerability(db: Session, osv: dict) -> Vulnerability:
    """Store an OSV record. The CVE alias is preferred as identity so KEV/EPSS data correlates."""
    aliases = [a for a in osv.get("aliases") or [] if isinstance(a, str)]
    cve = next((a.upper() for a in aliases if a.upper().startswith("CVE-")), None)
    external_id = cve or osv["id"]
    vuln = db.execute(select(Vulnerability).where(Vulnerability.external_id == external_id)).scalar_one_or_none()
    if vuln is None:
        vuln = Vulnerability(external_id=external_id, source="osv")
        db.add(vuln)
    vuln.aliases = sorted({osv["id"], *aliases} - {external_id})[:20]
    vuln.title = vuln.title or (osv.get("summary") or "")[:512]
    vuln.description = vuln.description or osv.get("details") or ""
    _, vector = _osv_severity(osv)
    vuln.cvss_vector = vuln.cvss_vector or vector
    db_specific = osv.get("database_specific") or {}
    vuln.cwe_ids = vuln.cwe_ids or [c for c in db_specific.get("cwe_ids") or [] if isinstance(c, str)][:10]
    fixed, affected = set(), []
    for a in osv.get("affected") or []:
        pkg = a.get("package") or {}
        affected.append({"ecosystem": pkg.get("ecosystem"), "package": pkg.get("name")})
        for r in a.get("ranges") or []:
            fixed.update(e["fixed"] for e in r.get("events") or [] if e.get("fixed"))
    vuln.affected = vuln.affected or affected[:50]
    vuln.fixed_versions = vuln.fixed_versions or sorted(fixed)[:20]
    vuln.references = vuln.references or [{"url": r.get("url"), "tags": [r.get("type")]} for r in (osv.get("references") or [])[:25]]
    vuln.published_at = vuln.published_at or _dt(osv.get("published"))
    vuln.modified_at = _dt(osv.get("modified")) or vuln.modified_at
    if vuln.source == "scanner":
        vuln.source = "osv"
    db.flush()
    return vuln


def osv_query(packages: list[dict]) -> list[list[str]]:
    """Batch-query OSV. `packages` items: {name, version, ecosystem} or {purl, version}.
    Returns, per package, the list of matching OSV ids."""
    api, out = _api(OSV_API, min_interval=0.1), []
    for start in range(0, len(packages), 500):
        queries = []
        for p in packages[start:start + 500]:
            if p.get("ecosystem") and p.get("name"):
                queries.append({"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]})
            else:
                queries.append({"package": {"purl": p["purl"].split("@")[0]}, "version": p["version"]})
        doc = api.request("POST", "/querybatch", json_body={"queries": queries}).json()
        out.extend([[v["id"] for v in r.get("vulns") or []] for r in doc.get("results") or []])
    return out


def osv_get(osv_id: str) -> dict:
    return _api(OSV_API, min_interval=0.05).get_json(f"/vulns/{osv_id}")


def sync_atlas(db: Session) -> dict:
    raw = _api(ATLAS_URL).request("GET", ATLAS_URL, max_bytes=20 * 1024 * 1024)
    doc = yaml.safe_load(raw.body)
    matrix = (doc.get("matrices") or [{}])[0]
    rows = []
    for kind, items in (("tactic", matrix.get("tactics")), ("technique", matrix.get("techniques")),
                        ("mitigation", matrix.get("mitigations")), ("case_study", doc.get("case-studies"))):
        for item in items or []:
            if not item.get("id"):
                continue
            rows.append({"source": "mitre_atlas", "external_id": item["id"], "kind": kind, "title": str(item.get("name", ""))[:600],
                         "description": str(item.get("description") or item.get("summary") or ""), "confidence": "high",
                         "source_url": f"https://atlas.mitre.org/{'studies' if kind == 'case_study' else kind + 's'}/{item['id']}",
                         "published_at": None, "source_modified_at": None, "references": [],
                         "data": {"tactics": item.get("tactics"), "subtechnique_of": item.get("subtechnique-of"),
                                  "atlas_version": doc.get("version")}})
    if not rows:
        raise ApiError("ATLAS data contained no objects", "upstream")
    _upsert_intel(db, rows)
    _state(db, "mitre_atlas").cursor = {"version": doc.get("version")}
    return {"source": "mitre_atlas", "records": len(rows), "version": doc.get("version")}


def sync_attack(db: Session) -> dict:
    doc = _api(ATTACK_URL, timeout=120).request("GET", ATTACK_URL, max_bytes=120 * 1024 * 1024).json()
    rows = []
    kinds = {"attack-pattern": "technique", "x-mitre-tactic": "tactic", "course-of-action": "mitigation"}
    for obj in doc.get("objects") or []:
        kind = kinds.get(obj.get("type"))
        if not kind or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in obj.get("external_references") or [] if r.get("source_name") == "mitre-attack"), None)
        if not ext or not ext.get("external_id"):
            continue
        rows.append({"source": "mitre_attack", "external_id": ext["external_id"], "kind": kind, "title": obj.get("name", "")[:600],
                     "description": obj.get("description", ""), "confidence": "high", "source_url": ext.get("url", ATTACK_URL),
                     "published_at": _dt(obj.get("created")), "source_modified_at": _dt(obj.get("modified")), "references": [],
                     "data": {"tactics": [p.get("phase_name") for p in obj.get("kill_chain_phases") or []],
                              "platforms": obj.get("x_mitre_platforms"), "is_subtechnique": obj.get("x_mitre_is_subtechnique")}})
    if not rows:
        raise ApiError("ATT&CK bundle contained no techniques", "upstream")
    _upsert_intel(db, rows)
    return {"source": "mitre_attack", "records": len(rows)}


SOURCES = {"cisa_kev": sync_kev, "epss": sync_epss, "nvd": sync_nvd, "mitre_atlas": sync_atlas, "mitre_attack": sync_attack}


def run_sync(db: Session, source: str) -> dict:
    """Run one source and record the outcome in intel_sync_state. Failures are re-raised."""
    state = _state(db, source)
    state.last_attempt_at = utcnow()
    db.commit()
    try:
        result = SOURCES[source](db)
    except Exception as exc:
        db.rollback()
        state = _state(db, source)
        state.last_attempt_at, state.last_error = utcnow(), f"{type(exc).__name__}: {exc}"[:1000]
        db.commit()
        raise
    state = _state(db, source)
    state.last_success_at, state.last_error, state.records = utcnow(), None, int(result.get("records", 0))
    db.commit()
    return result


for _key, _name, _desc in (
    ("cisa_kev", "CISA Known Exploited Vulnerabilities", "Full catalogue sync; sets KEV status, due dates and ransomware use."),
    ("epss", "FIRST EPSS", "Exploit prediction scores for CVEs present in the catalogue."),
    ("nvd", "NIST NVD", "CVSS, CWE, references and affected configurations for catalogue CVEs (API 2.0, rate limited)."),
    ("osv", "OSV.dev", "Package vulnerability lookups for SBOM and dependency analysis. Aggregates GitHub Security Advisories."),
    ("mitre_attack", "MITRE ATT&CK (Enterprise)", "Tactics, techniques and mitigations from the official STIX bundle."),
    ("mitre_atlas", "MITRE ATLAS", "Adversarial ML tactics, techniques, mitigations and case studies."),
):
    register_connector(ConnectorSpec(key=_key, name=_name, category="threat_intel", description=_desc, status="reference",
                                     configurable=False, live_validated=False))
