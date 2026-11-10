"""Unified risk engine (pure functions; no I/O).

The score is deliberately not an average of its inputs:

    likelihood = threat x exposure-dampening x evidence-confidence        (0..1)
    impact     = technical severity x asset-impact-dampening              (0..1)
    base       = 100 x likelihood x impact
    score      = min(100, max(floors, base + contextual escalators))

Each input is kept separate and reported in the breakdown so an analyst can see exactly why a
finding received its priority. CVSS, EPSS and KEV are independent inputs: CVSS feeds severity,
EPSS and KEV feed threat likelihood, and KEV additionally sets a floor.
"""

from dataclasses import dataclass, field

from app.domains.risk.policy import RiskPolicy

SEVERITY_BASE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.5}
LEVELS = ("critical", "high", "medium", "low", "info")


@dataclass
class RiskInputs:
    severity: str
    confidence: str = "firm"
    cvss_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    exploit_available: bool | None = None
    has_vulnerability_context: bool = False
    exposure: str = "unknown"
    asset_criticality: str = "medium"
    data_sensitivity: str = "unknown"
    attack_path_classification: str | None = None  # strongest path the finding enables
    privileged_identity: bool = False
    ai_autonomous: bool = False
    ai_unapproved_high_impact_tools: int = 0
    ai_sensitive_data: bool = False
    ai_tenant_isolation_missing: bool = False


@dataclass
class RiskResult:
    score: float
    level: str
    breakdown: dict = field(default_factory=dict)


def level_for(score: float, policy: RiskPolicy) -> str:
    t = policy.thresholds
    if score >= t.critical:
        return "critical"
    if score >= t.high:
        return "high"
    if score >= t.medium:
        return "medium"
    if score >= t.low:
        return "low"
    return "info"


def _threat(i: RiskInputs) -> tuple[float, str]:
    if i.kev:
        return 1.0, "Listed in CISA KEV: exploitation in the wild is confirmed"
    if i.exploit_available:
        return 0.85, "A public exploit is available"
    if i.epss_percentile is not None:
        value = 0.4 + 0.6 * max(0.0, min(1.0, i.epss_percentile))
        return value, f"EPSS percentile {i.epss_percentile:.2f} (probability {i.epss_score or 0:.4f})"
    if i.epss_score is not None:
        return 0.4 + 0.6 * max(0.0, min(1.0, i.epss_score)), f"EPSS probability {i.epss_score:.4f}"
    if i.has_vulnerability_context:
        return 0.6, "No exploitation intelligence available for this vulnerability"
    return 0.8, "Weakness without CVE context; exploitation intelligence does not apply"


def score(i: RiskInputs, policy: RiskPolicy) -> RiskResult:
    severity_value = i.cvss_score if i.cvss_score is not None else SEVERITY_BASE.get(i.severity, 0.5)
    severity = max(0.0, min(10.0, severity_value)) / 10
    threat, threat_reason = _threat(i)
    exposure = policy.exposure_factor.get(i.exposure, policy.exposure_factor["unknown"])
    confidence = policy.confidence_factor.get(i.confidence, 0.9)
    criticality = policy.criticality_factor.get(i.asset_criticality, 0.7)
    asset_impact = min(1.0, criticality + policy.sensitivity_bonus.get(i.data_sensitivity, 0.0))

    likelihood = threat * (0.5 + 0.5 * exposure) * confidence
    impact = severity * (0.6 + 0.4 * asset_impact)
    base = 100 * likelihood * impact

    escalators: list[dict] = []

    def add(name: str, points: float, reason: str) -> None:
        if points:
            escalators.append({"name": name, "points": points, "reason": reason})

    if i.attack_path_classification:
        add("attack_path", policy.attack_path_points.get(i.attack_path_classification, 0),
            f"Enables a {i.attack_path_classification} attack path")
    if i.privileged_identity:
        add("privileged_identity", policy.privileged_identity_points, "Affects a privileged identity")
    if i.ai_autonomous:
        add("ai_autonomy", policy.ai_autonomy_points, "AI agent acts autonomously without human approval")
    if i.ai_unapproved_high_impact_tools:
        add("ai_tool_permissions", policy.ai_unapproved_tools_points,
            f"{i.ai_unapproved_high_impact_tools} high-impact tool(s) invocable without approval")
    if i.ai_sensitive_data:
        add("ai_data_access", policy.ai_sensitive_data_points, "AI system processes sensitive data")
    if i.ai_tenant_isolation_missing:
        add("ai_tenant_isolation", policy.ai_tenant_isolation_points, "Tenant isolation is not enforced")

    escalated = base + sum(e["points"] for e in escalators)
    floors: list[dict] = []
    if i.kev and i.exposure == "internet":
        floors.append({"name": "kev_internet", "minimum": policy.kev_internet_floor,
                       "reason": "Known-exploited vulnerability on an internet-exposed asset"})
    elif i.kev:
        floors.append({"name": "kev", "minimum": policy.kev_floor, "reason": "Known-exploited vulnerability"})
    final = min(100.0, max([escalated, *[f["minimum"] for f in floors]]))
    final = round(final, 1)
    level = level_for(final, policy)
    if i.severity == "info" and not escalators and not floors:
        level = "info"

    return RiskResult(score=final, level=level, breakdown={
        "policy_version": policy.version,
        "formula": "min(100, max(floors, 100 * likelihood * impact + escalators))",
        "likelihood": {
            "value": round(likelihood, 4),
            "factors": [
                {"name": "threat", "value": round(threat, 3), "reason": threat_reason},
                {"name": "exposure", "value": exposure, "input": i.exposure,
                 "reason": f"Asset exposure is {i.exposure}; applied as 0.5 + 0.5 x factor"},
                {"name": "confidence", "value": confidence, "input": i.confidence,
                 "reason": f"Evidence confidence is {i.confidence}"},
            ],
        },
        "impact": {
            "value": round(impact, 4),
            "factors": [
                {"name": "technical_severity", "value": round(severity, 3),
                 "input": i.cvss_score if i.cvss_score is not None else i.severity,
                 "reason": "CVSS base score" if i.cvss_score is not None else "Engine-assigned severity"},
                {"name": "asset_impact", "value": round(asset_impact, 3),
                 "input": {"criticality": i.asset_criticality, "data_sensitivity": i.data_sensitivity},
                 "reason": "Asset criticality plus data-sensitivity bonus; applied as 0.6 + 0.4 x factor"},
            ],
        },
        "base_score": round(base, 1),
        "escalators": escalators,
        "floors": floors,
        "inputs": {"cvss": i.cvss_score, "epss": i.epss_score, "epss_percentile": i.epss_percentile, "kev": i.kev,
                   "exploit_available": i.exploit_available},
        "score": final,
        "level": level,
    })
