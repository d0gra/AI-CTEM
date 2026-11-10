"""Attack path analysis over the asset graph.

The graph's nodes are assets and its edges are recorded asset relationships. An attack path is
a route from an *entry point* (an internet-exposed asset, or a data source marked untrusted)
to a *target* (a critical asset or one holding sensitive data).

Every edge of a path is an evidence-backed relationship, and a path is only reported when at
least one open finding on it gives the attacker a foothold. Each hop is graded:

  verified     the node the attacker moves from has a confirmed high/critical finding and the
               relationship is authoritative (confidence >= 0.9)
  probable     a medium+ finding with firm/confirmed confidence and relationship confidence >= 0.6
  theoretical  the relationship exists but nothing demonstrates the step is exploitable

A path's classification is that of its weakest hop.
"""

import hashlib
import heapq
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.domains.notifications.service import notify
from app.models import Asset, AssetRelationship, AttackPath, AttackPathEdge, AttackPathNode, Finding
from app.models.asset import AI_ASSET_TYPES
from app.models.finding import OPEN_STATUSES

RANK = {"theoretical": 1, "probable": 2, "verified": 3}
COST = {"verified": 1.0, "probable": 2.0, "theoretical": 4.0}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_DEPTH = 7
MAX_PATHS = 300

# relationship type -> list of (direction, technique, description of what the attacker does)
# direction "forward": attacker at source reaches target; "reverse": attacker at target reaches source.
TRAVERSAL: dict[str, list[tuple[str, str | None, str]]] = {
    "EXPOSES": [("forward", "T1190", "reach the exposed service")],
    "RESOLVES_TO": [("forward", None, "reach the host the name resolves to")],
    "CONTAINS": [("forward", None, "reach a contained resource")],
    "CONNECTS_TO": [("forward", "T1021", "use the existing network connection")],
    "RUNS_ON": [("forward", "T1611", "break out to the underlying host"),
                ("reverse", "T1059", "control the workload from its host")],
    "AUTHENTICATES_TO": [("forward", "T1078", "reuse the credentials it authenticates with")],
    "CAN_ASSUME": [("forward", "T1548", "assume the trusted identity")],
    "HAS_PERMISSION": [("forward", "T1530", "use granted permissions on the resource")],
    "DEPENDS_ON": [("reverse", "T1195", "compromise a dependent system through its dependency")],
    "TRUSTS": [("reverse", "T1199", "abuse the trust relationship")],
    "RETRIEVES_FROM": [("forward", "T1213", "read data through the retrieval path"),
                       ("reverse", "AML.T0051.001", "inject instructions through retrieved content")],
    "INVOKES_TOOL": [("forward", "AML.T0053", "drive the tool through the agent")],
    "PROCESSES_DATA": [("forward", "T1005", "access the data it processes")],
}
PASS_THROUGH_TYPES = {"identity", "ip_address", "dns_record", "domain", "subdomain"}


@dataclass
class Step:
    relationship: AssetRelationship
    src: uuid.UUID
    dst: uuid.UUID
    technique: str | None
    action: str
    level: str
    enabling_finding: Finding | None


@dataclass
class Candidate:
    nodes: list[uuid.UUID]
    steps: list[Step] = field(default_factory=list)


def _best_finding(findings: list[Finding]) -> Finding | None:
    return max(findings, key=lambda f: (f.confidence == "confirmed", SEV_RANK.get(f.severity, 0), f.risk_score), default=None)


def _node_level(asset: Asset, findings: list[Finding], is_entry: bool) -> tuple[str, Finding | None]:
    best = _best_finding(findings)
    if best is not None:
        sev = SEV_RANK.get(best.severity, 0)
        if best.confidence == "confirmed" and sev >= 3:
            return "verified", best
        if best.confidence in ("confirmed", "firm") and sev >= 2:
            return "probable", best
        return "theoretical", best
    if asset.type in PASS_THROUGH_TYPES and not is_entry:
        return "verified", None  # holding an identity or resolving a name needs no further weakness
    return "theoretical", None


def _edge_level(rel: AssetRelationship) -> str:
    return "verified" if rel.confidence >= 0.9 else ("probable" if rel.confidence >= 0.6 else "theoretical")


def _is_entry(asset: Asset) -> bool:
    if asset.type in ("certificate", "ip_address", "dns_record", "package"):
        return False
    return asset.exposure == "internet" or bool((asset.attributes or {}).get("untrusted_content"))


def _is_target(asset: Asset) -> bool:
    return asset.criticality == "critical" or asset.data_sensitivity in ("restricted", "confidential")


def find_paths(assets: dict[uuid.UUID, Asset], relationships: list[AssetRelationship],
               findings_by_asset: dict[uuid.UUID, list[Finding]]) -> list[Candidate]:
    adjacency: dict[uuid.UUID, list[tuple[uuid.UUID, AssetRelationship, str | None, str]]] = {}
    for rel in relationships:
        if rel.source_asset_id not in assets or rel.target_asset_id not in assets:
            continue
        for direction, technique, action in TRAVERSAL.get(rel.type, []):
            a, b = (rel.source_asset_id, rel.target_asset_id) if direction == "forward" else (rel.target_asset_id, rel.source_asset_id)
            adjacency.setdefault(a, []).append((b, rel, technique, action))
    results: list[Candidate] = []
    for entry_id, entry in assets.items():
        if not _is_entry(entry) or entry_id not in adjacency:
            continue
        # Lowest-cost route from this entry to every reachable node (Dijkstra, bounded depth).
        best: dict[uuid.UUID, float] = {entry_id: 0.0}
        counter = 0
        heap: list[tuple[float, int, Candidate]] = [(0.0, counter, Candidate(nodes=[entry_id]))]
        while heap:
            cost, _, cand = heapq.heappop(heap)
            current = cand.nodes[-1]
            if cost > best.get(current, float("inf")):
                continue
            if len(cand.nodes) > 1 and _is_target(assets[current]) and any(s.enabling_finding for s in cand.steps):
                results.append(cand)
            if len(cand.nodes) > MAX_DEPTH:
                continue
            node_level, enabling = _node_level(assets[current], findings_by_asset.get(current, []), len(cand.nodes) == 1)
            for nxt, rel, technique, action in adjacency.get(current, []):
                if nxt in cand.nodes:
                    continue
                level = min(node_level, _edge_level(rel), key=lambda lv: RANK[lv])
                new_cost = cost + COST[level]
                if new_cost >= best.get(nxt, float("inf")):
                    continue
                best[nxt] = new_cost
                counter += 1
                step = Step(rel, current, nxt, technique, action, level, enabling)
                heapq.heappush(heap, (new_cost, counter, Candidate(nodes=[*cand.nodes, nxt], steps=[*cand.steps, step])))
    return results


def _classify(cand: Candidate) -> str:
    return min((s.level for s in cand.steps), key=lambda lv: RANK[lv])


def _score(cand: Candidate, target: Asset, classification: str) -> tuple[float, str, float]:
    class_factor = {"verified": 1.0, "probable": 0.75, "theoretical": 0.45}[classification]
    target_factor = 1.0 if target.criticality == "critical" else 0.85
    if target.data_sensitivity == "restricted":
        target_factor = min(1.0, target_factor + 0.1)
    length_factor = 0.95 ** max(0, len(cand.steps) - 1)
    score = round(100 * class_factor * target_factor * length_factor, 1)
    severity = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    levels = [RANK[s.level] for s in cand.steps]
    confidence = round(sum(levels) / (3 * len(levels)), 2)
    return score, severity, confidence


def _crosses_boundary(prev: Asset, cur: Asset) -> bool:
    rank = {"internet": 3, "internal": 2, "private": 1, "unknown": 0}
    return (rank[prev.exposure] > rank[cur.exposure] and cur.exposure != "unknown") or (
        prev.environment != cur.environment and "unknown" not in (prev.environment, cur.environment)
    ) or (cur.type == "identity" and prev.type != "identity") or (
        cur.type in AI_ASSET_TYPES and prev.type not in AI_ASSET_TYPES)


def compute(db: Session, organization_id: uuid.UUID) -> dict:
    assets = {a.id: a for a in db.execute(select(Asset).where(Asset.status != "retired")).scalars()}
    relationships = list(db.execute(select(AssetRelationship)).scalars())
    findings_by_asset: dict[uuid.UUID, list[Finding]] = {}
    for f in db.execute(select(Finding).where(Finding.status.in_(OPEN_STATUSES))).scalars():
        findings_by_asset.setdefault(f.asset_id, []).append(f)
    candidates = find_paths(assets, relationships, findings_by_asset)
    scored = []
    for cand in candidates:
        classification = _classify(cand)
        target = assets[cand.nodes[-1]]
        scored.append((cand, classification, *_score(cand, target, classification)))
    scored.sort(key=lambda row: row[2], reverse=True)
    scored = scored[:MAX_PATHS]

    now = utcnow()
    existing = {p.fingerprint: p for p in db.execute(select(AttackPath)).scalars()}
    seen: set[str] = set()
    created = 0
    enabling_ids: set[uuid.UUID] = set()
    for cand, classification, score, severity, confidence in scored:
        fingerprint = hashlib.sha256("|".join(str(n) for n in cand.nodes).encode()).hexdigest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        entry, target = assets[cand.nodes[0]], assets[cand.nodes[-1]]
        involves_ai = any(assets[n].type in AI_ASSET_TYPES for n in cand.nodes)
        path_findings: dict[uuid.UUID, Finding] = {}
        for step in cand.steps:
            if step.enabling_finding:
                path_findings[step.enabling_finding.id] = step.enabling_finding
        enabling_ids.update(path_findings)
        conditions = [
            f"From {assets[s.src].name}, the attacker must {s.action} ({s.relationship.type} -> {assets[s.dst].name})"
            + (f"; enabled by finding: {s.enabling_finding.title}" if s.enabling_finding else "; no demonstrated weakness on this step")
            for s in cand.steps
        ]
        opportunities = [{"type": "fix_finding", "finding_id": str(f.id), "title": f.title, "remediation": f.remediation[:500]}
                         for f in path_findings.values()]
        for s in cand.steps:
            if s.relationship.type in ("HAS_PERMISSION", "CAN_ASSUME", "INVOKES_TOOL", "TRUSTS"):
                opportunities.append({"type": "reduce_privilege", "relationship_id": str(s.relationship.id),
                                      "title": f"Remove or narrow {s.relationship.type} from {assets[s.relationship.source_asset_id].name} "
                                               f"to {assets[s.relationship.target_asset_id].name}"})
        impact = (f"Compromise of {target.name} ({target.type}, criticality {target.criticality}, "
                  f"data sensitivity {target.data_sensitivity}).")
        path = existing.get(fingerprint)
        if path is None:
            path = AttackPath(organization_id=organization_id, fingerprint=fingerprint, first_seen_at=now,
                              entry_asset_id=entry.id, target_asset_id=target.id, title="", classification=classification,
                              confidence=confidence, score=score, severity=severity, last_computed_at=now)
            db.add(path)
            created += 1
            is_new = True
        else:
            is_new = path.status != "active"
            path.nodes.clear()
            path.edges.clear()
            db.flush()
        path.title = f"{entry.name} -> {target.name} ({len(cand.steps)} step{'s' if len(cand.steps) != 1 else ''})"[:600]
        path.classification, path.confidence, path.score, path.severity = classification, confidence, score, severity
        path.involves_ai, path.business_impact, path.status, path.last_computed_at = involves_ai, impact, "active", now
        path.required_conditions, path.remediation_opportunities = conditions, opportunities
        for position, node_id in enumerate(cand.nodes):
            asset = assets[node_id]
            path.nodes.append(AttackPathNode(
                organization_id=organization_id, position=position, asset_id=asset.id, label=asset.name[:512],
                node_type=asset.type,
                crosses_trust_boundary=position > 0 and _crosses_boundary(assets[cand.nodes[position - 1]], asset),
                finding_ids=[str(f.id) for f in sorted(findings_by_asset.get(node_id, []), key=lambda f: -f.risk_score)[:5]],
            ))
        for position, step in enumerate(cand.steps):
            path.edges.append(AttackPathEdge(
                organization_id=organization_id, position=position, relationship_id=step.relationship.id,
                relationship_type=step.relationship.type, technique=step.technique, condition=conditions[position],
                evidence_level=step.level, enabling_finding_id=step.enabling_finding.id if step.enabling_finding else None,
            ))
        db.flush()
        if is_new and severity == "critical":
            notify(db, organization_id=organization_id, event_type="attack_path.critical", severity="critical",
                   title=f"Critical attack path: {path.title}", body=impact, entity_type="attack_path", entity_id=path.id)
    resolved = 0
    for fingerprint, path in existing.items():
        if fingerprint not in seen and path.status == "active":
            path.status = "resolved"
            resolved += 1
    db.flush()
    # Attack-path position is a risk input: rescore the findings that enable (or stopped enabling) paths.
    from app.domains.risk import service as risk

    rescored = risk.recalculate_all(db, organization_id) if (created or resolved or enabling_ids) else {"changed": 0}
    return {"paths": len(seen), "created": created, "resolved": resolved, "findings_rescored": rescored.get("changed", 0)}
