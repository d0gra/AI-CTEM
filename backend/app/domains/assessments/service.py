"""Assessment orchestration: engine registry, run lifecycle and the job handler.

An *engine* is a function that receives an `EngineContext` and reports assets and findings
through it. The context enforces authorized scope, tracks what was observed (for retest
reconciliation) and supports dry-run, in which the engine plans but performs no network I/O.
"""

import shutil
import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal
from app.core.errors import Conflict, ValidationFailed
from app.db.base import utcnow
from app.domains.assets import scope as scope_service
from app.domains.assets.service import AssetSpec, link_assets, upsert_asset
from app.domains.audit import service as audit
from app.domains.findings import service as findings
from app.domains.risk import service as risk
from app.models import Assessment, AssessmentRun, AssessmentTarget, Asset, Finding, Integration
from app.workers.queue import JobContext, PermanentJobError, enqueue, job_handler


class NoConfig(BaseModel):
    pass


@dataclass
class EngineSpec:
    kind: str
    name: str
    description: str
    module: str  # navigation module the engine belongs to
    run: Callable[["EngineContext"], None]
    config_model: type[BaseModel] = NoConfig
    target_kinds: tuple[str, ...] = ()  # accepted target kinds; empty = no targets
    active: bool = False  # sends traffic to the target beyond passive/public sources
    requires_tool: str | None = None  # external binary
    requires_connector: str | None = None  # integration connector key
    version_args: tuple[str, ...] = ("--version",)


ENGINES: dict[str, EngineSpec] = {}


def register(spec: EngineSpec) -> EngineSpec:
    ENGINES[spec.kind] = spec
    return spec


def tool_status(spec: EngineSpec) -> dict:
    """Whether the engine's external tool is installed on this worker, with its version."""
    if not spec.requires_tool:
        return {"required": None, "available": True, "version": None}
    path = shutil.which(spec.requires_tool)
    if not path:
        return {"required": spec.requires_tool, "available": False, "version": None}
    version = None
    try:
        out = subprocess.run([path, *spec.version_args], capture_output=True, text=True, timeout=10)  # noqa: S603
        import re

        text_out = re.sub(r"\x1b\[[0-9;]*m", "", out.stdout + "\n" + out.stderr)
        lines = [ln.strip() for ln in text_out.splitlines() if ln.strip()]
        version = next((ln for ln in lines if any(ch.isdigit() for ch in ln) and "WARN" not in ln.upper()), None)
    except (OSError, subprocess.SubprocessError):
        pass
    return {"required": spec.requires_tool, "available": True, "version": (version or "")[:120] or None}


@dataclass
class EngineContext:
    db: Session
    job: JobContext
    assessment: Assessment
    run: AssessmentRun
    spec: EngineSpec
    config: BaseModel
    targets: list[AssessmentTarget]
    integration: Integration | None = None
    observed_findings: set[uuid.UUID] = field(default_factory=set)
    touched_assets: set[uuid.UUID] = field(default_factory=set)
    complete_assets: set[uuid.UUID] = field(default_factory=set)
    stats: dict = field(default_factory=lambda: {"assets_created": 0, "assets_seen": 0, "findings_created": 0,
                                                 "findings_seen": 0, "requests": 0, "skipped": []})
    plan: list[str] = field(default_factory=list)

    @property
    def dry_run(self) -> bool:
        return self.run.dry_run

    @property
    def source(self) -> str:
        return self.spec.kind

    def scope(self, target: str, *, active: bool | None = None) -> scope_service.ScopeDecision:
        return scope_service.check_scope(self.db, target, active=self.spec.active if active is None else active)

    def planned(self, action: str) -> None:
        self.plan.append(action)

    def skip(self, target: str, reason: str) -> None:
        self.stats["skipped"].append({"target": target, "reason": reason})

    def asset(self, spec: AssetSpec) -> Asset:
        asset, created = upsert_asset(self.db, spec, source=self.source, job_id=self.job.job_id)
        self.stats["assets_created" if created else "assets_seen"] += 1
        self.touched_assets.add(asset.id)
        return asset

    def link(self, source: Asset, target: Asset, rel_type: str, *, evidence: dict | None = None,
             confidence: float = 1.0) -> None:
        if source.id != target.id:
            link_assets(self.db, source, target, rel_type, source=self.source, evidence=evidence, confidence=confidence)

    def finding(self, item: findings.FindingInput) -> Finding:
        item.source = item.source or self.source
        finding, created = findings.ingest(self.db, item, run_id=self.run.id)
        self.stats["findings_created" if created else "findings_seen"] += 1
        self.observed_findings.add(finding.id)
        self.touched_assets.add(item.asset.id)
        return finding

    def mark_complete(self, asset: Asset) -> None:
        """Declare that this run fully assessed `asset`, enabling retest reconciliation for it."""
        self.complete_assets.add(asset.id)

    def checkpoint(self) -> None:
        self.job.checkpoint()


def validate_definition(db: Session, kind: str, config: dict, targets: list[dict],
                        integration_id: uuid.UUID | None) -> tuple[EngineSpec, BaseModel, list[dict]]:
    spec = ENGINES.get(kind)
    if spec is None:
        raise ValidationFailed(f"Unknown assessment kind {kind!r}", details={"kinds": sorted(ENGINES)})
    try:
        parsed = spec.config_model.model_validate(config or {})
    except ValidationError as exc:
        raise ValidationFailed("Invalid assessment configuration", details={
            "issues": [{"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in exc.errors()]}) from exc
    if spec.target_kinds and not targets:
        raise ValidationFailed(f"This assessment requires at least one target of kind: {', '.join(spec.target_kinds)}")
    if len(targets) > 200:
        raise ValidationFailed("At most 200 targets per assessment")
    normalised = []
    for target in targets:
        kind_, value = target.get("kind"), str(target.get("value", "")).strip()
        if kind_ not in spec.target_kinds:
            raise ValidationFailed(f"Target kind {kind_!r} is not accepted by this assessment")
        if not value:
            raise ValidationFailed("Target value must not be empty")
        if kind_ != "asset":
            scope_service.check_scope(db, value, active=spec.active)  # refuse out-of-scope definitions early
        normalised.append({"kind": kind_, "value": value, "asset_id": target.get("asset_id")})
    if spec.requires_connector:
        integration = db.get(Integration, integration_id) if integration_id else None
        if integration is None or integration.connector != spec.requires_connector:
            raise ValidationFailed(f"This assessment requires a {spec.requires_connector} integration")
        if not integration.enabled:
            raise ValidationFailed("The selected integration is disabled")
    return spec, parsed, normalised


def start_run(db: Session, assessment: Assessment, principal: Principal | None, *, dry_run: bool = False,
              retest_of_finding_id: uuid.UUID | None = None) -> AssessmentRun:
    if assessment.kind not in ENGINES:
        raise ValidationFailed(f"Assessment kind {assessment.kind!r} is no longer available")
    active = db.execute(
        select(AssessmentRun.id).where(AssessmentRun.assessment_id == assessment.id,
                                       AssessmentRun.status.in_(("queued", "running")))
    ).first()
    if active:
        raise Conflict("This assessment already has a run in progress", details={"run_id": str(active[0])})
    run = AssessmentRun(organization_id=assessment.organization_id, assessment_id=assessment.id, dry_run=dry_run,
                        retest_of_finding_id=retest_of_finding_id,
                        triggered_by_user_id=principal.user_id if principal else None)
    db.add(run)
    db.flush()
    job = enqueue(db, organization_id=assessment.organization_id, job_type="assessment.run",
                  config={"run_id": str(run.id)}, idempotency_key=f"assessment:{assessment.id}",
                  created_by_user_id=principal.user_id if principal else None, max_attempts=1)
    run.job_id = job.id
    audit.record(db, organization_id=assessment.organization_id, action="assessment.run_started",
                 actor_user_id=principal.user_id if principal else None,
                 actor_email=principal.email if principal else "scheduler", entity_type="assessment",
                 entity_id=assessment.id, data={"run_id": str(run.id), "kind": assessment.kind, "dry_run": dry_run})
    db.flush()
    return run


@job_handler("assessment.run")
def run_assessment_job(job: JobContext, db: Session) -> dict:
    run = db.get(AssessmentRun, uuid.UUID(job.config["run_id"]))
    if run is None:
        raise PermanentJobError("Assessment run no longer exists")
    assessment = db.get(Assessment, run.assessment_id)
    assert assessment is not None
    spec = ENGINES.get(assessment.kind)
    if spec is None:
        raise PermanentJobError(f"Unknown assessment kind {assessment.kind}")
    tool = tool_status(spec)
    if not tool["available"] and not run.dry_run:
        raise PermanentJobError(f"Required tool '{spec.requires_tool}' is not installed on this worker")
    run.status, run.started_at = "running", utcnow()
    db.commit()
    targets = list(db.execute(select(AssessmentTarget).where(AssessmentTarget.assessment_id == assessment.id)).scalars())
    integration = db.get(Integration, assessment.integration_id) if assessment.integration_id else None
    if spec.requires_connector and (integration is None or not integration.enabled):
        raise PermanentJobError("The integration used by this assessment is missing or disabled")
    ctx = EngineContext(db=db, job=job, assessment=assessment, run=run, spec=spec,
                        config=spec.config_model.model_validate(assessment.config or {}), targets=targets,
                        integration=integration)
    spec.run(ctx)
    db.flush()
    reconciliation = {"verified_remediated": 0, "not_observed": 0}
    if not run.dry_run:
        reconciliation = findings.reconcile_unobserved(
            db, source=spec.kind, asset_ids=ctx.complete_assets, observed=ctx.observed_findings, run_id=run.id)
        risk.refresh_asset_risk(db, ctx.touched_assets)
    run.status, run.finished_at = "succeeded", utcnow()
    run.summary = {**ctx.stats, **reconciliation, "dry_run": run.dry_run, "plan": ctx.plan[:500],
                   "tool_version": tool["version"]}
    if assessment.schedule_interval_minutes:
        assessment.next_run_at = utcnow() + timedelta(minutes=assessment.schedule_interval_minutes)
    if not run.dry_run and (ctx.stats["findings_created"] or ctx.stats["assets_created"]
                            or reconciliation["verified_remediated"]):
        enqueue(db, organization_id=assessment.organization_id, job_type="attack_paths.compute",
                idempotency_key="attack_paths.compute")
    return {k: v for k, v in run.summary.items() if k != "plan"}
