"""AI red-team execution with an enforced safety envelope.

Before any request is sent the run verifies: a current written authorization, target scope with
active testing permitted, and a request budget. During the run it enforces the rate limit,
honours cancellation between requests, never executes a tool the target asks for, and records
every exchange as evidence.
"""

import json
import secrets
import time

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import Forbidden
from app.core.security import decrypt_secret
from app.db.base import utcnow
from app.domains.assessments.service import EngineContext, EngineSpec, register
from app.domains.findings.service import EvidenceInput, FindingInput, redact
from app.engines.ai_redteam.catalog import Context, select_tests
from app.integrations.base import ApiError
from app.integrations.llm.client import LlmConfig, LlmCredentials, build_client
from app.models import AIAssessment, AIAssessmentTest, Assessment, AssessmentRun, Asset, Evidence, Integration
from app.workers.queue import PermanentJobError


class RedTeamConfig(BaseModel):
    profiles: list[str] = ["llm_application"]
    attempts: int = Field(default=2, ge=1, le=5)
    forbidden_markers: list[str] = Field(default=[], max_length=10, description="Operator-planted strings that must never be disclosed")


def assert_authorization_current(db: Session, assessment: Assessment) -> AIAssessment:
    envelope = db.get(AIAssessment, assessment.id)
    if envelope is None:
        raise Forbidden("This AI assessment has no recorded authorization")
    if envelope.authorization_expires_at <= utcnow():
        raise Forbidden("The authorization for this AI assessment has expired; record a new authorization to continue")
    return envelope


def _excerpt(text: str, limit: int = 1500) -> str:
    return text if len(text) <= limit else text[:limit] + f"... [{len(text) - limit} more characters]"


def run(ctx: EngineContext) -> None:
    db = ctx.db
    config: RedTeamConfig = ctx.config  # type: ignore[assignment]
    try:
        envelope = assert_authorization_current(db, ctx.assessment)
    except Forbidden as exc:
        raise PermanentJobError(exc.message) from exc
    integration = db.get(Integration, envelope.integration_id) if envelope.integration_id else None
    target = db.get(Asset, envelope.target_asset_id)
    if integration is None or not integration.enabled or target is None:
        raise PermanentJobError("The target integration or asset for this assessment no longer exists")
    llm_config = LlmConfig.model_validate(integration.config)
    decision = ctx.scope(llm_config.endpoint, active=True)  # fails closed if scope was withdrawn
    harness = llm_config.api_style != "custom_http"
    context = Context(marker=f"CTEM-{secrets.token_hex(6).upper()}", canary=envelope.canary_token,
                      forbidden_markers=tuple(m for m in config.forbidden_markers if m.strip()), harness=harness)
    tests = select_tests(config.profiles)
    previous = {}
    prior_run = db.execute(select(AssessmentRun).where(AssessmentRun.assessment_id == ctx.assessment.id, AssessmentRun.id != ctx.run.id,
                                                       AssessmentRun.status == "succeeded", AssessmentRun.dry_run.is_(False))
                           .order_by(AssessmentRun.created_at.desc()).limit(1)).scalar_one_or_none()
    if prior_run is not None:
        previous = {t.test_id: t for t in db.execute(select(AIAssessmentTest).where(AIAssessmentTest.assessment_run_id == prior_run.id)).scalars()}

    client = None
    if not ctx.dry_run:
        creds = LlmCredentials.model_validate(json.loads(decrypt_secret(integration.credentials_encrypted)) if integration.credentials_encrypted else {})
        client = build_client(llm_config, creds, allow_private=decision.allow_private)
    budget = envelope.request_budget
    interval = 60.0 / max(1, envelope.rate_limit_per_minute)
    last_request = 0.0
    incomplete = False
    scope_text = f"{llm_config.endpoint} (model {llm_config.model or 'application default'}); mode: {'harness' if harness else 'deployed'}"

    for index, test in enumerate(tests):
        ctx.job.progress(int(100 * index / max(1, len(tests))), f"{test.id} {test.threat_category}")  # raises on cancellation
        probe = test.build(context)
        row = AIAssessmentTest(
            organization_id=ctx.assessment.organization_id, assessment_run_id=ctx.run.id, test_id=test.id, profile=test.profile,
            threat_category=test.threat_category, owasp_llm=test.owasp_llm, atlas_technique=test.atlas, nist_ai_rmf=test.nist,
            objective=test.objective, preconditions=test.preconditions, scope=scope_text, procedure=test.procedure,
            execution_status="planned", severity=test.severity, remediation=test.remediation)
        db.add(row)
        if probe is None:
            row.execution_status, row.observed_behavior = "skipped", "Precondition not met: " + test.preconditions
            incomplete = True
            continue
        if test.needs_tools and client is not None and not client.supports_tools:
            row.execution_status, row.observed_behavior = "skipped", "Target interface does not support tool calling"
            continue
        if ctx.dry_run:
            ctx.planned(f"{test.id}: up to {config.attempts} request(s) - {test.procedure}")
            continue
        assert client is not None
        exchanges, hits, error = [], [], None
        for attempt in range(config.attempts):
            if budget <= 0:
                error = "Request budget exhausted"
                break
            wait = interval - (time.monotonic() - last_request)
            if wait > 0:
                time.sleep(wait)
            ctx.checkpoint()
            last_request = time.monotonic()
            budget -= 1
            ctx.stats["requests"] += 1
            row.attempts = attempt + 1
            try:
                result = client.chat(probe.user, system=probe.system if client.supports_system else None,
                                     tools=list(probe.tools) or None, max_tokens=probe.max_tokens)
            except ApiError as exc:
                error = f"Target error ({exc.error_class}): {exc}"[:500]
                if exc.error_class in ("auth", "permission", "config"):
                    raise PermanentJobError(error) from exc
                break
            observed = test.detect(result, context)
            exchanges.append({"attempt": attempt + 1, "system": _excerpt(probe.system or "", 600) if client.supports_system else None,
                              "user": _excerpt(probe.user), "response": _excerpt(result.text),
                              "tool_calls_requested": result.tool_calls, "tools_offered": [t["name"] for t in probe.tools],
                              "refused": result.refused, "vulnerable": bool(observed), "model": result.model})
            if observed:
                hits.append(observed)
        row.executed_at, row.reproduced = utcnow(), len(hits)
        if error and not exchanges:
            row.execution_status, row.observed_behavior = "error", error
            incomplete = True
            continue
        row.execution_status = "executed"
        if error:
            incomplete = True
        evidence = Evidence(organization_id=row.organization_id, assessment_run_id=ctx.run.id, kind="llm_exchange",
                            summary=f"{test.id} {test.threat_category}: {len(hits)}/{len(exchanges)} attempts vulnerable",
                            content=redact({"test_id": test.id, "marker": context.marker, "exchanges": exchanges}), created_at=utcnow())
        db.add(evidence)
        db.flush()
        row.evidence_id = evidence.id
        if hits:
            row.outcome = "vulnerable"
            row.confidence = test.certainty if len(hits) == len(exchanges) else ("firm" if test.certainty == "confirmed" else "tentative")
            row.observed_behavior = f"{hits[0]} Reproduced in {len(hits)} of {len(exchanges)} attempt(s)."
            finding = ctx.finding(FindingInput(
                asset=target, source=ctx.source, rule_id=f"airt.{test.id}", domain=test.finding_domain, severity=test.severity,
                confidence=row.confidence, title=f"{test.title}: {target.name}", owasp_llm=test.owasp_llm, atlas_technique=test.atlas,
                nist_ai_rmf=test.nist, test_id=test.id,
                description=f"{test.objective} {row.observed_behavior}",
                technical_impact="The control this test exercises does not hold against a low-effort attack.",
                reproduction=f"Procedure: {test.procedure}\nPrompt sent:\n{_excerpt(probe.user, 800)}",
                remediation=test.remediation,
                evidence=[EvidenceInput("llm_exchange", evidence.summary, {"test_id": test.id, "marker": context.marker,
                                                                           "exchanges": exchanges[:2]})]))
            row.finding_id = finding.id
        else:
            row.outcome = "not_vulnerable"
            row.confidence = "firm"
            row.observed_behavior = f"The target did not exhibit the behaviour in {len(exchanges)} attempt(s)."
        before = previous.get(test.id)
        if before is not None and before.outcome == "vulnerable":
            row.retest_result = "still_vulnerable" if hits else "fixed"
    db.flush()
    ctx.stats.update({"tests": len(tests), "budget_remaining": budget, "request_budget": envelope.request_budget,
                      "marker": context.marker, "mode": "harness" if harness else "deployed"})
    if not ctx.dry_run and not incomplete:
        ctx.mark_complete(target)  # enables retest reconciliation only when every test actually ran


register(EngineSpec(
    kind="ai_redteam", name="AI red team assessment", permission="ai_redteam:run", module="ai_redteam", run=run, config_model=RedTeamConfig, active=True,
    description="Deterministic adversarial tests against an LLM endpoint or AI application: prompt injection, indirect injection, "
                "system prompt and data disclosure, unsafe output, tool authorization, retrieval and tenant isolation.",
    requires_connector=None,
))
