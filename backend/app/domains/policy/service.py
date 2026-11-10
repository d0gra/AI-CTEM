"""Policy installation and evaluation."""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.domains.policy import rules, views
from app.domains.policy.defaults import DEFAULT_POLICIES
from app.models import Policy, PolicyEvaluation, PolicyException

MAX_STORED_VIOLATIONS = 200


def install_default_policies(db: Session, organization_id: uuid.UUID) -> None:
    for spec in DEFAULT_POLICIES:
        db.add(Policy(organization_id=organization_id, **spec))
    db.flush()


def _active_exceptions(db: Session, policy_id: uuid.UUID) -> set[uuid.UUID]:
    return set(db.execute(
        select(PolicyException.entity_id).where(
            PolicyException.policy_id == policy_id, PolicyException.status == "approved",
            PolicyException.expires_at > utcnow(),
        )
    ).scalars())


def evaluate_policy(db: Session, policy: Policy, *, entity_views: list | None = None) -> PolicyEvaluation:
    if entity_views is None:
        entity_views = views.asset_views(db) if policy.entity_type == "asset" else views.finding_views(db)
    exempt_ids = _active_exceptions(db, policy.id)
    fields = rules.referenced_fields(policy.condition)
    total = passed = failed = exempt = 0
    violations: list[dict] = []
    for entity, view in entity_views:
        if not rules.evaluate(policy.scope or {}, view):
            continue
        total += 1
        if rules.evaluate(policy.condition, view):
            passed += 1
        elif entity.id in exempt_ids:
            exempt += 1
        else:
            failed += 1
            if len(violations) < MAX_STORED_VIOLATIONS:
                violations.append({
                    "entity_id": str(entity.id),
                    "label": getattr(entity, "name", None) or getattr(entity, "title", ""),
                    "observed": {f: rules.resolve(view, f) for f in fields},
                })
    status = "not_applicable" if total == 0 else ("compliant" if failed == 0 else "non_compliant")
    evaluation = PolicyEvaluation(
        organization_id=policy.organization_id, policy_id=policy.id, evaluated_at=utcnow(), total=total,
        passed=passed, failed=failed, exempt=exempt, status=status, violations=violations,
    )
    policy.last_evaluated_at = evaluation.evaluated_at
    db.add(evaluation)
    db.flush()
    return evaluation


def evaluate_all(db: Session) -> list[PolicyEvaluation]:
    policies = list(db.execute(select(Policy).where(Policy.enabled)).scalars())
    asset_views = views.asset_views(db) if any(p.entity_type == "asset" for p in policies) else []
    finding_views = views.finding_views(db) if any(p.entity_type == "finding" for p in policies) else []
    return [
        evaluate_policy(db, p, entity_views=asset_views if p.entity_type == "asset" else finding_views)
        for p in policies
    ]
