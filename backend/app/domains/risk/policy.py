"""Organization risk policy: the tunable parameters of the risk engine."""

import uuid

from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from app.models import Organization


class RiskThresholds(BaseModel):
    critical: float = Field(default=75, ge=1, le=100)
    high: float = Field(default=50, ge=1, le=100)
    medium: float = Field(default=25, ge=1, le=100)
    low: float = Field(default=10, ge=0, le=100)

    @model_validator(mode="after")
    def _ordered(self) -> "RiskThresholds":
        if not (self.critical > self.high > self.medium > self.low):
            raise ValueError("Thresholds must be strictly descending: critical > high > medium > low")
        return self


class RiskPolicy(BaseModel):
    version: int = 1
    thresholds: RiskThresholds = RiskThresholds()
    # Multipliers in (0, 1]: how much each context reduces likelihood or impact.
    exposure_factor: dict[str, float] = {"internet": 1.0, "internal": 0.7, "private": 0.55, "unknown": 0.75}
    criticality_factor: dict[str, float] = {"critical": 1.0, "high": 0.85, "medium": 0.7, "low": 0.5}
    sensitivity_bonus: dict[str, float] = {"restricted": 0.15, "confidential": 0.1, "internal": 0.0,
                                           "public": 0.0, "unknown": 0.0}
    confidence_factor: dict[str, float] = {"confirmed": 1.0, "firm": 0.9, "tentative": 0.65}
    # Additive escalators (points on the 0-100 scale).
    attack_path_points: dict[str, float] = {"verified": 10, "probable": 6, "theoretical": 3}
    privileged_identity_points: float = 5
    ai_autonomy_points: float = 6
    ai_unapproved_tools_points: float = 6
    ai_sensitive_data_points: float = 5
    ai_tenant_isolation_points: float = 6
    # Floors: minimum score when the stated condition holds.
    kev_internet_floor: float = Field(default=80, ge=0, le=100)
    kev_floor: float = Field(default=60, ge=0, le=100)
    # Remediation SLA in hours by risk level.
    sla_hours: dict[str, int] = {"critical": 168, "high": 720, "medium": 2160, "low": 4320}
    # AI governance inputs used by shadow-AI detection.
    approved_ai_providers: list[str] = []
    risk_acceptance_max_days: int = Field(default=180, ge=1, le=730)


def load_policy(db: Session, organization_id: uuid.UUID) -> RiskPolicy:
    org = db.get(Organization, organization_id)
    raw = (org.settings or {}).get("risk_policy") if org else None
    return RiskPolicy.model_validate(raw) if raw else RiskPolicy()


def save_policy(db: Session, organization_id: uuid.UUID, policy: RiskPolicy) -> RiskPolicy:
    org = db.get(Organization, organization_id)
    assert org is not None
    current = load_policy(db, organization_id)
    policy.version = current.version + 1
    org.settings = {**(org.settings or {}), "risk_policy": policy.model_dump()}
    return policy
