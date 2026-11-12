import json
import uuid

from fastapi import APIRouter
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select

from app.api.deps import Db, Principal, audit_event, require
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.security import decrypt_secret, encrypt_secret
from app.db.base import utcnow
from app.domains.assessments.service import ENGINES, tool_status
from app.domains.notifications.service import notify
from app.integrations.base import CONNECTORS, ConnectorSpec
from app.models import Integration, IntelSyncState

router = APIRouter(prefix="/integrations", tags=["Integrations"])


class IntegrationIn(BaseModel):
    connector: str
    name: str = Field(min_length=2, max_length=200)
    config: dict = {}
    credentials: dict = {}


class IntegrationPatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    config: dict | None = None
    credentials: dict | None = None  # omitted = keep existing secret
    enabled: bool | None = None


def _validate(spec: ConnectorSpec, config: dict, credentials: dict):
    try:
        return spec.config_model.model_validate(config), spec.credentials_model.model_validate(credentials)
    except ValidationError as exc:
        raise ValidationFailed("Invalid integration settings", details={
            "issues": [{"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in exc.errors()]}) from exc


def _spec(key: str) -> ConnectorSpec:
    spec = CONNECTORS.get(key)
    if spec is None or not spec.configurable:
        raise ValidationFailed(f"Connector {key!r} cannot be configured", details={
            "connectors": sorted(k for k, s in CONNECTORS.items() if s.configurable)})
    return spec


def _out(i: Integration) -> dict:
    """Credentials are never returned; only whether a secret is stored."""
    return {"id": i.id, "connector": i.connector, "name": i.name, "config": i.config, "enabled": i.enabled,
            "has_credentials": bool(i.credentials_encrypted), "health": i.health, "last_checked_at": i.last_checked_at,
            "last_error": i.last_error, "last_error_class": i.last_error_class, "last_sync_at": i.last_sync_at,
            "created_at": i.created_at}


def _get(db: Db, integration_id: uuid.UUID) -> Integration:
    i = db.get(Integration, integration_id)
    if i is None:
        raise NotFound("Integration not found")
    return i


@router.get("/catalog")
def catalog(db: Db, _: Principal = require("integrations:read")) -> list[dict]:
    """Every connector the platform knows about, with its real implementation status."""
    sync = {s.source: s for s in db.execute(select(IntelSyncState)).scalars()}
    engines_by_tool = {s.requires_tool: s for s in ENGINES.values() if s.requires_tool}
    out = []
    for spec in sorted(CONNECTORS.values(), key=lambda s: (s.category, s.name)):
        entry = {"key": spec.key, "name": spec.name, "category": spec.category, "description": spec.description,
                 "mode": spec.mode, "import_format": spec.import_format, "configurable": spec.configurable,
                 "required_permissions": spec.required_permissions,
                 "config_schema": spec.config_model.model_json_schema() if spec.configurable else None,
                 "credentials_schema": spec.credentials_model.model_json_schema() if spec.configurable else None}
        if spec.key in engines_by_tool:
            entry["tool"] = tool_status(engines_by_tool[spec.key])
        if spec.key in sync:
            s = sync[spec.key]
            entry["sync"] = {"last_success_at": s.last_success_at, "last_attempt_at": s.last_attempt_at,
                             "last_error": s.last_error, "records": s.records}
        out.append(entry)
    return out


@router.get("")
def list_integrations(db: Db, _: Principal = require("integrations:read")) -> list[dict]:
    return [_out(i) for i in db.execute(select(Integration).order_by(Integration.name)).scalars()]


@router.post("", status_code=201)
def create_integration(body: IntegrationIn, db: Db, principal: Principal = require("integrations:manage")) -> dict:
    spec = _spec(body.connector)
    from app.domains.demo import guard_credentials

    guard_credentials(bool(body.credentials))
    config, credentials = _validate(spec, body.config, body.credentials)
    if db.execute(select(Integration.id).where(Integration.name == body.name)).first():
        raise Conflict("An integration with this name already exists")
    secret = credentials.model_dump(mode="json")
    integration = Integration(organization_id=principal.organization_id, connector=spec.key, name=body.name,
                              config=config.model_dump(mode="json"),
                              credentials_encrypted=encrypt_secret(json.dumps(secret)) if secret else None)
    db.add(integration)
    db.flush()
    audit_event(db, principal, "integration.created", entity_type="integration", entity_id=integration.id,
                data={"connector": spec.key, "name": body.name})
    return _out(integration)


@router.patch("/{integration_id}")
def update_integration(integration_id: uuid.UUID, body: IntegrationPatch, db: Db,
                       principal: Principal = require("integrations:manage")) -> dict:
    integration = _get(db, integration_id)
    from app.domains.demo import guard_credentials

    guard_credentials(bool(body.credentials))
    spec = _spec(integration.connector)
    if body.name:
        integration.name = body.name
    if body.enabled is not None:
        integration.enabled = body.enabled
    if body.config is not None or body.credentials is not None:
        existing = json.loads(decrypt_secret(integration.credentials_encrypted)) if integration.credentials_encrypted else {}
        config, credentials = _validate(spec, body.config if body.config is not None else integration.config,
                                        body.credentials if body.credentials is not None else existing)
        integration.config = config.model_dump(mode="json")
        secret = credentials.model_dump(mode="json")
        integration.credentials_encrypted = encrypt_secret(json.dumps(secret)) if secret else None
        integration.health = "unverified"
    audit_event(db, principal, "integration.updated", entity_type="integration", entity_id=integration.id,
                data={"fields": sorted(body.model_fields_set), "credentials_rotated": body.credentials is not None})
    return _out(integration)


@router.delete("/{integration_id}", status_code=204)
def delete_integration(integration_id: uuid.UUID, db: Db, principal: Principal = require("integrations:manage")) -> None:
    integration = _get(db, integration_id)
    db.delete(integration)
    audit_event(db, principal, "integration.deleted", entity_type="integration", entity_id=integration_id,
                data={"connector": integration.connector})


@router.post("/{integration_id}/test")
def test_integration(integration_id: uuid.UUID, db: Db, principal: Principal = require("integrations:manage")) -> dict:
    integration = _get(db, integration_id)
    spec = _spec(integration.connector)
    if spec.test is None:
        raise ValidationFailed("This connector has no connection test")
    credentials = json.loads(decrypt_secret(integration.credentials_encrypted)) if integration.credentials_encrypted else {}
    config, creds = _validate(spec, integration.config, credentials)
    result = spec.test(config, creds)
    previous = integration.health
    integration.health = "healthy" if result.ok else "error"
    integration.last_checked_at = utcnow()
    integration.last_error = None if result.ok else result.detail[:1000]
    integration.last_error_class = None if result.ok else result.error_class
    if not result.ok and previous != "error":
        notify(db, organization_id=principal.organization_id, event_type="integration.failed", severity="medium",
               title=f"Integration check failed: {integration.name}", body=result.detail[:400],
               entity_type="integration", entity_id=integration.id)
    audit_event(db, principal, "integration.tested", entity_type="integration", entity_id=integration.id,
                outcome="success" if result.ok else "failure", data={"error_class": result.error_class})
    return {"ok": result.ok, "detail": result.detail, "error_class": result.error_class, "metadata": result.metadata,
            "integration": _out(integration)}
