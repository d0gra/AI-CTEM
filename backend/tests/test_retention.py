"""Retention of operational records, and exporting and deleting an organization."""

import json
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app import cli
from app.db.base import utcnow
from app.db.session import system_session
from app.domains.audit import service as audit
from app.domains.platform.retention import purge
from app.models import (
    Asset,
    AssetDiscoveryEvent,
    AuditEvent,
    Finding,
    Job,
    Notification,
    NotificationRead,
    Organization,
    User,
    UserSession,
    UserToken,
)
from app.workers import queue, runner


def _seed(org):
    asset = org.ok("POST", "/assets", json={"type": "api", "identifier": "https://api.acme.test", "name": "Public API", "exposure": "internet"})
    finding = org.ok("POST", "/findings", json={"asset_id": asset["id"], "title": "Missing rate limit", "severity": "medium", "domain": "api"})
    return asset, finding


def _count(db, model, org_id, *where):
    return db.execute(select(func.count()).select_from(model).where(model.organization_id == org_id, *where)).scalar()


def test_retention_removes_only_expired_operational_records(org):
    asset, finding = _seed(org)
    org_id, user_id, now = uuid.UUID(org.org_id), uuid.UUID(org.user_id), utcnow()
    old, recent = now - timedelta(days=400), now - timedelta(days=1)
    with system_session() as db:
        for when, state in ((old, "succeeded"), (old, "dead"), (recent, "succeeded")):
            db.add(Job(organization_id=org_id, type="risk.recalculate", state=state, run_after=when, finished_at=when))
        db.add(Job(organization_id=org_id, type="risk.recalculate", state="queued", run_after=old))  # never finished: not ours to remove
        for when in (old, recent):
            db.add(UserSession(organization_id=org_id, user_id=user_id, token_hash=uuid.uuid4().hex, csrf_token="x", created_at=when,
                               last_seen_at=when, expires_at=when + timedelta(hours=12)))
            db.add(UserToken(organization_id=org_id, user_id=user_id, purpose="password_reset", token_hash=uuid.uuid4().hex,
                             expires_at=when + timedelta(hours=1), created_at=when))
            note = Notification(organization_id=org_id, event_type="finding.created", severity="high", title="t", dedup_key=uuid.uuid4().hex,
                                created_at=when)
            db.add(note)
            db.flush()
            db.add(NotificationRead(organization_id=org_id, notification_id=note.id, user_id=user_id, read_at=when))
            db.add(AssetDiscoveryEvent(organization_id=org_id, asset_id=uuid.UUID(asset["id"]), event_type="observed", source="test", occurred_at=when))
        db.add(AssetDiscoveryEvent(organization_id=org_id, asset_id=uuid.UUID(asset["id"]), event_type="changed", source="test", occurred_at=old))
        db.flush()
        before = {m: _count(db, m, org_id) for m in (Job, UserSession, UserToken, Notification, AssetDiscoveryEvent)}

    with system_session() as db:
        removed = purge(db, org_id)
    assert removed == {"jobs": 2, "sessions": 1, "expired_links": 1, "notifications": 1, "asset_observations": 1}

    with system_session() as db:
        after = {m: _count(db, m, org_id) for m in before}
        assert {m.__name__: before[m] - after[m] for m in before} == {
            "Job": 2, "UserSession": 1, "UserToken": 1, "Notification": 1, "AssetDiscoveryEvent": 1}
        assert _count(db, Job, org_id, Job.state == "queued") >= 1
        assert _count(db, AssetDiscoveryEvent, org_id, AssetDiscoveryEvent.event_type == "changed", AssetDiscoveryEvent.occurred_at == old) == 1
        # The security record is untouched, and the purge itself is on the audit trail, which still verifies.
        assert db.get(Asset, uuid.UUID(asset["id"])) is not None and db.get(Finding, uuid.UUID(finding["id"])) is not None
        event = db.execute(select(AuditEvent).where(AuditEvent.organization_id == org_id, AuditEvent.action == "retention.purged")).scalar_one()
        assert event.data == removed
        assert audit.verify_chain(db, org_id)["valid"]

    with system_session() as db:  # nothing left to do: no second audit entry
        assert purge(db, org_id) == {}
        assert _count(db, AuditEvent, org_id, AuditEvent.action == "retention.purged") == 1
    assert org.get("/assets").status_code == 200  # the session in use is not expired, so it survived


def test_retention_period_of_zero_keeps_everything(org, monkeypatch):
    from app.core.config import get_settings

    org_id, old = uuid.UUID(org.org_id), utcnow() - timedelta(days=4000)
    with system_session() as db:
        db.add(Job(organization_id=org_id, type="risk.recalculate", state="succeeded", run_after=old, finished_at=old))
    monkeypatch.setattr(get_settings(), "retention_jobs_days", 0)
    with system_session() as db:
        assert "jobs" not in purge(db, org_id)
    monkeypatch.setattr(get_settings(), "retention_jobs_days", 1)  # below the scheduler's look-back: clamped, the old job still goes
    with system_session() as db:
        assert purge(db, org_id)["jobs"] == 1


def test_retention_is_scheduled_for_every_organization():
    assert "platform.retention" in queue.registered_job_types()
    assert runner.PERIODIC["platform.retention"] == timedelta(hours=24)


def test_export_then_delete_an_organization(make_org, tmp_path, capsys):
    doomed, kept = make_org("Doomed"), make_org("Kept")
    asset, finding = _seed(doomed)
    kept_asset, _ = _seed(kept)
    with system_session() as db:
        slug = db.get(Organization, uuid.UUID(doomed.org_id)).slug

    out = tmp_path / "export.json"
    cli.export_organization(slug, str(out))
    text = out.read_text()
    doc = json.loads(text)
    assert doc["organization"]["slug"] == slug
    assert [a["identifier"] for a in doc["tables"]["assets"]] == ["https://api.acme.test"]
    assert doc["tables"]["findings"][0]["title"] == "Missing rate limit" and doc["tables"]["audit_events"]
    assert doc["tables"]["users"][0]["email"] == doomed.email
    assert "password_hash" not in text and "token_hash" not in text and "sessions" not in doc["tables"]
    assert all(row["organization_id"] == doomed.org_id for rows in doc["tables"].values() for row in rows)  # nothing from another tenant

    with pytest.raises(SystemExit, match="--confirm"):
        cli.delete_organization(slug, "wrong")
    assert doomed.get("/assets").status_code == 200
    cli.delete_organization(slug, slug)
    assert "Deleted organization" in capsys.readouterr().out

    with system_session() as db:
        assert db.get(Organization, uuid.UUID(doomed.org_id)) is None
        for model in (Asset, Finding, AuditEvent, User, UserSession):
            assert _count(db, model, uuid.UUID(doomed.org_id)) == 0, model.__name__
        assert db.get(Asset, uuid.UUID(kept_asset["id"])) is not None
    assert doomed.get("/assets").status_code == 401
    assert kept.ok("GET", "/assets")["total"] == 1
    with pytest.raises(SystemExit, match="No organization"):
        cli.delete_organization(slug, slug)


def test_retention_removes_old_report_files_and_uploaded_scanner_files(org):
    from app.core import storage
    from app.models import Assessment, Report

    org_id, old = uuid.UUID(org.org_id), utcnow() - timedelta(days=500)
    store = storage.get_storage()
    keys = {name: storage.new_key(org_id, name, "json") for name in ("old-report", "new-report", "old-upload", "new-upload")}
    for key in keys.values():
        store.put(key, b"{}", "application/json")
    with system_session() as db:
        db.add(Report(organization_id=org_id, type="executive", format="json", title="Old", status="ready", storage_key=keys["old-report"], created_at=old))
        db.add(Report(organization_id=org_id, type="executive", format="json", title="New", status="ready", storage_key=keys["new-report"]))
        db.add(Assessment(organization_id=org_id, name="old upload", kind="scanner_import", created_at=old,
                          config={"format": "trivy", "storage_key": keys["old-upload"], "sha256": "0" * 64}))
        db.add(Assessment(organization_id=org_id, name="new upload", kind="scanner_import",
                          config={"format": "trivy", "storage_key": keys["new-upload"], "sha256": "0" * 64}))

    with system_session() as db:
        removed = purge(db, org_id)
    assert removed["reports"] == 1 and removed["uploaded_files"] == 1

    with system_session() as db:
        assert [r.title for r in db.execute(select(Report).where(Report.organization_id == org_id)).scalars()] == ["New"]
        uploads = {a.name: a.config for a in db.execute(select(Assessment).where(Assessment.organization_id == org_id,
                                                                                 Assessment.kind == "scanner_import")).scalars()}
        assert "file_purged_at" in uploads["old upload"] and "file_purged_at" not in uploads["new upload"]  # the record of the upload stays
    for name, gone in (("old-report", True), ("old-upload", True), ("new-report", False), ("new-upload", False)):
        if gone:
            with pytest.raises(Exception):  # noqa: B017, PT011  (the storage backend decides the error type)
                store.get(keys[name])
        else:
            assert store.get(keys[name]) == b"{}"
    with system_session() as db:  # a file already removed is not counted twice
        assert "uploaded_files" not in purge(db, org_id)


def test_repository_analysis_options_drop_parts_of_the_inventory():
    from app.engines.ai.repository import RepositoryConfig, select

    doc = {"assets": [{"type": t, "identifier": t, "ref": f"{t}:{t}"} for t in ("repository", "package", "ai_agent", "mcp_server", "ai_model")],
           "relationships": [{"source": "repository:repository", "target": f"{t}:{t}", "type": "CONTAINS"} for t in ("package", "ai_agent", "ai_model")],
           "findings": [{"asset": f"{t}:{t}", "domain": d} for t, d in (("repository", "secrets"), ("ai_agent", "ai_agent"),
                                                                       ("mcp_server", "ai_mcp"), ("ai_model", "ai_model"), ("repository", "shadow_ai"))]}
    assert select(doc, RepositoryConfig()) is doc
    no_ai = select(doc, RepositoryConfig(ai_discovery=False))
    assert [a["type"] for a in no_ai["assets"]] == ["repository", "package", "mcp_server", "ai_model"]
    assert [f["domain"] for f in no_ai["findings"]] == ["secrets", "ai_mcp", "ai_model"]
    assert [r["target"] for r in no_ai["relationships"]] == ["package:package", "ai_model:ai_model"]
    only_code = select(doc, RepositoryConfig(ai_discovery=False, mcp_configuration=False, model_artifacts=False))
    assert [a["type"] for a in only_code["assets"]] == ["repository", "package"] and [f["domain"] for f in only_code["findings"]] == ["secrets"]
