"""Outbound notification channels: generic webhook, Slack, Microsoft Teams, email."""

import hashlib
import hmac
import json
import time

from pydantic import BaseModel, Field, HttpUrl

from app.core.config import get_settings
from app.core.email import send_email
from app.core.net import safe_fetch
from app.core.security import decrypt_secret
from app.integrations.base import ConnectionResult, ConnectorSpec, register_connector, run_test


class WebhookConfig(BaseModel):
    url: HttpUrl


class WebhookCredentials(BaseModel):
    signing_secret: str = Field(default="", description="Optional HMAC-SHA256 signing secret")


class NoCredentials(BaseModel):
    pass


def _credentials(integration) -> dict:
    return json.loads(decrypt_secret(integration.credentials_encrypted)) if integration.credentials_encrypted else {}


def _post(url: str, payload: dict, headers: dict | None = None) -> None:
    body = json.dumps(payload, default=str).encode()
    result = safe_fetch("POST", url, content=body, allow_private=get_settings().allow_private_webhooks,
                        headers={"Content-Type": "application/json", **(headers or {})}, max_redirects=0, timeout=10)
    if result.status_code >= 300:
        raise RuntimeError(f"Endpoint returned HTTP {result.status_code}")


def _payload(notification) -> dict:
    return {"id": str(notification.id), "event_type": notification.event_type, "severity": notification.severity,
            "title": notification.title, "body": notification.body, "entity_type": notification.entity_type,
            "entity_id": str(notification.entity_id) if notification.entity_id else None,
            "created_at": notification.created_at.isoformat()}


def _link(notification) -> str:
    base = get_settings().public_base_url
    routes = {"finding": "findings", "asset": "assets", "attack_path": "attack-paths"}
    if notification.entity_type in routes and notification.entity_id:
        return f"{base}/{routes[notification.entity_type]}/{notification.entity_id}"
    return base


def send_webhook(url: str, secret: str, notification) -> None:
    payload = _payload(notification)
    headers = {}
    if secret:
        timestamp = str(int(time.time()))
        body = json.dumps(payload, default=str)
        signature = hmac.new(secret.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256).hexdigest()
        headers = {"X-CTEM-Timestamp": timestamp, "X-CTEM-Signature": f"sha256={signature}"}
        result = safe_fetch("POST", url, content=body.encode(), allow_private=get_settings().allow_private_webhooks,
                            headers={"Content-Type": "application/json", **headers}, max_redirects=0, timeout=10)
        if result.status_code >= 300:
            raise RuntimeError(f"Endpoint returned HTTP {result.status_code}")
        return
    _post(url, payload)


def send_slack(url: str, notification) -> None:
    _post(url, {"text": f"[{notification.severity.upper()}] {notification.title}", "blocks": [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*[{notification.severity.upper()}] {notification.title}*\n{notification.body[:1500]}"}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"{notification.event_type} · <{_link(notification)}|Open in CTEM>"}]},
    ]})


def send_teams(url: str, notification) -> None:
    _post(url, {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {"type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "body": [{"type": "TextBlock", "weight": "Bolder", "wrap": True,
                              "text": f"[{notification.severity.upper()}] {notification.title}"},
                             {"type": "TextBlock", "wrap": True, "text": notification.body[:1500] or notification.event_type}],
                    "actions": [{"type": "Action.OpenUrl", "title": "Open in CTEM", "url": _link(notification)}]},
    }]})


def send(rule, integration, notification) -> None:
    if rule.channel == "email":
        if not rule.email_to:
            raise RuntimeError("Rule has no email recipient")
        send_email(rule.email_to, f"[CTEM][{notification.severity.upper()}] {notification.title}",
                   f"{notification.title}\n\n{notification.body}\n\n{_link(notification)}\n")
        return
    if integration is None or not integration.enabled:
        raise RuntimeError("Rule's integration is missing or disabled")
    url = str(integration.config.get("url", ""))
    if rule.channel == "webhook":
        send_webhook(url, _credentials(integration).get("signing_secret", ""), notification)
    elif rule.channel == "slack":
        send_slack(url, notification)
    elif rule.channel == "teams":
        send_teams(url, notification)
    else:
        raise RuntimeError(f"Unknown channel {rule.channel}")


class _TestNotification:
    """Shape-compatible stand-in used for connection tests."""

    def __init__(self):
        import uuid
        from datetime import UTC, datetime

        self.id, self.event_type, self.severity = uuid.uuid4(), "integration.test", "info"
        self.title, self.body = "CTEM connection test", "This message confirms the integration is configured correctly."
        self.entity_type, self.entity_id, self.created_at = None, None, datetime.now(UTC)


def _tester(sender):
    def test(config: BaseModel, credentials: BaseModel) -> ConnectionResult:
        def go() -> ConnectionResult:
            sender(str(config.url), credentials, _TestNotification())  # type: ignore[attr-defined]
            return ConnectionResult(True, "Test message accepted by the endpoint")

        return run_test(go)

    return test


register_connector(ConnectorSpec(
    key="webhook", name="Webhook", category="notification", config_model=WebhookConfig,
    credentials_model=WebhookCredentials,
    description="POSTs notification JSON to an HTTPS endpoint, optionally signed with HMAC-SHA256.",
    test=_tester(lambda url, creds, n: send_webhook(url, getattr(creds, "signing_secret", ""), n)),
))
register_connector(ConnectorSpec(
    key="slack", name="Slack (incoming webhook)", category="notification", config_model=WebhookConfig,
    credentials_model=NoCredentials, description="Posts Block Kit messages to a Slack incoming webhook.",
    test=_tester(lambda url, creds, n: send_slack(url, n)),
))
register_connector(ConnectorSpec(
    key="teams", name="Microsoft Teams (workflow webhook)", category="notification", config_model=WebhookConfig,
    credentials_model=NoCredentials, description="Posts Adaptive Cards to a Teams workflow webhook.",
    test=_tester(lambda url, creds, n: send_teams(url, n)),
))
