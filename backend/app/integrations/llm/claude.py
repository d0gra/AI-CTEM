"""Claude connection for the platform's AI features.

Two credential sources, both billed to a Claude Console (platform.claude.com) organization:

  api_key   an API key created in the Console, stored encrypted per organization
  server    the API/worker host's own credentials, resolved by the Anthropic SDK in its standard
            order: ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, an `ant auth login` profile, or
            workload identity federation. Nothing is stored in the platform. Allowed only when
            the deployment sets CTEM_ALLOW_SERVER_CLAUDE_CREDENTIALS=true.

claude.ai plans (Pro, Max, Team, Enterprise seats) do not include API access, so they cannot be
used here; this is stated in the UI.
"""

from collections.abc import Callable
from typing import Literal

import anthropic
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.integrations.base import ApiError, ConnectionResult, ConnectorSpec, classify_status, register_connector

DEFAULT_MODEL = "claude-opus-5-5"


class ClaudeConfig(BaseModel):
    credential_source: Literal["api_key", "server"] = "api_key"
    model: str = Field(default=DEFAULT_MODEL, min_length=3, max_length=120)
    effort: Literal["low", "medium", "high"] = "medium"


class ClaudeCredentials(BaseModel):
    api_key: str = ""


def make_client(config: ClaudeConfig, credentials: ClaudeCredentials) -> anthropic.Anthropic:
    if config.credential_source == "server":
        if not get_settings().allow_server_claude_credentials:
            raise ApiError("This deployment does not allow using the server's Claude credentials", "config")
        try:
            return anthropic.Anthropic(max_retries=2, timeout=120.0)  # SDK default credential chain
        except anthropic.AnthropicError as exc:
            raise ApiError(f"No Claude credentials are configured on the server: {exc}", "config") from exc
    if not credentials.api_key:
        raise ApiError("An API key is required", "config")
    return anthropic.Anthropic(api_key=credentials.api_key, max_retries=2, timeout=120.0)


def call[T](fn: Callable[[], T]) -> T:
    """Run an SDK call and translate its errors into classified ApiErrors."""
    try:
        return fn()
    except anthropic.AuthenticationError as exc:
        raise ApiError("Claude rejected the credentials. Check the API key or the server's sign-in.", "auth", 401) from exc
    except anthropic.PermissionDeniedError as exc:
        raise ApiError(f"Permission denied: {exc.message}", "permission", 403) from exc
    except anthropic.NotFoundError as exc:
        raise ApiError(f"Not found: {exc.message}", "config", 404) from exc
    except anthropic.RateLimitError as exc:
        raise ApiError("Claude rate limit reached; try again shortly", "rate_limit", 429) from exc
    except anthropic.BadRequestError as exc:
        message = exc.message
        if "credit balance" in message.lower():
            message = "The Claude Console organization has no API credits. Add credits under Billing in the Console."
        raise ApiError(message, "config", 400) from exc
    except anthropic.APIStatusError as exc:
        raise ApiError(f"Claude API error {exc.status_code}: {exc.message}", classify_status(exc.status_code), exc.status_code) from exc
    except anthropic.APIConnectionError as exc:
        raise ApiError(f"Could not reach the Claude API: {exc}", "network") from exc


def list_models(client: anthropic.Anthropic) -> list[dict]:
    """Models available to the credential (the Models API is not billed)."""
    def fetch() -> list[dict]:
        out = []
        for m in client.models.list(limit=100):
            out.append({"id": m.id, "display_name": getattr(m, "display_name", m.id),
                        "created_at": str(getattr(m, "created_at", "") or ""),
                        "max_input_tokens": getattr(m, "max_input_tokens", None), "max_tokens": getattr(m, "max_tokens", None)})
        return out

    return call(fetch)


def test_claude(config: ClaudeConfig, credentials: ClaudeCredentials) -> ConnectionResult:
    try:
        models = list_models(make_client(config, credentials))
    except ApiError as exc:
        return ConnectionResult(False, str(exc), exc.error_class)
    ids = [m["id"] for m in models]
    if config.model not in ids:
        return ConnectionResult(False, f"Model {config.model} is not available to this credential", "config", {"models": models})
    return ConnectionResult(True, f"Connected. {len(ids)} models available; using {config.model}.", metadata={"models": models})


register_connector(ConnectorSpec(
    key="claude", name="Claude", category="ai", config_model=ClaudeConfig, credentials_model=ClaudeCredentials, test=test_claude,
    configurable=False,
    description="Powers AI-assisted analysis: finding and attack-path explanations and the executive briefing. "
                "Connect it under Administration → AI analysis.",
    required_permissions="An API key from platform.claude.com, or server credentials when the deployment allows them. "
                         "Usage is billed to the Claude Console organization.",
))
