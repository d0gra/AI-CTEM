"""LLM access used for (a) AI red-team targets and (b) the platform's own AI-assisted analysis.

Claude is called through the official Anthropic SDK. OpenAI-compatible servers (OpenAI, Azure
OpenAI v1, vLLM, Ollama, NVIDIA NIM, LiteLLM), Gemini and arbitrary application endpoints are
called over HTTP through the SSRF-guarded client.
"""

import json
from dataclasses import dataclass, field
from typing import Literal, Protocol

import anthropic
import httpx
from pydantic import BaseModel, Field, HttpUrl, model_validator

from app.core.net import safe_fetch
from app.integrations.base import (
    ApiError,
    ConnectionResult,
    ConnectorSpec,
    classify_status,
    register_connector,
    run_test,
)

ANTHROPIC_API_URL = "https://api.anthropic.com"
DEFAULT_CLAUDE_MODEL = "claude-opus-5-5"
TRANSPORT: httpx.BaseTransport | None = None  # replaced in tests


@dataclass
class ChatResult:
    text: str
    tool_calls: list[dict] = field(default_factory=list)  # [{name, arguments}] requested by the model; never executed
    input_tokens: int = 0
    output_tokens: int = 0
    refused: bool = False
    model: str = ""
    headers: dict = field(default_factory=dict)


class ChatClient(Protocol):
    supports_system: bool
    supports_tools: bool
    endpoint: str
    model: str

    def chat(self, user: str, *, system: str | None = None, tools: list[dict] | None = None, max_tokens: int = 1024) -> ChatResult: ...


class LlmConfig(BaseModel):
    api_style: Literal["openai_compatible", "anthropic", "gemini", "custom_http"]
    base_url: HttpUrl | None = Field(default=None, description="e.g. https://api.openai.com/v1, http://vllm.internal:8000/v1, or the application's chat URL")
    model: str = Field(default="", max_length=200)
    request_template: dict | None = Field(default=None, description='custom_http: JSON body with "{{prompt}}" where the user message goes')
    response_path: str | None = Field(default=None, description="custom_http: dotted path to the reply text, e.g. choices.0.message.content")
    max_tokens_parameter: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"

    @model_validator(mode="after")
    def _check(self) -> "LlmConfig":
        if self.api_style == "anthropic":
            if self.base_url is not None and str(self.base_url).rstrip("/") != ANTHROPIC_API_URL:
                raise ValueError("The anthropic style always uses https://api.anthropic.com; leave base_url empty")
            self.model = self.model or DEFAULT_CLAUDE_MODEL
        elif self.base_url is None:
            raise ValueError("base_url is required")
        if self.api_style in ("openai_compatible", "gemini") and not self.model:
            raise ValueError("model is required")
        if self.api_style == "custom_http":
            if not self.request_template or "{{prompt}}" not in json.dumps(self.request_template):
                raise ValueError('request_template must contain the placeholder "{{prompt}}"')
            if not self.response_path:
                raise ValueError("response_path is required")
        return self

    @property
    def endpoint(self) -> str:
        return ANTHROPIC_API_URL if self.api_style == "anthropic" else str(self.base_url).rstrip("/")


class LlmCredentials(BaseModel):
    api_key: str = ""
    header_name: str = Field(default="", description="custom_http: header that carries the key (default Authorization: Bearer)")


def _post(url: str, body: dict, headers: dict, allow_private: bool, timeout: float = 60.0):
    try:
        result = safe_fetch("POST", url, json_body=body, headers=headers, allow_private=allow_private, timeout=timeout,
                            max_redirects=0, max_bytes=4 * 1024 * 1024, transport=TRANSPORT, verify_tls=True)
    except (httpx.HTTPError, OSError) as exc:
        raise ApiError(f"Network error: {type(exc).__name__}: {exc}", "network") from exc
    if result.status_code >= 400:
        raise ApiError(f"HTTP {result.status_code}: {result.text()[:300]}", classify_status(result.status_code), result.status_code)
    try:
        return result.json(), result.headers
    except ValueError as exc:
        raise ApiError("Endpoint did not return JSON", "upstream") from exc


class OpenAICompatibleClient:
    supports_system, supports_tools = True, True

    def __init__(self, config: LlmConfig, creds: LlmCredentials, allow_private: bool = False):
        self.config, self.creds, self.allow_private = config, creds, allow_private
        self.endpoint, self.model = config.endpoint, config.model

    def chat(self, user, *, system=None, tools=None, max_tokens=1024) -> ChatResult:
        messages = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": user}]
        body: dict = {"model": self.model, "messages": messages, self.config.max_tokens_parameter: max_tokens}
        if tools:
            body["tools"] = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                               "parameters": t["input_schema"]}} for t in tools]
        headers = {"Authorization": f"Bearer {self.creds.api_key}"} if self.creds.api_key else {}
        doc, response_headers = _post(f"{self.endpoint}/chat/completions", body, headers, self.allow_private)
        message = ((doc.get("choices") or [{}])[0].get("message") or {})
        calls = []
        for call in message.get("tool_calls") or []:
            fn = call.get("function") or {}
            calls.append({"name": fn.get("name"), "arguments": str(fn.get("arguments"))[:500]})
        usage = doc.get("usage") or {}
        return ChatResult(text=str(message.get("content") or ""), tool_calls=calls, input_tokens=int(usage.get("prompt_tokens") or 0),
                          output_tokens=int(usage.get("completion_tokens") or 0), refused=bool(message.get("refusal")),
                          model=str(doc.get("model") or self.model), headers=response_headers)


class AnthropicClient:
    """Claude via the official SDK. The SDK retries 429/5xx itself (max_retries)."""

    supports_system, supports_tools = True, True

    # Models for which a safety-classifier refusal can be retried server-side on a fallback model.
    FALLBACK_MODELS = ("claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5", "claude-fable-5-2", "claude-fable-5-1")

    def __init__(self, config: LlmConfig, creds: LlmCredentials, allow_private: bool = False, effort: str | None = None,
                 refusal_fallback: bool = False):
        self.endpoint, self.model, self.effort = ANTHROPIC_API_URL, config.model or DEFAULT_CLAUDE_MODEL, effort
        # Used only for the platform's own analysis. Red-team targets must answer as the model under test.
        self.refusal_fallback = refusal_fallback and self.model in self.FALLBACK_MODELS
        self.client = anthropic.Anthropic(api_key=creds.api_key, max_retries=2, timeout=120.0)

    def chat(self, user, *, system=None, tools=None, max_tokens=1024) -> ChatResult:
        params: dict = {"model": self.model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": user}]}
        if system:
            params["system"] = system
        if tools:
            params["tools"] = [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]} for t in tools]
        if self.effort:
            params["output_config"] = {"effort": self.effort}
        try:
            if self.refusal_fallback:
                response = self.client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **params)
            else:
                response = self.client.messages.create(**params)
        except anthropic.AuthenticationError as exc:
            raise ApiError(f"Authentication failed: {exc.message}", "auth", 401) from exc
        except anthropic.PermissionDeniedError as exc:
            raise ApiError(f"Permission denied: {exc.message}", "permission", 403) from exc
        except anthropic.NotFoundError as exc:
            raise ApiError(f"Model or endpoint not found: {exc.message}", "config", 404) from exc
        except anthropic.RateLimitError as exc:
            raise ApiError(f"Rate limited: {exc.message}", "rate_limit", 429) from exc
        except anthropic.APIStatusError as exc:
            raise ApiError(f"API error {exc.status_code}: {exc.message}", classify_status(exc.status_code), exc.status_code) from exc
        except anthropic.APIConnectionError as exc:
            raise ApiError(f"Network error: {exc}", "network") from exc
        text = "".join(block.text for block in response.content if block.type == "text")
        calls = [{"name": block.name, "arguments": json.dumps(block.input)[:500]} for block in response.content if block.type == "tool_use"]
        return ChatResult(text=text, tool_calls=calls, input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens,
                          refused=response.stop_reason == "refusal", model=response.model)


class GeminiClient:
    supports_system, supports_tools = True, False

    def __init__(self, config: LlmConfig, creds: LlmCredentials, allow_private: bool = False):
        self.config, self.creds, self.allow_private = config, creds, allow_private
        self.endpoint, self.model = config.endpoint, config.model

    def chat(self, user, *, system=None, tools=None, max_tokens=1024) -> ChatResult:
        body: dict = {"contents": [{"role": "user", "parts": [{"text": user}]}], "generationConfig": {"maxOutputTokens": max_tokens}}
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        doc, headers = _post(f"{self.endpoint}/models/{self.model}:generateContent", body, {"x-goog-api-key": self.creds.api_key}, self.allow_private)
        candidate = (doc.get("candidates") or [{}])[0]
        text = "".join(p.get("text", "") for p in (candidate.get("content") or {}).get("parts") or [])
        usage = doc.get("usageMetadata") or {}
        return ChatResult(text=text, input_tokens=int(usage.get("promptTokenCount") or 0), output_tokens=int(usage.get("candidatesTokenCount") or 0),
                          refused=candidate.get("finishReason") in ("SAFETY", "PROHIBITED_CONTENT"), model=self.model, headers=headers)


def _substitute(node, prompt: str):
    if isinstance(node, str):
        return node.replace("{{prompt}}", prompt)
    if isinstance(node, dict):
        return {k: _substitute(v, prompt) for k, v in node.items()}
    if isinstance(node, list):
        return [_substitute(v, prompt) for v in node]
    return node


def _dig(doc, path: str):
    for part in path.split("."):
        if isinstance(doc, list) and part.isdigit() and int(part) < len(doc):
            doc = doc[int(part)]
        elif isinstance(doc, dict) and part in doc:
            doc = doc[part]
        else:
            raise ApiError(f"Response has no value at path '{path}'", "config")
    return doc


class CustomHttpClient:
    """A deployed application's own chat endpoint (black box: its system prompt is not controllable)."""

    supports_system, supports_tools = False, False

    def __init__(self, config: LlmConfig, creds: LlmCredentials, allow_private: bool = False):
        self.config, self.creds, self.allow_private = config, creds, allow_private
        self.endpoint, self.model = config.endpoint, config.model or "application"

    def chat(self, user, *, system=None, tools=None, max_tokens=1024) -> ChatResult:
        headers = {}
        if self.creds.api_key:
            headers = {self.creds.header_name: self.creds.api_key} if self.creds.header_name else {"Authorization": f"Bearer {self.creds.api_key}"}
        doc, response_headers = _post(self.endpoint, _substitute(self.config.request_template, user), headers, self.allow_private)
        return ChatResult(text=str(_dig(doc, self.config.response_path or "")), model=self.model, headers=response_headers)


_CLIENTS = {"openai_compatible": OpenAICompatibleClient, "anthropic": AnthropicClient, "gemini": GeminiClient, "custom_http": CustomHttpClient}


def build_client(config: LlmConfig, creds: LlmCredentials, *, allow_private: bool = False) -> ChatClient:
    return _CLIENTS[config.api_style](config, creds, allow_private)


def test_llm(config: LlmConfig, creds: LlmCredentials) -> ConnectionResult:
    """Sends one minimal prompt (a few tokens are billed by the provider)."""
    def go() -> ConnectionResult:
        result = build_client(config, creds).chat("Reply with the single word: OK", max_tokens=64)
        return ConnectionResult(True, f"Model {result.model or config.model} responded", metadata={"output_tokens": result.output_tokens})

    return run_test(go)


register_connector(ConnectorSpec(
    key="llm", name="LLM endpoint (OpenAI-compatible, Anthropic, Gemini, custom HTTP)", category="ai", config_model=LlmConfig,
    credentials_model=LlmCredentials, test=test_llm,
    description="A model API or AI application endpoint. Used as an AI red-team target and, when selected in AI analytics settings, "
                "as the provider for AI-assisted analysis. OpenAI-compatible covers OpenAI, Azure OpenAI (v1), vLLM, Ollama, NVIDIA NIM and LiteLLM.",
    required_permissions="An API key limited to inference. The connection test sends one short prompt.",
))
for _key, _name in (("aws_bedrock", "AWS Bedrock"), ("huggingface", "Hugging Face")):
    register_connector(ConnectorSpec(
        key=_key, name=_name, category="ai", status="import_only", configurable=False,
        description="Discovered through repository analysis (dependencies, endpoints, credentials). No direct connector; "
                    "Bedrock models reachable through an OpenAI-compatible gateway can be tested with the LLM endpoint connector."))
