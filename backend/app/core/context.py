"""Per-request context shared with logging and audit."""

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass
class RequestContext:
    request_id: str = ""
    ip_address: str | None = None
    user_agent: str | None = None


_ctx: ContextVar[RequestContext | None] = ContextVar("request_context", default=None)


def set_request_context(ctx: RequestContext) -> None:
    _ctx.set(ctx)


def get_request_context() -> RequestContext:
    return _ctx.get() or RequestContext()
