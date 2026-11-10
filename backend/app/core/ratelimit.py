"""Fixed-window rate limiting. Redis-backed when CTEM_REDIS_URL is set, otherwise in-process.

The in-process limiter is correct for a single API process only and is intended for
development and tests; multi-replica deployments must configure Redis.
"""

import threading
import time

from app.core.config import get_settings
from app.core.errors import RateLimited

_lock = threading.Lock()
_local: dict[str, tuple[int, int]] = {}
_redis_client = None


def _redis():
    global _redis_client
    url = get_settings().redis_url
    if not url:
        return None
    if _redis_client is None:
        import redis

        _redis_client = redis.Redis.from_url(url, socket_timeout=1.0, socket_connect_timeout=1.0)
    return _redis_client


def hit(bucket: str, limit: int, window_seconds: int = 60) -> int:
    """Record a hit and return the remaining allowance; raises RateLimited when exceeded."""
    window = int(time.time()) // window_seconds
    key = f"rl:{bucket}:{window}"
    client = _redis()
    if client is not None:
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds * 2)
        count = int(pipe.execute()[0])
    else:
        with _lock:
            stored_window, count = _local.get(bucket, (window, 0))
            count = count + 1 if stored_window == window else 1
            _local[bucket] = (window, count)
            if len(_local) > 50_000:
                for k in [k for k, (w, _) in _local.items() if w != window]:
                    _local.pop(k, None)
    if count > limit:
        raise RateLimited("Too many requests; retry later", details={"retry_after_seconds": window_seconds})
    return limit - count


def reset_local() -> None:
    with _lock:
        _local.clear()


def redis_healthy() -> bool | None:
    client = _redis()
    if client is None:
        return None
    try:
        return bool(client.ping())
    except Exception:
        return False
