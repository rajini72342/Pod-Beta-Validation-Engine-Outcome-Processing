"""Query result caching for the Validation Engine.

Repeated validation runs (re-running a Pod Beta scenario, retries,
overlapping batches) frequently ask the exact same question of the
SIEM connectors: same action_id + technique_ref + rule_id + time
window. There's no reason to re-run that query and pay the network
round trip again inside its TTL window, so results are cached.

Backed by Redis (async client) when available, with an automatic
in-memory fallback (a plain dict with per-key expiry) so the engine
still works - just without cross-process sharing - if no Redis
instance is reachable, e.g. in local dev or CI.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, Optional, Sequence

try:  # pragma: no cover - import guard, exercised implicitly
    from redis import asyncio as redis_asyncio
except ImportError:  # pragma: no cover
    redis_asyncio = None  # type: ignore[assignment]

DEFAULT_TTL_SECONDS = 300


def build_cache_key(
    *,
    action_id: str,
    technique_ref: str,
    rule_id: str,
    expected_observable: str,
    expected_fields: Sequence[str],
    window_start: Optional[str] = None,
    window_end: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> str:
    """Build a stable cache key from the query parameters that
    determine a SIEM query's result set."""
    payload = json.dumps(
        {
            "action_id": action_id,
            "technique_ref": technique_ref,
            "rule_id": rule_id,
            "expected_observable": expected_observable,
            "expected_fields": sorted(expected_fields),
            "window_start": window_start,
            "window_end": window_end,
            "tenant_id": tenant_id,
        },
        sort_keys=True,
        default=str,
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"validation-engine:query:{digest}"


class _InMemoryBackend:
    """Fallback backend used when Redis isn't configured/reachable."""

    def __init__(self) -> None:
        self._store: Dict[str, tuple[float, str]] = {}

    async def get(self, key: str) -> Optional[str]:
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at < time.monotonic():
            self._store.pop(key, None)
            return None
        return value

    async def set(self, key: str, value: str, ttl_seconds: int) -> None:
        self._store[key] = (time.monotonic() + ttl_seconds, value)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)

    async def clear(self) -> None:
        self._store.clear()

    async def close(self) -> None:  # pragma: no cover - nothing to close
        return None


class QueryCache:
    """Async cache for SIEM query results with TTL-based auto-expiration.

    Tries to use Redis (auto-expiring keys via `SETEX`) and transparently
    falls back to an in-process dict if Redis is unavailable, unset, or
    the connection fails at call time. All cache errors are swallowed as
    cache misses so a Redis outage degrades performance, not
    correctness.
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        default_ttl_seconds: int = DEFAULT_TTL_SECONDS,
        redis_client: Optional[Any] = None,
    ) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self._hits = 0
        self._misses = 0
        self._backend: Any
        self._using_redis = False

        if redis_client is not None:
            self._backend = redis_client
            self._using_redis = True
        elif redis_url and redis_asyncio is not None:
            try:
                self._backend = redis_asyncio.from_url(
                    redis_url, decode_responses=True, socket_connect_timeout=1
                )
                self._using_redis = True
            except Exception:
                self._backend = _InMemoryBackend()
        else:
            self._backend = _InMemoryBackend()

    @property
    def using_redis(self) -> bool:
        return self._using_redis

    @property
    def stats(self) -> Dict[str, int]:
        return {"hits": self._hits, "misses": self._misses}

    async def get(self, key: str) -> Optional[dict]:
        try:
            raw = await self._backend.get(key)
        except Exception:
            # Redis unreachable mid-run: fail open as a cache miss
            # rather than taking the whole validation run down.
            self._misses += 1
            return None
        if raw is None:
            self._misses += 1
            return None
        self._hits += 1
        return json.loads(raw)

    async def set(self, key: str, value: dict, ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        raw = json.dumps(value, default=str)
        try:
            if self._using_redis:
                await self._backend.set(key, raw, ex=ttl)
            else:
                await self._backend.set(key, raw, ttl)
        except Exception:
            # Best-effort cache write; a failure here should never
            # break the validation run itself.
            return

    async def close(self) -> None:
        close = getattr(self._backend, "close", None)
        if close is not None:
            try:
                await close()
            except Exception:
                pass
