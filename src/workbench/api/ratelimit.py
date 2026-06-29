"""
Rate limiting, sized to what it actually protects.

Two different jobs live here and they are not the same mechanism:

  **Login throttling** — a crude per-address counter that makes credential
    stuffing cost something. Keyed by IP and by email, because an attacker with
    a botnet gets past either one alone.

  **API quota** — a plan entitlement. A free org gets 30 requests a minute and a
    team gets 300, and the number comes from the plan catalogue rather than from
    a constant here, so a commercial decision lives in one place.

Fixed windows, not sliding. A sliding window is one sorted set per key and a
ZREM per request; a fixed window is an INCR with an expiry. The cost of the
choice is that a caller can do 2× the limit across a window boundary — which
matters for an adversary rationing an attack and does not matter at all for an
integration that occasionally bursts.

**It fails open, and that is deliberate.** If Redis is unreachable, requests
proceed. Rate limiting is a protection against abuse; refusing every request
during a cache outage turns a degraded dependency into a total outage, and the
people it hurts first are the paying customers who are already authenticated.
The alternative — failing closed — is defensible for a bank and wrong here.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_after: int

    @property
    def headers(self) -> dict[str, str]:
        return {
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(self.reset_after),
        }


class RateLimiter:
    """
    A counter with a window, over a pluggable store.

    The in-memory backend is the default and is honest about what it is: correct
    for one process, wrong for two. It is what development and the test suite
    use, and `create_app` swaps in Redis when one is configured.
    """

    def __init__(self, backend: object, *, name: str = "default") -> None:
        self._backend = backend
        self._name = name
        # Timestamp of the last "the backend is down" warning. See `_warn_once`.
        self._last_warning = 0.0

    # -- backends ----------------------------------------------------------

    @classmethod
    def in_memory(cls, name: str = "memory") -> RateLimiter:
        return cls(_MemoryBackend(), name=name)

    @classmethod
    def redis(cls, client: object, name: str = "redis") -> RateLimiter:
        return cls(_RedisBackend(client), name=name)

    # -- api ---------------------------------------------------------------

    async def check(self, key: str, *, limit: int, window_seconds: int = 60) -> RateLimitResult:
        """Count one hit and say whether it is allowed."""
        if limit <= 0:
            # Unlimited plans use 0 or a negative sentinel to mean "no limit".
            # Reading it literally would lock the org out entirely.
            return RateLimitResult(True, remaining=0, reset_after=0)

        namespaced = f"rl:{self._name}:{key}"
        try:
            count, ttl = await self._backend.incr(namespaced, window_seconds)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 — see "fails open" above
            self._warn_once()
            return RateLimitResult(True, remaining=0, reset_after=0)

        return RateLimitResult(
            allowed=count <= limit,
            remaining=limit - count,
            reset_after=max(1, ttl),
        )

    def _warn_once(self, every: float = 60.0) -> None:
        """
        Warn about a dead backend at most once a minute.

        Once per request, a Redis outage produces one traceback per API call, per
        replica — which buries the one line that explains the outage under a
        hundred copies of itself. The failure mode is already "we're allowing
        everything"; the log should say so once and stay out of the way.
        """
        now = time.monotonic()
        if now - self._last_warning < every:
            log.debug("rate limiter unavailable", exc_info=True)
            return
        self._last_warning = now
        log.warning("rate limiter unavailable — allowing requests (fails open)")

    async def peek(self, key: str, *, limit: int, window_seconds: int = 60) -> RateLimitResult:
        """Check without counting. Used by tests and the console's usage meter."""
        namespaced = f"rl:{self._name}:{key}"
        try:
            count, ttl = await self._backend.peek(namespaced, window_seconds)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return RateLimitResult(True, remaining=limit, reset_after=0)
        return RateLimitResult(
            allowed=count < limit, remaining=limit - count, reset_after=max(1, ttl)
        )

    async def reset(self, key: str) -> None:
        """Clear a counter — called after a successful login so a correct
        password resets the budget."""
        try:
            await self._backend.clear(f"rl:{self._name}:{key}")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            log.debug("rate limiter reset failed", exc_info=True)


class _MemoryBackend:
    """
    A dict of counters, with the expiry checked on read.

    Not a background sweeper: a process that only expires keys when it's asked
    about them keeps its memory proportional to traffic and needs no thread. The
    tradeoff is that keys for addresses that never call again stay until the
    process restarts, which for a login counter is a few hundred bytes.
    """

    def __init__(self) -> None:
        self._counts: dict[str, tuple[int, float]] = {}

    async def incr(self, key: str, window: int) -> tuple[int, int]:
        now = time.monotonic()
        count, expires_at = self._counts.get(key, (0, now + window))
        if now >= expires_at:
            count, expires_at = 0, now + window
        count += 1
        self._counts[key] = (count, expires_at)
        return count, int(expires_at - now)

    async def peek(self, key: str, window: int) -> tuple[int, int]:
        now = time.monotonic()
        count, expires_at = self._counts.get(key, (0, now + window))
        if now >= expires_at:
            return 0, window
        return count, int(expires_at - now)

    async def clear(self, key: str) -> None:
        self._counts.pop(key, None)


class _RedisBackend:
    """
    INCR + EXPIRE. Two round trips, and the race between them is benign: a crash
    between them leaves a key with no TTL, which the next request sets.
    """

    def __init__(self, client: object) -> None:
        self._client = client

    async def incr(self, key: str, window: int) -> tuple[int, int]:
        pipe = self._client.pipeline()  # type: ignore[attr-defined]
        pipe.incr(key)
        pipe.ttl(key)
        count, ttl = await pipe.execute()
        if ttl is None or ttl < 0:
            await self._client.expire(key, window)  # type: ignore[attr-defined]
            ttl = window
        return int(count), int(ttl)

    async def peek(self, key: str, window: int) -> tuple[int, int]:
        value = await self._client.get(key)  # type: ignore[attr-defined]
        ttl = await self._client.ttl(key)  # type: ignore[attr-defined]
        return int(value or 0), int(ttl if ttl and ttl > 0 else window)

    async def clear(self, key: str) -> None:
        await self._client.delete(key)  # type: ignore[attr-defined]
