"""Fixed-window rate limiting in Redis (INCR + EXPIRE in one MULTI), shared by all API workers."""

import hashlib
from collections.abc import Callable

from fastapi import HTTPException, Request, status
from redis import Redis

from ..config import Settings


class RateLimiter:
    def __init__(self, redis: Redis, prefix: str, clock: Callable[[], float]):
        self.redis, self.prefix, self.clock = redis, prefix, clock

    def hit(self, scope: str, key: str, spec: str) -> tuple[bool, int]:
        limit, window = (int(x) for x in spec.split("/"))
        now = int(self.clock())
        bucket = now // window
        digest = hashlib.sha256(key.encode()).hexdigest()[:32]  # keeps e-mails/IPs out of Redis keys
        rkey = f"{self.prefix}:rl:{scope}:{digest}:{bucket}"
        pipe = self.redis.pipeline(transaction=True)
        pipe.incr(rkey)
        pipe.expire(rkey, window + 1)
        count, _ = pipe.execute()
        if int(count) > limit:
            return False, window - (now % window)
        return True, 0


def client_ip(request: Request) -> str:
    settings: Settings = request.app.state.settings
    if settings.trust_forwarded_for:
        xff = request.headers.get("x-forwarded-for", "")
        # Right-most entry was appended by our own proxy; entries to its left are client-controlled.
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        if hops:
            return hops[-1]
    return request.client.host if request.client else "unknown"


def enforce(request: Request, scope: str, key: str, spec: str) -> None:
    allowed, retry_after = request.app.state.ratelimiter.hit(scope, key, spec)
    if not allowed:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate_limited",
                            headers={"Retry-After": str(max(retry_after, 1))})
