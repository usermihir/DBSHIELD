"""
redis_rate_limiter.py — Distributed Token Bucket Rate Limiter
=============================================================
Replaces the in-memory IPRateLimiter with Redis as shared state so that
rate limits are enforced globally across multiple backend instances.

Algorithm: Token Bucket
  - Each IP gets a virtual bucket with capacity BUCKET_CAPACITY tokens.
  - Tokens refill at REFILL_RATE tokens/second.
  - Each incoming request consumes 1 token. If the bucket is empty, the
    request is rejected (HTTP 429).
  - Refill is calculated lazily on each request using elapsed wall time,
    so no background thread or cron job is needed.

Why a Lua script?
  The check-and-decrement operation (read tokens, calculate refill, write back)
  must be atomic. Two servers hitting Redis simultaneously could both read the
  same token count and both proceed — a classic TOCTOU race condition. Redis
  executes Lua scripts as a single atomic transaction inside its single-threaded
  event loop, eliminating the race without any application-level locking.

Why Redis?
  The existing IPRateLimiter stores all state in Python dicts in memory.
  If you run N backend replicas behind a load balancer, each has independent
  counters — an attacker can send N * limit requests/second without triggering
  any single instance. Redis provides a single shared counter for all replicas.

Drop-in interface:
  Both RedisTokenBucketLimiter and IPRateLimiter expose:
      async def check_ip(ip: str) -> tuple[bool, str]
  app_protection.py uses duck typing and does not need to change.
"""
from __future__ import annotations

import os
import time

import redis.asyncio as aioredis

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------

BUCKET_CAPACITY: int = int(os.getenv("RATE_LIMIT_CAPACITY", "20"))
REFILL_RATE: float = float(os.getenv("RATE_LIMIT_REFILL_RATE", "10"))  # tokens/second
KEY_TTL: int = int(os.getenv("RATE_LIMIT_KEY_TTL", "300"))             # Redis key expiry (seconds)

# ---------------------------------------------------------------------------
# Lua script — runs atomically inside Redis
# ---------------------------------------------------------------------------

_TOKEN_BUCKET_LUA = """
local key        = KEYS[1]
local capacity   = tonumber(ARGV[1])
local refill_rate= tonumber(ARGV[2])
local now        = tonumber(ARGV[3])
local ttl        = tonumber(ARGV[4])

local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens      = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

-- First request from this IP: initialise the bucket
if tokens == nil then
    tokens      = capacity
    last_refill = now
end

-- Lazy refill: add tokens proportional to elapsed time
local elapsed = now - last_refill
local refilled = elapsed * refill_rate
tokens = math.min(capacity, tokens + refilled)

if tokens < 1 then
    -- Bucket empty — reject
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
    redis.call('EXPIRE', key, ttl)
    return 0
else
    -- Consume one token — allow
    tokens = tokens - 1
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
    redis.call('EXPIRE', key, ttl)
    return 1
end
"""


class RedisTokenBucketLimiter:
    """
    Distributed Token Bucket rate limiter backed by Redis.

    Usage:
        limiter = await RedisTokenBucketLimiter.create("redis://localhost:6379")
        allowed, reason = await limiter.check_ip("192.168.1.1")

    This class exposes the same async check_ip() interface as IPRateLimiter
    so it can be swapped in app_protection.py without any other changes.
    """

    def __init__(
        self,
        redis_client: aioredis.Redis,
        capacity: int = BUCKET_CAPACITY,
        refill_rate: float = REFILL_RATE,
        key_ttl: int = KEY_TTL,
    ) -> None:
        self._redis = redis_client
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._key_ttl = key_ttl
        self._script_sha: str | None = None

    @classmethod
    async def create(
        cls,
        redis_url: str,
        capacity: int = BUCKET_CAPACITY,
        refill_rate: float = REFILL_RATE,
        key_ttl: int = KEY_TTL,
    ) -> "RedisTokenBucketLimiter":
        """
        Async factory: connects to Redis and pre-loads the Lua script.
        Call once at application startup.
        """
        client = aioredis.from_url(redis_url, decode_responses=False)
        instance = cls(client, capacity, refill_rate, key_ttl)
        # SCRIPT LOAD caches the Lua script server-side and returns its SHA.
        # Subsequent calls use EVALSHA (cheaper than re-sending the full script).
        instance._script_sha = await client.script_load(_TOKEN_BUCKET_LUA)
        return instance

    async def check_ip(self, ip_address: str) -> tuple[bool, str]:
        """
        Check whether the given IP address is within its rate limit.

        Returns:
            (True, "")           — request is allowed
            (False, reason_str)  — request is rejected
        """
        key = f"ratelimit:{ip_address}"
        now = time.time()

        try:
            result = await self._redis.evalsha(
                self._script_sha,
                1,           # number of keys
                key,         # KEYS[1]
                str(self._capacity),     # ARGV[1]
                str(self._refill_rate),  # ARGV[2]
                str(now),                # ARGV[3]
                str(self._key_ttl),      # ARGV[4]
            )
        except aioredis.RedisError as exc:
            # If Redis is unreachable, fail open (allow the request) and log.
            # You can change this to fail closed depending on threat model.
            print(f"[REDIS RATE LIMITER] Redis error — failing open: {exc}")
            return True, ""

        if result == 1:
            return True, ""
        else:
            return False, (
                f"Rate limit exceeded: max {self._capacity} tokens, "
                f"refill {self._refill_rate}/s"
            )

    async def close(self) -> None:
        """Close the underlying Redis connection pool."""
        await self._redis.aclose()
