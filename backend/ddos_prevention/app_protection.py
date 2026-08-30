from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Union

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .rate_limiter import IPRateLimiter

def _env_flag(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}

@dataclass(frozen=True)
class AppDDoSProtectionSettings:
    enabled: bool = True
    trust_x_forwarded_for: bool = False
    max_concurrent_login_requests: int = 12
    spoof_unique_ip_threshold: int = 12
    spoof_window_seconds: int = 10
    use_redis: bool = False
    redis_url: str = "redis://localhost:6379"

def load_app_ddos_settings(enabled: bool) -> AppDDoSProtectionSettings:
    return AppDDoSProtectionSettings(
        enabled=enabled,
        trust_x_forwarded_for=_env_flag("TRUST_X_FORWARDED_FOR", False),
        max_concurrent_login_requests=int(os.getenv("MAX_CONCURRENT_LOGIN_REQUESTS", "12")),
        use_redis=_env_flag("ENABLE_REDIS_RATE_LIMITER", False),
        redis_url=os.getenv("REDIS_URL", "redis://localhost:6379"),
    )


async def build_rate_limiter(
    settings: AppDDoSProtectionSettings,
) -> Union["IPRateLimiter", Any]:
    """
    Factory that returns the appropriate rate limiter based on settings.

    - use_redis=False (default): returns the in-memory IPRateLimiter.
      Works out of the box, single-instance only.

    - use_redis=True: returns a RedisTokenBucketLimiter backed by Redis.
      Enforces rate limits globally across all backend replicas via a
      shared Redis counter and an atomic Lua script.
    """
    if settings.use_redis:
        from .redis_rate_limiter import RedisTokenBucketLimiter
        limiter = await RedisTokenBucketLimiter.create(settings.redis_url)
        print(f"[RATE LIMITER] Using Redis Token Bucket limiter at {settings.redis_url}")
        return limiter
    else:
        print("[RATE LIMITER] Using in-memory sliding-window limiter (single-instance)")
        return IPRateLimiter()

class IPSpoofDetector:
    def __init__(self, threshold: int, window: int):
        self._lock = asyncio.Lock()
        self._records: dict[str, list[tuple[str, float]]] = defaultdict(list)
        self._blocked_real_ips: set[str] = set()
        self.threshold = threshold
        self.window = window

    async def check(self, real_ip: str, forwarded_ip: str) -> tuple[bool, str]:
        async with self._lock:
            if real_ip in self._blocked_real_ips:
                return True, "Blocked: IP header spoofing detected"

            now = time.time()
            self._records[real_ip] = [
                (ip, timestamp)
                for ip, timestamp in self._records[real_ip]
                if now - timestamp < self.window
            ]
            self._records[real_ip].append((forwarded_ip, now))

            unique_count = len({ip for ip, _ in self._records[real_ip]})
            if unique_count > self.threshold:
                self._blocked_real_ips.add(real_ip)
                print(
                    f"[SPOOF BLOCK] {real_ip} claimed {unique_count} different "
                    f"X-Forwarded-For values in {self.window}s — blocked."
                )
                return True, (
                    "Blocked: IP spoofing detected "
                    f"({unique_count} unique forwarded IPs from one source)"
                )

            return False, ""

class AppDDoSProtection:
    def __init__(self, settings: AppDDoSProtectionSettings, rate_limiter=None):
        self.settings = settings
        # Accept any object with async check_ip(ip) -> (bool, str)
        # Defaults to in-memory limiter; pass a RedisTokenBucketLimiter for distributed mode.
        self.ip_limiter = rate_limiter if rate_limiter is not None else IPRateLimiter()
        self.spoof_detector = IPSpoofDetector(
            threshold=settings.spoof_unique_ip_threshold,
            window=settings.spoof_window_seconds,
        )
        self._login_semaphore = asyncio.Semaphore(settings.max_concurrent_login_requests)

    async def middleware(self, request: Request, call_next):
        if not self.settings.enabled:
            return await call_next(request)

        real_ip = request.client.host if request.client else "unknown"
        x_forwarded_for = request.headers.get("X-Forwarded-For", "")
        has_forwarded_for = bool(x_forwarded_for.strip())

        if has_forwarded_for and not self.settings.trust_x_forwarded_for:
            return JSONResponse(
                status_code=403,
                content={"detail": "Blocked: untrusted X-Forwarded-For header"},
            )

        if has_forwarded_for:
            forwarded_ip = x_forwarded_for.split(",")[0].strip()
            is_spoofing, reason = await self.spoof_detector.check(real_ip, forwarded_ip)
            if is_spoofing:
                return JSONResponse(status_code=429, content={"detail": reason})

            is_allowed, reason = await self.ip_limiter.check_ip(forwarded_ip)
            if not is_allowed:
                return JSONResponse(status_code=429, content={"detail": reason})
        else:
            is_allowed, reason = await self.ip_limiter.check_ip(real_ip)
            if not is_allowed:
                return JSONResponse(status_code=429, content={"detail": reason})

        return await call_next(request)

    async def run_login(
        self,
        login_handler: Callable[[str, str], Any],
        username: str,
        password: str,
    ) -> Any:
        if not self.settings.enabled:
            return await run_in_threadpool(login_handler, username, password)

        async with self._login_semaphore:
            return await run_in_threadpool(login_handler, username, password)
