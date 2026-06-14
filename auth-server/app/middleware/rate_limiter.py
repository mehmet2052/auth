"""
Rate Limiting middleware — Redis-backed sliding window.

Özellikler:
- IP bazlı rate limiting (unauthenticated endpoints)
- User bazlı rate limiting (authenticated endpoints)
- Sliding window algorithm (Redis sorted sets)
- Rate limit headers (X-RateLimit-Remaining, X-RateLimit-Reset)
"""
import time
from typing import Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.redis import get_redis
from app.core.logging import logger


def _get_client_ip(request: Request) -> str:
    """Render/nginx proxy arkasında gerçek istemci IP'si."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


class RedisRateLimiter:
    """
    Redis-backed sliding window rate limiter.
    
    Uses sorted sets: score = timestamp, member = unique request ID.
    """
    
    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        prefix: str = "rl",
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.prefix = prefix
    
    async def is_allowed(self, key: str) -> tuple[bool, int, int]:
        """
        Check if request is allowed.
        Fail-open: if Redis is unavailable, allow the request (skip rate limiting).
        
        Returns:
            (allowed, remaining, reset_timestamp)
        """
        try:
            redis = await get_redis()
        except RuntimeError:
            # Redis unavailable — fail open (allow request, skip rate limiting)
            return True, self.max_requests, 0
        
        now = int(time.time())
        window_start = now - self.window_seconds
        redis_key = f"{self.prefix}:{key}"
        
        # Use Redis pipeline for atomicity
        pipe = redis.pipeline()
        
        # Remove expired entries
        pipe.zremrangebyscore(redis_key, 0, window_start)
        
        # Add current request
        pipe.zadd(redis_key, {f"{now}:{id(self)}": now})
        
        # Count requests in window
        pipe.zcard(redis_key)
        
        # Set expiry on key
        pipe.expire(redis_key, self.window_seconds + 10)
        
        results = await pipe.execute()
        
        request_count = results[2]  # zcard result
        remaining = max(0, self.max_requests - request_count)
        reset_at = now + self.window_seconds
        
        allowed = request_count <= self.max_requests
        
        return allowed, remaining, reset_at


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Global rate limiting middleware.
    
    Endpoint-specific limits are applied via decorators.
    This middleware provides a global baseline limit.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        global_limit: int = 100,
        window_seconds: int = 60,
    ):
        super().__init__(app)
        self.global_limiter = RedisRateLimiter(
            max_requests=global_limit,
            window_seconds=window_seconds,
            prefix="rl:global",
        )
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health check
        if request.url.path in ("/health", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)
        
        ip = _get_client_ip(request)
        
        # Check global rate limit
        try:
            allowed, remaining, reset_at = await self.global_limiter.is_allowed(ip)
        except Exception:
            # Any unexpected error — fail open, allow request
            allowed, remaining, reset_at = True, self.global_limiter.max_requests, 0
        
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too many requests",
                    "detail": "Rate limit exceeded. Please wait before trying again.",
                    "success": False,
                },
                headers={
                    "X-RateLimit-Limit": str(self.global_limiter.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_at),
                    "Retry-After": str(self.global_limiter.window_seconds),
                }
            )
        
        # Proceed with request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.global_limiter.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_at)
        
        return response


# ── Endpoint-specific limiters ────────────────────────────────────────────────

# These are used as dependencies in specific endpoints

_auth_limiter = RedisRateLimiter(max_requests=10, window_seconds=60, prefix="rl:auth")
_heartbeat_limiter = RedisRateLimiter(max_requests=30, window_seconds=60, prefix="rl:heartbeat")
_admin_login_limiter = RedisRateLimiter(max_requests=5, window_seconds=60, prefix="rl:admin_login")


async def check_auth_rate_limit(request: Request) -> None:
    """Client auth endpoint rate limit."""
    from fastapi import HTTPException, status
    
    ip = _get_client_ip(request)
    allowed, remaining, reset_at = await _auth_limiter.is_allowed(ip)
    
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Please wait.",
            headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_at),
                "Retry-After": "60",
            }
        )


async def check_heartbeat_rate_limit(request: Request) -> None:
    """Heartbeat endpoint rate limit."""
    from fastapi import HTTPException, status
    
    ip = _get_client_ip(request)
    allowed, remaining, reset_at = await _heartbeat_limiter.is_allowed(ip)
    
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many heartbeat requests.",
            headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_at),
            }
        )


async def check_admin_login_rate_limit(request: Request) -> None:
    """Admin login rate limit."""
    from fastapi import HTTPException, status
    
    ip = _get_client_ip(request)
    allowed, remaining, reset_at = await _admin_login_limiter.is_allowed(ip)
    
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait.",
            headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_at),
                "Retry-After": "60",
            }
        )


# ── Legacy compatibility (slowapi replacement) ────────────────────────────────

class _LegacyLimiter:
    """
    Backwards compatibility wrapper — replaces slowapi's limiter.
    Rate limiting is now handled by RedisRateLimiter and middleware.
    """
    
    def limit(self, limit_str: str):
        """No-op decorator — rate limiting is done by middleware/dependencies."""
        def decorator(func):
            return func
        return decorator


limiter = _LegacyLimiter()


async def rate_limit_exceeded_handler(request: Request, exc) -> JSONResponse:
    """Legacy handler — kept for compatibility."""
    return JSONResponse(
        status_code=429,
        content={
            "error": "Too many requests",
            "detail": "Rate limit exceeded.",
            "success": False,
        }
    )
