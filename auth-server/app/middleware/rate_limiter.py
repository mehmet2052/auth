"""
Rate Limiting middleware — slowapi kullanımı.
IP bazlı istek sınırlama.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from fastapi.responses import JSONResponse


def _get_client_ip(request: Request) -> str:
    """Render/nginx proxy arkasında gerçek istemci IP'si."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return get_remote_address(request)


# IP'ye göre rate limit
limiter = Limiter(key_func=_get_client_ip)


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Rate limit aşıldığında JSON yanıtı döndür."""
    return JSONResponse(
        status_code=429,
        content={
            "error": "Çok fazla istek",
            "detail": f"Rate limit aşıldı. Lütfen bekleyin.",
            "success": False,
        }
    )
