"""
Rate Limiting middleware — slowapi kullanımı.
IP bazlı istek sınırlama.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from fastapi.responses import JSONResponse

# IP'ye göre rate limit
limiter = Limiter(key_func=get_remote_address)


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
