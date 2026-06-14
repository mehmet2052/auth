"""
Redis bağlantı yönetimi — async Redis client.
Rate limiting, token blacklisting, session caching için kullanılır.
"""
import redis.asyncio as redis
from typing import Optional

from app.core.config import get_settings
from app.core.logging import logger

settings = get_settings()

# Redis connection pool
_redis_pool: Optional[redis.Redis] = None


async def get_redis() -> redis.Redis:
    """
    Redis connection singleton.
    Fail-closed: Redis unavailable ise hata fırlatır (rate limiting güvenliğini korur).
    """
    global _redis_pool
    
    if _redis_pool is None:
        try:
            _redis_pool = redis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
            )
            # Connection test
            await _redis_pool.ping()
            logger.info("Redis bağlantısı kuruldu")
        except Exception as e:
            logger.error(f"Redis bağlantı hatası: {e}")
            _redis_pool = None
            raise RuntimeError("Redis unavailable — request rejected for security")
    
    # Health check
    try:
        await _redis_pool.ping()
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        _redis_pool = None
        raise RuntimeError("Redis unavailable — request rejected for security")
    
    return _redis_pool


async def close_redis() -> None:
    """Redis connection'ı kapat."""
    global _redis_pool
    if _redis_pool:
        await _redis_pool.close()
        _redis_pool = None
        logger.info("Redis bağlantısı kapatıldı")
