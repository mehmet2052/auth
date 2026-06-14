"""
Token Store — Redis-backed refresh token yönetimi.

Özellikler:
- Refresh token depolama (Redis, TTL ile)
- Token revocation (blacklist)
- Family-based revocation (token theft detection)
- Token rotation güvenliği
"""
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.core.redis import get_redis
from app.core.logging import logger

# Redis key prefix'leri
_TOKEN_PREFIX = "token:"
_REVOKED_PREFIX = "revoked:"
_FAMILY_PREFIX = "family:"


async def store_refresh_token(
    jti: str,
    user_id: str,
    expires_at: datetime,
    family_id: str,
) -> None:
    """
    Refresh token'ı Redis'e kaydet.
    TTL: token'ın expires_at'ine kadar.
    """
    redis = await get_redis()
    
    ttl_seconds = int((expires_at - datetime.now(timezone.utc)).total_seconds())
    if ttl_seconds <= 0:
        return
    
    # Token metadata
    key = f"{_TOKEN_PREFIX}{jti}"
    await redis.setex(
        key,
        ttl_seconds,
        f"{user_id}:{family_id}"
    )
    
    # Family tracking — tüm token'ları family altında topla
    family_key = f"{_FAMILY_PREFIX}{family_id}"
    await redis.sadd(family_key, jti)
    await redis.expire(family_key, ttl_seconds + 3600)  # +1 saat buffer


async def revoke_refresh_token(jti: str) -> bool:
    """
    Refresh token'ı revoke et (blacklist'e ekle).
    
    Returns:
        True if token was valid and now revoked, False if already revoked/not found
    """
    redis = await get_redis()
    
    token_key = f"{_TOKEN_PREFIX}{jti}"
    token_data = await redis.get(token_key)
    
    if not token_data:
        # Token zaten expired veya revoked
        # Blacklist'e ekle (kalan TTL kadar)
        revoked_key = f"{_REVOKED_PREFIX}{jti}"
        await redis.setex(revoked_key, 86400, "revoked")  # 24 saat
        return False
    
    # Token'ı sil ve blacklist'e ekle
    await redis.delete(token_key)
    
    revoked_key = f"{_REVOKED_PREFIX}{jti}"
    await redis.setex(revoked_key, 86400, "revoked")  # 24 saat
    
    logger.info(f"Refresh token revoked: jti={jti[:8]}...")
    return True


async def is_token_revoked(jti: str) -> bool:
    """
    Token revoked mı kontrol et.
    Access token blacklist kontrolü için kullanılır.
    """
    redis = await get_redis()
    revoked_key = f"{_REVOKED_PREFIX}{jti}"
    return await redis.exists(revoked_key) > 0


async def get_token_data(jti: str) -> Optional[tuple[str, str]]:
    """
    Token metadata'yı getir.
    
    Returns:
        (user_id, family_id) veya None if not found/revoked
    """
    redis = await get_redis()
    token_key = f"{_TOKEN_PREFIX}{jti}"
    data = await redis.get(token_key)
    
    if not data:
        return None
    
    parts = data.split(":", 1)
    if len(parts) != 2:
        return None
    
    return parts[0], parts[1]


async def revoke_family(family_id: str) -> int:
    """
    Tüm family'yi revoke et (token theft detection).
    
    Eğer revoked bir token reuse edilirse, tüm family revoke edilir.
    
    Returns:
        Number of tokens revoked
    """
    redis = await get_redis()
    
    family_key = f"{_FAMILY_PREFIX}{family_id}"
    members = await redis.smembers(family_key)
    
    count = 0
    for jti in members:
        await revoke_refresh_token(jti)
        count += 1
    
    await redis.delete(family_key)
    
    logger.warning(
        f"Token family revoked (breach detected): family={family_id[:8]}..., count={count}"
    )
    return count


async def revoke_all_for_user(user_id: str) -> int:
    """
    Kullanıcıya ait tüm refresh token'ları revoke et.
    Logout all devices senaryosu için.
    """
    redis = await get_redis()
    
    # Tüm token'ları scan et (pattern matching)
    pattern = f"{_TOKEN_PREFIX}*"
    count = 0
    
    async for key in redis.scan_iter(match=pattern, count=100):
        data = await redis.get(key)
        if data and data.startswith(f"{user_id}:"):
            jti = key.replace(_TOKEN_PREFIX, "")
            await revoke_refresh_token(jti)
            count += 1
    
    logger.info(f"All tokens revoked for user: user_id={user_id}, count={count}")
    return count
