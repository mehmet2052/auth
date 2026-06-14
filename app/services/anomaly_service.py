"""
Anomaly Service — Configurable anomaly detection with Redis sliding windows.

Features:
- DB-stored rules (hot-reloadable, 60s cache)
- Redis sorted sets for sliding window counters
- Actions: lock_license, flag_only, block_ip, webhook_alert
- Cooldown per rule+target to avoid spam
"""
import time
import uuid
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import logger
from app.core.redis import get_redis
from app.models.anomaly import AnomalyRule
from app.repositories.anomaly_repo import AnomalyRepository

settings = get_settings()

# In-memory cache: { rule_name: AnomalyRule }
_rule_cache: dict[str, AnomalyRule] = {}
_cache_timestamp: float = 0.0
_CACHE_TTL_SECONDS = 60


async def _load_rules(db: AsyncSession) -> dict[str, AnomalyRule]:
    """Load rules from DB with 60s in-memory cache."""
    global _rule_cache, _cache_timestamp

    now = time.time()
    if _rule_cache and (now - _cache_timestamp) < _CACHE_TTL_SECONDS:
        return _rule_cache

    repo = AnomalyRepository(db)
    rules = await repo.get_all_enabled()
    _rule_cache = {r.name: r for r in rules}
    _cache_timestamp = now
    return _rule_cache


def invalidate_cache():
    """Force cache invalidation (called when admin updates a rule)."""
    global _rule_cache, _cache_timestamp
    _rule_cache = {}
    _cache_timestamp = 0.0


async def _check_cooldown(
    redis,
    rule_name: str,
    target: str,
    cooldown_seconds: int,
) -> bool:
    """Check if cooldown is active. Returns True if in cooldown (skip trigger)."""
    key = f"anomaly_cooldown:{rule_name}:{target}"
    exists = await redis.exists(key)
    return bool(exists)


async def _set_cooldown(
    redis,
    rule_name: str,
    target: str,
    cooldown_seconds: int,
) -> None:
    """Set cooldown for a rule+target."""
    key = f"anomaly_cooldown:{rule_name}:{target}"
    await redis.setex(key, cooldown_seconds, "1")


async def _record_event(
    redis,
    rule_name: str,
    target: str,
    window_seconds: int,
) -> int:
    """
    Record an event in Redis sorted set and return count within window.
    Key format: anomaly:{rule_name}:{target}
    """
    now = time.time()
    key = f"anomaly:{rule_name}:{target}"
    window_start = now - window_seconds

    pipe = redis.pipeline()
    # Remove expired entries
    pipe.zremrangebyscore(key, 0, window_start)
    # Add current event
    pipe.zadd(key, {f"{now}:{id(pipe)}": now})
    # Count events in window
    pipe.zcard(key)
    # Set TTL
    pipe.expire(key, window_seconds + 10)

    results = await pipe.execute()
    return results[2]  # zcard result


async def _execute_action(
    action: str,
    license_id: Optional[uuid.UUID],
    ip_address: Optional[str],
    db: AsyncSession,
    detail: str,
) -> None:
    """Execute the configured action for a triggered rule."""
    from app.models.models import LogAction, LicenseStatus
    from app.repositories.license_repo import LicenseRepository, ActivityLogRepository

    log_repo = ActivityLogRepository(db)

    if action == "lock_license" and license_id:
        lic_repo = LicenseRepository(db)
        await lic_repo.update_status(license_id, LicenseStatus.LOCKED)
        await log_repo.create(
            action=LogAction.AUTO_LOCKED,
            license_id=license_id,
            ip_address=ip_address,
            detail=detail,
        )
        await db.commit()
        logger.warning(f"License auto-locked: {license_id} — {detail}")

    elif action == "block_ip" and ip_address:
        # Block IP via Redis TTL key (checked by rate limiter or middleware)
        try:
            redis = await get_redis()
            block_key = f"blocked_ip:{ip_address}"
            await redis.setex(block_key, 900, "blocked")  # 15 min block
        except Exception as e:
            logger.warning(f"IP block failed: {ip_address} — {e}")
        await log_repo.create(
            action=LogAction.IP_ANOMALY,
            ip_address=ip_address,
            detail=detail,
        )
        await db.commit()

    elif action == "flag_only" or action == "webhook_alert":
        await log_repo.create(
            action=LogAction.SUSPICIOUS_ACTIVITY,
            license_id=license_id,
            ip_address=ip_address,
            detail=detail,
        )
        await db.commit()

    # Dispatch webhook for all triggered actions
    try:
        from app.services.webhook_service import WebhookService
        import asyncio
        asyncio.create_task(
            WebhookService.dispatch_event_static("suspicious_activity", {
                "rule_name": detail.split(":")[0] if ":" in detail else "unknown",
                "ip": ip_address,
                "key_partial": str(license_id)[:8] + "..." if license_id else None,
                "detail": detail,
            })
        )
    except Exception:
        pass


class AnomalyService:
    """
    Configurable anomaly detection service.
    Rules are loaded from DB with 60s cache.
    Counters use Redis sorted sets.
    """

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def check_auth_anomalies(
        self,
        ip_address: Optional[str],
        license_key: Optional[str],
        license_id: Optional[uuid.UUID] = None,
    ) -> None:
        """
        Check IP-based and key-based anomalies on each auth attempt.
        Called from AuthService.authenticate().
        """
        if not getattr(settings, 'anomaly_detection_enabled', True):
            return

        if not ip_address:
            return

        try:
            rules = await _load_rules(self.db)
            redis = await get_redis()
        except Exception:
            return  # If Redis/DB unavailable, skip anomaly checks

        # Check brute_force_ip
        if "brute_force_ip" in rules:
            rule = rules["brute_force_ip"]
            if not await _check_cooldown(redis, rule.name, ip_address, rule.cooldown_seconds):
                count = await _record_event(redis, rule.name, ip_address, rule.window_seconds)
                if count >= rule.threshold:
                    await _set_cooldown(redis, rule.name, ip_address, rule.cooldown_seconds)
                    await _execute_action(
                        rule.action, license_id, ip_address, self.db,
                        f"brute_force_ip: {count} attempts from {ip_address}"
                    )

        # Check brute_force_key
        if license_key and "brute_force_key" in rules:
            rule = rules["brute_force_key"]
            if not await _check_cooldown(redis, rule.name, license_key, rule.cooldown_seconds):
                count = await _record_event(redis, rule.name, license_key, rule.window_seconds)
                if count >= rule.threshold:
                    await _set_cooldown(redis, rule.name, license_key, rule.cooldown_seconds)
                    await _execute_action(
                        rule.action, license_id, ip_address, self.db,
                        f"brute_force_key: {count} attempts for key {license_key[:8]}..."
                    )

        # Check ip_rapid_change (per license key)
        if license_key and "ip_rapid_change" in rules:
            rule = rules["ip_rapid_change"]
            target = license_key
            if not await _check_cooldown(redis, rule.name, target, rule.cooldown_seconds):
                # Track unique IPs per key in window
                ip_key = f"anomaly:ip_track:{license_key}"
                window_start = time.time() - rule.window_seconds
                pipe = redis.pipeline()
                pipe.zremrangebyscore(ip_key, 0, window_start)
                pipe.zadd(ip_key, {ip_address: time.time()})
                pipe.zcard(ip_key)
                pipe.expire(ip_key, rule.window_seconds + 10)
                results = await pipe.execute()
                unique_ips = results[2]

                if unique_ips >= rule.threshold:
                    await _set_cooldown(redis, rule.name, target, rule.cooldown_seconds)
                    await _execute_action(
                        rule.action, license_id, ip_address, self.db,
                        f"ip_rapid_change: {unique_ips} unique IPs for key {license_key[:8]}..."
                    )

    async def check_hwid_anomalies(
        self,
        license_id: uuid.UUID,
        hwid_hash: str,
        ip_address: Optional[str] = None,
    ) -> None:
        """Check HWID spoof patterns. Called on HWID mismatch."""
        if not getattr(settings, 'anomaly_detection_enabled', True):
            return

        try:
            rules = await _load_rules(self.db)
            redis = await get_redis()
        except Exception:
            return

        if "hwid_spoof" in rules:
            rule = rules["hwid_spoof"]
            target = str(license_id)
            if not await _check_cooldown(redis, rule.name, target, rule.cooldown_seconds):
                count = await _record_event(redis, rule.name, target, rule.window_seconds)
                if count >= rule.threshold:
                    await _set_cooldown(redis, rule.name, target, rule.cooldown_seconds)
                    await _execute_action(
                        rule.action, license_id, ip_address, self.db,
                        f"hwid_spoof: {count} HWID mismatches for license {str(license_id)[:8]}..."
                    )
