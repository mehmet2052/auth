"""
Webhook Service — Discord webhook dispatch with versioned schema.

Non-blocking: uses httpx.AsyncClient with 3s timeout.
Fire-and-forget: asyncio.create_task() so auth never waits.
"""
import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.core.config import get_settings
from app.core.logging import logger
from app.db.database import AsyncSessionLocal

settings = get_settings()

# ── Embed colors ─────────────────────────────────────────────────────────────
_COLOR_SUCCESS = 0x2ECC71   # green
_COLOR_WARNING = 0xF1C40F   # yellow
_COLOR_DANGER  = 0xE74C3C   # red

_EVENT_COLORS = {
    "login_success": _COLOR_SUCCESS,
    "login_failed": _COLOR_DANGER,
    "hwid_mismatch": _COLOR_WARNING,
    "discord_mismatch": _COLOR_WARNING,
    "key_created": _COLOR_SUCCESS,
    "key_banned": _COLOR_DANGER,
    "key_suspended": _COLOR_WARNING,
    "reseller_action": _COLOR_WARNING,
    "suspicious_activity": _COLOR_DANGER,
}


def _build_discord_embed(
    event_type: str,
    data: dict,
    schema_version: str,
) -> dict:
    """Build a Discord embed payload for the given event."""
    color = _EVENT_COLORS.get(event_type, _COLOR_WARNING)
    timestamp = datetime.now(timezone.utc).isoformat()

    fields = []
    for key, value in data.items():
        if value is not None:
            fields.append({"name": key.replace("_", " ").title(), "value": str(value), "inline": True})

    return {
        "title": f"Event: {event_type}",
        "color": color,
        "fields": fields,
        "timestamp": timestamp,
        "footer": {
            "text": f"Nexus Auth v{settings.app_version} | Schema v{schema_version}"
        },
    }


def _build_payload_v1(
    event_type: str,
    data: dict,
    schema_version: str,
) -> dict:
    """Build v1.x webhook payload with Discord embed."""
    embed = _build_discord_embed(event_type, data, schema_version)
    return {
        "schema_version": schema_version,
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
        "embeds": [embed],
    }


def _sign_payload(payload_str: str, secret: str) -> str:
    """HMAC-SHA256 sign the payload for webhook verification."""
    return hmac.new(secret.encode(), payload_str.encode(), hashlib.sha256).hexdigest()


async def _send_webhook(
    url: str,
    payload: dict,
    secret: Optional[str] = None,
) -> bool:
    """Send webhook with 3s timeout. Returns True on success."""
    payload_str = json.dumps(payload)
    headers = {"Content-Type": "application/json"}

    if secret:
        sig = _sign_payload(payload_str, secret)
        headers["X-Nexus-Webhook-Signature"] = f"sha256={sig}"

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(url, content=payload_str, headers=headers)

            if resp.status_code >= 500:
                # Retry once with 2s backoff
                await asyncio.sleep(2)
                resp = await client.post(url, content=payload_str, headers=headers)

            if resp.status_code >= 400:
                logger.warning(
                    f"Webhook dispatch failed: {url} -> {resp.status_code}",
                )
                return False
            return True
    except Exception as e:
        logger.warning(f"Webhook dispatch error: {url} -> {e}")
        return False


class WebhookService:
    """
    Webhook dispatch service.
    Static method allows fire-and-forget from any service without DI.
    """

    @staticmethod
    async def dispatch_event_static(
        event_type: str,
        data: dict,
    ) -> None:
        """
        Dispatch event to all active webhooks subscribed to this event.
        Standalone DB session — does not share caller's transaction.
        """
        try:
            async with AsyncSessionLocal() as db:
                from app.repositories.webhook_repo import WebhookRepository
                repo = WebhookRepository(db)
                webhooks = await repo.get_active_for_event(event_type)

                for wh in webhooks:
                    # Build versioned payload
                    if wh.schema_version.startswith("1"):
                        payload = _build_payload_v1(event_type, data, wh.schema_version)
                    else:
                        # Future versions — fallback to v1 for now
                        payload = _build_payload_v1(event_type, data, wh.schema_version)

                    success = await _send_webhook(wh.url, payload, wh.secret)

                    if not success:
                        # Log failure (best-effort)
                        try:
                            from app.models.models import LogAction
                            from app.repositories.license_repo import ActivityLogRepository
                            log_repo = ActivityLogRepository(db)
                            await log_repo.create(
                                action=LogAction.WEBHOOK_FAILED,
                                detail=f"Webhook {wh.id} failed for event {event_type}",
                            )
                            await db.commit()
                        except Exception:
                            pass
        except Exception as e:
            logger.warning(f"Webhook dispatch_event_static error: {e}")
