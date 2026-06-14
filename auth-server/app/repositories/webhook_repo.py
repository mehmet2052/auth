"""
Webhook Repository — WebhookConfig CRUD.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.webhook import WebhookConfig


class WebhookRepository:
    """Webhook veritabanı işlemleri."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_active_for_event(self, event_type: str) -> list[WebhookConfig]:
        """Get all active webhooks subscribed to a given event type."""
        result = await self.db.execute(
            select(WebhookConfig).where(WebhookConfig.is_active == True)  # noqa: E712
        )
        all_active = list(result.scalars().all())
        # Filter in Python (event_types is JSON array in TEXT column)
        matching = []
        for wh in all_active:
            try:
                events = json.loads(wh.event_types) if wh.event_types else []
            except (json.JSONDecodeError, TypeError):
                events = []
            if event_type in events or "*" in events:
                matching.append(wh)
        return matching

    async def get_by_id(self, webhook_id: uuid.UUID) -> Optional[WebhookConfig]:
        result = await self.db.execute(
            select(WebhookConfig).where(WebhookConfig.id == webhook_id)
        )
        return result.scalar_one_or_none()

    async def create(
        self,
        url: str,
        event_types: list[str],
        created_by: uuid.UUID,
        schema_version: str = "1.0",
        secret: Optional[str] = None,
    ) -> WebhookConfig:
        wh = WebhookConfig(
            url=url,
            event_types=json.dumps(event_types),
            schema_version=schema_version,
            created_by=created_by,
            secret=secret,
        )
        self.db.add(wh)
        await self.db.flush()
        await self.db.refresh(wh)
        return wh

    async def update(
        self,
        webhook_id: uuid.UUID,
        url: Optional[str] = None,
        event_types: Optional[list[str]] = None,
        schema_version: Optional[str] = None,
        is_active: Optional[bool] = None,
        secret: Optional[str] = None,
    ) -> bool:
        values = {"updated_at": datetime.now(timezone.utc)}
        if url is not None:
            values["url"] = url
        if event_types is not None:
            values["event_types"] = json.dumps(event_types)
        if schema_version is not None:
            values["schema_version"] = schema_version
        if is_active is not None:
            values["is_active"] = is_active
        if secret is not None:
            values["secret"] = secret

        result = await self.db.execute(
            update(WebhookConfig)
            .where(WebhookConfig.id == webhook_id)
            .values(**values)
        )
        return result.rowcount > 0

    async def delete(self, webhook_id: uuid.UUID) -> bool:
        result = await self.db.execute(
            delete(WebhookConfig).where(WebhookConfig.id == webhook_id)
        )
        return result.rowcount > 0

    async def list_all(
        self, page: int = 1, page_size: int = 20
    ) -> tuple[list[WebhookConfig], int]:
        query = (
            select(WebhookConfig)
            .order_by(WebhookConfig.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        count_query = select(func.count(WebhookConfig.id))

        items_result = await self.db.execute(query)
        count_result = await self.db.execute(count_query)
        return list(items_result.scalars().all()), count_result.scalar_one()
