"""
Anomaly Repository — AnomalyRule CRUD.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import AnomalyRule


class AnomalyRepository:
    """Anomaly rule veritabanı işlemleri."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_all_enabled(self) -> list[AnomalyRule]:
        result = await self.db.execute(
            select(AnomalyRule).where(AnomalyRule.is_enabled == True)  # noqa: E712
        )
        return list(result.scalars().all())

    async def get_all(self) -> list[AnomalyRule]:
        result = await self.db.execute(select(AnomalyRule))
        return list(result.scalars().all())

    async def get_by_id(self, rule_id: uuid.UUID) -> Optional[AnomalyRule]:
        result = await self.db.execute(
            select(AnomalyRule).where(AnomalyRule.id == rule_id)
        )
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Optional[AnomalyRule]:
        result = await self.db.execute(
            select(AnomalyRule).where(AnomalyRule.name == name)
        )
        return result.scalar_one_or_none()

    async def update(
        self,
        rule_id: uuid.UUID,
        is_enabled: Optional[bool] = None,
        threshold: Optional[int] = None,
        window_seconds: Optional[int] = None,
        action: Optional[str] = None,
        cooldown_seconds: Optional[int] = None,
    ) -> bool:
        values = {"updated_at": datetime.now(timezone.utc)}
        if is_enabled is not None:
            values["is_enabled"] = is_enabled
        if threshold is not None:
            values["threshold"] = threshold
        if window_seconds is not None:
            values["window_seconds"] = window_seconds
        if action is not None:
            values["action"] = action
        if cooldown_seconds is not None:
            values["cooldown_seconds"] = cooldown_seconds

        result = await self.db.execute(
            update(AnomalyRule)
            .where(AnomalyRule.id == rule_id)
            .values(**values)
        )
        return result.rowcount > 0
