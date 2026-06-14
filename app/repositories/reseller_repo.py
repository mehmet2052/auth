"""
Reseller Repository — Reseller veritabanı işlemleri.
"""
import uuid
from datetime import datetime, timezone, date
from typing import Optional

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.reseller import Reseller


class ResellerRepository:
    """Reseller veritabanı işlemleri."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_by_username(self, username: str) -> Optional[Reseller]:
        result = await self.db.execute(
            select(Reseller).where(Reseller.username == username)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, reseller_id: uuid.UUID) -> Optional[Reseller]:
        result = await self.db.execute(
            select(Reseller).where(Reseller.id == reseller_id)
        )
        return result.scalar_one_or_none()

    async def create(
        self,
        username: str,
        password_hash: str,
        created_by: uuid.UUID,
        key_quota_limit: Optional[int] = None,
        daily_key_limit: Optional[int] = None,
    ) -> Reseller:
        reseller = Reseller(
            username=username,
            password_hash=password_hash,
            created_by=created_by,
            key_quota_limit=key_quota_limit,
            daily_key_limit=daily_key_limit,
        )
        self.db.add(reseller)
        await self.db.flush()
        await self.db.refresh(reseller)
        return reseller

    async def update_last_login(self, reseller_id: uuid.UUID) -> None:
        await self.db.execute(
            update(Reseller)
            .where(Reseller.id == reseller_id)
            .values(last_login=datetime.now(timezone.utc))
        )

    async def set_active(self, reseller_id: uuid.UUID, is_active: bool) -> bool:
        result = await self.db.execute(
            update(Reseller)
            .where(Reseller.id == reseller_id)
            .values(is_active=is_active)
        )
        return result.rowcount > 0

    async def increment_keys_count(self, reseller_id: uuid.UUID, count: int = 1) -> bool:
        """Increment both lifetime and daily counters. Reset daily if date changed."""
        today = date.today()
        reseller = await self.get_by_id(reseller_id)
        if not reseller:
            return False

        # Reset daily counter if date changed
        if reseller.daily_keys_date != today:
            await self.db.execute(
                update(Reseller)
                .where(Reseller.id == reseller_id)
                .values(
                    keys_created_count=Reseller.keys_created_count + count,
                    daily_keys_created_today=count,
                    daily_keys_date=today,
                )
            )
        else:
            await self.db.execute(
                update(Reseller)
                .where(Reseller.id == reseller_id)
                .values(
                    keys_created_count=Reseller.keys_created_count + count,
                    daily_keys_created_today=Reseller.daily_keys_created_today + count,
                )
            )
        return True

    async def check_daily_quota(self, reseller_id: uuid.UUID, requested: int) -> tuple[bool, int]:
        """
        Check daily quota. Returns (allowed, remaining).
        Resets daily counter if date changed.
        """
        reseller = await self.get_by_id(reseller_id)
        if not reseller:
            return False, 0

        if reseller.daily_key_limit is None:
            return True, 999999  # Unlimited

        today = date.today()
        current_count = reseller.daily_keys_created_today
        if reseller.daily_keys_date != today:
            current_count = 0  # Reset on new day

        remaining = reseller.daily_key_limit - current_count
        return remaining >= requested, max(0, remaining)

    async def check_lifetime_quota(self, reseller_id: uuid.UUID, requested: int) -> tuple[bool, int]:
        """Check lifetime quota. Returns (allowed, remaining)."""
        reseller = await self.get_by_id(reseller_id)
        if not reseller:
            return False, 0

        if reseller.key_quota_limit is None:
            return True, 999999  # Unlimited

        remaining = reseller.key_quota_limit - reseller.keys_created_count
        return remaining >= requested, max(0, remaining)

    async def list_all(
        self,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Reseller], int]:
        query = select(Reseller).order_by(Reseller.created_at.desc())
        count_query = select(func.count(Reseller.id))

        query = query.offset((page - 1) * page_size).limit(page_size)

        items_result = await self.db.execute(query)
        count_result = await self.db.execute(count_query)

        return list(items_result.scalars().all()), count_result.scalar_one()
