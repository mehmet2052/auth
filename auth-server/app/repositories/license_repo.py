"""
Lisans Repository — Veritabanı erişim katmanı.
Tüm DB sorguları burada. Service katmanı bu sınıfı kullanır.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import License, LicenseStatus, LicenseType, ActivityLog, LogAction


class LicenseRepository:
    """Lisans veritabanı işlemleri."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(
        self,
        key: str,
        license_type: LicenseType,
        created_by: Optional[uuid.UUID] = None,
        note: Optional[str] = None,
    ) -> License:
        """Yeni lisans oluştur."""
        license_ = License(
            key=key,
            license_type=license_type,
            status=LicenseStatus.ACTIVE,
            created_by=created_by,
            note=note,
        )
        self.db.add(license_)
        await self.db.flush()
        await self.db.refresh(license_)
        return license_

    async def get_by_key(self, key: str) -> Optional[License]:
        """Anahtar ile lisans bul."""
        result = await self.db.execute(
            select(License).where(License.key == key)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, license_id: uuid.UUID) -> Optional[License]:
        """ID ile lisans bul."""
        result = await self.db.execute(
            select(License).where(License.id == license_id)
        )
        return result.scalar_one_or_none()

    async def list_all(
        self,
        page: int = 1,
        page_size: int = 20,
        status_filter: Optional[LicenseStatus] = None,
    ) -> tuple[list[License], int]:
        """Sayfalanmış lisans listesi."""
        query = select(License)
        count_query = select(func.count(License.id))

        if status_filter:
            query = query.where(License.status == status_filter)
            count_query = count_query.where(License.status == status_filter)

        query = query.order_by(License.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        items_result = await self.db.execute(query)
        count_result = await self.db.execute(count_query)

        return list(items_result.scalars().all()), count_result.scalar_one()

    async def activate(
        self,
        license_: License,
        hwid_hash: str,
        expires_at: Optional[datetime],
    ) -> License:
        """Lisansı aktive et — HWID bağla ve süreyi ayarla."""
        license_.status = LicenseStatus.USED
        license_.hwid_hash = hwid_hash
        license_.activated_at = datetime.now(timezone.utc)
        license_.expires_at = expires_at
        await self.db.flush()
        return license_

    async def update_status(
        self,
        license_id: uuid.UUID,
        status: LicenseStatus,
    ) -> bool:
        """Lisans durumunu güncelle."""
        result = await self.db.execute(
            update(License)
            .where(License.id == license_id)
            .values(status=status)
        )
        return result.rowcount > 0

    async def reset_hwid(self, license_id: uuid.UUID) -> bool:
        """HWID'i sıfırla — kullanıcı yeniden bağlanabilsin."""
        result = await self.db.execute(
            update(License)
            .where(License.id == license_id)
            .values(hwid_hash=None, status=LicenseStatus.ACTIVE)
        )
        return result.rowcount > 0

    async def mark_expired(self) -> int:
        """
        Süresi dolmuş lisansları toplu güncelle.
        Periyodik task tarafından çağrılır.
        """
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            update(License)
            .where(
                and_(
                    License.status == LicenseStatus.USED,
                    License.expires_at != None,  # noqa: E711
                    License.expires_at < now,
                )
            )
            .values(status=LicenseStatus.EXPIRED)
        )
        return result.rowcount


class ActivityLogRepository:
    """Aktivite log veritabanı işlemleri."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(
        self,
        action: LogAction,
        license_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        hwid_hash: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> ActivityLog:
        """Yeni log kaydı oluştur."""
        log = ActivityLog(
            action=action,
            license_id=license_id,
            ip_address=ip_address,
            hwid_hash=hwid_hash,
            detail=detail,
        )
        self.db.add(log)
        await self.db.flush()
        return log

    async def list_all(
        self,
        page: int = 1,
        page_size: int = 50,
        license_id: Optional[uuid.UUID] = None,
    ) -> tuple[list[ActivityLog], int]:
        """Sayfalanmış log listesi."""
        query = select(ActivityLog)
        count_query = select(func.count(ActivityLog.id))

        if license_id:
            query = query.where(ActivityLog.license_id == license_id)
            count_query = count_query.where(ActivityLog.license_id == license_id)

        query = query.order_by(ActivityLog.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        items_result = await self.db.execute(query)
        count_result = await self.db.execute(count_query)

        return list(items_result.scalars().all()), count_result.scalar_one()
