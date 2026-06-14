"""
Admin Repository.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Admin, AdminRole


class AdminRepository:
    """Admin veritabanı işlemleri."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_by_username(self, username: str) -> Optional[Admin]:
        """Kullanıcı adı ile admin bul."""
        result = await self.db.execute(
            select(Admin).where(Admin.username == username)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, admin_id: uuid.UUID) -> Optional[Admin]:
        """ID ile admin bul."""
        result = await self.db.execute(
            select(Admin).where(Admin.id == admin_id)
        )
        return result.scalar_one_or_none()

    async def create(self, username: str, password_hash: str) -> Admin:
        """Yeni admin oluştur."""
        admin = Admin(username=username, password_hash=password_hash)
        self.db.add(admin)
        await self.db.flush()
        await self.db.refresh(admin)
        return admin

    async def update_last_login(self, admin_id: uuid.UUID) -> None:
        """Son giriş zamanını güncelle."""
        await self.db.execute(
            update(Admin)
            .where(Admin.id == admin_id)
            .values(last_login=datetime.now(timezone.utc))
        )

    async def list_all(
        self,
        page: int = 1,
        page_size: int = 20,
        role_filter: Optional[AdminRole] = None,
    ) -> tuple[list[Admin], int]:
        """Sayfalanmış admin/reseller listesi."""
        query = select(Admin)
        count_query = select(func.count(Admin.id))

        if role_filter:
            query = query.where(Admin.role == role_filter)
            count_query = count_query.where(Admin.role == role_filter)

        query = query.order_by(Admin.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        items_result = await self.db.execute(query)
        count_result = await self.db.execute(count_query)

        return list(items_result.scalars().all()), count_result.scalar_one()

    async def update_role(self, admin_id: uuid.UUID, role: AdminRole) -> bool:
        """Admin rolünü güncelle."""
        result = await self.db.execute(
            update(Admin)
            .where(Admin.id == admin_id)
            .values(role=role)
        )
        return result.rowcount > 0

    async def set_active(self, admin_id: uuid.UUID, is_active: bool) -> bool:
        """Admin hesabını aktif/deaktif et."""
        result = await self.db.execute(
            update(Admin)
            .where(Admin.id == admin_id)
            .values(is_active=is_active)
        )
        return result.rowcount > 0

    async def increment_keys_count(self, admin_id: uuid.UUID, count: int = 1) -> bool:
        """Reseller'ın key sayacını arttır."""
        result = await self.db.execute(
            update(Admin)
            .where(Admin.id == admin_id)
            .values(keys_created_count=Admin.keys_created_count + count)
        )
        return result.rowcount > 0
