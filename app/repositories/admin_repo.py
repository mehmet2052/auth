"""
Admin Repository.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Admin


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
