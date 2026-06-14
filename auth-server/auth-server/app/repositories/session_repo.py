"""
Session ve Nonce Repository.
"""
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update, delete, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Session, UsedNonce


class SessionRepository:
    """Session veritabanı işlemleri."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    @staticmethod
    def _hash_token(token: str) -> str:
        """Token'ı SHA-256 ile hashle — plaintext saklanmaz."""
        return hashlib.sha256(token.encode()).hexdigest()

    async def create(
        self,
        license_id: uuid.UUID,
        token: str,
        hwid_hash: str,
        expires_at: datetime,
        ip_address: Optional[str] = None,
    ) -> Session:
        """Yeni session oluştur."""
        session = Session(
            license_id=license_id,
            token_hash=self._hash_token(token),
            hwid_hash=hwid_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            is_valid=True,
        )
        self.db.add(session)
        await self.db.flush()
        await self.db.refresh(session)
        return session

    async def get_by_token(self, token: str) -> Optional[Session]:
        """Token hash ile session bul."""
        token_hash = self._hash_token(token)
        result = await self.db.execute(
            select(Session).where(
                and_(
                    Session.token_hash == token_hash,
                    Session.is_valid == True,  # noqa: E712
                )
            )
        )
        return result.scalar_one_or_none()

    async def update_heartbeat(self, session_id: uuid.UUID, nonce: str) -> bool:
        """Son heartbeat zamanını güncelle."""
        result = await self.db.execute(
            update(Session)
            .where(Session.id == session_id)
            .values(
                last_heartbeat=datetime.now(timezone.utc),
                last_nonce=nonce,
            )
        )
        return result.rowcount > 0

    async def invalidate(self, session_id: uuid.UUID) -> bool:
        """Session'ı geçersiz kıl."""
        result = await self.db.execute(
            update(Session)
            .where(Session.id == session_id)
            .values(is_valid=False)
        )
        return result.rowcount > 0

    async def invalidate_all_for_license(self, license_id: uuid.UUID) -> int:
        """Bir lisansa ait tüm session'ları geçersiz kıl."""
        result = await self.db.execute(
            update(Session)
            .where(Session.license_id == license_id)
            .values(is_valid=False)
        )
        return result.rowcount


class NonceRepository:
    """Kullanılmış nonce yönetimi — Replay attack koruması."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def is_used(self, nonce: str) -> bool:
        """Nonce daha önce kullanılmış mı?"""
        result = await self.db.execute(
            select(UsedNonce).where(UsedNonce.nonce == nonce)
        )
        return result.scalar_one_or_none() is not None

    async def mark_used(self, nonce: str) -> None:
        """Nonce'u kullanılmış olarak işaretle."""
        used = UsedNonce(nonce=nonce)
        self.db.add(used)
        await self.db.flush()

    async def cleanup_old(self, older_than_minutes: int = 5) -> int:
        """
        Eski nonce kayıtlarını temizle.
        5 dakikadan eski nonce'lar tekrar kullanılamaz zaten
        (JWT exp süresi 5 dk'yı geçemez).
        """
        from sqlalchemy import func
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=older_than_minutes)
        result = await self.db.execute(
            delete(UsedNonce).where(UsedNonce.created_at < cutoff)
        )
        return result.rowcount
