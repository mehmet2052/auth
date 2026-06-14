"""
Reseller Service — Reseller kimlik doğrulama ve yönetim iş mantığı.
"""
import uuid
from datetime import timedelta, datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import (
    verify_password, hash_password,
    create_access_token, create_refresh_token,
)
from app.core.token_store import store_refresh_token, get_token_data, revoke_refresh_token, revoke_family
from app.models.models import LogAction
from app.repositories.reseller_repo import ResellerRepository
from app.repositories.license_repo import ActivityLogRepository
from app.schemas.schemas import TokenRefreshRequest, TokenRefreshResponse
from app.core.logging import logger

settings = get_settings()


class ResellerService:
    """Reseller iş mantığı servisi."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.reseller_repo = ResellerRepository(db)
        self.log_repo = ActivityLogRepository(db)

    async def login(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
    ) -> dict:
        """
        Reseller girişi.
        Returns: dict with access_token, refresh_token, expires_at, role.
        """
        reseller = await self.reseller_repo.get_by_username(username)

        # Timing-safe check
        stored_hash = reseller.password_hash if reseller else (
            "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        )
        password_ok = verify_password(password, stored_hash)

        if not reseller or not password_ok:
            logger.warning(
                "Başarısız reseller girişi",
                extra={"username": username, "ip": ip_address}
            )
            raise ValueError("Geçersiz kullanıcı adı veya şifre")

        if not reseller.is_active:
            raise ValueError("Bu hesap devre dışı")

        # Token oluştur — type "reseller_access"
        expire_delta = timedelta(minutes=settings.access_token_expire_minutes)
        expires_at = datetime.now(timezone.utc) + expire_delta
        token = create_access_token(
            data={
                "sub": str(reseller.id),
                "type": "access",
                "role": "reseller",
                "entity": "reseller",
            },
            expires_delta=expire_delta,
        )

        refresh_token, refresh_jti, refresh_expires = create_refresh_token(
            data={"sub": str(reseller.id), "entity": "reseller"}
        )

        await store_refresh_token(
            jti=refresh_jti,
            user_id=str(reseller.id),
            expires_at=refresh_expires,
            family_id=refresh_jti,
        )

        await self.reseller_repo.update_last_login(reseller.id)
        await self.log_repo.create(
            action=LogAction.ADMIN_LOGIN,
            ip_address=ip_address,
            detail=f"Reseller giriş: {reseller.username}"
        )
        await self.db.commit()

        logger.info(
            "Reseller girişi başarılı",
            extra={"reseller_id": str(reseller.id), "ip": ip_address}
        )

        return {
            "access_token": token,
            "refresh_token": refresh_token,
            "expires_at": expires_at,
            "role": "reseller",
        }

    async def create_reseller(
        self,
        username: str,
        password: str,
        created_by: uuid.UUID,
        key_quota_limit: Optional[int] = None,
        daily_key_limit: Optional[int] = None,
    ):
        """Yeni reseller oluştur (admin-only)."""
        existing = await self.reseller_repo.get_by_username(username)
        if existing:
            raise ValueError("Bu kullanıcı adı zaten kullanılıyor")

        password_hash = hash_password(password)
        reseller = await self.reseller_repo.create(
            username=username,
            password_hash=password_hash,
            created_by=created_by,
            key_quota_limit=key_quota_limit,
            daily_key_limit=daily_key_limit,
        )

        await self.log_repo.create(
            action=LogAction.ADMIN_LOGIN,
            detail=f"Reseller oluşturuldu: {reseller.username} (by: {created_by})"
        )
        await self.db.commit()

        logger.info(
            "Reseller oluşturuldu",
            extra={"reseller_id": str(reseller.id), "created_by": str(created_by)}
        )

        return reseller

    async def suspend_reseller(
        self,
        reseller_id: uuid.UUID,
        suspended_by: uuid.UUID,
    ) -> bool:
        """Reseller hesabını askıya al."""
        reseller = await self.reseller_repo.get_by_id(reseller_id)
        if not reseller:
            return False

        await self.reseller_repo.set_active(reseller_id, False)
        await self.log_repo.create(
            action=LogAction.ADMIN_LOGIN_FAIL,
            detail=f"Reseller suspend: {reseller.username} (by: {suspended_by})"
        )
        await self.db.commit()

        logger.info(
            "Reseller suspend edildi",
            extra={"reseller_id": str(reseller_id), "suspended_by": str(suspended_by)}
        )
        return True

    async def refresh_token(
        self,
        request: TokenRefreshRequest,
    ) -> TokenRefreshResponse:
        """
        Reseller refresh token doğrulama ve yeni token pair.
        Token rotation: eski refresh token revoke edilir.
        """
        from app.core.security import decode_refresh_token
        from app.core.token_store import is_token_revoked
        from jose import JWTError

        try:
            payload = decode_refresh_token(request.refresh_token)
            jti = payload.get("jti")
            user_id = payload.get("sub")
            family_id = payload.get("family")
            entity = payload.get("entity", "")

            if not jti or not user_id or not family_id:
                raise ValueError("Invalid refresh token")
            if entity != "reseller":
                raise ValueError("Not a reseller refresh token")
        except JWTError:
            raise ValueError("Invalid or expired refresh token")

        # Token Redis'te var mı kontrol et
        token_data = await get_token_data(jti)
        if token_data is None:
            await revoke_family(family_id)
            raise ValueError("Refresh token reuse detected — all sessions revoked")

        stored_user_id, stored_family_id = token_data
        if stored_user_id != user_id or stored_family_id != family_id:
            raise ValueError("Invalid refresh token")

        # Eski refresh token'ı revoke et (rotation)
        await revoke_refresh_token(jti)

        # Yeni token'lar oluştur — entity: reseller claims
        expire_delta = timedelta(minutes=settings.access_token_expire_minutes)
        expires_at = datetime.now(timezone.utc) + expire_delta

        new_access = create_access_token(
            data={
                "sub": user_id,
                "type": "access",
                "role": "reseller",
                "entity": "reseller",
            },
            expires_delta=expire_delta,
        )

        new_refresh, new_jti, new_refresh_expires = create_refresh_token(
            data={"sub": user_id, "entity": "reseller"},
            family_id=family_id,
        )

        await store_refresh_token(
            jti=new_jti,
            user_id=user_id,
            expires_at=new_refresh_expires,
            family_id=family_id,
        )

        logger.info(
            "Reseller token rotation",
            extra={"reseller_id": user_id}
        )

        return TokenRefreshResponse(
            access_token=new_access,
            refresh_token=new_refresh,
            expires_at=expires_at,
        )

    async def list_resellers(
        self,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list, int]:
        """Sayfalanmış reseller listesi."""
        return await self.reseller_repo.list_all(
            page=page, page_size=page_size
        )
