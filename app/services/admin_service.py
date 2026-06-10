"""
Admin Service — Yönetici kimlik doğrulama.
"""
from datetime import timedelta, datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import verify_password, create_access_token
from app.models.models import LogAction
from app.repositories.admin_repo import AdminRepository
from app.repositories.license_repo import ActivityLogRepository
from app.schemas.schemas import AdminLoginRequest, AdminLoginResponse
from app.core.logging import logger

settings = get_settings()


class AdminService:
    """Admin kimlik doğrulama servisi."""

    def __init__(self, db: AsyncSession) -> None:
        self.db         = db
        self.admin_repo = AdminRepository(db)
        self.log_repo   = ActivityLogRepository(db)

    async def login(
        self,
        request: AdminLoginRequest,
        ip_address: Optional[str] = None,
    ) -> AdminLoginResponse:
        """
        Admin girişi.
        Başarısız girişler loglanır.
        """
        admin = await self.admin_repo.get_by_username(request.username)

        # Timing-safe kontrol — kullanıcı bulunamasa da aynı süre geçsin
        if not admin or not verify_password(request.password, admin.password_hash):
            await self.log_repo.create(
                action=LogAction.ADMIN_LOGIN_FAIL,
                ip_address=ip_address,
                detail=f"Başarısız giriş: {request.username}"
            )
            await self.db.commit()
            logger.warning(
                "Başarısız admin girişi",
                extra={"username": request.username, "ip": ip_address}
            )
            raise ValueError("Geçersiz kullanıcı adı veya şifre")

        if not admin.is_active:
            raise ValueError("Bu hesap devre dışı")

        # Token oluştur
        expire_delta = timedelta(minutes=settings.access_token_expire_minutes)
        expires_at = datetime.now(timezone.utc) + expire_delta
        token = create_access_token(
            data={"sub": str(admin.id), "type": "admin"},
            expires_delta=expire_delta,
        )

        # Son giriş zamanını güncelle
        await self.admin_repo.update_last_login(admin.id)
        await self.log_repo.create(
            action=LogAction.ADMIN_LOGIN,
            ip_address=ip_address,
            detail=f"Başarılı giriş: {admin.username}"
        )
        await self.db.commit()

        logger.info(
            "Admin girişi başarılı",
            extra={"admin_id": str(admin.id), "ip": ip_address}
        )

        return AdminLoginResponse(
            access_token=token,
            expires_at=expires_at,
        )
