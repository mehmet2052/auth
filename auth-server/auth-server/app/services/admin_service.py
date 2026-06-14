"""
Admin Service — Yönetici kimlik doğrulama ve yönetim.
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
from app.core.token_store import store_refresh_token
from app.models.models import LogAction, AdminRole
from app.repositories.admin_repo import AdminRepository
from app.repositories.license_repo import ActivityLogRepository
from app.schemas.schemas import (
    AdminLoginRequest, AdminLoginResponse,
    ResellerCreateRequest, AdminCreateRequest, AdminResponse,
    TokenRefreshRequest, TokenRefreshResponse,
)
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

        # Timing-safe kontrol — her zaman verify_password çalıştır
        # (admin yoksa dummy hash ile, süre farkı vermemek için)
        stored_hash = admin.password_hash if admin else (
            "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        )
        password_ok = verify_password(request.password, stored_hash)

        if not admin or not password_ok:
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
            data={"sub": str(admin.id), "type": "access"},
            expires_delta=expire_delta,
        )
        
        # Refresh token oluştur
        refresh_token, refresh_jti, refresh_expires = create_refresh_token(
            data={"sub": str(admin.id)}
        )
        
        # Refresh token'ı Redis'e kaydet
        await store_refresh_token(
            jti=refresh_jti,
            user_id=str(admin.id),
            expires_at=refresh_expires,
            family_id=refresh_jti,  # İlk token — kendisi family_id
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
            refresh_token=refresh_token,
            expires_at=expires_at,
            role=admin.role,
        )

    async def create_reseller(
        self,
        request: ResellerCreateRequest,
        parent_id: uuid.UUID,
    ) -> AdminResponse:
        """
        Reseller oluşturur (admin-only).
        """
        # Kullanıcı adı kontrolü
        existing = await self.admin_repo.get_by_username(request.username)
        if existing:
            raise ValueError("Bu kullanıcı adı zaten kullanılıyor")

        password_hash = hash_password(request.password)
        reseller = await self.admin_repo.create(
            username=request.username,
            password_hash=password_hash,
        )
        
        # Role ve parent_id ayarla
        reseller.role = AdminRole.RESELLER
        reseller.parent_id = parent_id
        reseller.key_quota_limit = request.key_quota_limit
        await self.db.flush()
        await self.db.refresh(reseller)

        await self.log_repo.create(
            action=LogAction.ADMIN_LOGIN,
            detail=f"Reseller oluşturuldu: {reseller.username} (parent: {parent_id})"
        )
        await self.db.commit()

        logger.info(
            "Reseller oluşturuldu",
            extra={"reseller_id": str(reseller.id), "parent_id": str(parent_id)}
        )

        return AdminResponse.model_validate(reseller)

    async def create_admin(
        self,
        request: AdminCreateRequest,
    ) -> AdminResponse:
        """
        Admin oluşturur (admin-only).
        """
        existing = await self.admin_repo.get_by_username(request.username)
        if existing:
            raise ValueError("Bu kullanıcı adı zaten kullanılıyor")

        password_hash = hash_password(request.password)
        admin = await self.admin_repo.create(
            username=request.username,
            password_hash=password_hash,
        )
        
        admin.role = AdminRole.ADMIN
        await self.db.flush()
        await self.db.refresh(admin)

        await self.log_repo.create(
            action=LogAction.ADMIN_LOGIN,
            detail=f"Admin oluşturuldu: {admin.username}"
        )
        await self.db.commit()

        logger.info("Admin oluşturuldu", extra={"admin_id": str(admin.id)})

        return AdminResponse.model_validate(admin)

    async def suspend_admin(
        self,
        admin_id: uuid.UUID,
        suspended_by: uuid.UUID,
    ) -> bool:
        """
        Admin/reseller hesabını askıya al.
        """
        admin = await self.admin_repo.get_by_id(admin_id)
        if not admin:
            return False

        await self.admin_repo.set_active(admin_id, False)
        await self.log_repo.create(
            action=LogAction.ADMIN_LOGIN_FAIL,
            detail=f"Admin suspend edildi: {admin.username} (by: {suspended_by})"
        )
        await self.db.commit()

        logger.info(
            "Admin suspend edildi",
            extra={"admin_id": str(admin_id), "suspended_by": str(suspended_by)}
        )
        return True

    async def list_admins(
        self,
        page: int = 1,
        page_size: int = 20,
        role_filter: Optional[AdminRole] = None,
    ) -> tuple[list[AdminResponse], int]:
        """Admin/reseller listesi."""
        items, total = await self.admin_repo.list_all(
            page=page,
            page_size=page_size,
            role_filter=role_filter,
        )
        return [AdminResponse.model_validate(i) for i in items], total

    async def refresh_token(
        self,
        request: TokenRefreshRequest,
    ) -> TokenRefreshResponse:
        """
        Refresh token'ı doğrula ve yeni access + refresh token ver.
        Token rotation: eski refresh token revoke edilir.
        """
        from app.core.security import decode_refresh_token
        from app.core.token_store import (
            get_token_data, revoke_refresh_token, revoke_family,
            store_refresh_token,
        )
        from jose import JWTError
        
        try:
            payload = decode_refresh_token(request.refresh_token)
            jti = payload.get("jti")
            user_id = payload.get("sub")
            family_id = payload.get("family")
            
            if not jti or not user_id or not family_id:
                raise ValueError("Invalid refresh token")
        except JWTError:
            raise ValueError("Invalid or expired refresh token")
        
        # Token Redis'te var mı kontrol et
        token_data = await get_token_data(jti)
        
        if token_data is None:
            # Token bulunamadı — muhtemelen revoked
            # Güvenlik: tüm family'yi revoke et (token theft detection)
            await revoke_family(family_id)
            raise ValueError("Refresh token reuse detected — all sessions revoked")
        
        # Token'ı doğrula — user_id eşleşmeli
        stored_user_id, stored_family_id = token_data
        if stored_user_id != user_id or stored_family_id != family_id:
            raise ValueError("Invalid refresh token")
        
        # Eski refresh token'ı revoke et (rotation)
        await revoke_refresh_token(jti)
        
        # Yeni token'lar oluştur
        expire_delta = timedelta(minutes=settings.access_token_expire_minutes)
        expires_at = datetime.now(timezone.utc) + expire_delta
        
        new_access_token = create_access_token(
            data={"sub": user_id, "type": "access"},
            expires_delta=expire_delta,
        )
        
        new_refresh_token, new_jti, new_refresh_expires = create_refresh_token(
            data={"sub": user_id},
            family_id=family_id,  # Aynı family
        )
        
        # Yeni refresh token'ı Redis'e kaydet
        await store_refresh_token(
            jti=new_jti,
            user_id=user_id,
            expires_at=new_refresh_expires,
            family_id=family_id,
        )
        
        logger.info(
            "Token rotation completed",
            extra={"user_id": user_id}
        )
        
        return TokenRefreshResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_at=expires_at,
        )

    async def logout(
        self,
        refresh_token: str,
    ) -> bool:
        """
        Refresh token'ı revoke et (logout).
        """
        from app.core.security import decode_refresh_token
        from app.core.token_store import revoke_refresh_token
        from jose import JWTError
        
        try:
            payload = decode_refresh_token(refresh_token)
            jti = payload.get("jti")
            if jti:
                await revoke_refresh_token(jti)
                return True
        except JWTError:
            pass
        
        return False
