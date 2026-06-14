"""
License Service — Lisans yönetim iş mantığı (Admin paneli için).
"""
import uuid
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_license_key
from app.models.models import LicenseType, LicenseStatus, LogAction, ActivationAction
from app.repositories.license_repo import (
    LicenseRepository, ActivityLogRepository, ActivationHistoryRepository,
)
from app.repositories.session_repo import SessionRepository
from app.repositories.admin_repo import AdminRepository
from app.schemas.schemas import (
    LicenseCreateRequest, LicenseResponse,
    LicenseListResponse, ActivityLogListResponse,
    ActivationHistoryListResponse, ActivationHistoryResponse,
)
from app.core.logging import logger


class LicenseService:
    """Lisans yönetim servisi."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.license_repo = LicenseRepository(db)
        self.log_repo     = ActivityLogRepository(db)
        self.session_repo = SessionRepository(db)
        self.admin_repo   = AdminRepository(db)
        self.activation_repo = ActivationHistoryRepository(db)

    async def create_licenses(
        self,
        request: LicenseCreateRequest,
        admin_id: uuid.UUID,
    ) -> list[LicenseResponse]:
        """
        Toplu lisans oluştur.
        Her lisans için benzersiz key üretilir.
        """
        created = []
        for _ in range(request.count):
            key = generate_license_key()
            # Çakışma ihtimali astronomik küçük ama kontrol et
            while await self.license_repo.get_by_key(key):
                key = generate_license_key()

            license_ = await self.license_repo.create(
                key=key,
                license_type=request.license_type,
                created_by=admin_id,
                note=request.note,
            )
            await self.log_repo.create(
                action=LogAction.LICENSE_CREATED,
                license_id=license_.id,
                detail=f"Admin {admin_id} tarafından oluşturuldu"
            )
            created.append(LicenseResponse.model_validate(license_))

        await self.db.commit()
        
        # Reseller'ın keys_created_count'unu arttır
        await self.admin_repo.increment_keys_count(admin_id, len(created))
        
        logger.info(
            f"{len(created)} lisans oluşturuldu",
            extra={"admin_id": str(admin_id)}
        )
        return created

    async def get_list(
        self,
        page: int = 1,
        page_size: int = 20,
        status_filter: Optional[LicenseStatus] = None,
        created_by_filter: Optional[uuid.UUID] = None,
    ) -> LicenseListResponse:
        """Sayfalanmış lisans listesi."""
        items, total = await self.license_repo.list_all(
            page=page,
            page_size=page_size,
            status_filter=status_filter,
            created_by_filter=created_by_filter,
        )
        return LicenseListResponse(
            items=[LicenseResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            page_size=page_size,
        )

    async def suspend(self, license_id: uuid.UUID, admin_id: uuid.UUID) -> bool:
        """Lisansı askıya al."""
        license_ = await self.license_repo.get_by_id(license_id)
        if not license_:
            return False

        await self.license_repo.update_status(license_id, LicenseStatus.SUSPENDED)
        # Aktif session'ları kapat
        await self.session_repo.invalidate_all_for_license(license_id)
        await self.log_repo.create(
            action=LogAction.LICENSE_REVOKED,
            license_id=license_id,
            detail=f"Admin {admin_id} tarafından askıya alındı"
        )
        await self.db.commit()
        return True

    async def revoke(self, license_id: uuid.UUID, admin_id: uuid.UUID) -> bool:
        """Lisansı iptal et."""
        license_ = await self.license_repo.get_by_id(license_id)
        if not license_:
            return False

        await self.license_repo.update_status(license_id, LicenseStatus.REVOKED)
        await self.session_repo.invalidate_all_for_license(license_id)
        await self.log_repo.create(
            action=LogAction.LICENSE_REVOKED,
            license_id=license_id,
            detail=f"Admin {admin_id} tarafından iptal edildi"
        )
        await self.db.commit()
        return True

    async def reset_hwid(
        self,
        license_id: uuid.UUID,
        admin_id: uuid.UUID,
        reason: Optional[str] = None,
    ) -> bool:
        """HWID'i sıfırla."""
        license_ = await self.license_repo.get_by_id(license_id)
        if not license_:
            return False

        await self.license_repo.reset_hwid(license_id)
        await self.session_repo.invalidate_all_for_license(license_id)
        await self.log_repo.create(
            action=LogAction.HWID_RESET,
            license_id=license_id,
            detail=f"Admin {admin_id} tarafından sıfırlandı. Sebep: {reason or 'Belirtilmedi'}"
        )
        await self.db.commit()
        return True

    async def get_activity_logs(
        self,
        page: int = 1,
        page_size: int = 50,
        license_id: Optional[uuid.UUID] = None,
    ) -> ActivityLogListResponse:
        """Aktivite loglarını getir."""
        from app.schemas.schemas import ActivityLogResponse
        items, total = await self.log_repo.list_all(
            page=page,
            page_size=page_size,
            license_id=license_id,
        )
        return ActivityLogListResponse(
            items=[ActivityLogResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            page_size=page_size,
        )

    async def get_activation_history(
        self,
        license_id: uuid.UUID,
        page: int = 1,
        page_size: int = 50,
    ) -> ActivationHistoryListResponse:
        """Lisansın aktivasyon geçmişi."""
        items, total = await self.activation_repo.list_by_license(
            license_id=license_id,
            page=page,
            page_size=page_size,
        )
        return ActivationHistoryListResponse(
            items=[ActivationHistoryResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            page_size=page_size,
        )
