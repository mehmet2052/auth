"""
Admin panel API endpoint'leri.
Tüm endpoint'ler JWT ile korumalı.
"""
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Query, status

from app.api.deps import DBDep, AdminDep
from app.middleware.rate_limiter import limiter
from app.models.models import LicenseStatus
from app.services.admin_service import AdminService
from app.services.license_service import LicenseService
from app.schemas.schemas import (
    AdminLoginRequest, AdminLoginResponse,
    LicenseCreateRequest, LicenseResponse, LicenseListResponse,
    HwidResetRequest, MessageResponse,
    ActivityLogListResponse, ErrorResponse,
)

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


# ── Auth ──────────────────────────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=AdminLoginResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Admin girişi",
)
@limiter.limit("5/minute")
async def admin_login(
    request: Request,
    body: AdminLoginRequest,
    db: DBDep,
) -> AdminLoginResponse:
    """Admin giriş endpoint'i. Rate limit: 5/dk. API secret gerektirmez."""
    ip = request.client.host if request.client else None
    service = AdminService(db)
    try:
        return await service.login(body, ip_address=ip)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


# ── Lisans Yönetimi ────────────────────────────────────────────────────────────

@router.post(
    "/licenses",
    response_model=list[LicenseResponse],
    summary="Lisans oluştur",
)
@limiter.limit("30/minute")
async def create_licenses(
    request: Request,
    body: LicenseCreateRequest,
    db: DBDep,
    admin: AdminDep,
) -> list[LicenseResponse]:
    """Yeni lisans(lar) oluştur."""
    service = LicenseService(db)
    return await service.create_licenses(body, admin_id=admin["id"])


@router.get(
    "/licenses",
    response_model=LicenseListResponse,
    summary="Lisans listesi",
)
@limiter.limit("60/minute")
async def list_licenses(
    request: Request,
    db: DBDep,
    admin: AdminDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[LicenseStatus] = None,
) -> LicenseListResponse:
    """Sayfalanmış lisans listesi."""
    service = LicenseService(db)
    return await service.get_list(page=page, page_size=page_size, status_filter=status_filter)


@router.post(
    "/licenses/{license_id}/suspend",
    response_model=MessageResponse,
    summary="Lisansı askıya al",
)
@limiter.limit("30/minute")
async def suspend_license(
    request: Request,
    license_id: uuid.UUID,
    db: DBDep,
    admin: AdminDep,
) -> MessageResponse:
    service = LicenseService(db)
    ok = await service.suspend(license_id, admin_id=admin["id"])
    if not ok:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    return MessageResponse(message="Lisans askıya alındı")


@router.delete(
    "/licenses/{license_id}",
    response_model=MessageResponse,
    summary="Lisansı iptal et",
)
@limiter.limit("30/minute")
async def revoke_license(
    request: Request,
    license_id: uuid.UUID,
    db: DBDep,
    admin: AdminDep,
) -> MessageResponse:
    service = LicenseService(db)
    ok = await service.revoke(license_id, admin_id=admin["id"])
    if not ok:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    return MessageResponse(message="Lisans iptal edildi")


@router.post(
    "/licenses/reset-hwid",
    response_model=MessageResponse,
    summary="HWID sıfırla",
)
@limiter.limit("30/minute")
async def reset_hwid(
    request: Request,
    body: HwidResetRequest,
    db: DBDep,
    admin: AdminDep,
) -> MessageResponse:
    service = LicenseService(db)
    ok = await service.reset_hwid(
        body.license_id, admin_id=admin["id"], reason=body.reason
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    return MessageResponse(message="HWID sıfırlandı, kullanıcı yeniden aktive edebilir")


# ── Loglar ────────────────────────────────────────────────────────────────────

@router.get(
    "/logs",
    response_model=ActivityLogListResponse,
    summary="Aktivite logları",
)
@limiter.limit("60/minute")
async def get_logs(
    request: Request,
    db: DBDep,
    admin: AdminDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    license_id: Optional[uuid.UUID] = None,
) -> ActivityLogListResponse:
    """Tüm aktivite logları veya belirli bir lisansın logları."""
    service = LicenseService(db)
    return await service.get_activity_logs(
        page=page, page_size=page_size, license_id=license_id
    )
