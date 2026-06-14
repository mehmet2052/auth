"""
Admin panel API endpoint'leri.
Tüm endpoint'ler JWT ile korumalı.
"""
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Query, status

from app.api.deps import DBDep, AdminOnly, ResellerOrAdmin
from app.middleware.rate_limiter import limiter
from app.models.models import LicenseStatus, AdminRole
from app.services.admin_service import AdminService
from app.services.license_service import LicenseService
from app.schemas.schemas import (
    AdminLoginRequest, AdminLoginResponse,
    LicenseCreateRequest, LicenseResponse, LicenseListResponse,
    HwidResetRequest, MessageResponse,
    ActivityLogListResponse, ErrorResponse,
    ResellerCreateRequest, AdminCreateRequest, AdminResponse,
    TokenRefreshRequest, TokenRefreshResponse,
    ActivationHistoryListResponse,
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


@router.post(
    "/refresh",
    response_model=TokenRefreshResponse,
    summary="Token yenile",
)
@limiter.limit("30/minute")
async def refresh_token(
    request: Request,
    body: TokenRefreshRequest,
    db: DBDep,
) -> TokenRefreshResponse:
    """
    Refresh token ile yeni access + refresh token al.
    Token rotation: eski refresh token revoke edilir.
    """
    service = AdminService(db)
    try:
        return await service.refresh_token(body)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Çıkış",
)
@limiter.limit("30/minute")
async def logout(
    request: Request,
    body: TokenRefreshRequest,
    db: DBDep,
) -> MessageResponse:
    """
    Refresh token'ı revoke et (logout).
    """
    service = AdminService(db)
    await service.logout(body.refresh_token)
    return MessageResponse(message="Çıkış başarılı")


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
    admin: ResellerOrAdmin,
) -> list[LicenseResponse]:
    """
    Yeni lisans(lar) oluştur.
    Reseller'lar quota kontrolü ile sınırlandırılır.
    """
    # Reseller quota kontrolü
    if admin["role"] == AdminRole.RESELLER:
        quota_limit = admin["key_quota_limit"]
        current_count = admin["keys_created_count"]
        
        if quota_limit is not None:
            remaining = quota_limit - current_count
            if body.count > remaining:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Quota aşıldı. Kalan: {remaining}, İstenen: {body.count}"
                )
    
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
    admin: ResellerOrAdmin,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[LicenseStatus] = None,
) -> LicenseListResponse:
    """
    Sayfalanmış lisans listesi.
    Reseller'lar sadece kendi oluşturdukları lisansları görebilir.
    """
    # Reseller ise sadece kendi lisanslarını görsün
    created_by_filter = admin["id"] if admin["role"] == AdminRole.RESELLER else None
    
    service = LicenseService(db)
    return await service.get_list(
        page=page,
        page_size=page_size,
        status_filter=status_filter,
        created_by_filter=created_by_filter,
    )


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
    admin: ResellerOrAdmin,
) -> MessageResponse:
    service = LicenseService(db)
    
    # Reseller ise sadece kendi lisanslarını yönetebilir
    if admin["role"] == AdminRole.RESELLER:
        license_ = await service.license_repo.get_by_id(license_id)
        if not license_ or license_.created_by != admin["id"]:
            raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    
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
    admin: ResellerOrAdmin,
) -> MessageResponse:
    service = LicenseService(db)
    
    # Reseller ise sadece kendi lisanslarını yönetebilir
    if admin["role"] == AdminRole.RESELLER:
        license_ = await service.license_repo.get_by_id(license_id)
        if not license_ or license_.created_by != admin["id"]:
            raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    
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
    admin: ResellerOrAdmin,
) -> MessageResponse:
    service = LicenseService(db)
    
    # Reseller ise sadece kendi lisanslarını yönetebilir
    if admin["role"] == AdminRole.RESELLER:
        license_ = await service.license_repo.get_by_id(body.license_id)
        if not license_ or license_.created_by != admin["id"]:
            raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    
    ok = await service.reset_hwid(
        body.license_id, admin_id=admin["id"], reason=body.reason
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    return MessageResponse(message="HWID sıfırlandı, kullanıcı yeniden aktive edebilir")


@router.get(
    "/licenses/{license_id}/history",
    response_model=ActivationHistoryListResponse,
    summary="Aktivasyon geçmişi",
)
@limiter.limit("30/minute")
async def get_activation_history(
    request: Request,
    license_id: uuid.UUID,
    db: DBDep,
    admin: ResellerOrAdmin,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> ActivationHistoryListResponse:
    """
    Lisansın aktivasyon geçmişi.
    Reseller'lar sadece kendi lisanslarını görebilir.
    """
    service = LicenseService(db)
    
    if admin["role"] == AdminRole.RESELLER:
        license_ = await service.license_repo.get_by_id(license_id)
        if not license_ or license_.created_by != admin["id"]:
            raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    
    return await service.get_activation_history(
        license_id=license_id,
        page=page,
        page_size=page_size,
    )


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
    admin: ResellerOrAdmin,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    license_id: Optional[uuid.UUID] = None,
) -> ActivityLogListResponse:
    """
    Tüm aktivite logları veya belirli bir lisansın logları.
    Reseller'lar sadece kendi lisanslarının loglarını görebilir.
    """
    service = LicenseService(db)
    
    # Reseller ise license_id kendi lisansı olmalı
    if admin["role"] == AdminRole.RESELLER and license_id:
        license_ = await service.license_repo.get_by_id(license_id)
        if not license_ or license_.created_by != admin["id"]:
            raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    
    return await service.get_activity_logs(
        page=page, page_size=page_size, license_id=license_id
    )


# ── Reseller Yönetimi (Admin-Only) ──────────────────────────────────────────────

@router.post(
    "/resellers",
    response_model=AdminResponse,
    summary="Reseller oluştur",
)
@limiter.limit("10/minute")
async def create_reseller(
    request: Request,
    body: ResellerCreateRequest,
    db: DBDep,
    admin: AdminOnly,
) -> AdminResponse:
    """Reseller hesabı oluştur (admin-only)."""
    service = AdminService(db)
    try:
        return await service.create_reseller(body, parent_id=admin["id"])
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/resellers",
    response_model=list[AdminResponse],
    summary="Reseller listesi",
)
@limiter.limit("30/minute")
async def list_resellers(
    request: Request,
    db: DBDep,
    admin: AdminOnly,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> list[AdminResponse]:
    """Tüm reseller'ları listele (admin-only)."""
    service = AdminService(db)
    items, total = await service.list_admins(
        page=page,
        page_size=page_size,
        role_filter=AdminRole.RESELLER,
    )
    return items


@router.post(
    "/resellers/{reseller_id}/suspend",
    response_model=MessageResponse,
    summary="Reseller askıya al",
)
@limiter.limit("10/minute")
async def suspend_reseller(
    request: Request,
    reseller_id: uuid.UUID,
    db: DBDep,
    admin: AdminOnly,
) -> MessageResponse:
    """Reseller hesabını askıya al (admin-only)."""
    service = AdminService(db)
    ok = await service.suspend_admin(reseller_id, suspended_by=admin["id"])
    if not ok:
        raise HTTPException(status_code=404, detail="Reseller bulunamadı")
    return MessageResponse(message="Reseller askıya alındı")


@router.post(
    "/admins",
    response_model=AdminResponse,
    summary="Admin oluştur",
)
@limiter.limit("5/minute")
async def create_admin(
    request: Request,
    body: AdminCreateRequest,
    db: DBDep,
    admin: AdminOnly,
) -> AdminResponse:
    """Yeni admin hesabı oluştur (admin-only)."""
    service = AdminService(db)
    try:
        return await service.create_admin(body)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
