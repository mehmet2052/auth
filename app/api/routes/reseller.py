"""
Reseller API endpoints (v2 — separate entity).
All endpoints use ResellerOnly dependency (entity=reseller JWT).
"""
import uuid

from fastapi import APIRouter, HTTPException, Request, Query, status

from app.api.deps import DBDep, ResellerOnly
from app.middleware.rate_limiter import limiter
from app.services.reseller_service import ResellerService
from app.services.license_service import LicenseService
from app.repositories.reseller_repo import ResellerRepository
from app.schemas.schemas import (
    ResellerLoginRequest, ResellerLoginResponse,
    LicenseCreateRequest, LicenseResponse, LicenseListResponse,
    HwidResetRequest, MessageResponse, ErrorResponse,
    TokenRefreshRequest, TokenRefreshResponse,
)

router = APIRouter(prefix="/api/v1/reseller", tags=["Reseller"])


# ── Auth ──────────────────────────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=ResellerLoginResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Reseller girişi",
)
@limiter.limit("5/minute")
async def reseller_login(
    request: Request,
    body: ResellerLoginRequest,
    db: DBDep,
) -> ResellerLoginResponse:
    """Reseller giriş endpoint'i. Rate limit: 5/dk."""
    ip = request.client.host if request.client else None
    service = ResellerService(db)
    try:
        result = await service.login(body.username, body.password, ip_address=ip)
        return ResellerLoginResponse(**result)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)
        )


@router.post(
    "/refresh",
    response_model=TokenRefreshResponse,
    summary="Token yenile",
)
@limiter.limit("30/minute")
async def reseller_refresh(
    request: Request,
    body: TokenRefreshRequest,
    db: DBDep,
) -> TokenRefreshResponse:
    """
    Reseller token yenileme.
    Token rotation: eski refresh token revoke edilir.
    """
    service = ResellerService(db)
    try:
        return await service.refresh_token(body)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


# ── Key Management ────────────────────────────────────────────────────────────

@router.post(
    "/create-key",
    response_model=list[LicenseResponse],
    summary="Lisans anahtarı oluştur",
)
@limiter.limit("30/minute")
async def create_key(
    request: Request,
    body: LicenseCreateRequest,
    db: DBDep,
    reseller: ResellerOnly,
) -> list[LicenseResponse]:
    """
    Reseller lisans anahtarı oluşturur.
    Günlük ve toplam quota kontrolü uygulanır.
    """
    reseller_id = reseller["id"]
    reseller_repo = ResellerRepository(db)

    # Lifetime quota check
    lifetime_ok, lifetime_remaining = await reseller_repo.check_lifetime_quota(
        reseller_id, body.count
    )
    if not lifetime_ok:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Lifetime quota exceeded. Remaining: {lifetime_remaining}, Requested: {body.count}",
        )

    # Daily quota check
    daily_ok, daily_remaining = await reseller_repo.check_daily_quota(
        reseller_id, body.count
    )
    if not daily_ok:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Daily quota exceeded. Remaining: {daily_remaining}, Requested: {body.count}",
        )

    service = LicenseService(db)
    licenses = await service.create_licenses(body, admin_id=reseller_id)

    # Increment reseller key counters
    await reseller_repo.increment_keys_count(reseller_id, body.count)
    await db.commit()

    return licenses


@router.get(
    "/list-keys",
    response_model=LicenseListResponse,
    summary="Kendi lisanslarını listele",
)
@limiter.limit("60/minute")
async def list_keys(
    request: Request,
    db: DBDep,
    reseller: ResellerOnly,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> LicenseListResponse:
    """Reseller sadece kendi oluşturduğu lisansları görebilir."""
    service = LicenseService(db)
    return await service.get_list(
        page=page,
        page_size=page_size,
        created_by_filter=reseller["id"],
    )


@router.post(
    "/reset-hwid",
    response_model=MessageResponse,
    summary="HWID sıfırla",
)
@limiter.limit("30/minute")
async def reset_hwid(
    request: Request,
    body: HwidResetRequest,
    db: DBDep,
    reseller: ResellerOnly,
) -> MessageResponse:
    """Reseller sadece kendi lisanslarının HWID'ini sıfırlayabilir."""
    service = LicenseService(db)

    # Ownership check
    license_ = await service.license_repo.get_by_id(body.license_id)
    if not license_ or license_.reseller_id != reseller["id"]:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")

    ok = await service.reset_hwid(
        body.license_id, admin_id=reseller["id"], reason=body.reason
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    return MessageResponse(message="HWID sıfırlandı")
