"""
Admin panel API endpoint'leri.
Tüm endpoint'ler JWT ile korumalı.
"""
import json
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Query, status

from app.api.deps import DBDep, AdminOnly, ResellerOrAdmin
from app.middleware.rate_limiter import limiter
from app.models.models import LicenseStatus, AdminRole, LogAction
from app.services.admin_service import AdminService
from app.services.license_service import LicenseService
from app.services.reseller_service import ResellerService
from app.services.webhook_service import WebhookService
from app.services.anomaly_service import AnomalyService, invalidate_cache as invalidate_anomaly_cache
from app.repositories.webhook_repo import WebhookRepository
from app.repositories.anomaly_repo import AnomalyRepository
from app.repositories.license_repo import LicenseRepository, ActivityLogRepository
from app.schemas.schemas import (
    AdminLoginRequest, AdminLoginResponse,
    LicenseCreateRequest, LicenseResponse, LicenseListResponse,
    HwidResetRequest, MessageResponse,
    ActivityLogListResponse, ErrorResponse,
    ResellerCreateRequest, AdminCreateRequest, AdminResponse,
    TokenRefreshRequest, TokenRefreshResponse,
    ActivationHistoryListResponse,
    # v2 schemas
    LicenseStatusTransitionRequest,
    WebhookCreateRequest, WebhookUpdateRequest, WebhookResponse, WebhookListResponse,
    AnomalyRuleResponse, AnomalyRuleUpdateRequest, AnomalyRuleListResponse,
    ResellerCreateV2Request, ResellerResponse, ResellerListResponse,
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


# ── Reseller Yönetimi (Admin-Only, v1 — backward compat) ───────────────────────────

@router.post(
    "/resellers",
    response_model=AdminResponse,
    summary="Reseller oluştur (v1 — admins table)",
)
@limiter.limit("10/minute")
async def create_reseller(
    request: Request,
    body: ResellerCreateRequest,
    db: DBDep,
    admin: AdminOnly,
) -> AdminResponse:
    """Reseller hesabı oluştur (admin-only, v1 backward compat)."""
    service = AdminService(db)
    try:
        return await service.create_reseller(body, parent_id=admin["id"])
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/resellers",
    response_model=list[AdminResponse],
    summary="Reseller listesi (v1)",
)
@limiter.limit("30/minute")
async def list_resellers(
    request: Request,
    db: DBDep,
    admin: AdminOnly,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> list[AdminResponse]:
    """Tüm reseller'ları listele (admin-only, v1 backward compat)."""
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
    summary="Reseller askıya al (v1)",
)
@limiter.limit("10/minute")
async def suspend_reseller(
    request: Request,
    reseller_id: uuid.UUID,
    db: DBDep,
    admin: AdminOnly,
) -> MessageResponse:
    """Reseller hesabını askıya al (admin-only, v1 backward compat)."""
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


# ── v2: License State Transitions ──────────────────────────────────────────────

@router.post(
    "/licenses/{license_id}/ban",
    response_model=MessageResponse,
    summary="Lisansı yasakla",
)
@limiter.limit("30/minute")
async def ban_license(
    request: Request,
    license_id: uuid.UUID,
    db: DBDep,
    admin: AdminOnly,
) -> MessageResponse:
    """Lisansı BANNED durumuna geçir (admin-only)."""
    service = LicenseService(db)
    license_ = await service.license_repo.get_by_id(license_id)
    if not license_:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")

    # Python-level state transition validation
    license_.previous_status = license_.status.value if license_.status else None
    license_.status = LicenseStatus.BANNED
    license_.status_reason = f"Admin {admin['id']} tarafından yasaklandı"
    await db.flush()

    await service.session_repo.invalidate_all_for_license(license_id)
    await service.log_repo.create(
        action=LogAction.STATE_TRANSITION,
        license_id=license_id,
        detail=f"Banned by admin {admin['id']}",
    )
    await db.commit()

    # Webhook dispatch
    await service._dispatch_webhook("key_banned", {
        "key_partial": license_.key[:8] + "..." if license_.key else "unknown",
        "reason": "Admin banned",
        "admin": str(admin["id"]),
    })
    return MessageResponse(message="Lisans yasaklandı")


@router.post(
    "/licenses/{license_id}/lock",
    response_model=MessageResponse,
    summary="Lisansı kilitle",
)
@limiter.limit("30/minute")
async def lock_license(
    request: Request,
    license_id: uuid.UUID,
    db: DBDep,
    admin: AdminOnly,
) -> MessageResponse:
    """Lisansı LOCKED durumuna geçir (admin-only)."""
    service = LicenseService(db)
    license_ = await service.license_repo.get_by_id(license_id)
    if not license_:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")

    license_.previous_status = license_.status.value if license_.status else None
    license_.status = LicenseStatus.LOCKED
    license_.status_reason = f"Admin {admin['id']} tarafından kilitlendi"
    await db.flush()

    await service.session_repo.invalidate_all_for_license(license_id)
    await service.log_repo.create(
        action=LogAction.STATE_TRANSITION,
        license_id=license_id,
        detail=f"Locked by admin {admin['id']}",
    )
    await db.commit()
    return MessageResponse(message="Lisans kilitlendi")


@router.post(
    "/licenses/{license_id}/unlock",
    response_model=MessageResponse,
    summary="Lisans kilidini aç",
)
@limiter.limit("30/minute")
async def unlock_license(
    request: Request,
    license_id: uuid.UUID,
    db: DBDep,
    admin: AdminOnly,
) -> MessageResponse:
    """LOCKED → ACTIVE geçişi (admin-only)."""
    service = LicenseService(db)
    license_ = await service.license_repo.get_by_id(license_id)
    if not license_:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")

    if license_.status != LicenseStatus.LOCKED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Sadece LOCKED durumundaki lisanslar açılabilir. Mevcut: {license_.status.value}",
        )

    license_.previous_status = LicenseStatus.LOCKED.value
    license_.status = LicenseStatus.ACTIVE
    license_.status_reason = f"Admin {admin['id']} tarafından kilit açıldı"
    await db.flush()

    await service.log_repo.create(
        action=LogAction.STATE_TRANSITION,
        license_id=license_id,
        detail=f"Unlocked by admin {admin['id']}",
    )
    await db.commit()
    return MessageResponse(message="Lisans kilidi açıldı")


@router.post(
    "/licenses/{license_id}/transition",
    response_model=MessageResponse,
    summary="Lisans durum geçişi (generic)",
)
@limiter.limit("30/minute")
async def transition_license(
    request: Request,
    license_id: uuid.UUID,
    body: LicenseStatusTransitionRequest,
    db: DBDep,
    admin: AdminOnly,
) -> MessageResponse:
    """Generic lisans durum geçişi. DB trigger geçersiz geçişleri engeller."""
    service = LicenseService(db)
    license_ = await service.license_repo.get_by_id(license_id)
    if not license_:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")

    old_status = license_.status.value if license_.status else None
    license_.previous_status = old_status
    license_.status = body.new_status
    license_.status_reason = body.reason
    await db.flush()

    # Invalidate sessions on terminal states
    if body.new_status in (
        LicenseStatus.SUSPENDED, LicenseStatus.BANNED,
        LicenseStatus.LOCKED, LicenseStatus.DELETED,
    ):
        await service.session_repo.invalidate_all_for_license(license_id)

    await service.log_repo.create(
        action=LogAction.STATE_TRANSITION,
        license_id=license_id,
        detail=f"{old_status} → {body.new_status.value} by admin {admin['id']}. Reason: {body.reason or 'N/A'}",
    )
    await db.commit()
    return MessageResponse(
        message=f"Lisans durumu {old_status} → {body.new_status.value} olarak güncellendi"
    )


# ── v2: Webhook Management (Admin-Only) ────────────────────────────────────────

@router.post(
    "/webhooks",
    response_model=WebhookResponse,
    summary="Webhook oluştur",
)
@limiter.limit("10/minute")
async def create_webhook(
    request: Request,
    body: WebhookCreateRequest,
    db: DBDep,
    admin: AdminOnly,
) -> WebhookResponse:
    """Yeni webhook konfigürasyonu oluştur (admin-only)."""
    repo = WebhookRepository(db)
    wh = await repo.create(
        url=body.url,
        event_types=body.event_types,
        created_by=admin["id"],
        schema_version=body.schema_version,
        secret=body.secret,
    )
    await db.commit()
    await db.refresh(wh)
    # Parse event_types back from JSON string for response
    resp = WebhookResponse.model_validate(wh)
    resp.event_types = json.loads(wh.event_types) if isinstance(wh.event_types, str) else wh.event_types
    return resp


@router.get(
    "/webhooks",
    response_model=WebhookListResponse,
    summary="Webhook listesi",
)
@limiter.limit("30/minute")
async def list_webhooks(
    request: Request,
    db: DBDep,
    admin: AdminOnly,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> WebhookListResponse:
    """Tüm webhook konfigürasyonlarını listele (admin-only)."""
    repo = WebhookRepository(db)
    items, total = await repo.list_all(page=page, page_size=page_size)
    parsed_items = []
    for wh in items:
        resp = WebhookResponse.model_validate(wh)
        resp.event_types = json.loads(wh.event_types) if isinstance(wh.event_types, str) else wh.event_types
        parsed_items.append(resp)
    return WebhookListResponse(
        items=parsed_items, total=total, page=page, page_size=page_size
    )


@router.put(
    "/webhooks/{webhook_id}",
    response_model=MessageResponse,
    summary="Webhook güncelle",
)
@limiter.limit("30/minute")
async def update_webhook(
    request: Request,
    webhook_id: uuid.UUID,
    body: WebhookUpdateRequest,
    db: DBDep,
    admin: AdminOnly,
) -> MessageResponse:
    """Webhook konfigürasyonunu güncelle (admin-only)."""
    repo = WebhookRepository(db)
    ok = await repo.update(
        webhook_id,
        url=body.url,
        event_types=body.event_types,
        schema_version=body.schema_version,
        is_active=body.is_active,
        secret=body.secret,
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Webhook bulunamadı")
    await db.commit()
    return MessageResponse(message="Webhook güncellendi")


@router.delete(
    "/webhooks/{webhook_id}",
    response_model=MessageResponse,
    summary="Webhook sil",
)
@limiter.limit("10/minute")
async def delete_webhook(
    request: Request,
    webhook_id: uuid.UUID,
    db: DBDep,
    admin: AdminOnly,
) -> MessageResponse:
    """Webhook konfigürasyonunu sil (admin-only)."""
    repo = WebhookRepository(db)
    ok = await repo.delete(webhook_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Webhook bulunamadı")
    await db.commit()
    return MessageResponse(message="Webhook silindi")


# ── v2: Anomaly Rules (Admin-Only) ──────────────────────────────────────────────

@router.get(
    "/anomaly-rules",
    response_model=AnomalyRuleListResponse,
    summary="Anomaly kuralları listesi",
)
@limiter.limit("30/minute")
async def list_anomaly_rules(
    request: Request,
    db: DBDep,
    admin: AdminOnly,
) -> AnomalyRuleListResponse:
    """Tüm anomaly detection kurallarını listele (admin-only)."""
    repo = AnomalyRepository(db)
    rules = await repo.get_all()
    return AnomalyRuleListResponse(
        items=[AnomalyRuleResponse.model_validate(r) for r in rules]
    )


@router.put(
    "/anomaly-rules/{rule_id}",
    response_model=MessageResponse,
    summary="Anomaly kuralı güncelle",
)
@limiter.limit("30/minute")
async def update_anomaly_rule(
    request: Request,
    rule_id: uuid.UUID,
    body: AnomalyRuleUpdateRequest,
    db: DBDep,
    admin: AdminOnly,
) -> MessageResponse:
    """
    Anomaly kuralını güncelle (admin-only).
    Cache otomatik invalidation ile hot-reload destekli.
    """
    repo = AnomalyRepository(db)
    ok = await repo.update(
        rule_id,
        is_enabled=body.is_enabled,
        threshold=body.threshold,
        window_seconds=body.window_seconds,
        action=body.action,
        cooldown_seconds=body.cooldown_seconds,
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Anomaly kuralı bulunamadı")
    await db.commit()

    # Invalidate in-memory cache for hot-reload
    invalidate_anomaly_cache()

    return MessageResponse(message="Anomaly kuralı güncellendi, cache invalidated")


# ── v2: Reseller Management (separate table, Admin-Only) ────────────────────────

@router.post(
    "/v2/resellers",
    response_model=ResellerResponse,
    summary="Reseller oluştur (v2 — ayrı tablo)",
)
@limiter.limit("10/minute")
async def create_reseller_v2(
    request: Request,
    body: ResellerCreateV2Request,
    db: DBDep,
    admin: AdminOnly,
) -> ResellerResponse:
    """Yeni reseller oluştur — resellers tablosunda (admin-only)."""
    service = ResellerService(db)
    try:
        reseller = await service.create_reseller(
            username=body.username,
            password=body.password,
            created_by=admin["id"],
            key_quota_limit=body.key_quota_limit,
            daily_key_limit=body.daily_key_limit,
        )
        return ResellerResponse.model_validate(reseller)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/v2/resellers",
    response_model=ResellerListResponse,
    summary="Reseller listesi (v2)",
)
@limiter.limit("30/minute")
async def list_resellers_v2(
    request: Request,
    db: DBDep,
    admin: AdminOnly,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> ResellerListResponse:
    """Resellers tablosundan reseller listele (admin-only)."""
    service = ResellerService(db)
    items, total = await service.list_resellers(page=page, page_size=page_size)
    return ResellerListResponse(
        items=[ResellerResponse.model_validate(r) for r in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/v2/resellers/{reseller_id}/suspend",
    response_model=MessageResponse,
    summary="Reseller askıya al (v2)",
)
@limiter.limit("10/minute")
async def suspend_reseller_v2(
    request: Request,
    reseller_id: uuid.UUID,
    db: DBDep,
    admin: AdminOnly,
) -> MessageResponse:
    """Reseller hesabını askıya al — resellers tablosundan (admin-only)."""
    service = ResellerService(db)
    ok = await service.suspend_reseller(reseller_id, suspended_by=admin["id"])
    if not ok:
        raise HTTPException(status_code=404, detail="Reseller bulunamadı")
    return MessageResponse(message="Reseller askıya alındı (v2)")
