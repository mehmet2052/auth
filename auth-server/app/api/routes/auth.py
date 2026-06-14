"""
Client auth endpoint'leri.
/api/v1/auth/  — istemci doğrulama
/api/v1/heartbeat/ — oturum yenileme
"""
from fastapi import APIRouter, Request, HTTPException, status

from app.api.deps import DBDep, ApiSecret
from app.middleware.rate_limiter import check_auth_rate_limit, check_heartbeat_rate_limit
from app.services.auth_service import AuthService
from app.schemas.schemas import (
    AuthRequest, AuthResponse,
    HeartbeatRequest, HeartbeatResponse,
    ErrorResponse,
)

router = APIRouter(prefix="/api/v1", tags=["Client Auth"])


@router.post(
    "/auth",
    response_model=AuthResponse,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    summary="Lisans doğrulama",
    description="İstemci başlatma sırasında lisans anahtarını doğrular ve session token alır.",
)
async def authenticate(
    request: Request,
    body: AuthRequest,
    db: DBDep,
    _: ApiSecret,
) -> AuthResponse:
    """
    Lisans doğrulama endpoint'i.
    
    Güvenlik katmanları:
    - Rate limiting (IP bazlı, Redis-backed)
    - API secret header kontrolü
    - Nonce replay attack koruması
    - HWID doğrulama
    - Sunucu saati bazlı süre kontrolü
    """
    await check_auth_rate_limit(request)
    ip = request.client.host if request.client else None
    service = AuthService(db)

    try:
        return await service.authenticate(body, ip_address=ip)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post(
    "/heartbeat",
    response_model=HeartbeatResponse,
    responses={
        429: {"model": ErrorResponse},
    },
    summary="Oturum yenileme",
    description="Her 5 dakikada bir çağrılarak session'ın geçerliliği kontrol edilir.",
)
async def heartbeat(
    request: Request,
    body: HeartbeatRequest,
    db: DBDep,
    _: ApiSecret,
) -> HeartbeatResponse:
    """
    Heartbeat endpoint'i.
    Sunucu istediği zaman session'ı iptal edebilir — anında etki.
    """
    await check_heartbeat_rate_limit(request)
    ip = request.client.host if request.client else None
    service = AuthService(db)

    try:
        return await service.heartbeat(body, ip_address=ip)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
