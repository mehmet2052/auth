"""
FastAPI dependency injection yardımcıları.
"""
import uuid
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Security, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import decode_access_token
from app.db.database import get_db
from app.repositories.admin_repo import AdminRepository
from app.models.models import AdminRole

settings = get_settings()

# auto_error=False: OPTIONS preflight'ta Authorization olmayınca 401 vermez
bearer_scheme = HTTPBearer(auto_error=False)


async def verify_api_secret(
    x_nexus_secret: Annotated[Optional[str], Header()] = None
) -> None:
    """Client endpoint'leri için API secret doğrulama."""
    if x_nexus_secret != settings.api_secret_value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Geçersiz API secret"
        )


async def get_current_admin(
    credentials: Annotated[
        Optional[HTTPAuthorizationCredentials],
        Security(bearer_scheme)
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """JWT token'dan admin bilgisini çıkar."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Kimlik doğrulama başarısız",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials:
        raise credentials_exception

    try:
        payload = decode_access_token(credentials.credentials)
        admin_id_str: str = payload.get("sub")
        token_type: str = payload.get("type")
        jti: str = payload.get("jti")

        if not admin_id_str or token_type != "access":
            raise credentials_exception

        # Token blacklist kontrolü (Redis)
        from app.core.token_store import is_token_revoked
        if await is_token_revoked(jti):
            raise credentials_exception

        admin_id = uuid.UUID(admin_id_str)
    except (JWTError, ValueError):
        raise credentials_exception

    repo = AdminRepository(db)
    admin = await repo.get_by_id(admin_id)

    if not admin or not admin.is_active:
        raise credentials_exception

    return {
        "id": admin.id,
        "username": admin.username,
        "role": admin.role,
        "key_quota_limit": admin.key_quota_limit,
        "keys_created_count": admin.keys_created_count,
    }


def require_role(*roles: AdminRole):
    """
    Role-based access control dependency factory.
    Belirli rolleri gerektiren endpoint'ler için kullanılır.
    """
    async def role_checker(admin: Annotated[dict, Depends(get_current_admin)]) -> dict:
        if admin["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Bu işlem için yetkiniz yok"
            )
        return admin
    return role_checker


DBDep            = Annotated[AsyncSession, Depends(get_db)]
AdminDep         = Annotated[dict, Depends(get_current_admin)]
AdminOnly        = Annotated[dict, Depends(require_role(AdminRole.ADMIN))]
ResellerOrAdmin  = Annotated[dict, Depends(require_role(AdminRole.ADMIN, AdminRole.RESELLER))]
ApiSecret        = Annotated[None, Depends(verify_api_secret)]
