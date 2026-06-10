"""
FastAPI dependency injection yardımcıları.
JWT doğrulama, admin auth, DB session.
"""
import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Security, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import decode_access_token
from app.db.database import get_db
from app.repositories.admin_repo import AdminRepository

settings = get_settings()
bearer_scheme = HTTPBearer()


async def verify_api_secret(
    x_nexus_secret: Annotated[str | None, Header()] = None
) -> None:
    """
    API secret header doğrulama.
    Client isteklerinde bu header zorunlu — kimlik doğrulama değil,
    endpoint'lerin doğrudan taranmasını engeller.
    """
    if x_nexus_secret != settings.api_secret_value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Geçersiz API secret"
        )


async def get_current_admin(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    JWT token'dan admin bilgisini çıkar.
    Admin korumalı endpoint'lerde kullanılır.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Kimlik doğrulama başarısız",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(credentials.credentials)
        admin_id_str: str = payload.get("sub")
        token_type: str = payload.get("type")

        if not admin_id_str or token_type != "admin":
            raise credentials_exception

        admin_id = uuid.UUID(admin_id_str)
    except (JWTError, ValueError):
        raise credentials_exception

    # Admin hâlâ aktif mi?
    repo = AdminRepository(db)
    admin = await repo.get_by_id(admin_id)

    if not admin or not admin.is_active:
        raise credentials_exception

    return {"id": admin.id, "username": admin.username}


# Type alias'lar — endpoint'lerde kullanım kolaylığı
DBDep     = Annotated[AsyncSession, Depends(get_db)]
AdminDep  = Annotated[dict, Depends(get_current_admin)]
ApiSecret = Annotated[None, Depends(verify_api_secret)]
