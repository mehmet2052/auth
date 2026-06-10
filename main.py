"""
Nexus Auth Server — FastAPI uygulama giriş noktası.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import get_settings
from app.core.logging import setup_logging, logger
from app.core.security import hash_password
from app.db.database import create_tables, AsyncSessionLocal
from app.middleware.rate_limiter import limiter, rate_limit_exceeded_handler
from app.api.routes import auth, admin
from app.models.models import Admin

settings = get_settings()


async def _ensure_admin() -> None:
    """Başlangıçta admin yoksa .env'den otomatik oluştur."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(select(Admin).where(Admin.username == settings.admin_username))
        if result.scalar_one_or_none():
            logger.info(f"Admin '{settings.admin_username}' zaten mevcut")
            return
        admin = Admin(
            username=settings.admin_username,
            password_hash=hash_password(settings.admin_password),
            is_active=True,
        )
        db.add(admin)
        await db.commit()
        logger.info(f"Admin '{settings.admin_username}' otomatik oluşturuldu")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama başlangıç / bitiş hook'ları."""
    setup_logging(settings.debug)
    logger.info("Nexus Auth Server başlatılıyor...")

    # Tabloları oluştur
    await create_tables()
    logger.info("Veritabanı tabloları oluşturuldu")

    # İlk admin hesabını otomatik oluştur
    await _ensure_admin()

    logger.info(f"Nexus Auth Server hazır. Debug={settings.debug}")
    yield
    logger.info("Nexus Auth Server kapatılıyor...")


app = FastAPI(
    title="Nexus Auth API",
    description="CS2 External ESP Lisanslama ve Doğrulama Sistemi",
    version="1.0.0",
    lifespan=lifespan,
    # Production'da docs kapalı
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

# ── Middleware ────────────────────────────────────────────────────────────────

# Trusted Host — SSRF koruması
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts.split(","),
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# ── Router'lar ────────────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(admin.router)


@app.get("/health", tags=["Health"])
async def health_check():
    """Sunucu sağlık kontrolü."""
    return {"status": "ok", "version": settings.app_version}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        ssl_keyfile="./ssl/key.pem" if not settings.debug else None,
        ssl_certfile="./ssl/cert.pem" if not settings.debug else None,
    )
