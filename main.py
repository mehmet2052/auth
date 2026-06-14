"""
Nexus Auth Server — FastAPI uygulama giriş noktası.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

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
    logger.info("Veritabanı tabloları hazır")

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
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

# ── Security Headers Middleware ─────────────────────────────────────────────

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# ── Trusted Host Middleware ─────────────────────────────────────────────────

if not settings.debug and settings.allowed_hosts != "*":
    allowed = [h.strip() for h in settings.allowed_hosts.split(",") if h.strip()]
    if allowed:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed)

# ── Middleware ────────────────────────────────────────────────────────────────

# CORS — panel URL whitelist
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list if not settings.debug else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Rate Limiter
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# ── Router'lar ────────────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(admin.router)

# Admin paneli — /panel/
app.mount("/panel", StaticFiles(directory="panel", html=True), name="panel")


@app.get("/", tags=["Root"])
async def root():
    """Root path → panel'e yönlendir."""
    return RedirectResponse(url="/panel/")


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
