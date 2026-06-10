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
from app.db.database import create_tables
from app.middleware.rate_limiter import limiter, rate_limit_exceeded_handler
from app.api.routes import auth, admin

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama başlangıç / bitiş hook'ları."""
    setup_logging(settings.debug)
    logger.info("Nexus Auth Server başlatılıyor...")

    # Tabloları oluştur (geliştirme için)
    # Production'da: alembic upgrade head
    if settings.debug:
        await create_tables()
        logger.info("Veritabanı tabloları oluşturuldu (debug modu)")

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
