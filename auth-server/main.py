"""
Nexus Auth Server — FastAPI uygulama giriş noktası.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import secrets as _secrets

from app.core.config import get_settings
from app.core.logging import setup_logging, logger
from app.core.security import hash_password, validate_csrf_token
from app.core.redis import close_redis
from app.db.database import create_tables, AsyncSessionLocal
from app.middleware.rate_limiter import RateLimitMiddleware
from app.middleware.hmac_signing import HMACSigningMiddleware
from app.api.routes import auth, admin, csrf
from app.api.routes import reseller as reseller_routes
from app.models.models import Admin, AdminRole
# v2 model imports — ensure Base.metadata includes these tables
from app.models import webhook as _webhook_models  # noqa: F401
from app.models import anomaly as _anomaly_models  # noqa: F401

settings = get_settings()


async def _ensure_admin() -> None:
    """Başlangıçta admin yoksa .env'den otomatik oluştur."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select, text as sql_text

        # Safety: fix any invalid role values in the database before querying
        try:
            await db.execute(
                sql_text("UPDATE admins SET role = 'admin' WHERE role NOT IN ('admin', 'reseller')")
            )
            await db.commit()
        except Exception:
            await db.rollback()

        try:
            result = await db.execute(
                select(Admin).where(Admin.username == settings.admin_username)
            )
            existing = result.scalar_one_or_none()
        except Exception as e:
            # Enum lookup failure — force-fix via raw SQL and retry
            logger.warning(f"Admin sorgu hatası, düzeltme deneniyor: {e}")
            try:
                await db.execute(
                    sql_text("UPDATE admins SET role = 'admin' WHERE role IS NOT NULL")
                )
                await db.commit()
            except Exception:
                await db.rollback()
            # Retry query after fix
            result = await db.execute(
                select(Admin).where(Admin.username == settings.admin_username)
            )
            existing = result.scalar_one_or_none()

        if existing:
            logger.info(f"Admin '{settings.admin_username}' zaten mevcut")
            return

        new_admin = Admin(
            username=settings.admin_username,
            password_hash=hash_password(settings.admin_password),
            role=AdminRole.ADMIN,
            is_active=True,
        )
        db.add(new_admin)
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
    await close_redis()


app = FastAPI(
    title="Nexus Auth API",
    description="CS2 External ESP Lisanslama ve Doğrulama Sistemi",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

# ── CSRF Exempt Paths ───────────────────────────────────────────────────────

_CSRF_EXEMPT_PREFIXES = (
    "/api/v1/auth",
    "/api/v1/heartbeat",
    "/api/v1/csrf-token",
    "/api/v1/reseller/login",
    "/api/v1/reseller/refresh",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
)


@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    """CSRF protection for state-changing requests from browser clients."""
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        path = request.url.path
        is_exempt = any(path.startswith(p) for p in _CSRF_EXEMPT_PREFIXES)
        
        if not is_exempt:
            csrf_token = request.headers.get("X-CSRF-Token", "")
            if not csrf_token:
                csrf_token = request.cookies.get("csrf_token", "")
            
            if not csrf_token:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF token eksik"}
                )
            
            valid = await validate_csrf_token(csrf_token)
            if not valid:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF token geçersiz veya süresi dolmuş"}
                )
    
    return await call_next(request)


# ── Security Headers Middleware ─────────────────────────────────────────────

@app.middleware("http")
async def security_headers(request: Request, call_next):
    nonce = _secrets.token_hex(16)
    request.state.csp_nonce = nonce
    
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Nonce-based CSP — no unsafe-inline for scripts
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data:; "
        f"font-src 'self'; "
        f"connect-src 'self'"
    )
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

# Rate Limiter (Redis-backed)
app.add_middleware(RateLimitMiddleware, global_limit=100, window_seconds=60)

# HMAC Signing Middleware — dual auth mode (legacy + secure) for client endpoints
app.add_middleware(HMACSigningMiddleware)

# ── Router'lar ────────────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(csrf.router)
app.include_router(reseller_routes.router)

# Admin paneli — serve HTML with nonce injection, static assets separately
_PANEL_DIR = Path(__file__).parent / "panel"

@app.get("/panel/", response_class=HTMLResponse, include_in_schema=False)
@app.get("/panel", response_class=HTMLResponse, include_in_schema=False)
async def serve_panel(request: Request):
    """Serve panel HTML with CSP nonce injection."""
    html_path = _PANEL_DIR / "index.html"
    content = html_path.read_text(encoding="utf-8")
    nonce = request.state.csp_nonce
    content = content.replace("{{CSP_NONCE}}", nonce)
    return HTMLResponse(content)

app.mount("/panel", StaticFiles(directory="panel"), name="panel-static")


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
