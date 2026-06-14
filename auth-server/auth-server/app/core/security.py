"""
Güvenlik yardımcıları:
- JWT token oluşturma / doğrulama
- Şifre hashleme
- Lisans anahtarı üretme
- HWID hashleme
- Nonce (replay attack koruması)
"""
import secrets
import hashlib
import hmac
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()

# Bcrypt context — şifre hashleme için
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ─────────────────────────────────────────────────────────────────────────────
# Şifre Yönetimi
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Şifreyi bcrypt ile hashle. bcrypt max 72 byte destekler."""
    # bcrypt 72 byte limiti — önce SHA-256 hash al, sonra bcrypt uygula
    import hashlib, base64
    sha = base64.b64encode(hashlib.sha256(password.encode()).digest()).decode()
    return pwd_context.hash(sha)


def verify_password(plain: str, hashed: str) -> bool:
    """Şifre doğrulama — timing-safe."""
    import hashlib, base64
    sha = base64.b64encode(hashlib.sha256(plain.encode()).digest()).decode()
    return pwd_context.verify(sha, hashed)


# ─────────────────────────────────────────────────────────────────────────────
# JWT Token
# ─────────────────────────────────────────────────────────────────────────────

def create_access_token(
    data: dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    JWT access token oluştur.
    
    data içinde bulunması gerekenler:
      - sub: konu (admin username veya license key)
      - type: "access"
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
        # jti: JWT ID — replay attack koruması
        "jti": secrets.token_hex(16),
    })
    return jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )


def create_refresh_token(
    data: dict[str, Any],
    family_id: Optional[str] = None,
) -> tuple[str, str, datetime]:
    """
    JWT refresh token oluştur.
    
    Returns:
        (token, jti, expires_at)
    
    Token rotation: her refresh'te yeni token oluşturulur.
    Family tracking: tüm token'lar aynı family_id'ye sahip.
    """
    to_encode = data.copy()
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    jti = secrets.token_hex(16)
    
    to_encode.update({
        "exp": expires_at,
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
        "jti": jti,
        "family": family_id or secrets.token_hex(16),
    })
    
    token = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    
    return token, jti, expires_at


def decode_refresh_token(token: str) -> dict[str, Any]:
    """
    JWT refresh token decode.
    type="refresh" kontrolü yapılır.
    """
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm]
    )
    
    if payload.get("type") != "refresh":
        raise JWTError("Invalid token type — expected refresh")
    
    return payload


def decode_access_token(token: str) -> dict[str, Any]:
    """
    JWT token'ı decode et.
    Hata durumunda JWTError fırlatır.
    """
    return jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm]
    )


# ─────────────────────────────────────────────────────────────────────────────
# Lisans Anahtarı Üretimi
# ─────────────────────────────────────────────────────────────────────────────

def generate_license_key() -> str:
    """
    Kriptografik olarak güvenli lisans anahtarı üret.
    Format: NEXUS-XXXX-XXXX-XXXX-XXXX (Base32, okunabilir)
    
    32 byte entropi → Base32 → gruplara böl
    """
    raw = secrets.token_bytes(20)  # 160 bit entropi
    encoded = base64.b32encode(raw).decode("utf-8")
    # XXXXXXXXXXXXXXXXXXXXXXXXXXXXX → XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
    chunks = [encoded[i:i+5] for i in range(0, len(encoded), 5)]
    return "NEXUS-" + "-".join(chunks[:6])  # NEXUS-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX


# ─────────────────────────────────────────────────────────────────────────────
# HWID Hashleme
# ─────────────────────────────────────────────────────────────────────────────

def hash_hwid(raw_hwid: str) -> str:
    """
    HWID'i HMAC-SHA256 ile hashle.
    Ham donanım verisi veritabanında saklanmaz — sadece hash.
    
    HMAC kullanılıyor çünkü:
    - Basit SHA256'dan daha güvenli (secret key gerektirir)
    - Precomputed rainbow table saldırılarını engeller
    """
    return hmac.new(
        settings.jwt_secret_key.encode(),
        raw_hwid.encode(),
        hashlib.sha256
    ).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Nonce — Replay Attack Koruması
# ─────────────────────────────────────────────────────────────────────────────

def generate_nonce() -> str:
    """32 byte (256 bit) güvenli nonce üret."""
    return secrets.token_hex(32)


def hash_key(key: str) -> str:
    """
    API anahtarı veya challenge değerini hashle.
    Binary'de gömülü key doğrulama için kullanılır.
    """
    return hashlib.sha256(
        (key + settings.jwt_secret_key).encode()
    ).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# CSRF Token Yönetimi
# ─────────────────────────────────────────────────────────────────────────────

_CSRF_PREFIX = "csrf:"
_CSRF_TTL_SECONDS = 3600  # 1 hour


async def generate_csrf_token() -> str:
    """
    CSRF token oluştur ve Redis'e kaydet.
    Returns: token string
    """
    from app.core.redis import get_redis
    token = secrets.token_hex(32)
    redis = await get_redis()
    await redis.setex(f"{_CSRF_PREFIX}{token}", _CSRF_TTL_SECONDS, "1")
    return token


async def validate_csrf_token(token: str) -> bool:
    """
    CSRF token doğrula — Redis'te mevcut mu ve süresi dolmamış mı?
    Single-use: doğrulama sonrası silinir.
    """
    from app.core.redis import get_redis
    if not token or len(token) != 64:
        return False
    redis = await get_redis()
    key = f"{_CSRF_PREFIX}{token}"
    exists = await redis.exists(key)
    if exists:
        await redis.delete(key)
        return True
    return False
