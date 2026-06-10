"""
Pydantic şemaları — Request/Response doğrulama ve serileştirme.
Tüm giriş verileri burada doğrulanır.
"""
import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator
import re

from app.models.models import LicenseType, LicenseStatus, LogAction


# ─────────────────────────────────────────────────────────────────────────────
# Auth Şemaları (Client → Server)
# ─────────────────────────────────────────────────────────────────────────────

class AuthRequest(BaseModel):
    """
    Lisans doğrulama isteği.
    Client her başlatmada bu isteği gönderir.
    """
    key: str = Field(
        ...,
        min_length=10,
        max_length=64,
        description="Lisans anahtarı"
    )
    hwid: str = Field(
        ...,
        min_length=8,
        max_length=256,
        description="Ham HWID verisi (sunucuda hashlenecek)"
    )
    nonce: str = Field(
        ...,
        min_length=32,
        max_length=128,
        description="Replay attack koruması için benzersiz değer"
    )
    version: int = Field(..., ge=1, description="Client versiyon numarası")

    @field_validator("key")
    @classmethod
    def validate_key_format(cls, v: str) -> str:
        """Lisans anahtarı format kontrolü."""
        # Temel karakter kontrolü — injection engellemesi
        if not re.match(r'^[A-Z0-9\-]+$', v):
            raise ValueError("Geçersiz lisans anahtarı formatı")
        return v.strip().upper()

    @field_validator("hwid")
    @classmethod
    def validate_hwid(cls, v: str) -> str:
        """HWID XSS/injection kontrolü."""
        if not re.match(r'^[a-zA-Z0-9_\-\+\/=|:\.]+$', v):
            raise ValueError("Geçersiz HWID formatı")
        return v.strip()

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, v: str) -> str:
        """Nonce hex formatı kontrolü."""
        if not re.match(r'^[a-f0-9]+$', v):
            raise ValueError("Geçersiz nonce formatı")
        return v


class AuthResponse(BaseModel):
    """Başarılı auth yanıtı."""
    session_token: str
    expires_at: datetime
    message: str = "Authentication successful"


class HeartbeatRequest(BaseModel):
    """
    Periyodik oturum yenileme isteği.
    Her 5 dakikada bir gönderilir.
    """
    session_token: str = Field(..., min_length=10)
    hwid: str = Field(..., min_length=8, max_length=256)
    nonce: str = Field(..., min_length=32, max_length=128)

    @field_validator("session_token")
    @classmethod
    def validate_token(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', v):
            raise ValueError("Geçersiz token formatı")
        return v

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, v: str) -> str:
        if not re.match(r'^[a-f0-9]+$', v):
            raise ValueError("Geçersiz nonce formatı")
        return v


class HeartbeatResponse(BaseModel):
    """Heartbeat yanıtı."""
    valid: bool
    expires_at: Optional[datetime] = None
    message: str = "OK"


# ─────────────────────────────────────────────────────────────────────────────
# Admin Auth Şemaları
# ─────────────────────────────────────────────────────────────────────────────

class AdminLoginRequest(BaseModel):
    """Admin giriş isteği."""
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=256)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', v):
            raise ValueError("Geçersiz kullanıcı adı")
        return v.strip()


class AdminLoginResponse(BaseModel):
    """Admin giriş yanıtı."""
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


# ─────────────────────────────────────────────────────────────────────────────
# Lisans Şemaları
# ─────────────────────────────────────────────────────────────────────────────

class LicenseCreateRequest(BaseModel):
    """Yeni lisans oluşturma isteği."""
    license_type: LicenseType
    note: Optional[str] = Field(None, max_length=500)
    count: int = Field(1, ge=1, le=100, description="Kaç adet oluşturulsun")


class LicenseResponse(BaseModel):
    """Lisans yanıtı."""
    id: uuid.UUID
    key: str
    license_type: LicenseType
    status: LicenseStatus
    created_at: datetime
    activated_at: Optional[datetime]
    expires_at: Optional[datetime]
    note: Optional[str]

    model_config = {"from_attributes": True}


class LicenseListResponse(BaseModel):
    """Lisans listesi yanıtı."""
    items: list[LicenseResponse]
    total: int
    page: int
    page_size: int


class HwidResetRequest(BaseModel):
    """HWID sıfırlama isteği."""
    license_id: uuid.UUID
    reason: Optional[str] = Field(None, max_length=500)


# ─────────────────────────────────────────────────────────────────────────────
# Log Şemaları
# ─────────────────────────────────────────────────────────────────────────────

class ActivityLogResponse(BaseModel):
    """Aktivite log yanıtı."""
    id: uuid.UUID
    license_id: Optional[uuid.UUID]
    action: LogAction
    ip_address: Optional[str]
    detail: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class ActivityLogListResponse(BaseModel):
    """Log listesi yanıtı."""
    items: list[ActivityLogResponse]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────────────────────────────────────
# Genel Yanıt Şemaları
# ─────────────────────────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    """Basit mesaj yanıtı."""
    message: str
    success: bool = True


class ErrorResponse(BaseModel):
    """Hata yanıtı."""
    error: str
    detail: Optional[str] = None
    success: bool = False
