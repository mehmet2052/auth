"""
SQLAlchemy ORM modelleri.
Tüm tablolar normalize edilmiş, foreign key ve index yapıları eklenmiş.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional
from enum import Enum as PyEnum

from sqlalchemy import (
    String, Boolean, Integer, DateTime, Text,
    ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from sqlalchemy.types import TypeDecorator

from app.db.database import Base


class StrEnum(TypeDecorator):
    """
    Stores Python str-Enum as VARCHAR in the database.
    Completely avoids PostgreSQL enum types — no name/value mismatch possible.
    """
    impl = String
    cache_ok = True

    def __init__(self, enum_class, length=64):
        super().__init__()
        self.enum_class = enum_class
        self.impl = String(length)

    def process_bind_param(self, value, dialect):
        if value is not None:
            return value.value if isinstance(value, self.enum_class) else str(value)
        return None

    def process_result_value(self, value, dialect):
        if value is not None:
            try:
                return self.enum_class(value)
            except ValueError:
                return value  # Return raw string if enum lookup fails
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Enum Tipleri
# ─────────────────────────────────────────────────────────────────────────────

class AdminRole(str, PyEnum):
    """Yönetici rolleri."""
    ADMIN    = "admin"     # Full erişim
    RESELLER = "reseller"  # Sınırlı erişim, quota ile


class LicenseType(str, PyEnum):
    """Lisans türleri."""
    ONE_DAY    = "1d"
    THREE_DAY  = "3d"
    SEVEN_DAY  = "7d"
    THIRTY_DAY = "30d"
    LIFETIME   = "lifetime"


class LicenseStatus(str, PyEnum):
    """Lisans durumu."""
    ACTIVE    = "active"      # Aktif ve kullanılabilir
    USED      = "used"        # Aktive edildi
    EXPIRED   = "expired"     # Süresi doldu
    SUSPENDED = "suspended"   # Yönetici tarafından askıya alındı
    REVOKED   = "revoked"     # İptal edildi
    BANNED    = "banned"      # Kalıcı olarak yasaklandı


class LogAction(str, PyEnum):
    """Aktivite log eylemleri."""
    AUTH_SUCCESS    = "auth_success"
    AUTH_FAILED     = "auth_failed"
    AUTH_EXPIRED    = "auth_expired"
    AUTH_SUSPENDED  = "auth_suspended"
    HEARTBEAT_OK    = "heartbeat_ok"
    HEARTBEAT_FAIL  = "heartbeat_fail"
    HWID_MISMATCH   = "hwid_mismatch"
    HWID_RESET      = "hwid_reset"
    LICENSE_CREATED = "license_created"
    LICENSE_REVOKED = "license_revoked"
    ADMIN_LOGIN     = "admin_login"
    ADMIN_LOGIN_FAIL= "admin_login_fail"
    DISCORD_MISMATCH = "discord_mismatch"
    ACTIVATION_LIMIT = "activation_limit"


class ActivationAction(str, PyEnum):
    """Aktivasyon geçmişi eylemleri."""
    ACTIVATED   = "activated"
    DEACTIVATED = "deactivated"
    HWID_RESET  = "hwid_reset"


# ─────────────────────────────────────────────────────────────────────────────
# Admin Tablosu
# ─────────────────────────────────────────────────────────────────────────────

class Admin(Base):
    """
    Yönetici hesapları.
    Birden fazla admin desteklenir.
    """
    __tablename__ = "admins"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[AdminRole] = mapped_column(
        StrEnum(AdminRole, 32),
        default=AdminRole.ADMIN, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    
    # Reseller hierarchy
    parent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("admins.id", ondelete="SET NULL")
    )
    
    # Reseller quota
    key_quota_limit: Mapped[Optional[int]] = mapped_column(Integer)  # NULL = unlimited
    keys_created_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relations
    licenses: Mapped[list["License"]] = relationship(
        "License", back_populates="created_by_admin"
    )
    parent: Mapped[Optional["Admin"]] = relationship(
        "Admin", remote_side="Admin.id", foreign_keys=[parent_id]
    )

    __table_args__ = (
        UniqueConstraint("username"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Lisans Tablosu
# ─────────────────────────────────────────────────────────────────────────────

class License(Base):
    """
    Lisans anahtarları.
    Her lisans benzersiz, kriptografik olarak üretilmiş.
    """
    __tablename__ = "licenses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    key: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    license_type: Mapped[LicenseType] = mapped_column(
        StrEnum(LicenseType, 32), nullable=False
    )
    status: Mapped[LicenseStatus] = mapped_column(
        StrEnum(LicenseStatus, 32),
        default=LicenseStatus.ACTIVE, nullable=False
    )

    # Zamanlama — sunucu saatine göre
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )  # lifetime için NULL

    # HWID — hash olarak saklanır, ham veri saklanmaz
    hwid_hash: Mapped[Optional[str]] = mapped_column(String(64))

    # Discord ID — zorunlu bağlama (ilk aktivasyonda set edilir)
    discord_id: Mapped[Optional[str]] = mapped_column(String(32), index=True)

    # IP fingerprint — soft binding (uyarı amaçlı, engellemez)
    ip_fingerprint: Mapped[Optional[str]] = mapped_column(String(64))

    # Aktivasyon kontrolü
    activation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_activations: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Not alanı
    note: Mapped[Optional[str]] = mapped_column(Text)

    # Kim oluşturdu
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("admins.id", ondelete="SET NULL")
    )
    created_by_admin: Mapped[Optional["Admin"]] = relationship(
        "Admin", back_populates="licenses"
    )

    # Relations
    sessions: Mapped[list["Session"]] = relationship(
        "Session", back_populates="license", cascade="all, delete-orphan"
    )
    activity_logs: Mapped[list["ActivityLog"]] = relationship(
        "ActivityLog", back_populates="license", cascade="all, delete-orphan"
    )
    activation_history: Mapped[list["ActivationHistory"]] = relationship(
        "ActivationHistory", back_populates="license", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("key"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Session Tablosu
# ─────────────────────────────────────────────────────────────────────────────

class Session(Base):
    """
    Aktif oturumlar.
    Her başarılı auth → yeni session token.
    Heartbeat bu token ile yapılır.
    """
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    license_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("licenses.id", ondelete="CASCADE"),
        nullable=False
    )
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False
    )  # Token plaintext değil hash olarak saklanır
    hwid_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Replay attack koruması
    last_nonce: Mapped[Optional[str]] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_heartbeat: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # IP bilgisi
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))

    # Relations
    license: Mapped["License"] = relationship("License", back_populates="sessions")

    __table_args__ = (
        UniqueConstraint("token_hash"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Aktivite Log Tablosu
# ─────────────────────────────────────────────────────────────────────────────

class ActivityLog(Base):
    """
    Tüm önemli eylemler için audit trail.
    Hem başarılı hem başarısız işlemler kaydedilir.
    """
    __tablename__ = "activity_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    license_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("licenses.id", ondelete="SET NULL")
    )
    action: Mapped[LogAction] = mapped_column(
        StrEnum(LogAction, 64), nullable=False
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    hwid_hash: Mapped[Optional[str]] = mapped_column(String(64))
    detail: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relations
    license: Mapped[Optional["License"]] = relationship(
        "License", back_populates="activity_logs"
    )

    # activity_logs için __table_args__ yok — index'ler database.py'de IF NOT EXISTS ile ekleniyor


# ─────────────────────────────────────────────────────────────────────────────
# Kullanılmış Nonce Tablosu — Replay Attack Koruması
# ─────────────────────────────────────────────────────────────────────────────

class UsedNonce(Base):
    """
    Kullanılmış nonce değerleri.
    Aynı nonce iki kez kullanılamaz.
    TTL: 5 dakika (cron ile temizlenir).
    """
    __tablename__ = "used_nonces"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    nonce: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("nonce"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Aktivasyon Geçmişi Tablosu
# ─────────────────────────────────────────────────────────────────────────────

class ActivationHistory(Base):
    """
    Her lisans aktivasyonu/deaktivasyonu için kayıt.
    Kim, ne zaman, hangi HWID/IP ile aktive etti?
    """
    __tablename__ = "activation_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    license_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("licenses.id", ondelete="CASCADE"),
        nullable=False
    )
    action: Mapped[ActivationAction] = mapped_column(
        StrEnum(ActivationAction, 64), nullable=False
    )
    hwid_hash: Mapped[Optional[str]] = mapped_column(String(64))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    discord_id: Mapped[Optional[str]] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relations
    license: Mapped["License"] = relationship(
        "License", back_populates="activation_history"
    )
