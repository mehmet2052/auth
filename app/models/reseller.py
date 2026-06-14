"""
Reseller ORM modeli — Admin tablosundan ayrı, bağımsız reseller entity.
"""
import uuid
from datetime import datetime, date, timezone
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    String, Boolean, Integer, DateTime, Date, Text,
    ForeignKey, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.models import License


class Reseller(Base):
    """
    Reseller hesapları — Admin tablosundan tamamen ayrı.
    Bağımsız yaşam döngüsü, kimlik bilgileri ve kota takibi.
    """
    __tablename__ = "resellers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Who created this reseller (admin)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("admins.id", ondelete="SET NULL")
    )

    # ── Quota ─────────────────────────────────────────────────────────────────
    key_quota_limit: Mapped[Optional[int]] = mapped_column(Integer)  # NULL = unlimited
    keys_created_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    daily_key_limit: Mapped[Optional[int]] = mapped_column(Integer)  # NULL = unlimited
    daily_keys_created_today: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    daily_keys_date: Mapped[date] = mapped_column(
        Date, server_default=func.current_date(), nullable=False
    )

    # ── Relations ─────────────────────────────────────────────────────────────
    licenses: Mapped[list["License"]] = relationship(
        "License", back_populates="created_by_reseller"
    )

    __table_args__ = (
        UniqueConstraint("username"),
    )
