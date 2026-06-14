"""
AnomalyRule ORM modeli — DB-stored, hot-reloadable anomaly detection rules.
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Boolean, Integer, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.database import Base


class AnomalyRule(Base):
    """
    Anomaly detection kuralları.
    Her kural bağımsız olarak açılıp kapatılabilir, threshold/window değiştirilebilir.
    Hot-reload: sunucu restartı gerektirmez (60s cache).
    """
    __tablename__ = "anomaly_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # lock_license, flag_only, block_ip, webhook_alert
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
