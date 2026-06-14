"""
WebhookConfig ORM modeli — Discord webhook yapılandırması.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.database import Base


class WebhookConfig(Base):
    """
    Discord webhook yapılandırmaları.
    Her webhook belirli event tiplerine abone olur.
    schema_version ile payload formatı versiyonlanır.
    """
    __tablename__ = "webhook_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    secret: Mapped[Optional[str]] = mapped_column(String(256))  # For HMAC signing payload
    event_types: Mapped[str] = mapped_column(Text, default="[]", nullable=False)  # JSON array
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("admins.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
