"""
Veritabanı bağlantı yönetimi.
SQLAlchemy async engine + session factory.
"""
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.orm import DeclarativeBase
from typing import AsyncGenerator

from app.core.config import get_settings

settings = get_settings()

# Async engine — connection pool ile
engine: AsyncEngine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,      # Stale connection'ları tespit et
    pool_size=10,            # Min bağlantı sayısı
    max_overflow=20,         # Pik yükte ek bağlantılar
    pool_timeout=30,         # Bağlantı bekleme süresi (saniye)
    echo=settings.debug,     # Debug modda SQL logla
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Commit sonrası nesneler expire olmasın
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """Tüm model sınıflarının türediği temel sınıf."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency injection için veritabanı session'ı döndür.
    Her request için ayrı session — otomatik cleanup garantili.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables() -> None:
    """Tüm tabloları oluştur (geliştirme için — production'da Alembic kullan)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
