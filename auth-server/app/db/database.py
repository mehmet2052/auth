"""
Veritabanı bağlantı yönetimi.
"""
from sqlalchemy.ext.asyncio import (
    AsyncSession, AsyncEngine,
    create_async_engine, async_sessionmaker,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from typing import AsyncGenerator

from app.core.config import get_settings

settings = get_settings()

engine: AsyncEngine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    echo=settings.debug,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables() -> None:
    """
    Tabloları oluştur, index'leri IF NOT EXISTS ile ekle.
    Yeniden çalıştırılabilir — hata vermez.
    """
    # 1. Tabloları oluştur (tablo seviyesinde checkfirst çalışır)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 2. Index'leri IF NOT EXISTS ile oluştur (duplicate hatası olmaz)
    index_sqls = [
        "CREATE INDEX IF NOT EXISTS ix_admins_username ON admins (username)",
        "CREATE INDEX IF NOT EXISTS ix_licenses_key ON licenses (key)",
        "CREATE INDEX IF NOT EXISTS ix_licenses_status ON licenses (status)",
        "CREATE INDEX IF NOT EXISTS ix_licenses_hwid_hash ON licenses (hwid_hash)",
        "CREATE INDEX IF NOT EXISTS ix_licenses_expires_at ON licenses (expires_at)",
        "CREATE INDEX IF NOT EXISTS ix_sessions_token_hash ON sessions (token_hash)",
        "CREATE INDEX IF NOT EXISTS ix_sessions_license_id ON sessions (license_id)",
        "CREATE INDEX IF NOT EXISTS ix_sessions_expires_at ON sessions (expires_at)",
        "CREATE INDEX IF NOT EXISTS ix_activity_logs_license_id ON activity_logs (license_id)",
        "CREATE INDEX IF NOT EXISTS ix_activity_logs_action ON activity_logs (action)",
        "CREATE INDEX IF NOT EXISTS ix_activity_logs_created_at ON activity_logs (created_at)",
        "CREATE INDEX IF NOT EXISTS ix_used_nonces_nonce ON used_nonces (nonce)",
        "CREATE INDEX IF NOT EXISTS ix_used_nonces_created_at ON used_nonces (created_at)",
    ]
    async with engine.begin() as conn:
        for sql in index_sqls:
            await conn.execute(text(sql))
