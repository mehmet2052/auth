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
from sqlalchemy import text
from typing import AsyncGenerator

from app.core.config import get_settings

settings = get_settings()

engine: AsyncEngine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
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
    Tabloları ve index'leri IF NOT EXISTS ile oluştur.
    Tekrar çalıştırıldığında hata vermez.
    """
    async with engine.begin() as conn:
        # Tabloları oluştur (checkfirst tablo seviyesinde çalışır)
        await conn.run_sync(Base.metadata.create_all)


async def create_tables_safe() -> None:
    """
    Tablolar zaten varsa yoksay — index duplicate hatalarını da yoksay.
    Production restart'larında kullanılır.
    """
    # Her tabloyu ve index'i tek tek IF NOT EXISTS ile oluştur
    async with engine.begin() as conn:
        # Önce tabloları dene, hata olursa zaten var demek
        for table in Base.metadata.sorted_tables:
            try:
                await conn.run_sync(
                    lambda sync_conn, t=table: t.create(sync_conn, checkfirst=True)
                )
            except Exception:
                pass  # Tablo zaten var

        # Index'leri IF NOT EXISTS ile oluştur
        index_sql = [
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
        for sql in index_sql:
            try:
                await conn.execute(text(sql))
            except Exception:
                pass  # Index zaten var
