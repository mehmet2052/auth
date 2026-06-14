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
from app.core.logging import logger

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
    Mevcut tablolara eksik kolonları ekle (auto-migration).
    Yeniden çalıştırılabilir — hata vermez.
    """
    # 1. Tabloları oluştur (tablo seviyesinde checkfirst çalışır)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 2. Auto-migration: add missing columns to existing tables
    migration_sqls = [
        # ── admins: RBAC columns ──
        "ALTER TABLE admins ADD COLUMN IF NOT EXISTS parent_id UUID REFERENCES admins(id) ON DELETE SET NULL",
        "ALTER TABLE admins ADD COLUMN IF NOT EXISTS key_quota_limit INTEGER",
        "ALTER TABLE admins ADD COLUMN IF NOT EXISTS keys_created_count INTEGER NOT NULL DEFAULT 0",
    ]
    async with engine.begin() as conn:
        for sql in migration_sqls:
            try:
                await conn.execute(text(sql))
            except Exception:
                pass

    # 2b. Convert ALL enum columns to VARCHAR — avoids PostgreSQL enum name mismatch
    varchar_fix_sqls = [
        # admins.role → VARCHAR
        "ALTER TABLE admins ALTER COLUMN role TYPE VARCHAR(32) USING role::text",
        "ALTER TABLE admins ALTER COLUMN role SET DEFAULT 'admin'",
        # licenses → VARCHAR
        "ALTER TABLE licenses ALTER COLUMN license_type TYPE VARCHAR(32) USING license_type::text",
        "ALTER TABLE licenses ALTER COLUMN status TYPE VARCHAR(32) USING status::text",
        # activity_logs → VARCHAR
        "ALTER TABLE activity_logs ALTER COLUMN action TYPE VARCHAR(64) USING action::text",
        # activation_history → VARCHAR
        "ALTER TABLE activation_history ALTER COLUMN action TYPE VARCHAR(64) USING action::text",
        # Licenses hardening columns
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS discord_id VARCHAR(32)",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS ip_fingerprint VARCHAR(64)",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS activation_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS max_activations INTEGER NOT NULL DEFAULT 1",
    ]
    async with engine.begin() as conn:
        for sql in varchar_fix_sqls:
            try:
                await conn.execute(text(sql))
            except Exception as e:
                logger.warning(f"Migration SQL skipped (non-fatal): {sql[:60]}... — {e}")

    # 2c. Normalize enum data to lowercase .value format
    #     (handles data inserted by old create_all() which used UPPERCASE names)
    normalize_sqls = [
        "UPDATE admins SET role = LOWER(role) WHERE role IS NOT NULL",
        "UPDATE licenses SET status = LOWER(status) WHERE status IS NOT NULL",
        "UPDATE licenses SET license_type = LOWER(license_type) WHERE license_type IS NOT NULL",
        "UPDATE activity_logs SET action = LOWER(action) WHERE action IS NOT NULL",
    ]
    async with engine.begin() as conn:
        for sql in normalize_sqls:
            try:
                await conn.execute(text(sql))
            except Exception:
                pass

    # 3. Yeni tabloları oluştur (activation_history — create_all halleder ama garanti olsun)
    activation_history_sql = """
        CREATE TABLE IF NOT EXISTS activation_history (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            license_id UUID NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
            action VARCHAR(32) NOT NULL,
            hwid_hash VARCHAR(64),
            ip_address VARCHAR(45),
            discord_id VARCHAR(32),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    """
    async with engine.begin() as conn:
        await conn.execute(text(activation_history_sql))

    # 4. Index'leri IF NOT EXISTS ile oluştur
    index_sqls = [
        "CREATE INDEX IF NOT EXISTS ix_admins_username ON admins (username)",
        "CREATE INDEX IF NOT EXISTS ix_admins_role ON admins (role)",
        "CREATE INDEX IF NOT EXISTS ix_admins_parent_id ON admins (parent_id)",
        "CREATE INDEX IF NOT EXISTS ix_licenses_key ON licenses (key)",
        "CREATE INDEX IF NOT EXISTS ix_licenses_status ON licenses (status)",
        "CREATE INDEX IF NOT EXISTS ix_licenses_hwid_hash ON licenses (hwid_hash)",
        "CREATE INDEX IF NOT EXISTS ix_licenses_expires_at ON licenses (expires_at)",
        "CREATE INDEX IF NOT EXISTS ix_licenses_discord_id ON licenses (discord_id)",
        "CREATE INDEX IF NOT EXISTS ix_sessions_token_hash ON sessions (token_hash)",
        "CREATE INDEX IF NOT EXISTS ix_sessions_license_id ON sessions (license_id)",
        "CREATE INDEX IF NOT EXISTS ix_sessions_expires_at ON sessions (expires_at)",
        "CREATE INDEX IF NOT EXISTS ix_activity_logs_license_id ON activity_logs (license_id)",
        "CREATE INDEX IF NOT EXISTS ix_activity_logs_action ON activity_logs (action)",
        "CREATE INDEX IF NOT EXISTS ix_activity_logs_created_at ON activity_logs (created_at)",
        "CREATE INDEX IF NOT EXISTS ix_used_nonces_nonce ON used_nonces (nonce)",
        "CREATE INDEX IF NOT EXISTS ix_used_nonces_created_at ON used_nonces (created_at)",
        "CREATE INDEX IF NOT EXISTS ix_activation_history_license_id ON activation_history (license_id)",
        "CREATE INDEX IF NOT EXISTS ix_activation_history_action ON activation_history (action)",
        "CREATE INDEX IF NOT EXISTS ix_activation_history_created_at ON activation_history (created_at)",
    ]
    async with engine.begin() as conn:
        for sql in index_sqls:
            await conn.execute(text(sql))
