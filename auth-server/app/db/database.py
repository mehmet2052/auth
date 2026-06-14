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
    Mevcut tablolara eksik kolonları ekle (auto-migration).
    Yeniden çalıştırılabilir — hata vermez.
    """
    # 1. Tabloları oluştur (tablo seviyesinde checkfirst çalışır)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 2. Auto-migration: mevcut tablolara eksik kolonları ekle
    migration_sqls = [
        # ── admins: RBAC kolonları ──
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'adminrole') THEN CREATE TYPE adminrole AS ENUM ('ADMIN', 'RESELLER'); END IF; END $$",
        "ALTER TABLE admins ADD COLUMN IF NOT EXISTS role adminrole NOT NULL DEFAULT 'ADMIN'",
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

    # 2b. Fix role column — convert from VARCHAR to adminrole enum if needed
    #     (handles case where previous deploy created it as VARCHAR with lowercase values)
    role_fix_sqls = [
        "UPDATE admins SET role = UPPER(role::text)",
        "ALTER TABLE admins ALTER COLUMN role TYPE adminrole USING role::text::adminrole",
        "ALTER TABLE admins ALTER COLUMN role SET DEFAULT 'ADMIN'",
        "UPDATE admins SET role = 'ADMIN' WHERE role IS NULL",
    ]
    async with engine.begin() as conn:
        for sql in role_fix_sqls:
            try:
                await conn.execute(text(sql))
            except Exception:
                pass

    # 2c. Licenses hardening columns
    license_sqls = [
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS discord_id VARCHAR(32)",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS ip_fingerprint VARCHAR(64)",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS activation_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS max_activations INTEGER NOT NULL DEFAULT 1",
        "DO $$ BEGIN ALTER TYPE licensestatus ADD VALUE 'BANNED'; EXCEPTION WHEN duplicate_object THEN NULL; END $$",
    ]
    async with engine.begin() as conn:
        for sql in license_sqls:
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
