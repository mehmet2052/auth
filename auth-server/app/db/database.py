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
        "ALTER TABLE licenses ALTER COLUMN status TYPE VARCHAR(64) USING status::text",
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

    # 2c. Normalize enum data: convert old enum NAMES to VALUES
    normalize_sqls = [
        # admins.role — name→value (ADMIN→admin, RESELLER→reseller)
        "UPDATE admins SET role = LOWER(role) WHERE role IN ('ADMIN', 'RESELLER')",
        # licenses.license_type — name→value
        "UPDATE licenses SET license_type = '1d' WHERE license_type IN ('ONE_DAY', 'one_day')",
        "UPDATE licenses SET license_type = '3d' WHERE license_type IN ('THREE_DAY', 'three_day')",
        "UPDATE licenses SET license_type = '7d' WHERE license_type IN ('SEVEN_DAY', 'seven_day')",
        "UPDATE licenses SET license_type = '30d' WHERE license_type IN ('THIRTY_DAY', 'thirty_day')",
        "UPDATE licenses SET license_type = 'lifetime' WHERE license_type IN ('LIFETIME', 'lifetime')",
        # licenses.status — name→value
        "UPDATE licenses SET status = LOWER(status) WHERE status IN ('ACTIVE','USED','EXPIRED','SUSPENDED','REVOKED','BANNED')",
        # activity_logs.action — name→value
        "UPDATE activity_logs SET action = LOWER(action) WHERE action IN ('AUTH_SUCCESS','AUTH_FAILED','AUTH_EXPIRED','AUTH_SUSPENDED','HEARTBEAT_OK','HEARTBEAT_FAIL','HWID_MISMATCH','HWID_RESET','LICENSE_CREATED','LICENSE_REVOKED','ADMIN_LOGIN','ADMIN_LOGIN_FAIL','DISCORD_MISMATCH','ACTIVATION_LIMIT')",
    ]
    async with engine.begin() as conn:
        for sql in normalize_sqls:
            try:
                await conn.execute(text(sql))
            except Exception as e:
                logger.warning(f"Normalize SQL skipped: {sql[:50]}... — {e}")

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

    # ── v2 migrations ────────────────────────────────────────────────────────
    v2_license_columns = [
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS feature_flags TEXT DEFAULT '{}'",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS status_reason TEXT",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS previous_status VARCHAR(32)",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hwid_components_hash VARCHAR(64)",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hwid_first_seen TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hwid_last_seen TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hwid_reset_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS reseller_id UUID REFERENCES resellers(id) ON DELETE SET NULL",
    ]
    async with engine.begin() as conn:
        for sql in v2_license_columns:
            try:
                await conn.execute(text(sql))
            except Exception as e:
                logger.warning(f"v2 migration SQL skipped (non-fatal): {sql[:60]}... — {e}")

    # ── License state transitions table + trigger ──────────────────────────────
    state_transitions_table = """
        CREATE TABLE IF NOT EXISTS license_state_transitions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            from_status VARCHAR(32) NOT NULL,
            to_status VARCHAR(32) NOT NULL,
            allowed_roles VARCHAR(128) NOT NULL DEFAULT 'admin',
            requires_reason BOOLEAN NOT NULL DEFAULT false,
            is_active BOOLEAN NOT NULL DEFAULT true,
            UNIQUE(from_status, to_status)
        )
    """
    async with engine.begin() as conn:
        await conn.execute(text(state_transitions_table))

    # Seed default transitions (idempotent)
    seed_transitions = [
        ("created", "active", "admin,reseller", False),
        ("active", "used", "system", False),
        ("active", "suspended", "admin", True),
        ("active", "banned", "admin", True),
        ("active", "locked", "system,admin", False),
        ("used", "expired", "system", False),
        ("used", "suspended", "admin", True),
        ("used", "banned", "admin", True),
        ("used", "locked", "system,admin", False),
        ("locked", "active", "admin", False),
        ("locked", "banned", "admin", False),
        ("suspended", "active", "admin", False),
        ("expired", "renewed", "admin,reseller", False),
        ("renewed", "active", "system", False),
        ("active", "deleted", "admin", True),
        ("used", "deleted", "admin", True),
        ("suspended", "deleted", "admin", True),
        ("banned", "deleted", "admin", True),
    ]
    async with engine.begin() as conn:
        for from_s, to_s, roles, req_reason in seed_transitions:
            sql = (
                f"INSERT INTO license_state_transitions (from_status, to_status, allowed_roles, requires_reason, is_active) "
                f"VALUES ('{from_s}', '{to_s}', '{roles}', {str(req_reason).lower()}, true) "
                f"ON CONFLICT (from_status, to_status) DO NOTHING"
            )
            try:
                await conn.execute(text(sql))
            except Exception as e:
                logger.warning(f"Seed transition skipped: {from_s}->{to_s} — {e}")

    # DB trigger function for state transition enforcement
    trigger_function = """
        CREATE OR REPLACE FUNCTION validate_license_state_transition()
        RETURNS TRIGGER AS $$
        BEGIN
            -- Only fire when status actually changes
            IF OLD.status IS DISTINCT FROM NEW.status THEN
                -- Look up allowed transition
                IF NOT EXISTS (
                    SELECT 1 FROM license_state_transitions
                    WHERE from_status = OLD.status
                      AND to_status = NEW.status
                      AND is_active = true
                ) THEN
                    RAISE EXCEPTION 'Invalid state transition: % -> %', OLD.status, NEW.status;
                END IF;
                -- Set previous_status for audit
                NEW.previous_status := OLD.status;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """
    async with engine.begin() as conn:
        try:
            await conn.execute(text(trigger_function))
        except Exception as e:
            logger.warning(f"Trigger function creation skipped (non-fatal): {e}")

    # Create trigger (drop first for idempotency)
    trigger_sqls = [
        "DROP TRIGGER IF EXISTS trg_license_state_transition ON licenses",
        """
            CREATE TRIGGER trg_license_state_transition
            BEFORE UPDATE ON licenses
            FOR EACH ROW
            WHEN (OLD.status IS DISTINCT FROM NEW.status)
            EXECUTE FUNCTION validate_license_state_transition()
        """,
    ]
    async with engine.begin() as conn:
        for sql in trigger_sqls:
            try:
                await conn.execute(text(sql))
            except Exception as e:
                logger.warning(f"Trigger SQL skipped (non-fatal): {sql[:50]}... — {e}")

    # ── Anomaly rules table + seed ──────────────────────────────────────────────
    anomaly_rules_table = """
        CREATE TABLE IF NOT EXISTS anomaly_rules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(64) UNIQUE NOT NULL,
            is_enabled BOOLEAN NOT NULL DEFAULT true,
            threshold INTEGER NOT NULL,
            window_seconds INTEGER NOT NULL,
            action VARCHAR(32) NOT NULL,
            cooldown_seconds INTEGER NOT NULL DEFAULT 3600,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    """
    async with engine.begin() as conn:
        await conn.execute(text(anomaly_rules_table))

    seed_anomaly_rules = [
        ("ip_rapid_change", 3, 600, "lock_license", 3600),
        ("hwid_spoof", 2, 300, "webhook_alert", 1800),
        ("brute_force_ip", 10, 300, "block_ip", 900),
        ("brute_force_key", 5, 300, "lock_license", 1800),
    ]
    async with engine.begin() as conn:
        for name, threshold, window, action, cooldown in seed_anomaly_rules:
            sql = (
                f"INSERT INTO anomaly_rules (name, is_enabled, threshold, window_seconds, action, cooldown_seconds) "
                f"VALUES ('{name}', true, {threshold}, {window}, '{action}', {cooldown}) "
                f"ON CONFLICT (name) DO NOTHING"
            )
            try:
                await conn.execute(text(sql))
            except Exception as e:
                logger.warning(f"Seed anomaly rule skipped: {name} — {e}")

    # ── Webhook configs table ────────────────────────────────────────────────────
    webhooks_table = """
        CREATE TABLE IF NOT EXISTS webhook_configs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            url VARCHAR(512) NOT NULL,
            secret VARCHAR(256),
            event_types TEXT NOT NULL DEFAULT '[]',
            schema_version VARCHAR(16) NOT NULL DEFAULT '1.0',
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_by UUID REFERENCES admins(id) ON DELETE SET NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    """
    async with engine.begin() as conn:
        await conn.execute(text(webhooks_table))

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
        "CREATE INDEX IF NOT EXISTS ix_licenses_reseller_id ON licenses (reseller_id)",
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
        "CREATE INDEX IF NOT EXISTS ix_resellers_username ON resellers (username)",
        "CREATE INDEX IF NOT EXISTS ix_resellers_created_by ON resellers (created_by)",
        "CREATE INDEX IF NOT EXISTS ix_webhook_configs_is_active ON webhook_configs (is_active)",
        "CREATE INDEX IF NOT EXISTS ix_license_state_transitions_from_to ON license_state_transitions (from_status, to_status)",
    ]
    async with engine.begin() as conn:
        for sql in index_sqls:
            await conn.execute(text(sql))
