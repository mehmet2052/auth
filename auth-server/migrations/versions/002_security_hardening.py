"""Security hardening — RBAC, license hardening, activation history

Revision ID: 002
Revises: 001
Create Date: 2026-01-15

Changes:
  - admins: role, parent_id, key_quota_limit, keys_created_count
  - licenses: discord_id, ip_fingerprint, activation_count, max_activations, banned status
  - NEW TABLE: activation_history
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── admins: RBAC columns ─────────────────────────────────────────────────
    # Use VARCHAR for role (not PostgreSQL enum) — avoids name/value mismatch
    op.add_column('admins', sa.Column(
        'role',
        sa.String(32),
        nullable=False,
        server_default='admin',
    ))
    op.add_column('admins', sa.Column(
        'parent_id', UUID(as_uuid=True),
        sa.ForeignKey('admins.id', ondelete='SET NULL'),
        nullable=True,
    ))
    op.add_column('admins', sa.Column(
        'key_quota_limit', sa.Integer(), nullable=True,
    ))
    op.add_column('admins', sa.Column(
        'keys_created_count', sa.Integer(), nullable=False, server_default='0',
    ))

    # Set all existing admins to role=admin
    op.execute("UPDATE admins SET role = 'admin'")

    op.create_index('ix_admins_role', 'admins', ['role'])
    op.create_index('ix_admins_parent_id', 'admins', ['parent_id'])

    # ── licenses: hardening columns ──────────────────────────────────────────
    op.add_column('licenses', sa.Column(
        'discord_id', sa.String(32), nullable=True,
    ))
    op.add_column('licenses', sa.Column(
        'ip_fingerprint', sa.String(64), nullable=True,
    ))
    op.add_column('licenses', sa.Column(
        'activation_count', sa.Integer(), nullable=False, server_default='0',
    ))
    op.add_column('licenses', sa.Column(
        'max_activations', sa.Integer(), nullable=False, server_default='1',
    ))

    op.create_index('ix_licenses_discord_id', 'licenses', ['discord_id'])

    # Ensure 'banned' is a valid status value (Varchar column — no enum to alter)
    # No migration needed for VARCHAR-based status columns
    pass

    # ── activation_history: new table ────────────────────────────────────────
    op.create_table(
        'activation_history',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('license_id', UUID(as_uuid=True),
                  sa.ForeignKey('licenses.id', ondelete='CASCADE'), nullable=False),
        sa.Column('action', sa.String(32), nullable=False),
        sa.Column('hwid_hash', sa.String(64), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('discord_id', sa.String(32), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_activation_history_license_id', 'activation_history', ['license_id'])
    op.create_index('ix_activation_history_action', 'activation_history', ['action'])
    op.create_index('ix_activation_history_created_at', 'activation_history', ['created_at'])


def downgrade() -> None:
    # Drop activation_history table
    op.drop_index('ix_activation_history_created_at')
    op.drop_index('ix_activation_history_action')
    op.drop_index('ix_activation_history_license_id')
    op.drop_table('activation_history')

    # Remove license hardening columns
    op.drop_index('ix_licenses_discord_id')
    op.drop_column('licenses', 'max_activations')
    op.drop_column('licenses', 'activation_count')
    op.drop_column('licenses', 'ip_fingerprint')
    op.drop_column('licenses', 'discord_id')

    # Remove admin RBAC columns
    op.drop_index('ix_admins_parent_id')
    op.drop_index('ix_admins_role')
    op.drop_column('admins', 'keys_created_count')
    op.drop_column('admins', 'key_quota_limit')
    op.drop_column('admins', 'parent_id')
    op.drop_column('admins', 'role')

    # Drop enum type
    op.execute("DROP TYPE IF EXISTS adminrole")

    # Convert any remaining PostgreSQL enum columns back to VARCHAR
    for table_col in [
        ('licenses', 'license_type'),
        ('licenses', 'status'),
        ('activity_logs', 'action'),
    ]:
        try:
            op.execute(
                f"ALTER TABLE {table_col[0]} ALTER COLUMN {table_col[1]} TYPE VARCHAR(64)"
            )
        except Exception:
            pass

    # Note: Cannot remove 'banned' from PostgreSQL enum — requires recreating the type
    # This is intentionally left as-is for safety
