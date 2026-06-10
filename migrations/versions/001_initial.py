"""Initial schema

Revision ID: 001
Revises:
Create Date: 2026-01-01
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # admins
    op.create_table(
        'admins',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('username', sa.String(64), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(256), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_admins_username', 'admins', ['username'])

    # licenses
    op.create_table(
        'licenses',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('key', sa.String(64), nullable=False, unique=True),
        sa.Column('license_type', sa.String(16), nullable=False),
        sa.Column('status', sa.String(16), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('hwid_hash', sa.String(64), nullable=True),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('created_by', UUID(as_uuid=True),
                  sa.ForeignKey('admins.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_index('ix_licenses_key', 'licenses', ['key'])
    op.create_index('ix_licenses_status', 'licenses', ['status'])
    op.create_index('ix_licenses_hwid_hash', 'licenses', ['hwid_hash'])
    op.create_index('ix_licenses_expires_at', 'licenses', ['expires_at'])

    # sessions
    op.create_table(
        'sessions',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('license_id', UUID(as_uuid=True),
                  sa.ForeignKey('licenses.id', ondelete='CASCADE'), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('hwid_hash', sa.String(64), nullable=False),
        sa.Column('last_nonce', sa.String(64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_heartbeat', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_valid', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('ip_address', sa.String(45), nullable=True),
    )
    op.create_index('ix_sessions_token_hash', 'sessions', ['token_hash'])
    op.create_index('ix_sessions_license_id', 'sessions', ['license_id'])
    op.create_index('ix_sessions_expires_at', 'sessions', ['expires_at'])

    # activity_logs
    op.create_table(
        'activity_logs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('license_id', UUID(as_uuid=True),
                  sa.ForeignKey('licenses.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action', sa.String(32), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('hwid_hash', sa.String(64), nullable=True),
        sa.Column('detail', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_activity_logs_license_id', 'activity_logs', ['license_id'])
    op.create_index('ix_activity_logs_action', 'activity_logs', ['action'])
    op.create_index('ix_activity_logs_created_at', 'activity_logs', ['created_at'])

    # used_nonces
    op.create_table(
        'used_nonces',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('nonce', sa.String(64), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_used_nonces_nonce', 'used_nonces', ['nonce'])
    op.create_index('ix_used_nonces_created_at', 'used_nonces', ['created_at'])


def downgrade() -> None:
    op.drop_table('used_nonces')
    op.drop_table('activity_logs')
    op.drop_table('sessions')
    op.drop_table('licenses')
    op.drop_table('admins')
