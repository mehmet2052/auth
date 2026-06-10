"""Test yapılandırması."""
import os
import pytest

# Test için çevre değişkenleri
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://postgres:test@localhost:5432/nexus_test")
os.environ.setdefault("JWT_SECRET_KEY", "test_secret_key_that_is_long_enough_for_testing_purposes_only")
os.environ.setdefault("ADMIN_PASSWORD", "test_admin_pass_123")
os.environ.setdefault("API_SECRET_VALUE", "test_api_secret")
os.environ.setdefault("DEBUG", "true")

pytest_plugins = ["pytest_asyncio"]
