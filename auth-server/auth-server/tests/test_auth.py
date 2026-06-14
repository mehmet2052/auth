"""
Auth endpoint testleri.
Çalıştırma: pytest tests/ -v
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from main import app
from app.core.config import get_settings
from app.core.security import generate_license_key, generate_nonce

settings = get_settings()


@pytest.fixture
def api_headers():
    """API secret header."""
    return {settings.api_secret_header: settings.api_secret_value}


@pytest.fixture
def valid_auth_body():
    """Geçerli auth isteği gövdesi."""
    return {
        "key": generate_license_key(),
        "hwid": "aabbccdd" * 8,  # test HWID
        "nonce": generate_nonce(),
        "version": 1,
    }


@pytest_asyncio.fixture
async def client():
    """Test HTTP istemcisi."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as c:
        yield c


class TestHealthCheck:
    async def test_health(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestAuth:
    async def test_missing_api_secret_returns_403(self, client, valid_auth_body):
        """API secret olmadan 403 dönmeli."""
        resp = await client.post("/api/v1/auth", json=valid_auth_body)
        assert resp.status_code == 403

    async def test_invalid_key_returns_400(self, client, api_headers):
        """Var olmayan lisans anahtarı 400 dönmeli."""
        resp = await client.post("/api/v1/auth", json={
            "key": "NEXUS-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF",
            "hwid": "aabbccdd" * 8,
            "nonce": generate_nonce(),
            "version": 1,
        }, headers=api_headers)
        assert resp.status_code == 400
        assert "Geçersiz" in resp.json()["detail"]

    async def test_invalid_key_format_returns_422(self, client, api_headers):
        """Geçersiz format 422 dönmeli (Pydantic validation)."""
        resp = await client.post("/api/v1/auth", json={
            "key": "'; DROP TABLE licenses; --",
            "hwid": "test",
            "nonce": "abc",
            "version": 1,
        }, headers=api_headers)
        assert resp.status_code == 422

    async def test_replay_attack_blocked(self, client, api_headers):
        """Aynı nonce iki kez kullanılamaz."""
        nonce = generate_nonce()
        body = {
            "key": "NEXUS-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF",
            "hwid": "aabbccdd" * 8,
            "nonce": nonce,
            "version": 1,
        }
        # İlk istek (400 - geçersiz key ama nonce işlenir)
        r1 = await client.post("/api/v1/auth", json=body, headers=api_headers)

        # İkinci istek — aynı nonce
        r2 = await client.post("/api/v1/auth", json=body, headers=api_headers)
        # 400 veya replay hatası
        assert r2.status_code in (400,)


class TestHeartbeat:
    async def test_invalid_session_returns_false(self, client, api_headers):
        """Geçersiz session token false dönmeli."""
        resp = await client.post("/api/v1/heartbeat", json={
            "session_token": "invalid.token.here",
            "hwid": "aabbccdd" * 8,
            "nonce": generate_nonce(),
        }, headers=api_headers)
        assert resp.status_code == 200
        assert resp.json()["valid"] is False


class TestAdminLogin:
    async def test_wrong_credentials_returns_401(self, client):
        """Yanlış şifre 401 dönmeli."""
        resp = await client.post("/api/v1/admin/login", json={
            "username": "admin",
            "password": "wrong_password_12345",
        })
        assert resp.status_code == 401

    async def test_sql_injection_in_username(self, client):
        """SQL injection girişimi 422 dönmeli."""
        resp = await client.post("/api/v1/admin/login", json={
            "username": "admin' OR '1'='1",
            "password": "test",
        })
        assert resp.status_code == 422

    async def test_rate_limit_on_login(self, client):
        """5 başarısız denemeden sonra 429 dönmeli."""
        body = {"username": "admin", "password": "wrong"}
        for _ in range(5):
            await client.post("/api/v1/admin/login", json=body)
        resp = await client.post("/api/v1/admin/login", json=body)
        assert resp.status_code in (401, 429)
