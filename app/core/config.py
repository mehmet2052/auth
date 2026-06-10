"""
Uygulama konfigürasyonu — .env dosyasından okunur.
Pydantic Settings ile tip güvenliği sağlanır.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Database
    database_url: str

    # JWT
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    session_token_expire_hours: int = 24

    # Admin
    admin_username: str = "admin"
    admin_password: str

    # API Security
    api_secret_header: str = "X-Nexus-Secret"
    api_secret_value: str

    # Rate Limiting
    rate_limit_auth: str = "10/minute"
    rate_limit_heartbeat: str = "30/minute"

    # App
    debug: bool = False
    app_version: int = 1
    allowed_hosts: str = "*"
    cors_origins: str = "http://localhost:3000"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Singleton ayar nesnesi — her çağrıda yeniden parse edilmez."""
    return Settings()
