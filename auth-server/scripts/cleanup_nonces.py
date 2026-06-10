"""
Eski nonce kayıtlarını ve süresi dolmuş session'ları temizle.
Cron ile her 5 dakikada bir çalıştır:
    */5 * * * * python /path/to/cleanup_nonces.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import AsyncSessionLocal
from app.repositories.session_repo import NonceRepository
from app.repositories.license_repo import LicenseRepository


async def cleanup() -> None:
    async with AsyncSessionLocal() as db:
        # Eski nonce'ları temizle (5 dakikadan eski)
        nonce_repo = NonceRepository(db)
        nonce_count = await nonce_repo.cleanup_old(older_than_minutes=5)

        # Süresi dolmuş lisansları güncelle
        license_repo = LicenseRepository(db)
        expired_count = await license_repo.mark_expired()

        await db.commit()
        print(f"[cleanup] {nonce_count} nonce silindi, {expired_count} lisans expired işaretlendi")


if __name__ == "__main__":
    asyncio.run(cleanup())
