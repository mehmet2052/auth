"""
İlk admin hesabını oluştur.
Kullanım: python scripts/create_admin.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import AsyncSessionLocal, create_tables
from app.core.security import hash_password
from app.models.models import Admin


async def create_admin(username: str, password: str) -> None:
    await create_tables()

    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(select(Admin).where(Admin.username == username))
        existing = result.scalar_one_or_none()

        if existing:
            print(f"[!] Admin '{username}' zaten mevcut")
            return

        admin = Admin(
            username=username,
            password_hash=hash_password(password),
            is_active=True,
        )
        db.add(admin)
        await db.commit()
        print(f"[+] Admin '{username}' başarıyla oluşturuldu")


if __name__ == "__main__":
    from app.core.config import get_settings
    settings = get_settings()

    username = input(f"Admin kullanıcı adı [{settings.admin_username}]: ").strip()
    if not username:
        username = settings.admin_username

    import getpass
    password = getpass.getpass("Şifre: ")

    asyncio.run(create_admin(username, password))
