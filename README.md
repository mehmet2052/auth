# Nexus Auth Server — Kurulum Kılavuzu

## Gereksinimler
- Python 3.11+
- PostgreSQL 14+
- Nginx (production)
- SSL sertifikası (Let's Encrypt önerilir)

---

## 1. Kurulum

```bash
# Repoyu kopyala
git clone ...
cd auth-server

# Sanal ortam oluştur
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Bağımlılıkları yükle
pip install -r requirements.txt
```

---

## 2. Yapılandırma

```bash
cp .env.example .env
```

`.env` dosyasını düzenle:

```env
DATABASE_URL=postgresql+asyncpg://postgres:GUCLU_SIFRE@localhost:5432/nexus_auth
JWT_SECRET_KEY=EN_AZ_64_KARAKTER_RASTGELE_SECRET
ADMIN_PASSWORD=GUCLU_ADMIN_SIFRE
API_SECRET_VALUE=RASTGELE_API_SECRET_DEGER
```

**Güvenli secret üretimi:**
```bash
python -c "import secrets; print(secrets.token_hex(64))"
```

---

## 3. Veritabanı Kurulumu

```bash
# PostgreSQL'de veritabanı oluştur
createdb nexus_auth

# Migration'ları çalıştır
alembic upgrade head

# İlk admin hesabını oluştur
python scripts/create_admin.py
```

---

## 4. Sunucuyu Başlat

**Geliştirme:**
```bash
python main.py
# veya
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Production (SSL ile):**
```bash
# SSL sertifikalarını ssl/ klasörüne koy
mkdir ssl
cp /path/to/cert.pem ssl/
cp /path/to/key.pem ssl/

uvicorn main:app --host 0.0.0.0 --port 8000 \
    --ssl-keyfile ssl/key.pem \
    --ssl-certfile ssl/cert.pem \
    --workers 4
```

---

## 5. Nginx Yapılandırması (Production)

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Güvenlik başlıkları
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Panel statik dosyaları
    location /panel/ {
        root /var/www/nexus;
        try_files $uri $uri/ =404;
        # Sadece yetkili IP'lerden erişim
        allow 192.168.1.0/24;  # Kendi IP'n
        deny all;
    }
}
```

---

## 6. C++ Client Yapılandırması

`src/core/auth/AuthClient.cpp` içinde şu değerleri güncelle:

```cpp
static const char* GetAuthUrl()   { return "https://SUNUCU_ADRESIN/api/v1/auth"; }
static const char* GetHbUrl()     { return "https://SUNUCU_ADRESIN/api/v1/heartbeat"; }
static const char* GetSecretHdr() { return "X-Nexus-Secret: API_SECRET_DEGER"; }
```

---

## 7. Panel Kullanımı

`panel/index.html` dosyasında API_BASE değerini güncelle:

```javascript
const API_BASE = "https://SUNUCU_ADRESIN";
```

Panele tarayıcıdan `panel/index.html` açarak erişebilirsin.

---

## 8. Testleri Çalıştır

```bash
pytest tests/ -v
```

---

## 9. Periyodik Görevler (Cron)

Süresi dolmuş lisansları ve eski nonce'ları temizlemek için:

```bash
# crontab -e
# Her saat başı süresi dolmuş lisansları işaretle
0 * * * * cd /path/to/auth-server && python -c "
import asyncio
from app.db.database import AsyncSessionLocal
from app.repositories.license_repo import LicenseRepository

async def cleanup():
    async with AsyncSessionLocal() as db:
        repo = LicenseRepository(db)
        count = await repo.mark_expired()
        await db.commit()
        print(f'{count} lisans expired olarak işaretlendi')

asyncio.run(cleanup())
"
```

---

## 10. Güvenlik Kontrol Listesi

- [x] `.env` dosyasında güçlü secret'lar
- [x] PostgreSQL şifresi güçlü
- [x] SSL/TLS zorunlu
- [x] Admin paneli IP kısıtlamalı
- [x] Rate limiting aktif
- [x] Debug modu production'da kapalı (`DEBUG=false`)
- [x] API docs production'da kapalı
- [x] Firewall: sadece 443 ve 22 açık
- [ ] Düzenli yedek (pg_dump)
- [ ] Log izleme sistemi
