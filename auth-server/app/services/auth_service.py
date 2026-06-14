"""
Auth Service — İstemci doğrulama iş mantığı.

Akış:
1. Nonce kontrolü (replay attack)
2. Lisans key doğrulama
3. Lisans durumu kontrolü
4. HWID eşleştirme / ilk aktivasyon
5. Session token oluşturma
6. Log kaydı
"""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import hash_hwid, create_access_token
from app.models.models import LicenseType, LicenseStatus, LogAction, ActivationAction
from app.repositories.license_repo import (
    LicenseRepository, ActivityLogRepository, ActivationHistoryRepository,
)
from app.repositories.session_repo import SessionRepository, NonceRepository
from app.schemas.schemas import AuthRequest, AuthResponse, HeartbeatRequest, HeartbeatResponse
from app.core.logging import logger

settings = get_settings()


def _calculate_expiry(license_type: LicenseType) -> Optional[datetime]:
    """Lisans tipine göre bitiş tarihini hesapla — sunucu saatine göre."""
    now = datetime.now(timezone.utc)
    durations = {
        LicenseType.ONE_DAY:    timedelta(days=1),
        LicenseType.THREE_DAY:  timedelta(days=3),
        LicenseType.SEVEN_DAY:  timedelta(days=7),
        LicenseType.THIRTY_DAY: timedelta(days=30),
        LicenseType.LIFETIME:   None,
    }
    delta = durations.get(license_type)
    return (now + delta) if delta else None


class AuthService:
    """İstemci doğrulama servisi."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.license_repo   = LicenseRepository(db)
        self.session_repo   = SessionRepository(db)
        self.nonce_repo     = NonceRepository(db)
        self.log_repo       = ActivityLogRepository(db)
        self.activation_repo = ActivationHistoryRepository(db)

    async def authenticate(
        self,
        request: AuthRequest,
        ip_address: Optional[str] = None,
    ) -> AuthResponse:
        """
        Tam doğrulama akışı.
        Hata durumunda ValueError fırlatır.
        """
        # ── 1. Nonce kontrolü — EARLY COMMIT: replay koruması transaction
        #    bağımsız çalışmalı, lisans doğrulamasından önce commit edilmeli
        if await self.nonce_repo.is_used(request.nonce):
            logger.warning("Replay attack tespit edildi", extra={"ip": ip_address})
            raise ValueError("Bu istek zaten işlendi (replay attack koruması)")

        await self.nonce_repo.mark_used(request.nonce)
        await self.db.commit()  # Replay koruması: nonce hemen kalıcı hale getir

        # ── 2. Lisans key doğrulama ───────────────────────────────────────────
        license_ = await self.license_repo.get_by_key(request.key)
        if not license_:
            await self._log(LogAction.AUTH_FAILED, ip_address=ip_address,
                            detail="Lisans bulunamadı")
            await self._dispatch_webhook("login_failed", {
                "key_partial": request.key[:8] + "...",
                "ip": ip_address,
                "reason": "License not found",
            })
            raise ValueError("Geçersiz lisans anahtarı")

        # ── 3. Lisans durum kontrolü ──────────────────────────────────────────
        if license_.status == LicenseStatus.SUSPENDED:
            await self._log(LogAction.AUTH_SUSPENDED, license_.id, ip_address,
                            detail="Askıya alınmış lisans")
            raise ValueError("Bu lisans askıya alınmış")

        if license_.status == LicenseStatus.REVOKED:
            await self._log(LogAction.AUTH_FAILED, license_.id, ip_address,
                            detail="İptal edilmiş lisans")
            raise ValueError("Bu lisans iptal edilmiş")

        if license_.status == LicenseStatus.BANNED:
            await self._log(LogAction.AUTH_FAILED, license_.id, ip_address,
                            detail="Yasaklanmış lisans")
            raise ValueError("Bu lisans yasaklanmış")

        if license_.status == LicenseStatus.LOCKED:
            await self._log(LogAction.AUTH_FAILED, license_.id, ip_address,
                            detail="Kilitli lisans (şüpheli aktivite)")
            raise ValueError("Bu lisans şüpheli aktivite nedeniyle kilitlendi")

        if license_.status == LicenseStatus.EXPIRED:
            await self._log(LogAction.AUTH_EXPIRED, license_.id, ip_address,
                            detail="Süresi dolmuş lisans")
            raise ValueError("Lisans süresi dolmuş")

        # Süresi geçmiş ama status güncellenmemişse kontrol et
        if (
            license_.expires_at
            and license_.expires_at < datetime.now(timezone.utc)
        ):
            await self.license_repo.update_status(license_.id, LicenseStatus.EXPIRED)
            await self._log(LogAction.AUTH_EXPIRED, license_.id, ip_address,
                            detail="Gerçek zamanlı süre kontrolü")
            raise ValueError("Lisans süresi dolmuş")

        # ── 4. HWID eşleştirme ────────────────────────────────────────────────
        hwid_hash = hash_hwid(request.hwid)

        if license_.status == LicenseStatus.ACTIVE and not license_.hwid_hash:
            # İlk aktivasyon — HWID bağla
            
            # Aktivasyon limiti kontrolü
            if license_.activation_count >= license_.max_activations:
                await self._log(
                    LogAction.ACTIVATION_LIMIT, license_.id, ip_address,
                    detail=f"Aktivasyon limiti aşıldı ({license_.max_activations})"
                )
                raise ValueError("Bu lisans için aktivasyon limiti dolmuş")
            
            expires_at = _calculate_expiry(license_.license_type)
            license_ = await self.license_repo.activate(
                license_, hwid_hash, expires_at
            )
            
            # Aktivasyon geçmişi kaydı
            await self.activation_repo.create(
                license_id=license_.id,
                action=ActivationAction.ACTIVATED,
                hwid_hash=hwid_hash,
                ip_address=ip_address,
                discord_id=request.discord_id,
            )
            
            # HWID first_seen / last_seen set
            now_utc = datetime.now(timezone.utc)
            license_.hwid_first_seen = now_utc
            license_.hwid_last_seen = now_utc
            if hasattr(request, 'hwid_components') and request.hwid_components:
                license_.hwid_components_hash = hash_hwid(request.hwid_components)
            await self.db.flush()

            logger.info(
                "Lisans ilk kez aktive edildi",
                extra={"license_id": str(license_.id), "ip": ip_address}
            )
        elif license_.hwid_hash and license_.hwid_hash != hwid_hash:
            # HWID uyuşmuyor
            await self._log(
                LogAction.HWID_MISMATCH, license_.id, ip_address,
                hwid_hash=hwid_hash,
                detail="HWID eşleşmedi"
            )
            # Webhook dispatch point — hwid_mismatch (wired in Task 3)
            await self._dispatch_webhook("hwid_mismatch", {
                "key_partial": license_.key[:8] + "...",
                "ip": ip_address,
                "expected_hwid_partial": license_.hwid_hash[:12] + "..." if license_.hwid_hash else None,
                "got_hwid_partial": hwid_hash[:12] + "...",
            })
            raise ValueError("Bu lisans farklı bir donanıma bağlı")

        # HWID last_seen güncelle (başarılı auth)
        if license_.hwid_hash and license_.hwid_hash == hwid_hash:
            license_.hwid_last_seen = datetime.now(timezone.utc)
            if hasattr(request, 'hwid_components') and request.hwid_components:
                new_components_hash = hash_hwid(request.hwid_components)
                if license_.hwid_components_hash and license_.hwid_components_hash != new_components_hash:
                    await self._log(
                        LogAction.SUSPICIOUS_ACTIVITY, license_.id, ip_address,
                        detail="HWID component hash değişikliği tespit edildi"
                    )
            await self.db.flush()

        # ── 4.5 Discord ID bağlama ─────────────────────────────────────────
        if not license_.discord_id:
            # İlk aktivasyonda Discord ID bağla
            await self.license_repo.bind_discord_id(license_.id, request.discord_id)
            logger.info(
                "Discord ID bağlandı",
                extra={"license_id": str(license_.id), "discord_id": request.discord_id}
            )
        elif license_.discord_id != request.discord_id:
            # Discord ID uyuşmuyor
            await self._log(
                LogAction.DISCORD_MISMATCH, license_.id, ip_address,
                detail=f"Discord ID eşleşmedi (beklenen: {license_.discord_id}, gelen: {request.discord_id})"
            )
            raise ValueError("Bu lisans farklı bir Discord hesabına bağlı")

        # ── 4.6 IP fingerprint (soft binding) ─────────────────────────────
        if ip_address:
            ip_hash = hash_hwid(ip_address)  # Reuse hash function for IP
            if not license_.ip_fingerprint:
                await self.license_repo.update_ip_fingerprint(license_.id, ip_hash)
            elif license_.ip_fingerprint != ip_hash:
                # Sadece log — engellemez
                await self._log(
                    LogAction.AUTH_SUCCESS, license_.id, ip_address,
                    detail="IP değişikliği tespit edildi (soft binding)"
                )

        # ── 5. Mevcut session'ları invalidate et (tek cihaz politikası)
        await self.session_repo.invalidate_all_for_license(license_.id)

        # ── 7. Session token oluştur ──────────────────────────────────────────
        session_token = secrets.token_urlsafe(48)
        session_expires = datetime.now(timezone.utc) + timedelta(
            hours=settings.session_token_expire_hours
        )

        await self.session_repo.create(
            license_id=license_.id,
            token=session_token,
            hwid_hash=hwid_hash,
            expires_at=session_expires,
            ip_address=ip_address,
        )

        # ── 7. Log kaydı ──────────────────────────────────────────────────────
        await self._log(
            LogAction.AUTH_SUCCESS, license_.id, ip_address,
            hwid_hash=hwid_hash,
            detail=f"Client v{request.version}"
        )

        await self.db.commit()

        # Webhook dispatch — login_success (non-blocking, wired in Task 3)
        await self._dispatch_webhook("login_success", {
            "key_partial": license_.key[:8] + "...",
            "ip": ip_address,
            "hwid_partial": hwid_hash[:12] + "...",
            "discord_id": request.discord_id,
        })

        logger.info(
            "Başarılı auth — önceki session'lar invalidate edildi",
            extra={"license_id": str(license_.id), "ip": ip_address}
        )

        # Include feature_flags in response
        import json as _json
        try:
            flags = _json.loads(license_.feature_flags) if license_.feature_flags else {}
        except (TypeError, _json.JSONDecodeError):
            flags = {}

        return AuthResponse(
            session_token=session_token,
            expires_at=session_expires,
            feature_flags=flags,
        )

    async def heartbeat(
        self,
        request: HeartbeatRequest,
        ip_address: Optional[str] = None,
    ) -> HeartbeatResponse:
        """
        Oturum yenileme.
        Token geçerliyse ve HWID eşleşiyorsa onaylar.
        """
        # ── Nonce kontrolü — EARLY COMMIT ─────────────────────────────────────
        if await self.nonce_repo.is_used(request.nonce):
            raise ValueError("Tekrar eden istek")

        await self.nonce_repo.mark_used(request.nonce)
        await self.db.commit()  # Replay koruması

        # ── Session doğrulama ─────────────────────────────────────────────────
        session = await self.session_repo.get_by_token(request.session_token)
        if not session:
            await self._log(LogAction.HEARTBEAT_FAIL, ip_address=ip_address,
                            detail="Session bulunamadı")
            return HeartbeatResponse(valid=False, message="Geçersiz session")

        # Session süresi kontrolü
        if session.expires_at < datetime.now(timezone.utc):
            await self.session_repo.invalidate(session.id)
            return HeartbeatResponse(valid=False, message="Session süresi doldu")

        # HWID kontrolü
        hwid_hash = hash_hwid(request.hwid)
        if session.hwid_hash != hwid_hash:
            await self._log(
                LogAction.HWID_MISMATCH,
                session.license_id, ip_address,
                hwid_hash=hwid_hash,
                detail="Heartbeat HWID uyuşmazlığı"
            )
            await self.session_repo.invalidate(session.id)
            return HeartbeatResponse(valid=False, message="HWID uyuşmazlığı")

        # Lisans hâlâ geçerli mi?
        license_ = await self.license_repo.get_by_id(session.license_id)
        if not license_ or license_.status in (
            LicenseStatus.SUSPENDED, LicenseStatus.REVOKED, LicenseStatus.EXPIRED,
            LicenseStatus.LOCKED
        ):
            await self.session_repo.invalidate(session.id)
            return HeartbeatResponse(valid=False, message="Lisans artık geçerli değil")

        # Heartbeat güncelle
        await self.session_repo.update_heartbeat(session.id, request.nonce)
        await self._log(
            LogAction.HEARTBEAT_OK, session.license_id, ip_address
        )
        await self.db.commit()

        return HeartbeatResponse(
            valid=True,
            expires_at=session.expires_at,
            message="OK"
        )

    async def _log(
        self,
        action: LogAction,
        license_id=None,
        ip_address: Optional[str] = None,
        hwid_hash: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        """İç log yardımcısı."""
        await self.log_repo.create(
            action=action,
            license_id=license_id,
            ip_address=ip_address,
            hwid_hash=hwid_hash,
            detail=detail,
        )

    async def _dispatch_webhook(
        self,
        event_type: str,
        data: dict,
    ) -> None:
        """
        Webhook dispatch stub — fires non-blocking webhook for given event.
        Actual dispatch is handled by WebhookService (wired in Task 3).
        Uses fire-and-forget to never block auth flow.
        """
        try:
            from app.services.webhook_service import WebhookService
            import asyncio
            asyncio.create_task(
                WebhookService.dispatch_event_static(event_type, data)
            )
        except Exception:
            pass  # Webhook dispatch must never break auth flow
