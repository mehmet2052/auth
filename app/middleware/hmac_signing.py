"""
HMAC Request Signing Middleware — Dual auth mode support.

Auth modes:
- "legacy" (or header absent): Validate X-Nexus-Secret header (current behavior)
- "secure": Validate HMAC-SHA256 signature + timestamp

Applied only to client auth endpoints (/api/v1/auth, /api/v1/heartbeat).
"""
import hashlib
import hmac
import time
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import get_settings
from app.core.logging import logger

settings = get_settings()

# Endpoints that require auth mode validation
_CLIENT_AUTH_PREFIXES = ("/api/v1/auth", "/api/v1/heartbeat")


def _get_auth_mode(request: Request) -> str:
    """Determine auth mode from X-Nexus-Auth-Mode header."""
    mode = request.headers.get("X-Nexus-Auth-Mode", "").lower().strip()
    if mode == "secure":
        return "secure"
    if mode == "legacy" or not mode:
        return "legacy"
    return "unknown"


def _validate_legacy(request: Request) -> Optional[JSONResponse]:
    """Validate legacy API secret header."""
    secret = request.headers.get(settings.api_secret_header, "")
    if secret != settings.api_secret_value:
        return JSONResponse(
            status_code=403,
            content={"error": "Geçersiz API secret", "success": False},
        )
    return None


async def _validate_secure(request: Request) -> Optional[JSONResponse]:
    """Validate HMAC-SHA256 signature + timestamp."""
    timestamp_str = request.headers.get("X-Nexus-Timestamp", "")
    signature = request.headers.get("X-Nexus-Signature", "")

    if not timestamp_str or not signature:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Missing X-Nexus-Timestamp or X-Nexus-Signature headers",
                "success": False,
            },
        )

    # Parse timestamp
    try:
        timestamp = int(timestamp_str)
    except (ValueError, TypeError):
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid timestamp format", "success": False},
        )

    # Check timestamp tolerance
    tolerance = getattr(settings, 'hmac_timestamp_tolerance_seconds', 30)
    now = int(time.time())
    if abs(now - timestamp) > tolerance:
        return JSONResponse(
            status_code=401,
            content={
                "error": f"Request timestamp expired (tolerance: {tolerance}s)",
                "success": False,
            },
        )

    # Read request body
    body = await request.body()

    # Compute expected signature
    payload = f"{timestamp_str}:".encode() + body
    expected_sig = hmac.new(
        settings.api_secret_value.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    expected_header = f"sha256={expected_sig}"

    # Constant-time comparison
    if not hmac.compare_digest(signature, expected_header):
        return JSONResponse(
            status_code=403,
            content={"error": "Invalid HMAC signature", "success": False},
        )

    return None


class HMACSigningMiddleware(BaseHTTPMiddleware):
    """
    Dual auth mode middleware for client endpoints.
    Negotiates between legacy (API secret) and secure (HMAC) modes.
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Only apply to client auth endpoints
        if not any(path.startswith(p) for p in _CLIENT_AUTH_PREFIXES):
            return await call_next(request)

        # Skip for OPTIONS (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        auth_mode = _get_auth_mode(request)

        # Check mode validity
        if auth_mode == "unknown":
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Unknown auth mode. Use 'legacy' or 'secure'.",
                    "success": False,
                },
            )

        # Check if mode is enabled
        if auth_mode == "legacy":
            if not getattr(settings, 'auth_mode_legacy_enabled', True):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Legacy auth mode is deprecated. Use X-Nexus-Auth-Mode: secure",
                        "success": False,
                    },
                )
            error_response = _validate_legacy(request)
            if error_response:
                return error_response

        elif auth_mode == "secure":
            if not getattr(settings, 'auth_mode_secure_enabled', True):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Secure auth mode is not enabled.",
                        "success": False,
                    },
                )
            error_response = await _validate_secure(request)
            if error_response:
                return error_response

        return await call_next(request)
