"""
CSRF token endpoint.
Panel gibi browser-based client'lar için CSRF token sağlar.
"""
from fastapi import APIRouter, Response

from app.core.security import generate_csrf_token

router = APIRouter(prefix="/api/v1", tags=["CSRF"])


@router.get("/csrf-token", summary="CSRF token al")
async def get_csrf_token(response: Response) -> dict:
    """
    CSRF token oluşturur.
    Token hem cookie olarak set edilir hem de response body'de döner.
    Client, state-changing isteklerde (POST/PUT/DELETE) bu token'ı
    X-CSRF-Token header'ında göndermelidir.
    """
    token = await generate_csrf_token()
    
    # Set as non-HttpOnly cookie (JS needs to read it for double-submit pattern)
    response.set_cookie(
        key="csrf_token",
        value=token,
        httponly=False,  # JS needs to read this
        samesite="strict",
        secure=True,
        max_age=3600,
        path="/",
    )
    
    return {"csrf_token": token}
