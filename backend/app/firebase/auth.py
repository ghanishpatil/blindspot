"""Firebase Authentication — backend token verification.

Trust boundary: the frontend authenticates with Firebase and sends the
resulting ID token as ``Authorization: Bearer <token>``. The backend verifies
that token with the Admin SDK and derives the user identity from the verified
claims.

A user ID supplied directly by the client is never trusted.

``AUTH_DISABLED=true`` short-circuits verification with a clearly-labelled demo
principal. It is refused when ``BLINDSPOT_ENV=production``, so the escape hatch
cannot be left on by accident in a deployed environment.

Full enforcement lands in Phase 2; the structure and the dependency contract
are established here.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import Settings, get_settings
from app.firebase.client import get_firebase
from app.models.base import BlindspotModel

logger = logging.getLogger(__name__)

DEMO_USER_ID = "demo-user"

# auto_error=False so a missing header produces our own message rather than a
# bare 403 from the security scheme.
bearer_scheme = HTTPBearer(auto_error=False, description="Firebase ID token")


class AuthenticatedUser(BlindspotModel):
    """Identity derived from a verified Firebase ID token."""

    uid: str
    email: str | None = None
    display_name: str | None = None
    email_verified: bool = False
    is_demo_principal: bool = False
    """True when auth was bypassed for local development."""

    @classmethod
    def demo(cls) -> AuthenticatedUser:
        return cls(
            uid=DEMO_USER_ID,
            email="demo@blindspot.local",
            display_name="Demo User (auth bypassed)",
            email_verified=False,
            is_demo_principal=True,
        )

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> AuthenticatedUser:
        uid = claims.get("uid") or claims.get("user_id") or claims.get("sub")
        if not uid:
            raise ValueError("Verified token contained no subject claim.")
        return cls(
            uid=str(uid),
            email=claims.get("email"),
            display_name=claims.get("name") or claims.get("displayName"),
            email_verified=bool(claims.get("email_verified", False)),
            is_demo_principal=False,
        )


def verify_id_token(token: str, settings: Settings | None = None) -> AuthenticatedUser:
    """Verify a Firebase ID token and return the identity it asserts.

    Raises:
        HTTPException: 503 when Firebase is unavailable, 401 when the token is
            missing, malformed, expired, revoked, or otherwise invalid.
    """
    settings = settings or get_settings()
    state = get_firebase(settings)

    if not state.available:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Authentication is unavailable because Firebase is not configured: "
                f"{state.reason}"
            ),
        )

    from firebase_admin import auth as fb_auth

    try:
        claims = fb_auth.verify_id_token(token, check_revoked=True)
    except Exception as exc:  # noqa: BLE001 - SDK raises several distinct types
        logger.info("Rejected ID token: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    try:
        return AuthenticatedUser.from_claims(claims)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing required claims.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ] = None,
    settings: Annotated[Settings, Depends(get_settings)] = None,  # type: ignore[assignment]
) -> AuthenticatedUser:
    """FastAPI dependency resolving the caller's verified identity."""
    settings = settings or get_settings()

    if settings.auth_bypass_allowed():
        logger.debug("AUTH_DISABLED is set; using the demo principal.")
        return AuthenticatedUser.demo()

    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token. Sign in and send a Firebase ID token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization scheme must be Bearer.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return verify_id_token(credentials.credentials, settings)


CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]
"""Dependency alias for protected routes."""
