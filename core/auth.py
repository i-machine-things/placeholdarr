"""Single-admin dashboard auth: password login (session cookie) plus a
separate API key for the inbound /webhook endpoint.

Modeled on Sonarr/Radarr's own Authentication design (NzbDrone.Core.Authentication /
Sonarr.Http.Authentication): salted PBKDF2 password hashing, a forced
create-credentials step on first run, and a *separate* API-key scheme for
non-browser callers (their ApiKeyAuthenticationHandler) rather than making
webhook senders subject to the same cookie/session check as the browser UI.

Two independent secrets live in AppConfig (see services/app_config.py for the
established key/value row pattern):
  - AUTH_SESSION_SECRET: signs session cookies; rotated on every password change,
    which is what invalidates all other existing sessions.
  - AUTH_WEBHOOK_API_KEY: required as ?apikey= on POST /webhook; generated once
    at first credential setup and NOT rotated by password changes, since that
    would silently break every already-configured Radarr/Sonarr/Tautulli/Jellyfin
    webhook connection. Only an explicit "regenerate" action rotates it.

Deliberately not implemented (see the PR description for rationale): Sonarr's
"Authentication Required: Disabled for Local Addresses" IP-based bypass, and
brute-force throttling on /api/auth/login.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import time
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.responses import Response

from services.postgres.db import get_session
from services.postgres.models import AppConfig

SESSION_COOKIE_NAME = "placeholdarr_session"
SESSION_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days, matches Sonarr's ExpireTimeSpan default
MIN_PASSWORD_LENGTH = 8
PBKDF2_ITERATIONS = 210_000  # OWASP's current floor for PBKDF2-HMAC-SHA512
DEFAULT_USERNAME = "admin"

ADMIN_USERNAME_KEY = "AUTH_ADMIN_USERNAME"
ADMIN_PASSWORD_HASH_KEY = "AUTH_ADMIN_PASSWORD_HASH"
SESSION_SECRET_KEY = "AUTH_SESSION_SECRET"
WEBHOOK_API_KEY_KEY = "AUTH_WEBHOOK_API_KEY"


# ---------------------------------------------------------------------------
# Pure functions — no DB access. These are what tests/test_core_auth.py covers.
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha512${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo, iterations_s, salt_hex, expected_hex = str(stored_hash or "").split("$", 3)
        if algo != "pbkdf2_sha512":
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
    except (ValueError, AttributeError, binascii.Error):
        return False
    digest = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest.hex(), expected_hex)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def create_session_token(secret: str, *, now: float | None = None) -> str:
    issued_at = int(now if now is not None else time.time())
    nonce = secrets.token_hex(8)
    payload = f"{issued_at}.{nonce}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    return f"{_b64url_encode(payload)}.{_b64url_encode(sig)}"


def verify_session_token(
    token: str,
    secret: str,
    *,
    ttl_seconds: int = SESSION_TTL_SECONDS,
    now: float | None = None,
) -> bool:
    try:
        payload_part, sig_part = str(token or "").split(".", 1)
        payload = _b64url_decode(payload_part)
        sig = _b64url_decode(sig_part)
    except (ValueError, binascii.Error):
        return False

    expected_sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected_sig):
        return False

    try:
        issued_at_s, _nonce = payload.decode("ascii").split(".", 1)
        issued_at = int(issued_at_s)
    except (ValueError, UnicodeDecodeError):
        return False

    current = now if now is not None else time.time()
    return 0 <= (current - issued_at) <= ttl_seconds


def generate_webhook_api_key() -> str:
    return secrets.token_hex(20)  # 40 hex chars, matches a typical Radarr/Sonarr API key's shape


# ---------------------------------------------------------------------------
# DB-backed functions — mirror the get_session()/try-finally idiom used
# throughout services/app_config.py (not the less-common session_scope()).
# ---------------------------------------------------------------------------

def _get_row(session, key: str) -> AppConfig | None:
    return session.query(AppConfig).filter(AppConfig.key == key).first()


def _set_row(session, key: str, value: Any) -> None:
    row = _get_row(session, key)
    if row:
        row.value = value
    else:
        session.add(AppConfig(key=key, value=value, value_type="string"))


def is_password_set(session=None) -> bool:
    owns_session = session is None
    session = session or get_session()
    try:
        row = _get_row(session, ADMIN_PASSWORD_HASH_KEY)
        return bool(row and row.value)
    finally:
        if owns_session:
            session.close()


def get_session_secret(session=None) -> str | None:
    owns_session = session is None
    session = session or get_session()
    try:
        row = _get_row(session, SESSION_SECRET_KEY)
        return str(row.value) if row and row.value else None
    finally:
        if owns_session:
            session.close()


def get_admin_username(session=None) -> str:
    owns_session = session is None
    session = session or get_session()
    try:
        row = _get_row(session, ADMIN_USERNAME_KEY)
        return str(row.value) if row and row.value else DEFAULT_USERNAME
    finally:
        if owns_session:
            session.close()


def get_webhook_api_key(session=None) -> str | None:
    owns_session = session is None
    session = session or get_session()
    try:
        row = _get_row(session, WEBHOOK_API_KEY_KEY)
        return str(row.value) if row and row.value else None
    finally:
        if owns_session:
            session.close()


def set_credentials(username: str, new_password: str, session=None) -> None:
    """Create or update the admin username/password.

    Always mints a fresh session secret (invalidates every other existing
    session — the intended behavior both for first-time setup and for a
    deliberate password change). Only generates the webhook API key if one
    doesn't exist yet; a password change must never rotate it out from under
    already-configured Radarr/Sonarr/Tautulli/Jellyfin webhook connections.
    """
    clean_username = str(username or "").strip() or DEFAULT_USERNAME
    if len(new_password or "") < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

    owns_session = session is None
    session = session or get_session()
    try:
        _set_row(session, ADMIN_USERNAME_KEY, clean_username)
        _set_row(session, ADMIN_PASSWORD_HASH_KEY, hash_password(new_password))
        _set_row(session, SESSION_SECRET_KEY, secrets.token_hex(32))
        if not _get_row(session, WEBHOOK_API_KEY_KEY):
            _set_row(session, WEBHOOK_API_KEY_KEY, generate_webhook_api_key())
        session.commit()
    finally:
        if owns_session:
            session.close()


def regenerate_webhook_api_key(session=None) -> str:
    """Explicit Settings action — rotates the webhook key, breaking every
    existing webhook connection until URLs are re-pasted with the new key."""
    owns_session = session is None
    session = session or get_session()
    try:
        new_key = generate_webhook_api_key()
        _set_row(session, WEBHOOK_API_KEY_KEY, new_key)
        session.commit()
        return new_key
    finally:
        if owns_session:
            session.close()


def verify_admin_credentials(username: str, password: str, session=None) -> bool:
    owns_session = session is None
    session = session or get_session()
    try:
        password_row = _get_row(session, ADMIN_PASSWORD_HASH_KEY)
        if not password_row or not password_row.value:
            return False
        username_row = _get_row(session, ADMIN_USERNAME_KEY)
        expected_username = str(username_row.value) if username_row and username_row.value else DEFAULT_USERNAME
        username_ok = str(username or "").strip().lower() == expected_username.strip().lower()
        password_ok = verify_password(password or "", str(password_row.value))
        # Always run verify_password even on a username mismatch so response
        # timing doesn't leak which check failed.
        return username_ok and password_ok
    finally:
        if owns_session:
            session.close()


def verify_webhook_api_key(provided: str | None, session=None) -> bool:
    if not provided:
        return False
    owns_session = session is None
    session = session or get_session()
    try:
        stored = get_webhook_api_key(session=session)
        if not stored:
            return False
        return hmac.compare_digest(str(provided), stored)
    finally:
        if owns_session:
            session.close()


def is_request_authenticated(request: Request, session=None) -> bool:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return False
    owns_session = session is None
    session = session or get_session()
    try:
        secret = get_session_secret(session=session)
        if not secret:
            return False
        return verify_session_token(token, secret)
    finally:
        if owns_session:
            session.close()


def set_session_cookie(response: Response, token: str, *, persistent: bool) -> None:
    kwargs: dict[str, Any] = {
        "key": SESSION_COOKIE_NAME,
        "value": token,
        "httponly": True,
        "samesite": "lax",
        "secure": False,  # self-hosted, LAN-first, typically plain HTTP — see PR description
        "path": "/",
    }
    if persistent:
        kwargs["max_age"] = SESSION_TTL_SECONDS
    response.set_cookie(**kwargs)


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")


# ---------------------------------------------------------------------------
# Global cookie/session gate. /webhook is allowlisted here because it's
# authenticated by a completely separate scheme (2b in the plan) — the same
# architectural split Sonarr uses (AddCookie for the UI, a distinct
# AddApiKey scheme for API callers, neither depending on the other).
# ---------------------------------------------------------------------------

PUBLIC_EXACT_PATHS = frozenset(
    {
        "/",
        "/activity",
        "/library",
        "/calendar",
        "/errors",
        "/logs",
        "/settings",
        "/setup",
        "/dashboard-next",
        "/api/health",
        "/api/ready",
        "/api/auth/status",
        "/api/auth/setup",
        "/api/auth/login",
        "/api/auth/logout",
        "/webhook",
    }
)
PUBLIC_PREFIXES = (
    "/activity/",
    "/library/",
    "/settings/",
    "/setup/",
    "/dashboard-next/",
    "/assets/",
    "/overlay-examples/",
)


def _is_public_path(path: str) -> bool:
    return path in PUBLIC_EXACT_PATHS or any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)


async def auth_gate_middleware(request: Request, call_next):
    if _is_public_path(request.url.path):
        return await call_next(request)
    if is_request_authenticated(request):
        return await call_next(request)
    return JSONResponse({"ok": False, "message": "Authentication required"}, status_code=401)
