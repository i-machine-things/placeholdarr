from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.auth import (
    DEFAULT_USERNAME,
    clear_session_cookie,
    create_session_token,
    get_admin_username,
    get_session_secret,
    get_webhook_api_key,
    is_password_set,
    is_request_authenticated,
    regenerate_webhook_api_key,
    set_credentials,
    set_session_cookie,
    verify_admin_credentials,
)
from services.postgres.db import get_session

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/status")
async def auth_status(request: Request):
    session = get_session()
    try:
        password_set = is_password_set(session=session)
        username = get_admin_username(session=session) if password_set else None
        authenticated = is_request_authenticated(request, session=session) if password_set else False
        return JSONResponse(
            {"password_set": password_set, "authenticated": authenticated, "username": username}
        )
    finally:
        session.close()


@router.post("/setup")
async def auth_setup(request: Request):
    payload = await request.json()
    username = str((payload or {}).get("username") or "").strip() or DEFAULT_USERNAME
    password = str((payload or {}).get("password") or "")

    session = get_session()
    try:
        if is_password_set(session=session):
            return JSONResponse({"ok": False, "message": "Password already set"}, status_code=409)

        try:
            set_credentials(username, password, session=session)
        except ValueError as exc:
            return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)

        secret = get_session_secret(session=session)
        token = create_session_token(secret)
        response = JSONResponse({"ok": True})
        set_session_cookie(response, token, persistent=True)
        return response
    finally:
        session.close()


@router.post("/login")
async def auth_login(request: Request):
    payload = await request.json()
    username = str((payload or {}).get("username") or "")
    password = str((payload or {}).get("password") or "")
    remember_me = bool((payload or {}).get("remember_me", True))

    session = get_session()
    try:
        if not is_password_set(session=session):
            return JSONResponse({"ok": False, "message": "No password has been set yet"}, status_code=409)

        if not verify_admin_credentials(username, password, session=session):
            return JSONResponse({"ok": False, "message": "Invalid username or password"}, status_code=401)

        secret = get_session_secret(session=session)
        token = create_session_token(secret)
        response = JSONResponse({"ok": True})
        set_session_cookie(response, token, persistent=remember_me)
        return response
    finally:
        session.close()


@router.post("/logout")
async def auth_logout():
    response = JSONResponse({"ok": True})
    clear_session_cookie(response)
    return response


@router.post("/change-password")
async def auth_change_password(request: Request):
    # Not in the public allowlist, so auth_gate_middleware has already
    # rejected unauthenticated callers before this handler runs.
    payload = await request.json()
    current_password = str((payload or {}).get("current_password") or "")
    new_password = str((payload or {}).get("new_password") or "")
    new_username = str((payload or {}).get("new_username") or "").strip()

    session = get_session()
    try:
        current_username = get_admin_username(session=session)
        if not verify_admin_credentials(current_username, current_password, session=session):
            return JSONResponse({"ok": False, "message": "Current password is incorrect"}, status_code=401)

        try:
            set_credentials(new_username or current_username, new_password, session=session)
        except ValueError as exc:
            return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)

        # set_credentials rotated the session secret, invalidating every
        # existing session including this caller's — re-issue immediately so
        # changing your own password doesn't log you out.
        secret = get_session_secret(session=session)
        token = create_session_token(secret)
        response = JSONResponse({"ok": True})
        set_session_cookie(response, token, persistent=True)
        return response
    finally:
        session.close()


@router.get("/webhook-key")
async def auth_webhook_key():
    # Not in the public allowlist — session-protected.
    session = get_session()
    try:
        return JSONResponse({"webhook_api_key": get_webhook_api_key(session=session)})
    finally:
        session.close()


@router.post("/webhook-key/regenerate")
async def auth_webhook_key_regenerate():
    # Not in the public allowlist — session-protected. Rotating this breaks
    # every already-configured Radarr/Sonarr/Tautulli/Jellyfin webhook until
    # the URLs are re-pasted with the new key — the frontend action that
    # calls this must warn before doing so.
    session = get_session()
    try:
        new_key = regenerate_webhook_api_key(session=session)
        return JSONResponse({"webhook_api_key": new_key})
    finally:
        session.close()
