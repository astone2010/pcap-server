from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.auth import (
    RateLimiter,
    check_device_trust,
    cleanup_expired_sessions,
    create_device_trust,
    create_session_token,
    delete_session,
    generate_qr_data_uri,
    generate_totp_secret,
    get_totp_uri,
    hash_password,
    needs_rehash,
    validate_session,
    verify_password,
    verify_totp,
)
from backend.capture import CaptureLimitExceeded, CaptureManager, InterfaceAlreadyCapturing
from backend.crypto import CryptoError
from backend.database import Database
from backend.models import (
    CaptureRename,
    CaptureRequest,
    CaptureStatus,
    ServerAuth,
    ServerInfo,
    UsernameRequest,
)
from backend.packet_parser import (
    ALLOWED_VIEW_FLAGS,
    DisplayFilterError,
    get_packet_detail,
    get_packet_list,
)
from backend.localnet import SELF_CAPTURE_EXPLANATION, describe_if_local
from backend.ssh_manager import SSHManager
from backend.vault import CaptureVault, StartupRefused

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SSH_KEYS_DIR = Path(os.environ.get("SSH_KEYS_DIR", "/app/ssh-keys"))
CAPTURES_DIR = Path(os.environ.get("CAPTURES_DIR", "/app/captures"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))

APP_VERSION = "0.1.0-dev.13"
REPO_URL = "https://github.com/darthrater78/pcap-server"

@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Shutdown only; there is no startup work to do here.

    capture_manager is built further down this module, so it is resolved when
    the app shuts down rather than captured now -- by then the module has
    finished importing. This replaced @app.on_event("shutdown"), which
    starlette 1.x removed.
    """
    yield
    await capture_manager.shutdown()


app = FastAPI(title="pcap-server", version=APP_VERSION, lifespan=_lifespan)

db = Database(DATA_DIR / "pcap-server.db")

# Fail closed: a missing or wrong key stops the app rather than silently storing
# captures in the clear. StartupRefused carries the exact remedy.
try:
    vault = CaptureVault(dict(os.environ), db, CAPTURES_DIR)
except StartupRefused as exc:
    logger.error("REFUSING TO START\n\n%s\n", exc)
    raise SystemExit(1) from exc

if vault.cryptor is not None:
    _migrated, _failed = vault.migrate_plaintext()
    if _failed:
        logger.error("%d capture(s) could not be encrypted; they remain plaintext", _failed)

ssh_manager = SSHManager(SSH_KEYS_DIR, db, DATA_DIR, vault=vault)

if vault.cryptor is not None:
    _migrated_keys, _failed_keys = ssh_manager.migrate_plaintext_keys()
    if _failed_keys:
        logger.error("%d SSH key(s) could not be encrypted; they remain plaintext", _failed_keys)

capture_manager = CaptureManager(ssh_manager, CAPTURES_DIR, db.get_setting_int, db, vault)
rate_limiter = RateLimiter(
    max_attempts=db.get_setting_int("rate_limit_max_attempts"),
    lockout_minutes=db.get_setting_int("rate_limit_lockout_minutes"),
)

# A restart must not leave anyone signed in. Sessions live in SQLite on a
# persistent volume, so without this they outlive the container that issued
# them -- including one restarted to apply a security change.
#
# This runs once per process, which is correct for the single uvicorn process
# the image starts. Running with --workers would wipe sessions once per worker
# as each boots, signing users out repeatedly; keep this app single-process, or
# move session state out of SQLite first.
_dropped_sessions = db.delete_all_sessions()
if _dropped_sessions:
    logger.info("invalidated %d session(s) carried over from a previous run", _dropped_sessions)


# --- auth helpers ---

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str = ""
    trust_device: bool = False


class RegisterRequest(BaseModel):
    username: str
    password: str


class TOTPSetupRequest(BaseModel):
    code: str


class SettingUpdate(BaseModel):
    key: str
    value: str


def _client_ip(request: Request) -> str:
    """The address the login rate limiter counts against.

    X-Forwarded-For is only consulted when a trusted proxy is configured. It is
    set by whatever spoke to us last, so an app reachable directly would let a
    caller invent a fresh address per request and never trip the limiter at all
    -- which is the whole brute-force protection gone.

    When it is consulted, the RIGHTMOST entry is used, not the leftmost. A proxy
    appends the peer it actually saw, so anything to the left of that may have
    been supplied by the client. This assumes a single trusted hop, which is the
    normal single-nginx deployment.
    """
    if _TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for", "")
        for candidate in reversed([p.strip() for p in forwarded.split(",") if p.strip()]):
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                continue
    return request.client.host if request.client else "unknown"


def get_session_user(request: Request) -> dict:
    """A live session, with the second factor not yet considered.

    Only TOTP enrolment depends on this: it is the one thing a half-enrolled
    account has to be able to reach. Everything else depends on
    get_current_user below.
    """
    token = request.cookies.get("session")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "not authenticated")
    user = validate_session(db, token)
    if not user:
        raise HTTPException(401, "session expired or invalid")
    return user


def get_current_user(user: dict = Depends(get_session_user)) -> dict:
    """Both factors, not just the first.

    TOTP used to be enforced by the frontend alone. A first login returns
    needs_totp_setup and the UI acts on it, but nothing on this side looked at
    totp_confirmed -- so a client that simply ignored the flag held a session
    backed by a password and nothing else, with the full API behind it. Putting
    the check on the dependency every route already uses means a new route
    cannot forget it, and the enrolment endpoints opt out visibly by depending
    on get_session_user instead.
    """
    if not user["totp_confirmed"]:
        raise HTTPException(403, {
            "code": "totp_setup_required",
            "reason": (
                "Two-factor authentication has not been set up on this account, so "
                "it is protected by a password alone."
            ),
            "remedy": (
                "Scan the enrolment code with an authenticator app and enter a current "
                "code to finish signing in."
            ),
        })
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if not user["is_admin"]:
        raise HTTPException(403, "admin only")
    return user


_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() in ("1", "true", "yes")

# X-Forwarded-Proto is set by whatever spoke to us last, so a client can send it
# too. It is only evidence of TLS when a proxy we trust is known to be in front
# and to overwrite it -- so trusting it is opt-in, not a default.
_TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "").lower() in ("1", "true", "yes")


def _is_secure_transport(request: Request) -> bool:
    """True only when the capture cannot be read off the wire in transit."""
    if request.url.scheme == "https":
        return True
    if _TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-proto", "")
        if forwarded.split(",")[0].strip().lower() == "https":
            return True
    # Loopback never leaves the machine, so there is no wire to read.
    host = (request.client.host if request.client else "") or ""
    return host in ("127.0.0.1", "::1", "localhost")


# Over plain HTTP the app is read-only. Anything that changes state, and
# anything that hands back capture contents in bulk, is refused: on an
# unencrypted connection those either cross the wire in the clear or let an
# observer replay them. Looking is allowed; changing and exporting are not.
#
# The exceptions are the endpoints without which the app cannot be used at all.
# Sign-in over HTTP is already unsafe and the banner says so loudly -- but
# refusing it too would leave no way in rather than a degraded way in.
_INSECURE_ALLOWED_PATHS = frozenset({
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/register",
    "/api/auth/totp/confirm",
})

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_HTTPS_REMEDY = (
    "Put pcap-server behind an HTTPS reverse proxy that can obtain and renew its "
    "own certificates (Caddy, Nginx Proxy Manager and Traefik all do this "
    "automatically; plain nginx needs certbot or similar alongside it), then set "
    "TRUST_PROXY_HEADERS=true so pcap-server recognises the proxy's TLS."
)


def _insecure_error(reason: str) -> HTTPException:
    """Structured so the UI can recognise this and explain it, not just show a 403."""
    return HTTPException(403, {
        "code": "https_required",
        "reason": reason,
        "remedy": _HTTPS_REMEDY,
    })


def _require_secure_transport(request: Request) -> None:
    if _is_secure_transport(request):
        return
    raise _insecure_error(
        "A capture routinely contains credentials in cleartext. Downloading it over "
        "an unencrypted connection would put the whole capture on the wire in the clear."
    )


# Defence in depth against injected script. Output escaping (escHtml) is the
# first line and is tested, but one missed escape in 38 innerHTML sites would be
# an XSS -- so the page is also constrained in what injected script could do.
#
# connect-src, img-src and form-action are the ones that matter for "diverting
# traffic from the page": they mean script running on this origin cannot send
# anything to another host -- not by fetch, not by loading an image URL, not by
# submitting a form. frame-ancestors stops the page being framed for clickjacking,
# and base-uri stops a injected <base> silently re-pointing every relative URL.
#
# script-src no longer needs 'unsafe-inline': every onclick/onchange attribute
# in the UI was moved to addEventListener (delegate()/initStaticHandlers() in
# app.js), so the only inline script left is the theme-flash-prevention
# snippet in index.html's <head>, which has to run before app.js is even
# loaded. That one is pinned by content hash instead -- a hash is legitimate
# CSP script-src source syntax alongside 'self' and nonces, not a bypass, and
# it means changing that snippet's content one character breaks the hash and
# the browser silently drops it. index.html documents how to recompute it.
#
# style-src keeps 'unsafe-inline': this UI still uses inline style="" for
# layout throughout, which is a separate, much larger change not attempted
# here.
_CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'sha256-Oo/SPLxOcyb+avwLL/t3VBebRknOuRMijJxJ7+/q8l8='",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",          # data: for the TOTP QR code
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
])

_SECURITY_HEADERS = {
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for header, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    # HSTS only where TLS is genuinely in use. Sending it over plain HTTP is
    # ignored by browsers, and sending it from a LAN deployment that later
    # cannot do TLS would lock users out of their own tool.
    if _is_secure_transport(request) and request.url.scheme == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


@app.middleware("http")
async def enforce_read_only_over_http(request: Request, call_next):
    """Read-only over plain HTTP: refuse anything that changes state."""
    if (
        request.method in _MUTATING_METHODS
        and request.url.path.startswith("/api/")
        and request.url.path not in _INSECURE_ALLOWED_PATHS
        and not _is_secure_transport(request)
    ):
        reason = (
            "Uploading a private key over an unencrypted connection would put the key "
            "itself on the wire, where anyone on the path could take a copy."
            if "ssh-keys" in request.url.path else
            "pcap-server is running over plain HTTP, so it is read-only: anything that "
            "changes configuration is refused, because the request would cross the network "
            "in the clear and could be read or replayed."
        )
        return JSONResponse(
            status_code=403,
            content={"detail": {
                "code": "https_required",
                "reason": reason,
                "remedy": _HTTPS_REMEDY,
            }},
        )
    return await call_next(request)


def _set_session_cookie(response: Response, token: str) -> None:
    max_age = db.get_setting_int("session_duration_hours") * 3600
    response.set_cookie(
        "session", token,
        # Strict, not Lax: nothing here is reached by cross-site navigation, so
        # the cookie never needs to ride one -- and Lax would still send it on a
        # top-level GET, which includes the capture download URL.
        httponly=True, samesite="strict", secure=_COOKIE_SECURE,
        max_age=max_age,
    )


# --- auth routes ---

@app.get("/api/auth/status")
async def auth_status(request: Request):
    has_users = db.user_count() > 0
    token = request.cookies.get("session")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    user = validate_session(db, token) if token else None
    return {
        "has_users": has_users,
        "cookie_secure": _COOKIE_SECURE,
        # The repo and its releases page are public; the exact running version
        # is not published to unauthenticated callers, since it tells anyone who
        # can reach the login page which build to match advisories against.
        "repo_url": REPO_URL,
        "releases_url": f"{REPO_URL}/releases",
        "secure_transport": _is_secure_transport(request),
        "read_only": not _is_secure_transport(request),
        "trust_proxy_headers": _TRUST_PROXY_HEADERS,
        "encryption": vault.status() if user else {
            "enabled": vault.enabled, "locked": vault.locked,
        },
        "version": APP_VERSION if user else "",
        "release_notes_url": f"{REPO_URL}/releases/tag/v{APP_VERSION}" if user else "",
        "authenticated": user is not None,
        "user": {
            "username": user["username"],
            "is_admin": bool(user["is_admin"]),
            "totp_confirmed": bool(user["totp_confirmed"]),
        } if user else None,
    }


@app.post("/api/auth/register")
async def register(req: RegisterRequest, response: Response):
    if db.user_count() > 0:
        raise HTTPException(403, "registration closed -- ask an admin to create your account")
    if len(req.username) < 3:
        raise HTTPException(400, "username must be at least 3 characters")
    if len(req.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    if db.get_user_by_username(req.username):
        raise HTTPException(409, "username taken")

    user_id = str(uuid.uuid4())
    pw_hash = await asyncio.to_thread(hash_password, req.password)
    db.create_user(user_id, req.username, pw_hash, is_admin=True)

    token, expires = create_session_token(db, user_id)
    _set_session_cookie(response, token)
    return {"ok": True, "user_id": user_id, "needs_totp_setup": True}


@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    client_ip = _client_ip(request)
    if rate_limiter.is_locked(client_ip):
        raise HTTPException(429, "too many failed attempts, try again later")

    user = db.get_user_by_username(req.username)
    password_ok = bool(user) and await asyncio.to_thread(
        verify_password, req.password, user["password_hash"]
    )
    if not password_ok:
        rate_limiter.record_failure(client_ip)
        raise HTTPException(401, "invalid credentials")

    if user["totp_confirmed"]:
        device_token = request.cookies.get("device_trust")
        device_trusted = check_device_trust(db, user["id"], device_token)
        if not device_trusted:
            if not req.totp_code:
                return {"needs_totp": True}
            if not verify_totp(user["totp_secret"], req.totp_code):
                rate_limiter.record_failure(client_ip)
                raise HTTPException(401, "invalid TOTP code")
            if req.trust_device:
                trust_days = db.get_setting_int("device_trust_days")
                trust_token = create_device_trust(db, user["id"])
                response.set_cookie(
                    "device_trust", trust_token,
                    httponly=True, samesite="strict", secure=_COOKIE_SECURE,
                    max_age=trust_days * 86400,
                )

    # The password is in hand and verified, so this is the only moment a hash
    # written under weaker parameters can be upgraded without asking the user
    # to change anything.
    if needs_rehash(user["password_hash"]):
        db.update_password_hash(
            user["id"], await asyncio.to_thread(hash_password, req.password)
        )
        logger.info("upgraded password hash cost for %s", user["username"])

    rate_limiter.reset(client_ip)
    token, expires = create_session_token(db, user["id"])
    _set_session_cookie(response, token)
    return {"ok": True, "needs_totp_setup": not user["totp_confirmed"]}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("session")
    if token:
        delete_session(db, token)
    response.delete_cookie("session")
    return {"ok": True}


@app.get("/api/auth/totp/setup")
async def totp_setup(user: dict = Depends(get_session_user)):
    if user["totp_confirmed"]:
        raise HTTPException(400, "TOTP already configured")
    secret = user.get("totp_secret")
    if not secret:
        secret = generate_totp_secret()
        db.set_totp_secret(user["id"], secret)
    uri = get_totp_uri(secret, user["username"])
    qr = generate_qr_data_uri(uri)
    return {"secret": secret, "uri": uri, "qr_data_uri": qr}


@app.post("/api/auth/totp/confirm")
async def totp_confirm(req: TOTPSetupRequest, user: dict = Depends(get_session_user)):
    if user["totp_confirmed"]:
        raise HTTPException(400, "TOTP already confirmed")
    secret = user.get("totp_secret")
    if not secret:
        raise HTTPException(400, "run TOTP setup first")
    if not verify_totp(secret, req.code):
        raise HTTPException(400, "invalid code -- scan the QR and enter the current code")
    db.confirm_totp(user["id"])
    return {"ok": True}


# --- admin: user management ---

@app.post("/api/admin/users")
async def admin_create_user(req: RegisterRequest, user: dict = Depends(require_admin)):
    if len(req.username) < 3:
        raise HTTPException(400, "username must be at least 3 characters")
    if len(req.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    if db.get_user_by_username(req.username):
        raise HTTPException(409, "username taken")
    user_id = str(uuid.uuid4())
    db.create_user(user_id, req.username, await asyncio.to_thread(hash_password, req.password))
    return {"ok": True, "user_id": user_id}


@app.get("/api/admin/users")
async def admin_list_users(user: dict = Depends(require_admin)):
    return db.list_users()


@app.delete("/api/admin/users/{target_user_id}")
async def admin_delete_user(target_user_id: str, user: dict = Depends(require_admin)):
    if target_user_id == user["id"]:
        raise HTTPException(400, "cannot delete yourself")
    if not db.delete_user(target_user_id):
        raise HTTPException(404, "user not found")
    return {"ok": True}


# --- admin: settings ---

@app.get("/api/admin/settings")
async def admin_get_settings(user: dict = Depends(require_admin)):
    return db.get_all_settings()


@app.put("/api/admin/settings")
async def admin_update_setting(req: SettingUpdate, user: dict = Depends(require_admin)):
    allowed_keys = set(Database.DEFAULTS.keys())
    if req.key not in allowed_keys:
        raise HTTPException(400, f"unknown setting: {req.key}")
    # Idle timeout treats 0 as "no idle expiry"; every other setting needs >= 1.
    minimum = 0 if req.key == "session_idle_timeout_minutes" else 1
    try:
        int_val = int(req.value)
        if int_val < minimum:
            raise ValueError
    except ValueError:
        raise HTTPException(
            400,
            "value must be 0 or a positive integer" if minimum == 0
            else "value must be a positive integer",
        )
    db.set_setting(req.key, req.value)
    if req.key in ("rate_limit_max_attempts", "rate_limit_lockout_minutes"):
        rate_limiter.update_config(
            db.get_setting_int("rate_limit_max_attempts"),
            db.get_setting_int("rate_limit_lockout_minutes"),
        )
    return {"ok": True}


# --- admin: encryption ---

class UnlockRequest(BaseModel):
    passphrase: str


@app.get("/api/admin/encryption")
async def admin_encryption_status(user: dict = Depends(require_admin)):
    return vault.status()


@app.post("/api/admin/encryption/unlock")
async def admin_encryption_unlock(req: UnlockRequest, user: dict = Depends(require_admin)):
    """Passphrase mode only: derive the key into memory for this process."""
    if not vault.locked:
        raise HTTPException(400, "encryption is not locked")
    try:
        await asyncio.to_thread(vault.unlock, req.passphrase)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    migrated, failed = vault.migrate_plaintext()
    return {"ok": True, "migrated": migrated, "failed": failed}


# --- admin: known hosts ---

@app.get("/api/admin/known-hosts")
async def admin_list_known_hosts(user: dict = Depends(require_admin)):
    return db.list_known_hosts()


def _endpoint_from_body(body: dict) -> tuple[str, int]:
    """The (hostname, port) pair both host-key endpoints take.

    Shared so the two cannot drift apart. A non-numeric port used to reach
    int() unguarded and surface as a 500; it is a bad request.
    """
    hostname = str(body.get("hostname", "")).strip()
    if not hostname or any(c in hostname for c in " ;|&$`\\\n\r"):
        raise HTTPException(400, "invalid hostname")
    try:
        port = int(body.get("port", 22))
    except (TypeError, ValueError):
        raise HTTPException(400, "invalid port")
    if not (1 <= port <= 65535):
        raise HTTPException(400, "invalid port")
    return hostname, port


@app.post("/api/admin/known-hosts/scan")
async def admin_scan_host(request: Request, user: dict = Depends(require_admin)):
    hostname, port = _endpoint_from_body(await request.json())
    keys = await ssh_manager.scan_host_keys(hostname, port, user["id"])
    if not keys:
        raise HTTPException(502, "no host keys found")
    return {"ok": True, "keys": keys}


@app.get("/api/admin/host-trust")
async def admin_host_trust(user: dict = Depends(require_admin)):
    """Every configured host and whether its keys are trusted.

    Driven by the servers that exist rather than a typed-in hostname: the
    endpoints worth trusting are exactly the ones something connects to, and
    an admin should not have to retype a host already configured.
    """
    known = db.list_known_hosts()
    by_endpoint: dict[tuple[str, int], list[dict]] = {}
    for entry in known:
        by_endpoint.setdefault((entry["hostname"], entry["port"]), []).append(entry)

    hosts = []
    for endpoint in db.list_server_endpoints():
        keys = by_endpoint.pop((endpoint["hostname"], endpoint["port"]), [])
        hosts.append({
            "hostname": endpoint["hostname"],
            "port": endpoint["port"],
            "labels": ", ".join(endpoint["labels"]),
            "configured": True,
            "key_types": sorted(k["key_type"] for k in keys),
            "added_at": min((k["added_at"] for k in keys), default=""),
        })
    # Keys for hosts no server points at any more -- still verified against, so
    # still worth showing and being able to drop.
    for (hostname, port), keys in sorted(by_endpoint.items()):
        hosts.append({
            "hostname": hostname,
            "port": port,
            "labels": "",
            "configured": False,
            "key_types": sorted(k["key_type"] for k in keys),
            "added_at": min(k["added_at"] for k in keys),
        })
    return hosts


@app.delete("/api/admin/known-hosts/{host_id}")
async def admin_delete_known_host(host_id: int, user: dict = Depends(require_admin)):
    if not db.delete_known_host(host_id):
        raise HTTPException(404, "known host not found")
    return {"ok": True}


@app.post("/api/admin/known-hosts/forget")
async def admin_forget_host(request: Request, user: dict = Depends(require_admin)):
    """Drop every key for one endpoint at once.

    Per-key removal reads as broken: the remaining keys still verify the host,
    and the next scan brings the removed one back with them.
    """
    hostname, port = _endpoint_from_body(await request.json())
    removed = db.forget_known_host(hostname, port)
    if not removed:
        raise HTTPException(404, "no stored keys for that host")
    return {"ok": True, "removed": removed}


# --- servers (persistent, per-user) ---
#
# These used to live in a module-level dict, which meant they were lost on every
# restart and were visible to every logged-in user. They are now rows scoped to
# the user who added them, and they last until that user deletes them.


def _server_from_row(row: dict) -> ServerInfo:
    return ServerInfo(
        id=row["id"],
        name=row["name"],
        hostname=row["hostname"],
        port=row["port"],
        username=row["username"],
        ssh_key_name=row["ssh_key_name"],
        use_sudo=bool(row["use_sudo"]),
        tcpdump_path=row["tcpdump_path"] if "tcpdump_path" in row.keys() else "",
        added_at=datetime.fromisoformat(row["added_at"]),
    )


def _require_server(server_id: str, user_id: str) -> ServerInfo:
    row = db.get_active_server(server_id, user_id)
    if not row:
        raise HTTPException(404, "server not found")
    return _server_from_row(row)


async def _reject_self_target(hostname: str) -> None:
    """A capture target must not be the machine pcap-server runs on.

    Resolution can block on DNS, so it runs off the event loop.
    """
    finding = await asyncio.to_thread(describe_if_local, hostname)
    if finding:
        raise HTTPException(400, {
            "code": "self_capture",
            "reason": f"This server cannot be added: {finding}.",
            "explanation": SELF_CAPTURE_EXPLANATION,
        })


def _require_key(ssh_key_name: str) -> None:
    key_path = (SSH_KEYS_DIR / ssh_key_name).resolve()
    if not str(key_path).startswith(str(SSH_KEYS_DIR.resolve())):
        raise HTTPException(400, "invalid key path")
    if not key_path.exists():
        raise HTTPException(400, f"SSH key '{ssh_key_name}' not found in keys directory")


@app.get("/api/servers")
async def list_servers(user: dict = Depends(get_current_user)):
    return [_server_from_row(row) for row in db.list_active_servers(user["id"])]


@app.post("/api/servers")
async def add_server(auth: ServerAuth, user: dict = Depends(get_current_user)):
    await _reject_self_target(auth.hostname)
    _require_key(auth.ssh_key_name)
    info = ServerInfo(**auth.model_dump())
    db.add_active_server(
        info.id, user["id"], info.name, info.hostname, info.port,
        info.username, info.ssh_key_name, info.use_sudo,
    )
    return info


@app.delete("/api/servers/{server_id}")
async def remove_server(server_id: str, user: dict = Depends(get_current_user)):
    if not db.delete_active_server(server_id, user["id"]):
        raise HTTPException(404, "server not found")
    return {"ok": True}


@app.get("/api/servers/{server_id}/interfaces")
async def list_server_interfaces(server_id: str, user: dict = Depends(get_current_user)):
    srv = _require_server(server_id, user["id"])
    try:
        return {"interfaces": await ssh_manager.list_interfaces(srv)}
    except ConnectionError as exc:
        raise HTTPException(502, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/servers/{server_id}/prereq-check")
async def prereq_check(server_id: str, user: dict = Depends(get_current_user)):
    """Read-only capability probe against the target host.

    Nothing is installed and nothing is elevated beyond `sudo -n true`. The one
    side effect is local: a validated tcpdump path is recorded against the
    server so captures can invoke it by absolute path.
    """
    srv = _require_server(server_id, user["id"])
    try:
        result = await ssh_manager.check_prerequisites(srv)
    except ConnectionError as exc:
        raise HTTPException(502, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        logger.exception("prerequisite check failed for %s", server_id)
        raise HTTPException(502, "prerequisite check failed")

    discovered = result.get("tcpdump_path", "")
    if discovered and discovered != srv.tcpdump_path:
        # Re-validate before persisting: this value came off the remote host.
        try:
            ServerAuth(hostname=srv.hostname, username=srv.username,
                       ssh_key_name=srv.ssh_key_name, tcpdump_path=discovered)
        except Exception:
            logger.warning("discarding implausible tcpdump path from %s", srv.hostname)
            discovered = ""
        if discovered:
            db.set_active_server_tcpdump_path(server_id, user["id"], discovered)
    return {
        "checks": result["checks"],
        "tcpdump_path": discovered or srv.tcpdump_path,
        "os": result["facts"]["os_release"].get("PRETTY_NAME", ""),
    }


@app.post("/api/servers/{server_id}/test")
async def test_server(server_id: str, user: dict = Depends(get_current_user)):
    srv = _require_server(server_id, user["id"])
    try:
        result = await ssh_manager.test_connection(srv)
        return {"ok": True, **result}
    except ConnectionError as exc:
        raise HTTPException(502, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(502, "connection failed")


@app.put("/api/servers/{server_id}")
async def update_server(server_id: str, auth: ServerAuth, user: dict = Depends(get_current_user)):
    # Checked on edit too: otherwise a benign server could be repointed at the host.
    await _reject_self_target(auth.hostname)
    _require_key(auth.ssh_key_name)
    updated = db.update_active_server(
        server_id, user["id"], auth.name, auth.hostname, auth.port,
        auth.username, auth.ssh_key_name, auth.use_sudo,
    )
    if not updated:
        raise HTTPException(404, "server not found")
    return _server_from_row(db.get_active_server(server_id, user["id"]))


# --- stored SSH usernames ---
#
# Per-user, like the servers they are offered to. The management screen sits in
# the Admin panel, so a non-admin gets the picker and the automatic recording
# but cannot prune the list.

@app.get("/api/usernames")
async def list_usernames(user: dict = Depends(get_current_user)):
    """Stored SSH usernames, so the server forms can offer them back."""
    return db.list_usernames(user["id"])


@app.post("/api/usernames")
async def add_username(req: UsernameRequest, user: dict = Depends(get_current_user)):
    db.remember_username(user["id"], req.username)
    return db.list_usernames(user["id"])


@app.put("/api/usernames/{username_id}")
async def rename_username(
    username_id: str,
    req: UsernameRequest,
    user: dict = Depends(get_current_user),
):
    try:
        renamed = db.rename_username(user["id"], username_id, req.username)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    if not renamed:
        raise HTTPException(404, "username not found")
    return db.list_usernames(user["id"])


@app.delete("/api/usernames/{username_id}")
async def delete_username(username_id: str, user: dict = Depends(get_current_user)):
    """Removes the suggestion only. Servers already configured with this name
    keep working -- the list is what the forms offer, not a reference they hold."""
    if not db.delete_username(user["id"], username_id):
        raise HTTPException(404, "username not found")
    return {"ok": True}


# --- ad-hoc probes ---
#
# Same two checks as the per-server endpoints, but against details typed into
# the add form rather than a stored row: a server that cannot be reached should
# be discovered before it is saved, not after.

@app.post("/api/probe/test")
async def probe_test(auth: ServerAuth, user: dict = Depends(get_current_user)):
    await _reject_self_target(auth.hostname)
    _require_key(auth.ssh_key_name)
    try:
        result = await ssh_manager.test_connection(auth)
        return {"ok": True, **result}
    except ConnectionError as exc:
        raise HTTPException(502, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(502, "connection failed")


@app.post("/api/probe/prereq-check")
async def probe_prereq_check(auth: ServerAuth, user: dict = Depends(get_current_user)):
    await _reject_self_target(auth.hostname)
    _require_key(auth.ssh_key_name)
    try:
        result = await ssh_manager.check_prerequisites(auth)
    except ConnectionError as exc:
        raise HTTPException(502, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        logger.exception("prerequisite check failed for %s", auth.hostname)
        raise HTTPException(502, "prerequisite check failed")

    # Nothing is stored: there is no server row to attach a path to yet. The
    # path is returned so the check that runs after saving can confirm it.
    discovered = result.get("tcpdump_path", "")
    if discovered:
        try:
            ServerAuth(hostname=auth.hostname, username=auth.username,
                       ssh_key_name=auth.ssh_key_name, tcpdump_path=discovered)
        except Exception:
            logger.warning("discarding implausible tcpdump path from %s", auth.hostname)
            discovered = ""
    return {
        "checks": result["checks"],
        "tcpdump_path": discovered,
        "os": result["facts"]["os_release"].get("PRETTY_NAME", ""),
    }


# --- ssh keys ---

@app.get("/api/ssh-keys")
async def list_ssh_keys(user: dict = Depends(get_current_user)):
    SSH_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    keys = []
    for f in SSH_KEYS_DIR.iterdir():
        if f.is_file() and f.name != ".gitkeep":
            keys.append(f.name)
    return sorted(keys)


@app.post("/api/admin/ssh-keys")
async def upload_ssh_key(file: UploadFile, user: dict = Depends(require_admin)):
    import re
    name = file.filename or ""
    if not name or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise HTTPException(400, "invalid key name — use only letters, digits, dots, dashes, underscores")
    if len(name) > 255:
        raise HTTPException(400, "filename too long")
    dest = (SSH_KEYS_DIR / name).resolve()
    if not str(dest).startswith(str(SSH_KEYS_DIR.resolve())):
        raise HTTPException(400, "invalid key path")
    if dest.exists():
        raise HTTPException(409, f"key '{name}' already exists")
    content = await file.read()
    if len(content) > 64 * 1024:
        raise HTTPException(400, "key file too large (max 64 KB)")
    SSH_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    # Sealed before it ever touches disk when a master key is configured --
    # same as captures, an uploaded private key never exists as a plaintext
    # file on the volume.
    dest.write_bytes(vault.cryptor.seal_bytes(content) if vault.cryptor else content)
    dest.chmod(0o600)
    return {"ok": True, "name": name}


@app.delete("/api/admin/ssh-keys/{key_name}")
async def delete_ssh_key(key_name: str, user: dict = Depends(require_admin)):
    import re
    if not re.fullmatch(r"[A-Za-z0-9._-]+", key_name):
        raise HTTPException(400, "invalid key name")
    path = (SSH_KEYS_DIR / key_name).resolve()
    if not str(path).startswith(str(SSH_KEYS_DIR.resolve())):
        raise HTTPException(400, "invalid key path")
    if not path.exists():
        raise HTTPException(404, "key not found")
    path.unlink()
    return {"ok": True}


# --- captures ---

@app.get("/api/captures")
async def list_captures(user: dict = Depends(get_current_user)):
    return capture_manager.list_for_user(user["id"])


@app.post("/api/captures")
async def start_capture(req: CaptureRequest, user: dict = Depends(get_current_user)):
    srv = _require_server(req.server_id, user["id"])
    try:
        info = await capture_manager.start(req, srv, user["id"])
        return info
    except CaptureLimitExceeded as exc:
        raise HTTPException(429, str(exc))
    except InterfaceAlreadyCapturing as exc:
        # 409, not 429: this is a conflict over one link that waiting will not
        # clear, so retrying the same request is not the remedy.
        raise HTTPException(409, str(exc))
    except Exception:
        logger.exception("failed to start capture")
        raise HTTPException(500, "failed to start capture")


@app.post("/api/captures/{capture_id}/stop")
async def stop_capture(capture_id: str, user: dict = Depends(get_current_user)):
    info = capture_manager.get(capture_id)
    if not info or info.user_id != user["id"]:
        raise HTTPException(404, "capture not found")
    try:
        return await capture_manager.stop(capture_id)
    except KeyError:
        raise HTTPException(404, "capture not found")


@app.post("/api/captures/{capture_id}/rename")
async def rename_capture(
    capture_id: str,
    body: CaptureRename,
    user: dict = Depends(get_current_user),
):
    """Give a capture a label. Allowed in any state, including while running."""
    info = capture_manager.get(capture_id)
    if not info or info.user_id != user["id"]:
        raise HTTPException(404, "capture not found")
    return capture_manager.rename(capture_id, body.name)


@app.delete("/api/captures/{capture_id}")
async def delete_capture(capture_id: str, user: dict = Depends(get_current_user)):
    info = capture_manager.get(capture_id)
    if not info or info.user_id != user["id"]:
        raise HTTPException(404, "capture not found")
    await capture_manager.delete(capture_id)
    return {"ok": True}


@app.get("/api/captures/{capture_id}")
async def get_capture(capture_id: str, user: dict = Depends(get_current_user)):
    info = capture_manager.get(capture_id)
    if not info or info.user_id != user["id"]:
        raise HTTPException(404, "capture not found")
    return info


@app.get("/api/captures/{capture_id}/download")
async def download_capture(capture_id: str, request: Request, user: dict = Depends(get_current_user)):
    # Encrypting at rest and then handing the plaintext to a cleartext socket
    # would defeat the point of the storage work entirely.
    _require_secure_transport(request)
    info = capture_manager.get(capture_id)
    if not info or info.user_id != user["id"]:
        raise HTTPException(404, "capture not found")
    if info.status != CaptureStatus.COMPLETED:
        raise HTTPException(400, "capture not yet completed")
    path = Path(info.local_path)
    if not path.exists():
        raise HTTPException(404, "pcap file not found on disk")

    try:
        source = vault.source_for(path)
    except CryptoError as exc:
        raise HTTPException(503, str(exc))

    async def body():
        """Decrypt into the response. No plaintext copy is written to serve it."""
        try:
            async for chunk in source.chunks():
                yield chunk
        except CryptoError:
            logger.exception("capture %s failed to decrypt during download", capture_id)
            # The response has already begun, so the only honest signal left is
            # to cut it off rather than hand over a truncated capture that looks whole.
            raise

    return StreamingResponse(
        body(),
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="{capture_id}.pcap"'},
    )


# --- packets ---

@app.get("/api/captures/{capture_id}/packets")
async def list_packets(
    capture_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=5000),
    display_filter: str = Query(""),
    flags: str = Query(""),
    resolve_names: bool = Query(False),
    user: dict = Depends(get_current_user),
):
    view_flags = [f for f in flags.split(",") if f]
    unknown = set(view_flags) - ALLOWED_VIEW_FLAGS
    if unknown:
        raise HTTPException(400, f"unknown view flags: {sorted(unknown)}")
    info = capture_manager.get(capture_id)
    if not info or info.user_id != user["id"]:
        raise HTTPException(404, "capture not found")
    if info.status != CaptureStatus.COMPLETED:
        raise HTTPException(400, "capture not yet completed")
    path = Path(info.local_path)
    if not path.exists():
        raise HTTPException(404, "pcap file missing")
    try:
        packets = await get_packet_list(
            vault.source_for(path), offset=offset, limit=limit,
            display_filter=display_filter, view_flags=view_flags,
            resolve_names=resolve_names,
        )
        return {"packets": packets, "total": info.packet_count}
    except DisplayFilterError as exc:
        # The filter is wrong, not the capture. Structured so the UI can put the
        # message under the filter box instead of blanking the packet list.
        raise HTTPException(400, {"code": "bad_display_filter", "reason": str(exc)})
    except Exception:
        logger.exception("packet list failed")
        raise HTTPException(500, "failed to list packets")


@app.get("/api/captures/{capture_id}/packets/{frame_number}")
async def packet_detail(capture_id: str, frame_number: int, user: dict = Depends(get_current_user)):
    info = capture_manager.get(capture_id)
    if not info or info.user_id != user["id"]:
        raise HTTPException(404, "capture not found")
    if info.status != CaptureStatus.COMPLETED:
        raise HTTPException(400, "capture not yet completed")
    path = Path(info.local_path)
    if not path.exists():
        raise HTTPException(404, "pcap file missing")
    try:
        return await get_packet_detail(vault.source_for(path), frame_number)
    except Exception:
        raise HTTPException(500, "failed to get packet detail")


# --- static files (frontend) ---

frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
