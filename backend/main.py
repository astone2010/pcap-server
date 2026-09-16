from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.auth import (
    RateLimiter,
    SlidingWindowLimiter,
    check_device_trust,
    cleanup_expired_sessions,
    create_device_trust,
    create_session_token,
    delete_session,
    generate_qr_data_uri,
    generate_totp_secret,
    get_totp_uri,
    hash_password_async,
    needs_rehash,
    validate_session,
    verify_absent_user_async,
    verify_password_async,
    verify_totp,
)
from backend.capture import (
    CaptureLimitExceeded,
    CaptureManager,
    InterfaceAlreadyCapturing,
)
from backend.bpf import check_filter
from backend.crypto import CryptoError
from backend.database import Database
from backend.models import (
    ANY_INTERFACE,
    BPF_FORBIDDEN_CHARS,
    CaptureRename,
    CaptureRequest,
    CaptureStatus,
    CaptureView,
    CaptureViewRequest,
    ColumnLayout,
    CustomFilter,
    CustomFilterRequest,
    DEFAULT_PACKET_COLUMNS,
    DisplayFilterRequest,
    KnownHostConfirm,
    KnownHostEndpoint,
    PastedPrivateKey,
    ServerAuth,
    ServerCreate,
    ServerInfo,
    ServerProbe,
    UsernameRequest,
)
from backend.packet_parser import (
    ALLOWED_VIEW_FLAGS,
    ColumnFieldError,
    DisplayFilterError,
    MAX_EXTRA_COLUMNS,
    get_conversations,
    get_follow_stream,
    get_packet_detail,
    get_packet_list,
    get_protocol_hierarchy,
    stream_filtered_pcap,
    unknown_packet_fields,
    validate_column_fields,
)
from backend.localnet import (
    SELF_CAPTURE_EXPLANATION,
    SelfCaptureRefused,
    describe_if_local,
    describe_if_same_kernel,
)
from backend.sanitizer import (
    FilteredSource,
    SanitizeError,
    SanitizeOptions,
    SanitizeSummary,
    capture_key,
    check_capture,
    stream_sanitized_pcap,
)
from backend.ssh_manager import (
    HostNotTrusted,
    PrivateKeyRejected,
    SSHManager,
    host_key_fingerprint,
    normalise_private_key,
    resolve_key_path,
)
from backend.tls import INSECURE_ALLOWED_PATHS as TLS_INSECURE_ALLOWED_PATHS
from backend.tls import TlsManager, build_router as build_tls_router
from backend.vault import CaptureVault, StartupRefused

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SSH_KEYS_DIR = Path(os.environ.get("SSH_KEYS_DIR", "/app/ssh-keys"))
CAPTURES_DIR = Path(os.environ.get("CAPTURES_DIR", "/app/captures"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))

APP_VERSION = "0.1.0-dev.38"
REPO_URL = "https://github.com/darthrater78/pcap-server"

# Expired rows and aged-out limiter keys are rejected wherever they are read,
# so nothing is ever *served* from them -- but nothing deleted them either.
# cleanup_expired_sessions was imported and never called, and the two limiters
# only ever pruned the one key they were asked about, so a long-running
# container accumulated dead session rows, dead trusted-device rows, and a
# limiter entry per client address seen since boot. Hourly is far more often
# than any of them needs.
_HOUSEKEEPING_INTERVAL_SECONDS = 3600


async def _housekeeping() -> None:
    while True:
        await asyncio.sleep(_HOUSEKEEPING_INTERVAL_SECONDS)
        try:
            sessions = cleanup_expired_sessions(db)
            devices = db.cleanup_expired_devices()
            rate_limiter.prune()
            packet_rate_limiter.prune()
            capture_start_rate_limiter.prune()
            filter_check_rate_limiter.prune()
            host_scan_rate_limiter.prune()
            # Renews under 30 days left, and picks up a certificate renewed from
            # the CLI. lego can take minutes, so it runs off the event loop.
            await asyncio.to_thread(tls_manager.maybe_renew)
            if sessions or devices:
                logger.info(
                    "housekeeping: removed %d expired session(s), %d expired device(s)",
                    sessions, devices,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            # Housekeeping failing is not a reason to take the app down with
            # it; the next pass will try again in an hour.
            logger.warning("housekeeping pass failed", exc_info=True)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Start the housekeeping sweep, and shut the capture manager down.

    capture_manager is built further down this module, so it is resolved when
    the app shuts down rather than captured now -- by then the module has
    finished importing. This replaced @app.on_event("shutdown"), which
    starlette 1.x removed.
    """
    sweeper = asyncio.create_task(_housekeeping())
    try:
        yield
    finally:
        sweeper.cancel()
        # Awaiting is what runs the task's cancellation to completion; without
        # it the coroutine is finalised by the garbage collector after the loop
        # has closed, same as the capture monitors.
        await asyncio.gather(sweeper, return_exceptions=True)
        await capture_manager.shutdown()


app = FastAPI(title="pcap-server", version=APP_VERSION, lifespan=_lifespan)



def warn_if_data_dir_exposed(path: Path) -> bool:
    """Say so when other accounts on the host can reach the database.

    The database holds every user's TOTP secret in plain text -- codes have to
    be computed from it -- so a data directory other accounts can enter hands
    them a working second factor for every user. The Quick start creates it
    0700; installs made before that did not, and nothing else would tell them.
    A warning rather than a refusal: an upgrade should not stop a working app
    over something one chmod fixes.
    """
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return False
    if not mode & 0o077:
        return False
    logger.warning(
        "DATA DIRECTORY IS NOT PRIVATE: %s is mode %03o, so other accounts on the "
        "host can read the database -- including every user's TOTP secret. On the "
        "host, close the directory mounted there (./data in the Quick start):\n"
        "    chmod 0700 data\n"
        "Nothing needs to restart. A Docker named volume is already closed by "
        "/var/lib/docker's own permissions and can ignore this. See docs/security.md.",
        path, mode,
    )
    return True


warn_if_data_dir_exposed(DATA_DIR)

db = Database(DATA_DIR / "pcap-server.db")

# Fail closed: a missing or wrong key stops the app rather than silently storing
# captures in the clear. StartupRefused carries the exact remedy.
try:
    vault = CaptureVault(dict(os.environ), db, CAPTURES_DIR)
    tls_manager = TlsManager(DATA_DIR / "tls", vault)
    tls_manager.startup_check()
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
# Login has its own lockout-on-failure limiter above. These two throttle the
# rate of two other authenticated actions that spawn real work per call --
# tshark for packet listing, an SSH connection for capture start -- keyed per
# user rather than per IP, since both require a session already.
packet_rate_limiter = SlidingWindowLimiter(
    max_per_minute=db.get_setting_int("rate_limit_packets_per_min"),
)
capture_start_rate_limiter = SlidingWindowLimiter(
    max_per_minute=db.get_setting_int("rate_limit_captures_per_min"),
)

# The filter check compiles an expression with tcpdump -- a short-lived
# subprocess per call. Cheaper than a capture and far cheaper than a tshark
# run, but it is still a process spawn driven by a keystroke-adjacent action,
# so it gets a budget of its own rather than eating the capture-start one. It
# shares that setting deliberately: the check exists to be called immediately
# before a start, and giving it a separate admin knob would be one more number
# to keep in step for no benefit.
filter_check_rate_limiter = SlidingWindowLimiter(
    max_per_minute=db.get_setting_int("rate_limit_packets_per_min"),
)

# Scanning a host for its keys spawns ssh-keyscan against an address the caller
# chose, and it is now reachable by any signed-in user rather than admins only
# -- the add form has to show fingerprints before the server exists, and every
# user can add a server. Two consequences follow from the widening, and this
# budget is the answer to both: a process spawn per call, and an outbound
# connection to an arbitrary host, neither of which should be available in a
# tight loop. The same per-minute figure as the filter check, for the same
# reason -- it is a spawn driven by a form button.
host_scan_rate_limiter = SlidingWindowLimiter(
    max_per_minute=db.get_setting_int("rate_limit_packets_per_min"),
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


def _cookie_secure() -> bool:
    """Built-in HTTPS always marks cookies Secure, whatever COOKIE_SECURE says:
    the compose file sets that false so plain-HTTP sign-in works at all."""
    return _COOKIE_SECURE or tls_manager.serving

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
#
# The built-in HTTPS routes are the other exception, and a deliberate one: they
# are how an installation gets *off* plain HTTP. backend/tls/routes.py says why,
# and what it costs.
_INSECURE_ALLOWED_PATHS = frozenset({
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/register",
    "/api/auth/totp/confirm",
}) | TLS_INSECURE_ALLOWED_PATHS

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_HTTPS_REMEDY = (
    "Turn on HTTPS. Recommended: Admin \u2192 HTTPS, where pcap-server gets its own "
    "Let's Encrypt certificate \u2014 no proxy, no inbound ports. Or put it behind a "
    "reverse proxy (Nginx Proxy Manager, Caddy or nginx) with TRUST_PROXY_HEADERS=true; "
    "with no domain, the proxy can use a self-signed certificate."
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
    # API responses carry per-user data -- server lists, capture metadata, auth
    # state -- that must not sit in a shared or disk cache. setdefault, so a
    # route that deliberately sets its own Cache-Control (none do today) still
    # wins; static assets are served by their own handler and are untouched.
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    # HSTS only where TLS is genuinely in use. Sending it over plain HTTP is
    # ignored by browsers, and sending it from a LAN deployment that later
    # cannot do TLS would lock users out of their own tool.
    if _is_secure_transport(request) and request.url.scheme == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


# A body is refused by its Content-Length before anything parses it.
#
# The SSH key upload has always checked its own 64 KB limit -- but only after
# `await file.read()`, and by then starlette has parsed the whole multipart
# body. Starlette's max_part_size guards *field* parts; a *file* part is
# appended to _file_parts_to_write with no cap at all and spools to a temp file
# once it passes 1 MB. So the limit ran after the cost it exists to prevent,
# and the cost landed on the same volume the captures are written to.
#
# Two caps rather than one, because the shapes are not comparable: every JSON
# body this API takes is a handful of fields, and the one upload it accepts is
# a private key.
#
# The residual, stated rather than implied: a chunked request carries no
# Content-Length and cannot be refused up front. Those still reach the
# per-endpoint checks, which is where every request stood before this. Closing
# that too means counting bytes off the stream, which is a larger change than
# the hole justifies while the only upload route is admin-only and HTTPS-only.
_MAX_BODY_BYTES = 64 * 1024
_MAX_UPLOAD_BYTES = 128 * 1024  # the 64 KB key limit, with room for multipart framing


def _body_limit(path: str) -> int:
    return _MAX_UPLOAD_BYTES if path.startswith("/api/admin/ssh-keys") else _MAX_BODY_BYTES


@app.middleware("http")
async def limit_request_body(request: Request, call_next):
    """Refuse an oversized body on the headers, before it is read."""
    declared = request.headers.get("content-length")
    if declared is not None:
        limit = _body_limit(request.url.path)
        try:
            length = int(declared)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "invalid Content-Length"})
        if length > limit:
            return JSONResponse(
                status_code=413,
                content={"detail": f"request body too large (max {limit // 1024} KB)"},
            )
    return await call_next(request)


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
        httponly=True, samesite="strict", secure=_cookie_secure(),
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
    # Both factors, not just the first. validate_session proves the password
    # only; the version string is withheld until TOTP is confirmed too, for the
    # same reason it is withheld from anonymous callers -- it tells whoever holds
    # it which build to match advisories against, and a password-only session
    # (a stolen or guessed password, no second factor) is exactly the threshold
    # that gate is meant to sit above. Every other sensitive route already
    # requires get_current_user (both factors); this field now matches.
    full_auth = user is not None and bool(user["totp_confirmed"])
    return {
        "has_users": has_users,
        # The flag actually applied, not the variable. With built-in HTTPS the
        # cookie is Secure whatever COOKIE_SECURE says, and reporting the raw
        # variable made the sign-in page warn "session cookies are not
        # protected" on exactly the install that had just protected them.
        "cookie_secure": _cookie_secure(),
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
        "version": APP_VERSION if full_auth else "",
        "release_notes_url": f"{REPO_URL}/releases/tag/v{APP_VERSION}" if full_auth else "",
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
    pw_hash = await hash_password_async(req.password)
    # Atomic: creates the first user as admin only if the table is still empty.
    # The user_count() check above is a fast, friendly early-out; THIS is the
    # guard that holds under concurrency. Without it, several registrations
    # racing during the slow password hash each saw an empty table and each
    # became admin -- so an attacker firing a burst alongside the operator's own
    # first registration got an admin account of their own.
    if not db.create_first_user(user_id, req.username, pw_hash):
        raise HTTPException(403, "registration closed -- ask an admin to create your account")

    token, expires = create_session_token(db, user_id)
    _set_session_cookie(response, token)
    return {"ok": True, "user_id": user_id, "needs_totp_setup": True}


@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    client_ip = _client_ip(request)
    if rate_limiter.is_locked(client_ip):
        raise HTTPException(429, "too many failed attempts, try again later")

    user = db.get_user_by_username(req.username)
    if user:
        password_ok = await verify_password_async(req.password, user["password_hash"])
    else:
        # Deliberately does the same scrypt work as a real verification.
        # `bool(user) and verify_password(...)` short-circuited, so an unknown
        # username answered in microseconds where a real one took ~100 ms --
        # a username oracle measurable from anywhere that can reach /login.
        password_ok = await verify_absent_user_async(req.password)
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
                    httponly=True, samesite="strict", secure=_cookie_secure(),
                    max_age=trust_days * 86400,
                )

    # The password is in hand and verified, so this is the only moment a hash
    # written under weaker parameters can be upgraded without asking the user
    # to change anything.
    if needs_rehash(user["password_hash"]):
        db.update_password_hash(
            user["id"], await hash_password_async(req.password)
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
    db.create_user(user_id, req.username, await hash_password_async(req.password))
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


@app.post("/api/admin/users/{target_user_id}/totp/reset")
async def admin_reset_totp(target_user_id: str, user: dict = Depends(require_admin)):
    """Clear another account's second factor so it enrols again at next login.

    The alternative was deleting the user and making them again, which also
    discards their servers, their stored usernames, their saved filters and
    every capture they own -- a punishment for losing a phone.

    AN ADMIN MAY NOT RESET THEIR OWN, and the refusal is the security property
    here rather than an inconvenience:

      * It would not help. Reaching this route means holding a session, and
        holding a session means already being past the second factor. The
        admin who is actually locked out cannot call it. Their way back in is
        `python -m backend.resetmfa`, run against the container by someone with
        access to the host -- which is the right bar for the one operation that
        can strip MFA from the top account.
      * It would hurt. A stolen session cookie on an admin account could strip
        that account's second factor and enrol the thief's own authenticator,
        turning a session that expires in hours into a login that does not.
        Self-service MFA removal from inside a session is exactly the
        persistence step to refuse.

    Both halves of the revocation are here, and neither is optional. A live
    session carries both factors already, so leaving one alive would let the
    old authenticator's holder keep working for up to session_hours after the
    reset. A trusted device is a second factor in its own right -- the whole
    point of it is skipping TOTP -- so it goes too, or the reset is skipped on
    exactly the devices that already had the most access.
    """
    if target_user_id == user["id"]:
        raise HTTPException(400, {
            "code": "cannot_reset_own_totp",
            "reason": (
                "An admin cannot reset their own two-factor authentication from "
                "inside a signed-in session. It would not help if you were locked "
                "out -- you could not sign in to reach it -- and it would let "
                "anyone holding a stolen session replace your second factor with "
                "their own."
            ),
            "remedy": (
                "Ask another admin to reset it, or run "
                "`docker compose run --rm --entrypoint python pcap-server "
                "-m backend.resetmfa <username> --apply` on the host."
            ),
        })
    if not db.reset_totp(target_user_id):
        raise HTTPException(404, "user not found")
    db.delete_sessions_for_user(target_user_id)
    db.delete_trusted_devices(target_user_id)
    logger.warning(
        "MFA reset for user %s by admin %s", target_user_id, user["id"]
    )
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
    elif req.key == "rate_limit_packets_per_min":
        packet_rate_limiter.update_config(int_val)
    elif req.key == "rate_limit_captures_per_min":
        capture_start_rate_limiter.update_config(int_val)
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


# --- admin: built-in HTTPS (backend/tls) ---

app.include_router(build_tls_router(tls_manager, require_admin, lambda: capture_manager.active_count()))


# --- admin: known hosts ---

@app.get("/api/admin/known-hosts")
async def admin_list_known_hosts(user: dict = Depends(require_admin)):
    return db.list_known_hosts()


@app.post("/api/admin/known-hosts/scan")
async def admin_scan_host(req: KnownHostEndpoint, user: dict = Depends(require_admin)):
    """Ask the host for its keys and hand them back for review. Stores nothing.

    This route used to scan and pin in one step, so "Trust host" accepted
    whatever answered on the address and the operator never saw what they had
    accepted. It is now the first half of a two-step flow: this returns each
    key with its SHA256 fingerprint, and /known-hosts/confirm stores the ones
    the operator agreed to.

    Being non-mutating is the whole point, so it is worth saying plainly: a
    scan can no longer change what this server trusts. Calling it is safe.
    """
    keys = await ssh_manager.scan_host_keys(req.hostname, req.port)
    if not keys:
        raise HTTPException(502, "no host keys found")
    return {"ok": True, "keys": keys}


@app.post("/api/admin/known-hosts/confirm")
async def admin_confirm_host(req: KnownHostConfirm, user: dict = Depends(require_admin)):
    """Pin the keys an admin reviewed, exactly as they were shown.

    Deliberately does NOT re-scan. The keys in the body are the ones that were
    on screen when the operator said yes; fetching them again here would mean
    a key could change between the review and the acceptance and be pinned
    unseen, which is the hole this whole flow exists to close.

    Every key is fingerprinted again on the way in. That is not distrust of
    the client so much as a refusal to store anything unverifiable: a blob
    that will not parse cannot have been reviewed, whatever the UI displayed,
    and it would sit in known_hosts breaking connections with no explanation.
    The fingerprints come back so the caller can report what was pinned
    without inventing it.
    """
    stored = []
    for key in req.keys:
        fingerprint = host_key_fingerprint(key.key_type, key.host_key)
        if not fingerprint:
            raise HTTPException(400, f"{key.key_type} key is not a usable public key")
        stored.append({"key_type": key.key_type, "fingerprint": fingerprint})

    ssh_manager.store_host_keys(
        req.hostname,
        req.port,
        [{"key_type": k.key_type, "host_key": k.host_key} for k in req.keys],
        user["id"],
    )
    logger.info(
        "admin %s pinned %d host key(s) for %s:%d: %s",
        user["id"], len(stored), req.hostname, req.port,
        ", ".join(k["fingerprint"] for k in stored),
    )
    return {"ok": True, "stored": len(stored), "keys": stored}


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
async def admin_forget_host(req: KnownHostEndpoint, user: dict = Depends(require_admin)):
    """Drop every key for one endpoint at once.

    Per-key removal reads as broken: the remaining keys still verify the host,
    and the next scan brings the removed one back with them.
    """
    removed = db.forget_known_host(req.hostname, req.port)
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
        os_name=row.get("os_name", ""),
        self_target_reason=row.get("self_target_reason", ""),
        kernel_verified_at=row.get("kernel_verified_at", ""),
        added_at=datetime.fromisoformat(row["added_at"]),
    )


def _require_server(server_id: str, user_id: str) -> ServerInfo:
    row = db.get_active_server(server_id, user_id)
    if not row:
        raise HTTPException(404, "server not found")
    return _server_from_row(row)


def _refuse_self_target(finding: str, action: str) -> NoReturn:
    """The one shape a self-capture refusal takes, wherever it is found.

    One builder because the UI keys off the code (app.js): a second refusal
    phrased by hand would be the one that does not raise the blocking alert.
    """
    raise HTTPException(400, {
        "code": "self_capture",
        "reason": f"{action}: {finding}.",
        "explanation": SELF_CAPTURE_EXPLANATION,
    })


async def _reject_self_target(hostname: str, action: str = "This server cannot be added") -> None:
    """A capture target must not be the machine pcap-server runs on.

    Address-level checks only -- everything that can be known without
    connecting. Resolution can block on DNS, so it runs off the event loop.
    """
    finding = await asyncio.to_thread(describe_if_local, hostname)
    if finding:
        _refuse_self_target(finding, action)


def _record_self_target(server_id: str, user_id: str, reason: str) -> None:
    """Persist (or clear) a connection-time finding against a stored server.

    Written whenever something actually reached the host, so the server list can
    say why an entry is refused instead of leaving the user at a dead end. A
    clear is as meaningful as a set: a host that has moved should stop carrying
    someone else's finding.
    """
    try:
        db.set_active_server_self_target(server_id, user_id, reason)
    except Exception:
        # Never turn a successful refusal into a 500 over bookkeeping.
        logger.warning("could not record self-target finding for %s", server_id, exc_info=True)


def _record_kernel_verified(server_id: str, user_id: str) -> None:
    """Note that a connection ran the self-target check and it did not refuse.

    Deliberately not "proved remote". A target that reports no boot id -- a BSD
    host, a masked /proc -- proves nothing either way, and localnet is explicit
    that this must never become a refusal. So what is recorded is the weaker,
    true statement: something connected, the check ran, and the answer was not
    "this is the machine pcap-server runs on". That is exactly the claim the
    capture gate needs, and it is not a claim about the boot id being readable.
    """
    try:
        db.set_active_server_kernel_verified(server_id, user_id)
    except Exception:
        # Never turn a successful check into a 500 over bookkeeping.
        logger.warning("could not record kernel check for %s", server_id, exc_info=True)


async def _reject_self_kernel(boot_id: str, server_id: str, user_id: str, action: str) -> None:
    """Refuse a target that proves, over its own connection, to be this machine.

    The strong check: a shared kernel boot id is not topology-dependent, so it
    catches the host LAN address that no amount of resolving ever could.
    """
    finding = describe_if_same_kernel(boot_id)
    _record_self_target(server_id, user_id, finding)
    if finding:
        _refuse_self_target(finding, action)
    _record_kernel_verified(server_id, user_id)


def _server_is_grandfathered(srv: ServerInfo) -> bool:
    """True for a server that predates the self-target check being recorded.

    Those rows read as unverified because nothing ever recorded a check for
    them, not because a check failed. Refusing their captures on upgrade would
    be a regression dressed as a security improvement: the capture's own
    connection already runs the boot-id check, so what they would gain is a
    better message, and what they would cost is every existing server breaking
    at once. The migration writes the cutoff; see it for the full reasoning.
    """
    enforced = db.kernel_verify_enforced_from()
    if not enforced:
        return True
    try:
        cutoff = datetime.fromisoformat(enforced)
    except ValueError:
        logger.warning("kernel_verify_enforced_from is not a timestamp: %r", enforced)
        return True
    added = srv.added_at
    if added.tzinfo is None:
        added = added.replace(tzinfo=timezone.utc)
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    return added < cutoff


def _require_kernel_checked(srv: ServerInfo) -> None:
    """Refuse a capture from a server nothing has ever successfully connected to.

    This is the honest state for a server added while its host was down: the
    add flow pins its keys and creates the row, but no connection ever ran the
    self-target check against it, so nothing has ruled out that it is this very
    machine. run_tcpdump checks the capture's own connection and would refuse
    it there anyway -- what this adds is the refusal arriving before a capture
    is started on the remote host, with a sentence saying what to do about it.
    """
    if srv.kernel_verified_at or _server_is_grandfathered(srv):
        return
    raise HTTPException(400, {
        "code": "server_unverified",
        "reason": (
            f"Nothing has successfully connected to {srv.hostname}:{srv.port} yet, "
            "so it has never been checked against this machine."
        ),
        "explanation":
            "This server was added while its host could not be reached, so the check "
            "that it is not the machine pcap-server runs on has never had a "
            "connection to run over. Use Check prerequisites on this server -- once "
            "that connects, captures are allowed.",
    })


def _key_path(key_name: str) -> Path:
    """The stored key by that name. 400, not 500, when the name escapes the directory."""
    try:
        return resolve_key_path(SSH_KEYS_DIR, key_name)
    except ValueError:
        raise HTTPException(400, "invalid key path")


def _require_key(ssh_key_name: str) -> None:
    if not _key_path(ssh_key_name).exists():
        raise HTTPException(400, f"SSH key '{ssh_key_name}' not found in keys directory")


@app.get("/api/servers")
async def list_servers(user: dict = Depends(get_current_user)):
    """Each server, plus whether its host is trusted yet.

    A connection to an untrusted host is refused outright, so a server list
    that does not say which of its entries are unusable is a list that sends
    people to a failure they cannot explain. Trust itself stays admin-owned
    and endpoint-scoped -- this only reports the state of a host the caller
    has already configured, which tells them nothing they could not learn by
    pressing Test connection.
    """
    servers = []
    for row in db.list_active_servers(user["id"]):
        info = _server_from_row(row)
        servers.append({
            **info.model_dump(),
            "host_trusted": bool(db.get_known_hosts(info.hostname, info.port)),
            # Reported rather than left to be discovered at capture time, for
            # the same reason host_trusted is: a list that does not say which
            # entries cannot be used sends people to a failure they cannot
            # explain. Grandfathered rows report True because the gate lets
            # them through -- this field is what the gate will do, not a claim
            # about what was checked.
            "verified": bool(info.kernel_verified_at) or _server_is_grandfathered(info),
        })
    return servers


@app.post("/api/host-keys/scan")
async def scan_host_keys(req: KnownHostEndpoint, user: dict = Depends(get_current_user)):
    """Ask a host for its keys and hand them back for review. Stores nothing.

    The non-admin twin of /api/admin/known-hosts/scan, and the first half of
    adding a server. It exists because the add form has to show fingerprints
    before the server row is created, and adding a server is something every
    user can do -- see ServerCreate for why the ordering had to change.

    Widening this to non-admins is safe in a way the *confirm* half is not:
    scanning is non-mutating by construction, so calling it cannot change what
    this server trusts. What it can do is spawn ssh-keyscan against an address
    the caller chose, which is why it is rate limited.
    """
    if not host_scan_rate_limiter.allow(user["id"]):
        raise HTTPException(429, "too many host key scans, slow down")
    keys = await ssh_manager.scan_host_keys(req.hostname, req.port)
    if not keys:
        raise HTTPException(502, "no host keys found")
    return {"ok": True, "keys": keys}


@app.post("/api/servers")
async def add_server(req: ServerCreate, user: dict = Depends(get_current_user)):
    """Trust the reviewed keys, probe the host, and only then create the row.

    The old order made the strong check unreachable here by construction: the
    kernel check needs a connection, a connection needs trusted host keys, and
    trusting was only offered once a server existed to trust it for. So a
    server pointing at this very machine was always created, and refused later.

    Reversing it costs one invariant, enforced by the `finally` below: host
    keys pinned by this request survive only if a row is created. An abandoned
    form, a refused self-target and a host that turns out to be unreachable all
    leave known_hosts exactly as they found it. Trust never outlives the
    request that asked for it, so this flow manufactures no orphans of the kind
    the delete path now cleans up.
    """
    await _reject_self_target(req.hostname)
    _require_key(req.ssh_key_name)

    auth = ServerAuth(**{
        k: v for k, v in req.model_dump().items()
        if k not in ("host_keys", "add_unverified")
    })

    # Only ever pinned when the endpoint has nothing stored. An endpoint another
    # server already trusts keeps the keys it has: re-pinning from this request
    # would let one user silently replace a key an admin reviewed, and the
    # rollback below could then not restore it.
    pinned = False
    if not db.get_known_hosts(req.hostname, req.port):
        if not req.host_keys and not req.add_unverified:
            raise _host_keys_required_error(
                req.hostname, req.port,
                f"{req.hostname}:{req.port} has no trusted host keys yet.",
            )
        if req.host_keys:
            _pin_reviewed_keys(req.hostname, req.port, req.host_keys, user["id"])
            pinned = True
        else:
            # add_unverified: a host that could not be scanned because it is
            # not up yet. The probe below still runs and still fails closed --
            # _connect refuses a host with no trusted keys -- so this lands in
            # the unreachable path and creates an untrusted, unverified row.
            logger.info(
                "user %s added %s:%d unverified -- no host keys could be scanned",
                user["id"], req.hostname, req.port,
            )

    created = False
    try:
        verified_at, unreachable = await _probe_before_create(auth)
        info = ServerInfo(**auth.model_dump(), kernel_verified_at=verified_at)
        db.add_active_server(
            info.id, user["id"], info.name, info.hostname, info.port,
            info.username, info.ssh_key_name, info.use_sudo,
            kernel_verified_at=verified_at,
        )
        created = True
        return {**info.model_dump(), "unreachable": unreachable}
    finally:
        # The whole invariant, in one place: keys are kept if and only if a row
        # references them.
        if pinned and not created:
            forgotten = db.forget_known_host(req.hostname, req.port)
            logger.info(
                "rolled back %d host key(s) for %s:%d -- the server was not created",
                forgotten, req.hostname, req.port,
            )


@app.post("/api/servers/{server_id}/trust-host")
async def trust_server_host(
    server_id: str,
    req: KnownHostConfirm,
    user: dict = Depends(get_current_user),
):
    """Pin reviewed keys for a server the caller owns.

    The counterpart to accepting fingerprints in the add form, for a server
    that already exists -- one added before this flow, or one whose keys were
    forgotten when a sibling was deleted. Trusting was admin-only, which is now
    theatre rather than a control: a non-admin who can accept fingerprints
    while adding a server can reach the same state by deleting this row and
    adding it again, and that path is strictly longer for no gain.

    So the authorisation is 'you own a server at this endpoint' rather than
    'you are an admin'. Two things keep that bounded:

      * the keys must be for THIS server's endpoint, not any host the caller
        can name; and
      * an endpoint that already has keys is refused outright. This route
        establishes trust where there is none -- it never replaces it. Without
        that rule a non-admin could add a server pointing at an endpoint an
        admin trusts, re-pin keys of their own choosing, and stand in the
        middle of the admin's connections to it.

    Admin -> Known Hosts keeps the operations this one refuses: replacing and
    forgetting keys for any endpoint at all.
    """
    srv = _require_server(server_id, user["id"])
    if (req.hostname, req.port) != (srv.hostname, srv.port):
        raise HTTPException(400, "those keys are for a different host than this server")
    if db.get_known_hosts(srv.hostname, srv.port):
        raise HTTPException(409, {
            "code": "host_already_trusted",
            "reason": f"{srv.hostname}:{srv.port} already has stored host keys.",
            "explanation":
                "This route establishes trust where there is none; it never replaces "
                "it. If the host has genuinely been rebuilt, the old keys have to go "
                "first -- an admin can forget them under Admin -> Known Hosts, and if "
                "this is the only server pointing at that endpoint, deleting it "
                "forgets them too and you can add it again.",
        })
    fingerprints = _pin_reviewed_keys(srv.hostname, srv.port, req.keys, user["id"])
    return {"ok": True, "stored": len(fingerprints), "keys": fingerprints}


def _pin_reviewed_keys(hostname: str, port: int, keys, user_id: str) -> list[dict]:
    """Store the keys the user accepted, exactly as they were shown.

    The same rule /api/admin/known-hosts/confirm follows and for the same
    reason: what gets pinned is what was on screen, never a fresh scan, so a
    key cannot change between the review and the acceptance. Every key is
    fingerprinted again on the way in, because a blob that will not parse
    cannot have been reviewed whatever the UI displayed.
    """
    fingerprints = []
    for key in keys:
        fingerprint = host_key_fingerprint(key.key_type, key.host_key)
        if not fingerprint:
            raise HTTPException(400, f"{key.key_type} key is not a usable public key")
        fingerprints.append({"key_type": key.key_type, "fingerprint": fingerprint})

    ssh_manager.store_host_keys(
        hostname, port,
        [{"key_type": k.key_type, "host_key": k.host_key} for k in keys],
        user_id,
    )
    logger.info(
        "user %s pinned %d host key(s) for %s:%d: %s",
        user_id, len(keys), hostname, port,
        ", ".join(f["fingerprint"] for f in fingerprints),
    )
    return fingerprints


@asynccontextmanager
async def _transient_host_keys(hostname: str, port: int, host_keys, user_id: str):
    """Pin reviewed keys just long enough to probe a not-yet-created server.

    The add form's review step hands the accepted keys to Test connection and
    Check prerequisites -- whichever of them asked for them -- so they can reach
    a host that has never been trusted. Same no-orphan invariant as add_server: keys pinned here for an
    endpoint that had none are always forgotten again on the way out, because no
    row references them. An endpoint that is already trusted is left untouched --
    the probe uses what is stored, and this pins and forgets nothing.
    """
    pinned = False
    if host_keys and not db.get_known_hosts(hostname, port):
        _pin_reviewed_keys(hostname, port, host_keys, user_id)
        pinned = True
    try:
        yield
    finally:
        if pinned:
            forgotten = db.forget_known_host(hostname, port)
            logger.info(
                "rolled back %d transient host key(s) for %s:%d after a probe",
                forgotten, hostname, port,
            )


# One code for one condition. add_server refuses before it connects (the
# endpoint has nothing stored and the caller sent nothing), the probes find out
# from the handshake -- but to a caller both mean the same thing: this endpoint
# needs host keys before anything can talk to it. They used to answer with two
# different codes, so every caller had to know both, and the add form's two
# probe buttons handled one of them while add handled the other.
HOST_KEYS_REQUIRED = "host_keys_required"


def _host_keys_required_error(hostname: str, port: int, reason: str) -> HTTPException:
    """Structured so the caller can go and collect fingerprints rather than
    showing a bare failure. Every route that needs trust raises this one."""
    return HTTPException(409, {
        "code": HOST_KEYS_REQUIRED,
        "reason": reason,
        "hostname": hostname,
        "port": port,
        "explanation":
            "Nothing can connect to a host until its identity is pinned -- "
            "including the check that this is not the machine pcap-server runs on. "
            "Review its fingerprints and accept them, then try again.",
    })


def _from_host_not_trusted(exc: HostNotTrusted) -> HTTPException:
    """The same refusal as add_server's, reached from the other direction."""
    return _host_keys_required_error(exc.hostname, exc.port, str(exc))


async def _probe_before_create(auth: ServerAuth) -> tuple[str, str]:
    """Connect, run the self-target check, and report what was learned.

    Returns (kernel_verified_at, unreachable_reason). A self-target raises --
    that is the point of probing here at all. An unreachable host does not:
    pre-staging a server for a machine that is not up yet is a capability the
    old flow had, and taking it away to close this hole would be a poor trade.
    Such a row is created unverified, and the capture gate refuses it until
    something has actually connected.
    """
    try:
        result = await ssh_manager.test_connection(auth)
    except FileNotFoundError as exc:
        # A missing key is the caller's mistake, not an unreachable host.
        raise HTTPException(400, str(exc))
    except ConnectionError as exc:
        return "", str(exc)
    except Exception:
        logger.exception("probe failed while adding %s", auth.hostname)
        return "", "the host could not be reached"

    finding = describe_if_same_kernel(result.get("boot_id", ""))
    if finding:
        # No row to record it against, which is the whole improvement: this
        # refusal now happens before the server exists rather than after.
        _refuse_self_target(finding, "This server cannot be added")
    return datetime.now(timezone.utc).isoformat(), ""


@app.delete("/api/servers/{server_id}")
async def remove_server(server_id: str, user: dict = Depends(get_current_user)):
    """Delete the server, and the host's keys with it when nothing else needs them.

    Trust used to outlive its subject: known_hosts carries no reference to any
    server row, so deleting a server left its keys pinned and re-adding that
    host silently inherited a pinning nobody had re-verified. In a multi-user
    install the same free pass went to anyone else who added that hostname.

    The refcount is across ALL users, not the caller's own servers, because the
    table it guards is global -- forgetting keys another user's server still
    verifies against would break their connections to prove a point about this
    one. Accepted consequence, decided with the user: when the last server for
    an endpoint belongs to a non-admin, deleting it drops a decision an admin
    made. Admin -> Known hosts is where that becomes visible.
    """
    srv = _require_server(server_id, user["id"])
    if not db.delete_active_server(server_id, user["id"]):
        raise HTTPException(404, "server not found")

    forgotten = 0
    if db.count_servers_for_endpoint(srv.hostname, srv.port) == 0:
        forgotten = db.forget_known_host(srv.hostname, srv.port)
        if forgotten:
            logger.info(
                "forgot %d host key(s) for %s:%d -- no server points at it any more",
                forgotten, srv.hostname, srv.port,
            )
    return {"ok": True, "host_keys_forgotten": forgotten}


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
    # Already cut to one printable, bounded line by parse_prereq_output. Kept
    # as reported, including empty, once the probe finished: a host with no
    # os-release says nothing, and a stale name would be someone else's. A
    # probe cut short proves nothing either way, so it leaves the name alone.
    os_release = result["facts"]["os_release"]
    os_name = os_release.get("PRETTY_NAME") or os_release.get("NAME", "")
    if result["facts"]["complete"] and os_name != srv.os_name:
        db.set_active_server_os(server_id, user["id"], os_name)
    # The probe reached the host, so its boot id is the best evidence available
    # about whether this is the machine we are running on. Checked after the
    # persistence above so a refused server still carries what was learned.
    await _reject_self_kernel(
        result["facts"].get("boot_id", ""), server_id, user["id"],
        "This server cannot be used as a capture target",
    )
    return {
        "checks": result["checks"],
        "tcpdump_path": discovered or srv.tcpdump_path,
        "os": os_name,
    }


@app.post("/api/servers/{server_id}/test")
async def test_server(server_id: str, user: dict = Depends(get_current_user)):
    srv = _require_server(server_id, user["id"])
    try:
        result = await ssh_manager.test_connection(srv)
    except ConnectionError as exc:
        raise HTTPException(502, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(502, "connection failed")
    # Test connection is the one action a user reaches for when a server is
    # misbehaving, so it is also where a self-target should surface.
    await _reject_self_kernel(
        result.get("boot_id", ""), server_id, user["id"],
        "This server cannot be used as a capture target",
    )
    return {"ok": True, **result}


@app.put("/api/servers/{server_id}")
async def update_server(server_id: str, auth: ServerAuth, user: dict = Depends(get_current_user)):
    """Repoint a server, and clean up the endpoint it left behind.

    Deleting a server already forgets the keys for an endpoint nothing points
    at any more (remove_server). Editing did not, so every corrected typo and
    every host that moved left its keys pinned forever with no server
    referencing them -- the same orphans Admin -> Known hosts grew a purge
    button for, manufactured by the edit path faster than the button could
    clear them.

    Same refcount and the same cross-user rule as the delete path, for the same
    reason: the table is global, so another user's server still verifying
    against that endpoint keeps it trusted.
    """
    # Checked on edit too: otherwise a benign server could be repointed at the host.
    await _reject_self_target(auth.hostname)
    _require_key(auth.ssh_key_name)

    # Read before the update -- afterwards the row names the new endpoint and
    # the old one is unrecoverable.
    previous = _require_server(server_id, user["id"])
    updated = db.update_active_server(
        server_id, user["id"], auth.name, auth.hostname, auth.port,
        auth.username, auth.ssh_key_name, auth.use_sudo,
    )
    if not updated:
        raise HTTPException(404, "server not found")

    forgotten = 0
    moved = (previous.hostname, previous.port) != (auth.hostname, auth.port)
    if moved and db.count_servers_for_endpoint(previous.hostname, previous.port) == 0:
        forgotten = db.forget_known_host(previous.hostname, previous.port)
        if forgotten:
            logger.info(
                "forgot %d host key(s) for %s:%d -- the last server pointing at it "
                "was repointed to %s:%d",
                forgotten, previous.hostname, previous.port, auth.hostname, auth.port,
            )

    row = _server_from_row(db.get_active_server(server_id, user["id"]))
    return {**row.model_dump(), "host_keys_forgotten": forgotten}


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
async def probe_test(req: ServerProbe, user: dict = Depends(get_current_user)):
    await _reject_self_target(req.hostname)
    _require_key(req.ssh_key_name)
    auth = ServerAuth(**{k: v for k, v in req.model_dump().items() if k != "host_keys"})
    try:
        async with _transient_host_keys(req.hostname, req.port, req.host_keys, user["id"]):
            result = await ssh_manager.test_connection(auth)
    except HostNotTrusted as exc:
        raise _from_host_not_trusted(exc)
    except ConnectionError as exc:
        raise HTTPException(502, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(502, "connection failed")
    # No row to record against -- this server does not exist yet, which is the
    # point: catching it here is what stops it being created at all.
    finding = describe_if_same_kernel(result.get("boot_id", ""))
    if finding:
        _refuse_self_target(finding, "This server cannot be added")
    return {"ok": True, **result}


@app.post("/api/probe/prereq-check")
async def probe_prereq_check(req: ServerProbe, user: dict = Depends(get_current_user)):
    await _reject_self_target(req.hostname)
    _require_key(req.ssh_key_name)
    auth = ServerAuth(**{k: v for k, v in req.model_dump().items() if k != "host_keys"})
    try:
        async with _transient_host_keys(req.hostname, req.port, req.host_keys, user["id"]):
            result = await ssh_manager.check_prerequisites(auth)
    except HostNotTrusted as exc:
        raise _from_host_not_trusted(exc)
    except ConnectionError as exc:
        raise HTTPException(502, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        logger.exception("prerequisite check failed for %s", req.hostname)
        raise HTTPException(502, "prerequisite check failed")

    finding = describe_if_same_kernel(result["facts"].get("boot_id", ""))
    if finding:
        _refuse_self_target(finding, "This server cannot be added")

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


def _store_ssh_key(name: str, content: bytes) -> dict:
    """Validate, normalise and seal a private key under `name`.

    Shared by the upload and the paste route so the two cannot drift: the same
    name rule, the same size bound, the same refusal to overwrite, the same
    parse check, and the same sealing. Before this existed only the upload
    route stored keys, and it checked the name and the size but never whether
    the bytes were a private key at all.
    """
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise HTTPException(400, "invalid key name — use only letters, digits, dots, dashes, underscores")
    if len(name) > 255:
        raise HTTPException(400, "key name too long")
    dest = _key_path(name)
    if dest.exists():
        raise HTTPException(409, f"key '{name}' already exists")
    if len(content) > 64 * 1024:
        raise HTTPException(400, "key is too large (max 64 KB)")

    # Parsed before it is stored, not at connect time. A public key or a
    # passphrase-protected key used to be accepted here and fail minutes later
    # against a host, reported from a screen that never mentioned the key.
    try:
        content = normalise_private_key(content)
    except PrivateKeyRejected as exc:
        raise HTTPException(400, str(exc)) from exc

    SSH_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    # Sealed before it ever touches disk when a master key is configured --
    # same as captures, a stored private key never exists as a plaintext file
    # on the volume.
    dest.write_bytes(vault.cryptor.seal_bytes(content) if vault.cryptor else content)
    dest.chmod(0o600)
    logger.info("stored SSH private key %r (%d bytes)", name, len(content))
    return {"ok": True, "name": name}


@app.post("/api/admin/ssh-keys")
async def upload_ssh_key(file: UploadFile, user: dict = Depends(require_admin)):
    return _store_ssh_key(file.filename or "", await file.read())


@app.post("/api/admin/ssh-keys/paste")
async def paste_ssh_key(req: PastedPrivateKey, user: dict = Depends(require_admin)):
    """Store a private key that was typed or pasted rather than uploaded.

    The same operation as the upload, reached a different way: copying a key
    out of a terminal is how people usually have one to hand, and requiring it
    to become a file first was a step that existed only because the route did.

    Deliberately NOT widened to every user. Adding a server is something any
    user can do, but the key store is shared -- every server picks from the
    same list -- so who may put a credential into it stays an admin decision,
    exactly as the upload route has it.

    The body is JSON, so this rides the same 64 KB cap the middleware already
    grants anything under /api/admin/ssh-keys rather than the small default.
    """
    return _store_ssh_key(req.name, req.key.encode())


@app.delete("/api/admin/ssh-keys/{key_name}")
async def delete_ssh_key(key_name: str, user: dict = Depends(require_admin)):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", key_name):
        raise HTTPException(400, "invalid key name")
    path = _key_path(key_name)
    if not path.exists():
        raise HTTPException(404, "key not found")
    path.unlink()
    return {"ok": True}


# --- capture filter checking ---

# Deliberately a GET, and deliberately not under /api/captures/.
#
# GET because it changes nothing: it compiles an expression and throws the
# result away. That is not pedantry -- the read-only-over-HTTP middleware
# refuses mutating calls, and a checker that vanished exactly when the app went
# read-only would be missing from the one configuration where a wasted capture
# is hardest to retry.
#
# Its own prefix because /api/captures/{capture_id} would otherwise match
# `check-filter` as an id, leaving the routes ordered by declaration and a
# reordering away from breaking quietly.
@app.get("/api/bpf/check")
async def check_bpf_filter(
    bpf_filter: str = Query("", max_length=2000),
    interface: str = Query(ANY_INTERFACE, max_length=64),
    user: dict = Depends(get_current_user),
):
    """Advisory only. Never refuses a capture, and never blocks one either.

    Everything here is a warning the operator can overrule, so a caller that
    cannot reach this endpoint, or gets an error from it, should start the
    capture anyway. Refusing on the checker's behalf would turn an advisory
    into a gate that nobody asked for.
    """
    if not filter_check_rate_limiter.allow(user["id"]):
        raise HTTPException(429, "too many filter checks, slow down")

    # Reported rather than raised. These characters are refused outright when a
    # capture actually starts (models.validate_bpf), but that refusal arrives
    # as a 422 on the start button; saying so here means it is on screen while
    # the field is still being edited.
    bad = sorted({c for c in bpf_filter if c in BPF_FORBIDDEN_CHARS})
    if bad:
        return {"ok": False, "warning": {
            "code": "bpf_invalid",
            "message": "This filter contains characters that are not allowed.",
            "detail": "Remove " + " ".join(f"`{c}`" for c in bad)
                      + ". None of them mean anything in a BPF expression.",
        }}

    warning = await check_filter(bpf_filter, interface)
    if warning is None:
        return {"ok": True, "warning": None}
    return {"ok": False, "warning": {
        "code": warning.code,
        "message": warning.message,
        "detail": warning.detail,
    }}


# --- the operator's own saved capture filters ---
#
# The built-in library is a constant in app.js and is the same for everyone.
# These sit alongside it and belong to one account: a capture filter routinely
# names the hosts and ports somebody is investigating, so it is treated the way
# this app treats servers and usernames rather than as shared reference
# material. Every query below is scoped by user_id in the statement itself.


@app.get("/api/filters")
async def list_custom_filters(user: dict = Depends(get_current_user)):
    return [CustomFilter(**row) for row in db.list_custom_filters(user["id"])]


@app.post("/api/filters")
async def create_custom_filter(
    body: CustomFilterRequest,
    user: dict = Depends(get_current_user),
):
    try:
        row = db.add_custom_filter(user["id"], body.label, body.expression)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return CustomFilter(**row)


@app.delete("/api/filters/{filter_id}")
async def delete_custom_filter(
    filter_id: str,
    user: dict = Depends(get_current_user),
):
    # 404 on someone else's id for the same reason _require_own_capture gives
    # it: a 403 would confirm the id exists.
    if not db.delete_custom_filter(user["id"], filter_id):
        raise HTTPException(404, "filter not found")
    return {"ok": True}


# --- the operator's own saved display filters ---
#
# Private to the account for the same reason as the capture filters above, and
# distinct from saved views: a view is a tab on one capture, these are for any.


@app.get("/api/display-filters")
async def list_display_filters(user: dict = Depends(get_current_user)):
    return [CustomFilter(**row) for row in db.list_custom_filters(user["id"], "display")]


@app.post("/api/display-filters")
async def create_display_filter(
    body: DisplayFilterRequest,
    user: dict = Depends(get_current_user),
):
    try:
        row = db.add_custom_filter(user["id"], body.label, body.expression, "display")
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return CustomFilter(**row)


@app.delete("/api/display-filters/{filter_id}")
async def delete_display_filter(
    filter_id: str,
    user: dict = Depends(get_current_user),
):
    if not db.delete_custom_filter(user["id"], filter_id, "display"):
        raise HTTPException(404, "filter not found")
    return {"ok": True}


# --- the packet list's column layout ---
#
# Per account and used on every capture, the way a Wireshark preference is --
# not per capture and not per view, so that a column added while reading one
# capture is still there in the next.


@app.get("/api/column-layout")
async def get_column_layout(user: dict = Depends(get_current_user)):
    columns = db.get_column_layout(user["id"])
    # default tells the UI whether this account has ever arranged its columns,
    # which is what its Reset control keys off -- not derivable from a list
    # that happens to match the built-in one.
    return {"columns": columns, "default": columns is None}


@app.put("/api/column-layout")
async def put_column_layout(
    layout: ColumnLayout,
    user: dict = Depends(get_current_user),
):
    fields = [c.field for c in layout.columns if c.field]
    try:
        validate_column_fields(fields)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not filter_check_rate_limiter.allow(user["id"]):
        # Saving a layout with a field this tshark has not seen before spawns
        # `tshark -G fields`, so the check that reaches a subprocess sits behind
        # the same budget as the other one that does.
        raise HTTPException(429, "too many layout saves, slow down")
    try:
        unknown = await unknown_packet_fields(fields)
    except Exception:
        logger.exception("tshark field registry lookup failed")
        raise HTTPException(500, "could not check those field names against tshark")
    if unknown:
        raise HTTPException(
            400,
            "tshark does not know " + ", ".join(unknown)
            + " -- check the spelling against the field name Wireshark shows",
        )
    db.set_column_layout(user["id"], [c.model_dump() for c in layout.columns])
    return {"columns": [c.model_dump() for c in layout.columns], "default": False}


@app.delete("/api/column-layout")
async def delete_column_layout(user: dict = Depends(get_current_user)):
    """Back to the built-in columns."""
    db.clear_column_layout(user["id"])
    return {"columns": None, "default": True}


@app.get("/api/column-layout/default")
async def default_column_layout(_user: dict = Depends(get_current_user)):
    """The built-in ids, in order, so the UI's Reset does not carry its own
    copy of a list the server already decides."""
    return {"columns": DEFAULT_PACKET_COLUMNS}


# --- captures ---

def _require_own_capture(capture_id: str, user: dict):
    """This user's capture, or 404.

    404 rather than 403 on someone else's: a 403 would confirm that the id
    exists, which is the one thing a caller guessing ids should not learn.
    """
    info = capture_manager.get(capture_id)
    if not info or info.user_id != user["id"]:
        raise HTTPException(404, "capture not found")
    return info


def _require_readable_capture(capture_id: str, user: dict):
    """...and it finished, and its file is still on the volume."""
    info = _require_own_capture(capture_id, user)
    if info.status != CaptureStatus.COMPLETED:
        raise HTTPException(400, "capture not yet completed")
    path = Path(info.local_path)
    if not path.exists():
        raise HTTPException(404, "pcap file not found on disk")
    return info, path


@app.get("/api/captures")
async def list_captures(user: dict = Depends(get_current_user)):
    return capture_manager.list_for_user(user["id"])


@app.post("/api/captures")
async def start_capture(req: CaptureRequest, user: dict = Depends(get_current_user)):
    if not capture_start_rate_limiter.allow(user["id"]):
        raise HTTPException(429, "too many capture start requests, slow down")
    srv = _require_server(req.server_id, user["id"])
    # The guard used to run only when a server was added, which left every row
    # already in the database outside it -- including rows added before the
    # guard existed, and rows whose hostname has since come to resolve to this
    # machine. A stored finding is not re-proved here: whatever connected last
    # had the target in front of it, and nothing since has said otherwise.
    if srv.self_target_reason:
        _refuse_self_target(srv.self_target_reason, "This capture cannot start")
    # Recorded, not just refused: a row that fails every time with nothing said
    # about why is the dead end the flag exists to prevent, and an address that
    # has moved to this machine is exactly the case nobody would think to look
    # for. Cleared again by the next Test connection that finds otherwise.
    finding = await asyncio.to_thread(describe_if_local, srv.hostname)
    if finding:
        _record_self_target(srv.id, user["id"], finding)
        _refuse_self_target(finding, "This capture cannot start")
    # Last of the pre-flight refusals, deliberately. "Nothing has ever checked
    # this server" is the weakest thing that can be said about a target, and it
    # must never be said in place of "this IS the machine pcap-server runs on"
    # -- both are 400s, but only the self-capture code raises the blocking
    # alert in the UI, and an unverified row that is also a self-target would
    # have been reported as the lesser problem.
    _require_kernel_checked(srv)
    try:
        info = await capture_manager.start(req, srv, user["id"])
        return info
    except SelfCaptureRefused as exc:
        # Raised on the capture's own connection, after everything above passed:
        # the host LAN address case, which no resolving can see. Recorded so the
        # server list can say why rather than leaving a dead entry behind.
        _record_self_target(srv.id, user["id"], str(exc))
        _refuse_self_target(str(exc), "This capture cannot start")
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
    _require_own_capture(capture_id, user)
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
    _require_own_capture(capture_id, user)
    return capture_manager.rename(capture_id, body.name)


@app.delete("/api/captures/{capture_id}")
async def delete_capture(capture_id: str, user: dict = Depends(get_current_user)):
    _require_own_capture(capture_id, user)
    # What was done is reported back rather than swallowed: deleting a running
    # capture terminates it on the target host and removes the file it was
    # writing, and an operator who asked for that is owed confirmation it
    # happened -- particularly when the remote half did not.
    result = await capture_manager.delete(capture_id)
    return {"ok": True, **result}


@app.get("/api/captures/{capture_id}")
async def get_capture(capture_id: str, user: dict = Depends(get_current_user)):
    return _require_own_capture(capture_id, user)


@app.get("/api/captures/{capture_id}/download")
async def download_capture(capture_id: str, request: Request, user: dict = Depends(get_current_user)):
    # Encrypting at rest and then handing the plaintext to a cleartext socket
    # would defeat the point of the storage work entirely.
    _require_secure_transport(request)
    _info, path = _require_readable_capture(capture_id, user)

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


# --- saved views ---
#
# A named display filter, remembered against one capture for the user who
# saved it. The viewer offers them as tabs, so a capture you come back to a
# week later still has "auth traffic" and "retransmissions" where you left
# them, and each one downloads as its own pcap containing only what it selects.
#
# Stored in SQLite rather than the browser, unlike the drawer and split-height
# state in app.js. Those are per-viewer conveniences worth nothing if lost;
# these are named, deliberate work that the user expects to find again -- and
# a download endpoint has to be able to read the filter server-side anyway.


def _view_or_404(capture_id: str, view_id: str, user: dict) -> dict:
    row = db.get_capture_view(view_id, user["id"])
    # capture_id is checked as well as the view's owner: a view id is only
    # meaningful against the capture it belongs to, and accepting a mismatched
    # pair would let one capture's URL serve another's filter.
    if not row or row["capture_id"] != capture_id:
        raise HTTPException(404, "view not found")
    return row


@app.get("/api/captures/{capture_id}/views")
async def list_capture_views(capture_id: str, user: dict = Depends(get_current_user)):
    _require_own_capture(capture_id, user)
    return [CaptureView(**row) for row in db.list_capture_views(capture_id, user["id"])]


@app.post("/api/captures/{capture_id}/views")
async def create_capture_view(
    capture_id: str,
    body: CaptureViewRequest,
    user: dict = Depends(get_current_user),
):
    _require_own_capture(capture_id, user)
    try:
        row = db.add_capture_view(capture_id, user["id"], body.name, body.display_filter)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return CaptureView(**row)


@app.put("/api/captures/{capture_id}/views/{view_id}")
async def update_capture_view(
    capture_id: str,
    view_id: str,
    body: CaptureViewRequest,
    user: dict = Depends(get_current_user),
):
    """Rename a view, change the filter behind it, or both."""
    _require_own_capture(capture_id, user)
    _view_or_404(capture_id, view_id, user)
    try:
        row = db.update_capture_view(view_id, user["id"], body.name, body.display_filter)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    if not row:
        raise HTTPException(404, "view not found")
    return CaptureView(**row)


@app.delete("/api/captures/{capture_id}/views/{view_id}")
async def delete_capture_view(
    capture_id: str,
    view_id: str,
    user: dict = Depends(get_current_user),
):
    _require_own_capture(capture_id, user)
    _view_or_404(capture_id, view_id, user)
    if not db.delete_capture_view(view_id, user["id"]):
        raise HTTPException(404, "view not found")
    return {"ok": True}


@app.get("/api/captures/{capture_id}/views/{view_id}/download")
async def download_capture_view(
    capture_id: str,
    view_id: str,
    request: Request,
    user: dict = Depends(get_current_user),
):
    """The capture, filtered to this view, as its own pcap.

    HTTPS-only for the same reason the full download is: what comes back is
    still packet data, and a filtered capture is not a less sensitive one --
    "just the authentication traffic" is frequently the most sensitive slice
    there is.
    """
    _require_secure_transport(request)
    _info, path = _require_readable_capture(capture_id, user)
    view = _view_or_404(capture_id, view_id, user)

    if not view["display_filter"]:
        # A view with no filter is the whole capture. Saying so beats handing
        # back a copy through a second code path that means the same thing.
        raise HTTPException(
            400,
            "this view has no filter -- download the capture itself instead",
        )

    # tshark spawns per download, same as a packet list, so it draws on the
    # same per-user budget.
    if not packet_rate_limiter.allow(user["id"]):
        raise HTTPException(429, "too many filtered download requests, slow down")

    try:
        source = vault.source_for(path)
    except CryptoError as exc:
        raise HTTPException(503, str(exc))

    filename = _view_download_name(capture_id, view["name"])

    async def body():
        try:
            async for chunk in stream_filtered_pcap(source, view["display_filter"]):
                yield chunk
        except (CryptoError, DisplayFilterError):
            logger.exception("filtered download failed for view %s", view_id)
            # The response has begun, so cutting it off is the only signal
            # left -- same reasoning as the full download.
            raise

    return StreamingResponse(
        body(),
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# A view name is free text; a Content-Disposition filename is not. Everything
# outside this set is replaced rather than quoted, so the header can never be
# split by a newline or terminated early by a quote.
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _view_download_name(capture_id: str, view_name: str) -> str:
    slug = _FILENAME_SAFE.sub("-", view_name).strip("-")[:60]
    return f"{capture_id}-{slug}.pcap" if slug else f"{capture_id}-view.pcap"


# --- sanitized downloads ---
#
# A copy of a finished capture with its credentials, addresses and names
# replaced, built while it downloads (backend.sanitizer). The stored capture is
# untouched and no sanitized copy is ever written anywhere.
#
# What was replaced -- and, more importantly, what could not be -- is known only
# once the whole capture has gone through, by which point the response body is
# long gone. So the browser names each download with a random ticket, and asks
# for that ticket's summary afterwards. Summaries hold counts, protocol names
# and port numbers only, never a value from the capture; they are kept in
# memory, briefly, and handed out once.

_SANITIZE_TICKET = re.compile(r"[A-Za-z0-9_-]{16,64}")
_SANITIZE_SUMMARY_TTL_SECONDS = 15 * 60
_SANITIZE_SUMMARY_LIMIT = 500
_sanitize_summaries: dict[tuple[str, str, str], tuple[float, dict]] = {}


def _remember_sanitize_summary(key: tuple[str, str, str], entry: dict) -> None:
    now = time.monotonic()
    for stale in [k for k, (at, _) in _sanitize_summaries.items() if now - at > _SANITIZE_SUMMARY_TTL_SECONDS]:
        del _sanitize_summaries[stale]
    if key not in _sanitize_summaries and len(_sanitize_summaries) >= _SANITIZE_SUMMARY_LIMIT:
        del _sanitize_summaries[min(_sanitize_summaries, key=lambda k: _sanitize_summaries[k][0])]
    _sanitize_summaries[key] = (now, entry)


def _sanitized_download_name(info, view: dict | None) -> str:
    base = _FILENAME_SAFE.sub("-", info.name).strip("-")[:60] if info.name else ""
    base = base or info.id
    if view:
        slug = _FILENAME_SAFE.sub("-", view["name"]).strip("-")[:60]
        base = f"{base}-{slug or 'view'}"
    return f"{base}-sanitized.pcap"


@app.get("/api/captures/{capture_id}/sanitize")
async def download_sanitized_capture(
    capture_id: str,
    request: Request,
    user: dict = Depends(get_current_user),
    credentials: bool = True,
    ips: bool = True,
    keep_private: bool = False,
    macs: bool = True,
    keep_oui: bool = False,
    hostnames: bool = False,
    usernames: bool = False,
    strip_payload: bool = False,
    view: str = "",
    ticket: str = "",
):
    """The capture, or one saved view of it, sanitized as it downloads.

    HTTPS-only like every other download. Sanitizing is best effort by nature
    -- no tool finds every secret in every protocol -- so a sanitized file is
    still treated as packet data until the operator has read its summary.
    """
    _require_secure_transport(request)
    info, path = _require_readable_capture(capture_id, user)
    view_row = _view_or_404(capture_id, view, user) if view else None

    options = SanitizeOptions(
        credentials=credentials, ips=ips, keep_private=keep_private, macs=macs,
        keep_oui=keep_oui, hostnames=hostnames, usernames=usernames,
        strip_payload=strip_payload,
    )
    if not options.anything_selected():
        raise HTTPException(400, "choose at least one thing to sanitize")
    if ticket and not _SANITIZE_TICKET.fullmatch(ticket):
        raise HTTPException(400, "invalid summary ticket")

    # Two tshark runs per download at least, so the same per-user budget as a
    # filtered download.
    if not packet_rate_limiter.allow(user["id"]):
        raise HTTPException(429, "too many sanitize requests, slow down")

    try:
        source = vault.source_for(path)
        key = capture_key(vault, path, capture_id, DATA_DIR)
        await check_capture(source)
    except CryptoError as exc:
        raise HTTPException(503, str(exc))
    except SanitizeError as exc:
        raise HTTPException(400, str(exc))
    except OSError:
        logger.exception("could not prepare capture %s for sanitizing", capture_id)
        raise HTTPException(500, "could not prepare the capture for sanitizing")

    if view_row and view_row["display_filter"]:
        source = FilteredSource(source, view_row["display_filter"])

    summary = SanitizeSummary()
    summary_key = (user["id"], capture_id, ticket)
    if ticket:
        _remember_sanitize_summary(summary_key, {"done": False})

    async def body():
        outcome: dict = {"done": True, "error": "the download was interrupted before it finished"}
        try:
            async for chunk in stream_sanitized_pcap(source, key, options, summary):
                yield chunk
            outcome = {"done": True, "summary": summary.as_dict()}
        except (CryptoError, DisplayFilterError, SanitizeError) as exc:
            logger.exception("sanitized download of %s failed", capture_id)
            outcome = {"done": True, "error": str(exc)[:400]}
            # The response has begun, so cutting it off is the only signal
            # left -- a truncated file must never pass for a sanitized one.
            raise
        except Exception:
            logger.exception("sanitized download of %s failed", capture_id)
            outcome = {"done": True, "error": "sanitizing failed; see the server log"}
            raise
        finally:
            if ticket:
                _remember_sanitize_summary(summary_key, outcome)

    return StreamingResponse(
        body(),
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="{_sanitized_download_name(info, view_row)}"',
        },
    )


@app.get("/api/captures/{capture_id}/sanitize/summary")
async def sanitized_download_summary(
    capture_id: str,
    ticket: str,
    user: dict = Depends(get_current_user),
):
    """What one sanitized download replaced, once it has finished.

    {"done": false} while it is still running. A finished summary is handed
    out once and forgotten.
    """
    _require_own_capture(capture_id, user)
    if not _SANITIZE_TICKET.fullmatch(ticket):
        raise HTTPException(400, "invalid summary ticket")
    key = (user["id"], capture_id, ticket)
    held = _sanitize_summaries.get(key)
    if held is None:
        raise HTTPException(404, "no sanitized download with that ticket")
    entry = held[1]
    if entry.get("done"):
        _sanitize_summaries.pop(key, None)
    return entry


# --- packets ---

@app.get("/api/captures/{capture_id}/packets")
async def list_packets(
    capture_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=5000),
    display_filter: str = Query(""),
    flags: str = Query(""),
    resolve_names: bool = Query(False),
    columns: str = Query("", max_length=64 * MAX_EXTRA_COLUMNS),
    user: dict = Depends(get_current_user),
):
    if not packet_rate_limiter.allow(user["id"]):
        raise HTTPException(429, "too many packet list requests, slow down")
    view_flags = [f for f in flags.split(",") if f]
    unknown = set(view_flags) - ALLOWED_VIEW_FLAGS
    if unknown:
        raise HTTPException(400, f"unknown view flags: {sorted(unknown)}")
    # The added columns, checked for shape and count here rather than against
    # tshark's registry: that check ran when the layout was saved, and this is
    # the hot path. What matters on every call is that nothing reaches argv
    # that could be read as a flag.
    try:
        extra_fields = validate_column_fields([c for c in columns.split(",") if c])
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    info, path = _require_readable_capture(capture_id, user)
    try:
        packets = await get_packet_list(
            vault.source_for(path), offset=offset, limit=limit,
            display_filter=display_filter, view_flags=view_flags,
            resolve_names=resolve_names, interface_names=info.interface_names,
            extra_fields=extra_fields,
        )
        return {"packets": packets, "total": info.packet_count}
    except ColumnFieldError as exc:
        # A column naming a field this tshark does not dissect. 400 rather than
        # the 500 below, and with tshark's own words: the layout is the thing to
        # fix, and an empty packet list would say nothing at all.
        raise HTTPException(400, f"a column asks for a field tshark does not have: {exc}")
    except DisplayFilterError as exc:
        # The filter is wrong, not the capture. Structured so the UI can put the
        # message under the filter box instead of blanking the packet list.
        raise HTTPException(400, {"code": "bad_display_filter", "reason": str(exc)})
    except Exception:
        logger.exception("packet list failed")
        raise HTTPException(500, "failed to list packets")


@app.get("/api/captures/{capture_id}/packets/{frame_number}")
async def packet_detail(capture_id: str, frame_number: int, user: dict = Depends(get_current_user)):
    # Shares the packet-listing budget: this spawns tshark twice per call
    # (PDML, then the frame bytes), so leaving it unthrottled left the more
    # expensive of the two packet routes as the one with no cap at all.
    if not packet_rate_limiter.allow(user["id"]):
        raise HTTPException(429, "too many packet detail requests, slow down")
    _info, path = _require_readable_capture(capture_id, user)
    try:
        return await get_packet_detail(vault.source_for(path), frame_number)
    except Exception:
        raise HTTPException(500, "failed to get packet detail")


@app.get("/api/captures/{capture_id}/protocol-hierarchy")
async def protocol_hierarchy(
    capture_id: str, display_filter: str = Query(""), user: dict = Depends(get_current_user),
):
    """Statistics > Protocol Hierarchy, over the whole capture or a display
    filter's slice of it. Shares the packet-list budget: one tshark spawn
    over the capture, same cost class as listing it."""
    if not packet_rate_limiter.allow(user["id"]):
        raise HTTPException(429, "too many requests, slow down")
    _info, path = _require_readable_capture(capture_id, user)
    try:
        return await get_protocol_hierarchy(vault.source_for(path), display_filter)
    except DisplayFilterError as exc:
        raise HTTPException(400, {"code": "bad_display_filter", "reason": str(exc)})
    except Exception:
        logger.exception("protocol hierarchy failed")
        raise HTTPException(500, "failed to compute protocol hierarchy")


@app.get("/api/captures/{capture_id}/conversations")
async def conversations(
    capture_id: str, display_filter: str = Query(""), user: dict = Depends(get_current_user),
):
    """Statistics > Conversations and Endpoints, from the same tshark pass."""
    if not packet_rate_limiter.allow(user["id"]):
        raise HTTPException(429, "too many requests, slow down")
    _info, path = _require_readable_capture(capture_id, user)
    try:
        convs, endpoints = await get_conversations(vault.source_for(path), display_filter)
        return {"conversations": convs, "endpoints": endpoints}
    except DisplayFilterError as exc:
        raise HTTPException(400, {"code": "bad_display_filter", "reason": str(exc)})
    except Exception:
        logger.exception("conversations failed")
        raise HTTPException(500, "failed to compute conversations")


@app.get("/api/captures/{capture_id}/stream/{protocol}/{stream}")
async def follow_stream(
    capture_id: str, protocol: str, stream: int, user: dict = Depends(get_current_user),
):
    """Follow TCP/UDP Stream: one conversation, reassembled in order."""
    if protocol not in ("tcp", "udp"):
        raise HTTPException(400, "protocol must be tcp or udp")
    if not packet_rate_limiter.allow(user["id"]):
        raise HTTPException(429, "too many requests, slow down")
    _info, path = _require_readable_capture(capture_id, user)
    try:
        return await get_follow_stream(vault.source_for(path), protocol, stream)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    except Exception:
        logger.exception("follow stream failed")
        raise HTTPException(500, "failed to follow stream")


# --- static files (frontend) ---


class RevalidatedStatic(StaticFiles):
    """Serve the frontend with Cache-Control: no-cache.

    StaticFiles sends ETag and Last-Modified and nothing else. With no
    Cache-Control at all a browser falls back to heuristic freshness -- around
    a tenth of the file's age since Last-Modified -- and serves app.js from its
    own cache without asking us. The result is a deployment where the backend
    is the new version and the page is the old one, which from the outside is
    indistinguishable from the fix not working: a button that was repaired and
    released still does nothing, because the browser is running last release's
    script against this release's API.

    That is not hypothetical. dev.18 shipped a fix for a dead button and the
    button stayed dead for exactly this reason.

    "no-cache" means revalidate before reuse, not "do not store". The ETag is
    already being sent, so a reload costs one conditional request answered 304
    with no body -- the file is still not re-downloaded unless it changed.
    """

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers.setdefault("Cache-Control", "no-cache")
        return response


frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.is_dir():
    app.mount("/", RevalidatedStatic(directory=str(frontend_dir), html=True), name="frontend")
