from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
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
    validate_session,
    verify_password,
    verify_totp,
)
from backend.capture import CaptureManager
from backend.database import Database
from backend.models import (
    ALLOWED_TCPDUMP_FLAGS,
    CaptureRequest,
    CaptureStatus,
    ServerAuth,
    ServerInfo,
)
from backend.packet_parser import get_packet_detail, get_packet_list
from backend.ssh_manager import SSHManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SSH_KEYS_DIR = Path(os.environ.get("SSH_KEYS_DIR", "/app/ssh-keys"))
CAPTURES_DIR = Path(os.environ.get("CAPTURES_DIR", "/app/captures"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))

app = FastAPI(title="pcap-server", version="0.1.0-dev.1")

db = Database(DATA_DIR / "pcap-server.db")
ssh_manager = SSHManager(SSH_KEYS_DIR, db, DATA_DIR)
capture_manager = CaptureManager(ssh_manager, CAPTURES_DIR, db.get_setting_int)
rate_limiter = RateLimiter(
    max_attempts=db.get_setting_int("rate_limit_max_attempts"),
    lockout_minutes=db.get_setting_int("rate_limit_lockout_minutes"),
)


@app.on_event("shutdown")
async def on_shutdown():
    await capture_manager.shutdown()


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


class SaveServerRequest(BaseModel):
    name: str
    hostname: str
    port: int = 22
    username: str
    ssh_key_name: str


class SettingUpdate(BaseModel):
    key: str
    value: str


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_current_user(request: Request) -> dict:
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


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if not user["is_admin"]:
        raise HTTPException(403, "admin only")
    return user


def _set_session_cookie(response: Response, token: str) -> None:
    max_age = db.get_setting_int("session_duration_hours") * 3600
    response.set_cookie(
        "session", token,
        httponly=True, samesite="strict", secure=True,
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
    pw_hash = hash_password(req.password)
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
    if not user or not verify_password(req.password, user["password_hash"]):
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
                    httponly=True, samesite="strict", secure=True,
                    max_age=trust_days * 86400,
                )

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
async def totp_setup(user: dict = Depends(get_current_user)):
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
async def totp_confirm(req: TOTPSetupRequest, user: dict = Depends(get_current_user)):
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
    db.create_user(user_id, req.username, hash_password(req.password))
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
    try:
        int_val = int(req.value)
        if int_val < 1:
            raise ValueError
    except ValueError:
        raise HTTPException(400, "value must be a positive integer")
    db.set_setting(req.key, req.value)
    if req.key in ("rate_limit_max_attempts", "rate_limit_lockout_minutes"):
        rate_limiter.update_config(
            db.get_setting_int("rate_limit_max_attempts"),
            db.get_setting_int("rate_limit_lockout_minutes"),
        )
    return {"ok": True}


# --- admin: known hosts ---

@app.get("/api/admin/known-hosts")
async def admin_list_known_hosts(user: dict = Depends(require_admin)):
    return db.list_known_hosts()


@app.post("/api/admin/known-hosts/scan")
async def admin_scan_host(request: Request, user: dict = Depends(require_admin)):
    body = await request.json()
    hostname = body.get("hostname", "").strip()
    port = int(body.get("port", 22))
    if not hostname or any(c in hostname for c in " ;|&$`\\\n\r"):
        raise HTTPException(400, "invalid hostname")
    if not (1 <= port <= 65535):
        raise HTTPException(400, "invalid port")
    keys = await ssh_manager.scan_host_keys(hostname, port, user["id"])
    if not keys:
        raise HTTPException(502, "no host keys found")
    return {"ok": True, "keys": keys}


@app.delete("/api/admin/known-hosts/{host_id}")
async def admin_delete_known_host(host_id: int, user: dict = Depends(require_admin)):
    if not db.delete_known_host(host_id):
        raise HTTPException(404, "known host not found")
    return {"ok": True}


# --- servers (runtime, per-session) ---

runtime_servers: dict[str, ServerInfo] = {}


@app.get("/api/servers")
async def list_servers(user: dict = Depends(get_current_user)):
    return list(runtime_servers.values())


@app.post("/api/servers")
async def add_server(auth: ServerAuth, user: dict = Depends(get_current_user)):
    key_path = (SSH_KEYS_DIR / auth.ssh_key_name).resolve()
    if not str(key_path).startswith(str(SSH_KEYS_DIR.resolve())):
        raise HTTPException(400, "invalid key path")
    if not key_path.exists():
        raise HTTPException(400, f"SSH key '{auth.ssh_key_name}' not found in keys directory")
    info = ServerInfo(**auth.model_dump())
    runtime_servers[info.id] = info
    return info


@app.delete("/api/servers/{server_id}")
async def remove_server(server_id: str, user: dict = Depends(get_current_user)):
    if server_id not in runtime_servers:
        raise HTTPException(404, "server not found")
    del runtime_servers[server_id]
    return {"ok": True}


@app.post("/api/servers/{server_id}/test")
async def test_server(server_id: str, user: dict = Depends(get_current_user)):
    srv = runtime_servers.get(server_id)
    if not srv:
        raise HTTPException(404, "server not found")
    try:
        result = await ssh_manager.test_connection(srv)
        return {"ok": True, "result": result}
    except ConnectionError as exc:
        raise HTTPException(502, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(502, "connection failed")


# --- saved servers (persistent, per-user) ---

@app.get("/api/saved-servers")
async def list_saved_servers(user: dict = Depends(get_current_user)):
    return db.list_saved_servers(user["id"])


@app.post("/api/saved-servers")
async def save_server(req: SaveServerRequest, user: dict = Depends(get_current_user)):
    key_path = (SSH_KEYS_DIR / req.ssh_key_name).resolve()
    if not str(key_path).startswith(str(SSH_KEYS_DIR.resolve())):
        raise HTTPException(400, "invalid key path")
    server_id = str(uuid.uuid4())
    db.save_server(server_id, user["id"], req.name, req.hostname, req.port, req.username, req.ssh_key_name)
    return {"ok": True, "id": server_id}


@app.delete("/api/saved-servers/{server_id}")
async def delete_saved_server(server_id: str, user: dict = Depends(get_current_user)):
    if not db.delete_saved_server(server_id, user["id"]):
        raise HTTPException(404, "saved server not found")
    return {"ok": True}


@app.post("/api/saved-servers/{server_id}/load")
async def load_saved_server(server_id: str, user: dict = Depends(get_current_user)):
    saved = db.get_saved_server(server_id, user["id"])
    if not saved:
        raise HTTPException(404, "saved server not found")
    auth = ServerAuth(
        hostname=saved["hostname"],
        port=saved["port"],
        username=saved["username"],
        ssh_key_name=saved["ssh_key_name"],
    )
    info = ServerInfo(**auth.model_dump())
    runtime_servers[info.id] = info
    return info


# --- ssh keys ---

@app.get("/api/ssh-keys")
async def list_ssh_keys(user: dict = Depends(get_current_user)):
    SSH_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    keys = []
    for f in SSH_KEYS_DIR.iterdir():
        if f.is_file() and f.name != ".gitkeep":
            keys.append(f.name)
    return sorted(keys)


# --- captures ---

@app.get("/api/captures")
async def list_captures(user: dict = Depends(get_current_user)):
    return capture_manager.list_for_user(user["id"])


@app.post("/api/captures")
async def start_capture(req: CaptureRequest, user: dict = Depends(get_current_user)):
    srv = runtime_servers.get(req.server_id)
    if not srv:
        raise HTTPException(404, "server not found")
    try:
        info = await capture_manager.start(req, srv, user["id"])
        return info
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
async def download_capture(capture_id: str, user: dict = Depends(get_current_user)):
    info = capture_manager.get(capture_id)
    if not info or info.user_id != user["id"]:
        raise HTTPException(404, "capture not found")
    if info.status != CaptureStatus.COMPLETED:
        raise HTTPException(400, "capture not yet completed")
    path = Path(info.local_path)
    if not path.exists():
        raise HTTPException(404, "pcap file not found on disk")
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=f"{capture_id}.pcap")


# --- packets ---

@app.get("/api/captures/{capture_id}/packets")
async def list_packets(
    capture_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=5000),
    display_filter: str = Query(""),
    user: dict = Depends(get_current_user),
):
    info = capture_manager.get(capture_id)
    if not info or info.user_id != user["id"]:
        raise HTTPException(404, "capture not found")
    if info.status != CaptureStatus.COMPLETED:
        raise HTTPException(400, "capture not yet completed")
    path = Path(info.local_path)
    if not path.exists():
        raise HTTPException(404, "pcap file missing")
    try:
        packets = await get_packet_list(path, offset=offset, limit=limit, display_filter=display_filter)
        return {"packets": packets, "total": info.packet_count}
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
        return await get_packet_detail(path, frame_number)
    except Exception:
        raise HTTPException(500, "failed to get packet detail")


# --- reference ---

@app.get("/api/tcpdump-flags")
async def tcpdump_flags(user: dict = Depends(get_current_user)):
    return {"allowed": sorted(ALLOWED_TCPDUMP_FLAGS)}


# --- static files (frontend) ---

frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
