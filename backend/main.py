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
    TRUST_DURATION_DAYS,
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
MAX_CAPTURE_SECONDS = int(os.environ.get("MAX_CAPTURE_SECONDS", "300"))
MAX_CAPTURE_PACKETS = int(os.environ.get("MAX_CAPTURE_PACKETS", "100000"))

app = FastAPI(title="pcap-server", version="0.1.0")

db = Database(DATA_DIR / "pcap-server.db")
ssh_manager = SSHManager(SSH_KEYS_DIR)
capture_manager = CaptureManager(ssh_manager, CAPTURES_DIR, MAX_CAPTURE_SECONDS, MAX_CAPTURE_PACKETS)


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
        "user": {"username": user["username"], "totp_confirmed": bool(user["totp_confirmed"])} if user else None,
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

    user_id = str(uuid.uuid4())[:8]
    pw_hash = hash_password(req.password)
    db.create_user(user_id, req.username, pw_hash, is_admin=True)

    token, expires = create_session_token(db, user_id)
    response.set_cookie("session", token, httponly=True, samesite="strict", max_age=8 * 3600)
    return {"ok": True, "user_id": user_id, "needs_totp_setup": True}


@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    user = db.get_user_by_username(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "invalid credentials")

    if user["totp_confirmed"]:
        device_token = request.cookies.get("device_trust")
        device_trusted = check_device_trust(db, user["id"], device_token)
        if not device_trusted:
            if not req.totp_code:
                return {"needs_totp": True}
            if not verify_totp(user["totp_secret"], req.totp_code):
                raise HTTPException(401, "invalid TOTP code")
            if req.trust_device:
                trust_token = create_device_trust(db, user["id"])
                response.set_cookie(
                    "device_trust", trust_token,
                    httponly=True, samesite="strict",
                    max_age=TRUST_DURATION_DAYS * 86400,
                )

    token, expires = create_session_token(db, user["id"])
    response.set_cookie("session", token, httponly=True, samesite="strict", max_age=8 * 3600)
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
async def admin_create_user(req: RegisterRequest, user: dict = Depends(get_current_user)):
    if not user["is_admin"]:
        raise HTTPException(403, "admin only")
    if len(req.username) < 3:
        raise HTTPException(400, "username must be at least 3 characters")
    if len(req.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    if db.get_user_by_username(req.username):
        raise HTTPException(409, "username taken")
    user_id = str(uuid.uuid4())[:8]
    db.create_user(user_id, req.username, hash_password(req.password))
    return {"ok": True, "user_id": user_id}


@app.get("/api/admin/users")
async def admin_list_users(user: dict = Depends(get_current_user)):
    if not user["is_admin"]:
        raise HTTPException(403, "admin only")
    return db.list_users()


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
    except Exception as exc:
        raise HTTPException(502, f"connection failed: {exc}")


# --- saved servers (persistent, per-user) ---

@app.get("/api/saved-servers")
async def list_saved_servers(user: dict = Depends(get_current_user)):
    return db.list_saved_servers(user["id"])


@app.post("/api/saved-servers")
async def save_server(req: SaveServerRequest, user: dict = Depends(get_current_user)):
    key_path = (SSH_KEYS_DIR / req.ssh_key_name).resolve()
    if not str(key_path).startswith(str(SSH_KEYS_DIR.resolve())):
        raise HTTPException(400, "invalid key path")
    server_id = str(uuid.uuid4())[:8]
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
    return list(capture_manager.captures.values())


@app.post("/api/captures")
async def start_capture(req: CaptureRequest, user: dict = Depends(get_current_user)):
    srv = runtime_servers.get(req.server_id)
    if not srv:
        raise HTTPException(404, "server not found")
    try:
        info = await capture_manager.start(req, srv)
        return info
    except Exception as exc:
        logger.exception("failed to start capture")
        raise HTTPException(500, str(exc))


@app.post("/api/captures/{capture_id}/stop")
async def stop_capture(capture_id: str, user: dict = Depends(get_current_user)):
    try:
        return await capture_manager.stop(capture_id)
    except KeyError:
        raise HTTPException(404, "capture not found")


@app.delete("/api/captures/{capture_id}")
async def delete_capture(capture_id: str, user: dict = Depends(get_current_user)):
    try:
        await capture_manager.delete(capture_id)
        return {"ok": True}
    except KeyError:
        raise HTTPException(404, "capture not found")


@app.get("/api/captures/{capture_id}")
async def get_capture(capture_id: str, user: dict = Depends(get_current_user)):
    info = capture_manager.get(capture_id)
    if not info:
        raise HTTPException(404, "capture not found")
    return info


@app.get("/api/captures/{capture_id}/download")
async def download_capture(capture_id: str, user: dict = Depends(get_current_user)):
    info = capture_manager.get(capture_id)
    if not info:
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
    if not info:
        raise HTTPException(404, "capture not found")
    if info.status != CaptureStatus.COMPLETED:
        raise HTTPException(400, "capture not yet completed")
    path = Path(info.local_path)
    if not path.exists():
        raise HTTPException(404, "pcap file missing")
    try:
        packets = await get_packet_list(path, offset=offset, limit=limit, display_filter=display_filter)
        return {"packets": packets, "total": info.packet_count}
    except Exception as exc:
        logger.exception("packet list failed")
        raise HTTPException(500, str(exc))


@app.get("/api/captures/{capture_id}/packets/{frame_number}")
async def packet_detail(capture_id: str, frame_number: int, user: dict = Depends(get_current_user)):
    info = capture_manager.get(capture_id)
    if not info:
        raise HTTPException(404, "capture not found")
    if info.status != CaptureStatus.COMPLETED:
        raise HTTPException(400, "capture not yet completed")
    path = Path(info.local_path)
    if not path.exists():
        raise HTTPException(404, "pcap file missing")
    try:
        return await get_packet_detail(path, frame_number)
    except Exception as exc:
        raise HTTPException(500, str(exc))


# --- reference ---

@app.get("/api/tcpdump-flags")
async def tcpdump_flags(user: dict = Depends(get_current_user)):
    return {"allowed": sorted(ALLOWED_TCPDUMP_FLAGS)}


# --- static files (frontend) ---

frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
