"""The Admin panel's HTTPS routes.

Built by build_router() so this package needs nothing from main.py but the two
things it is handed: the admin dependency, and a way to count running captures.

These routes are reachable over plain HTTP -- INSECURE_ALLOWED_PATHS, which
main.py folds into its read-only exception list. They are how an installation
gets *off* plain HTTP without a proxy, so refusing them there would leave the
proxy guides as the only way out. They stay admin-only, and what crossing HTTP
costs is stated rather than hidden: the DNS credentials in the request can be
read off the wire. The Admin panel says so, and `python -m backend.tls issue`
inside the container does the same job without them touching the network.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.tls import providers
from backend.tls.errors import AcmeBusy, AcmeError
from backend.tls.manager import TlsManager

logger = logging.getLogger("backend.tls")

INSECURE_ALLOWED_PATHS = frozenset({
    "/api/admin/tls",
    "/api/admin/tls/acme",
    "/api/admin/tls/renew",
    "/api/admin/tls/restart",
})


class AcmeRequest(BaseModel):
    # Plain str/dict, validated in the handler: a 422 echoes the submitted
    # value back, and these carry API credentials.
    domain: str = ""
    email: str = ""
    provider: str = ""
    credentials: dict = {}
    staging: bool = False
    validation_delay: str | int = ""


def _error(exc: Exception) -> HTTPException:
    return HTTPException(409 if isinstance(exc, AcmeBusy) else 400, str(exc))


def build_router(manager: TlsManager, require_admin, active_captures: Callable[[], int]) -> APIRouter:
    router = APIRouter()

    # status() reads the certificate and decrypts the stored credentials to name
    # them. Small, but disk and crypto all the same, so never on the event loop.
    async def status() -> dict:
        return await asyncio.to_thread(manager.status)

    @router.get("/api/admin/tls")
    async def tls_status(user: dict = Depends(require_admin)):
        return await status()

    @router.get("/api/admin/tls/providers")
    async def tls_providers(user: dict = Depends(require_admin)):
        return {"lego_version": providers.lego_version(), "providers": providers.catalog_for_ui()}

    @router.post("/api/admin/tls/acme")
    async def tls_issue(req: AcmeRequest, user: dict = Depends(require_admin)):
        """Request a certificate and store the settings. Blocks until lego is done."""
        try:
            info = await asyncio.to_thread(
                manager.issue, req.domain, req.email, req.provider, req.credentials, req.staging,
                req.validation_delay,
            )
        except (AcmeError, ValueError) as exc:
            raise _error(exc)
        logger.info("certificate issued for %s by admin %s", ", ".join(info.names), user["id"])
        return await status()

    @router.post("/api/admin/tls/renew")
    async def tls_renew(user: dict = Depends(require_admin)):
        try:
            await asyncio.to_thread(manager.renew)
        except AcmeError as exc:
            raise _error(exc)
        return await status()

    @router.post("/api/admin/tls/restart")
    async def tls_restart(user: dict = Depends(require_admin)):
        """Restart the server process so a stored certificate is served."""
        active = active_captures()
        if active:
            raise HTTPException(
                409,
                f"{active} capture(s) are still running, and restarting would end them. "
                "Stop them or let them finish first.",
            )
        try:
            manager.request_restart()
        except AcmeError as exc:
            raise _error(exc)
        logger.warning("restart into HTTPS requested by admin %s", user["id"])
        return {"ok": True, "restarting": True}

    @router.delete("/api/admin/tls")
    async def tls_remove(user: dict = Depends(require_admin)):
        """Forget the certificate, key, credentials and settings. Takes effect at the next restart."""
        removed = await asyncio.to_thread(manager.remove)
        logger.warning("built-in HTTPS material removed by admin %s: %s", user["id"], removed)
        return await status()

    return router
