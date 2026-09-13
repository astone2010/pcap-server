"""The container's entry point: start uvicorn, over HTTPS when a certificate is stored.

    python -m backend.serve [--host 0.0.0.0] [--port 8080]

This replaces `python -m uvicorn backend.main:app` because the order matters.
uvicorn's own CLI builds its TLS context before it imports the app, but the
TLS key is sealed and only the app's vault can open it. So the app is imported
first, the key opened into a memfd (backend/tls.py), and uvicorn configured
from that.

When an admin switches from HTTP to HTTPS, the server exits and this process
re-executes itself in place -- same PID, so the container does not stop.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

import uvicorn

from backend.tls import TLS12_CIPHERS, AcmeError, harden, key_path_in_memory

logger = logging.getLogger("backend.serve")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m backend.serve")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--log-level", default="info")
    return p.parse_args(argv)


def build_config(
    app, tls_manager, host: str, port: int, log_level: str = "info",
) -> tuple[uvicorn.Config, object]:
    """A loaded uvicorn config, over TLS if there is material to serve."""
    try:
        material = tls_manager.serving_material()
    except AcmeError as exc:
        logger.error(
            "HTTPS NOT ENABLED: %s\nServing plain HTTP, which is read-only.", exc
        )
        material = None

    if material is None:
        config = uvicorn.Config(app, host=host, port=port, log_level=log_level)
        config.load()
        return config, None

    cert_path, key_pem, info = material
    with key_path_in_memory(key_pem) as key_path:
        config = uvicorn.Config(
            app, host=host, port=port, log_level=log_level,
            ssl_certfile=str(cert_path), ssl_keyfile=key_path, ssl_ciphers=TLS12_CIPHERS,
        )
        # load() is what reads the key; the memfd closes straight after.
        config.load()
    del key_pem
    harden(config.ssl)
    logger.info("serving HTTPS for %s (certificate expires %s)",
                ", ".join(info.names), info.not_after.date())
    return config, info


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    # Importing the app opens the database and the vault, and exits on a
    # refused start -- exactly as it did under uvicorn's CLI.
    from backend import main as app_module

    config, info = build_config(
        app_module.app, app_module.tls_manager, args.host, args.port, args.log_level,
    )
    server = uvicorn.Server(config)
    app_module.tls_manager.attach(server, config.ssl if info else None, info)
    server.run()

    if app_module.tls_manager.restart_requested:
        logger.info("restarting to switch to HTTPS")
        sys.stdout.flush()
        sys.stderr.flush()
        os.execv(sys.executable, [sys.executable, "-m", "backend.serve", *sys.argv[1:]])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
