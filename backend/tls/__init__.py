"""Built-in HTTPS: pcap-server obtains, stores, serves and renews its own certificate.

Self-contained on purpose. The rest of the app touches it through what this
module exports, and nothing else:

    TlsManager              state, issuance, renewal, reload, restart
    build_router()          the Admin panel's routes
    INSECURE_ALLOWED_PATHS  those routes, for the read-only-over-HTTP exception
    key_path_in_memory, harden, TLS12_CIPHERS
                            what backend.serve needs to start uvicorn over TLS

Inside:

    providers.py            the DNS providers and the credential allowlist
    lego_providers.json     generated from lego's own metadata
    store.py                what is kept in DATA_DIR/tls, sealed or not
    lego.py                 the one place lego runs
    manager.py              the running app's view of all of it
    serving.py              the memfd hand-off and the TLS settings
    routes.py, cli.py       the two ways in: Admin panel and `python -m backend.tls`

The ACME client is lego (https://go-acme.github.io/lego/), a single static
binary the Dockerfile downloads by pinned version and checksum.
"""

from backend.tls.errors import AcmeBusy, AcmeError
from backend.tls.manager import TlsManager
from backend.tls.routes import INSECURE_ALLOWED_PATHS, build_router
from backend.tls.serving import TLS12_CIPHERS, harden, key_path_in_memory

__all__ = [
    "AcmeBusy", "AcmeError", "INSECURE_ALLOWED_PATHS", "TLS12_CIPHERS", "TlsManager",
    "build_router", "harden", "key_path_in_memory",
]
