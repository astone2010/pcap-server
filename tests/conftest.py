"""backend.main runs Database(), CaptureVault() and delete_all_sessions() at
module scope, and SystemExit(1)s on a refused vault. So the environment it
reads has to exist before backend.main is ever imported -- which means before
pytest imports any test module that imports it, not inside a fixture (a
fixture, even session-scoped, only runs after collection has already imported
the test modules). Plain module-level code in conftest.py runs at collection
time, ahead of that import, which is why it lives here instead of in a
fixture."""

from __future__ import annotations

import base64
import os
import secrets
import tempfile

_tmp_root = tempfile.mkdtemp(prefix="pcap-server-tests-")

os.environ.setdefault("DATA_DIR", os.path.join(_tmp_root, "data"))
os.environ.setdefault("CAPTURES_DIR", os.path.join(_tmp_root, "captures"))
os.environ.setdefault("SSH_KEYS_DIR", os.path.join(_tmp_root, "ssh-keys"))
os.environ.setdefault("PCAP_MASTER_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
os.environ.setdefault("COOKIE_SECURE", "false")

os.makedirs(os.environ["DATA_DIR"], exist_ok=True)
os.makedirs(os.environ["CAPTURES_DIR"], exist_ok=True)
os.makedirs(os.environ["SSH_KEYS_DIR"], exist_ok=True)
