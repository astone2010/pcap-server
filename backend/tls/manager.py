"""The running app's view of built-in HTTPS: serve, reload, renew, restart.

Renewal needs no restart: SSLContext.load_cert_chain on the context the server
is already using swaps the certificate for every later handshake. Housekeeping
renews under 30 days and reloads in place, and a renewal done from the CLI is
picked up the same way, by noticing the stored certificate's fingerprint has
changed.

The first switch does: going from plain HTTP to HTTPS changes what the
listening socket speaks. backend.serve re-executes itself when asked to, so the
process (PID 1 in the container) is replaced in place rather than exiting.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.crypto import CryptoError, Cryptor
from backend.tls import lego, providers, store
from backend.tls.errors import AcmeBusy, AcmeError
from backend.tls.serving import key_path_in_memory
from backend.tls.store import AcmeConfig, CertInfo

logger = logging.getLogger("backend.tls")

# A failed automatic renewal is retried, but not hourly: Let's Encrypt allows
# five failed validations per hostname per hour, and a broken credential fails
# the same way every time.
RENEW_RETRY_AFTER = timedelta(hours=6)


def require_unattended_key(vault) -> Cryptor:
    """Built-in TLS needs a master key the app can read without a person present."""
    if not vault.enabled:
        raise AcmeError(
            "built-in HTTPS needs a master key to seal the certificate's private key, "
            "and this installation runs without one"
        )
    if vault.mode == "passphrase":
        raise AcmeError(
            "built-in HTTPS is not available in passphrase mode: after a restart the "
            "app is locked, so it could not open its own certificate key to serve "
            "HTTPS -- and over plain HTTP it cannot be unlocked. Use MASTER_KEY_FILE, "
            "or a reverse proxy (docs/reverse-proxy.md)"
        )
    if vault.cryptor is None:
        raise AcmeError("the master key is not loaded")
    return vault.cryptor


class TlsManager:
    def __init__(self, tls_dir: Path, vault) -> None:
        self.tls_dir = tls_dir
        self._vault = vault
        self._context: ssl.SSLContext | None = None
        self._server = None
        self._loaded_fingerprint: str | None = None
        self._lock = threading.Lock()
        self._last_failure: datetime | None = None
        self.last_error: str | None = None
        self.restart_requested = False

    # --- startup ---

    def startup_check(self) -> None:
        """Refuse the one combination that cannot work: a certificate to serve
        and a key only a person can unlock. Raised as the vault's own
        StartupRefused so main.py reports it the same way."""
        from backend.vault import StartupRefused

        if store.has_material(self.tls_dir) and self._vault.mode == "passphrase":
            raise StartupRefused(
                "A certificate for built-in HTTPS is stored, but ENCRYPTION_MODE=passphrase\n"
                "is set. In passphrase mode the app starts locked, so it cannot open the\n"
                "certificate's private key to serve HTTPS -- and over plain HTTP it cannot\n"
                "be unlocked either.\n\n"
                "Either switch back to MASTER_KEY_FILE, or remove the stored certificate:\n"
                f"  rm {self.tls_dir}/{store.CERT_FILE} {self.tls_dir}/{store.KEY_FILE}\n"
                "and put pcap-server behind a reverse proxy instead (docs/reverse-proxy.md)."
            )

    def serving_material(self) -> tuple[Path, bytes, CertInfo] | None:
        """What to start uvicorn with, or None for plain HTTP."""
        if not store.has_material(self.tls_dir):
            return None
        cryptor = require_unattended_key(self._vault)
        info = store.stored_cert_info(self.tls_dir)
        try:
            key = store.open_key(self.tls_dir, cryptor)
        except (CryptoError, OSError) as exc:
            raise AcmeError(f"the stored TLS key could not be opened: {exc}") from exc
        return self.tls_dir / store.CERT_FILE, key, info

    def attach(self, server, context: ssl.SSLContext | None, info: CertInfo | None) -> None:
        """Called by backend.serve once uvicorn's config is loaded."""
        self._server = server
        self._context = context
        self._loaded_fingerprint = info.fingerprint if info else None

    @property
    def serving(self) -> bool:
        return self._context is not None

    # --- reload ---

    def reload_if_changed(self) -> bool:
        if self._context is None:
            return False
        info = store.stored_cert_info(self.tls_dir)
        if info is None or info.fingerprint == self._loaded_fingerprint:
            return False
        cryptor = require_unattended_key(self._vault)
        try:
            key = store.open_key(self.tls_dir, cryptor)
            with key_path_in_memory(key) as key_path:
                self._context.load_cert_chain(str(self.tls_dir / store.CERT_FILE), key_path)
        except (CryptoError, OSError, ssl.SSLError) as exc:
            raise AcmeError(f"the renewed certificate could not be loaded: {exc}") from exc
        self._loaded_fingerprint = info.fingerprint
        logger.info("now serving the renewed certificate (expires %s)", info.not_after.date())
        return True

    # --- issuance ---

    def issue(self, domain: str, email: str, provider: str, credentials: dict | None,
              staging: bool, validation_delay=None) -> CertInfo:
        """Blocking -- run it in a thread. Saves the settings only on success.

        A blank field keeps the value already stored for the same provider, so
        an admin changing the domain does not have to re-enter a token they
        cannot see. Choosing a different provider starts from nothing.
        """
        cryptor = require_unattended_key(self._vault)
        config = AcmeConfig.validated(domain, email, provider, staging, validation_delay)
        fresh = providers.validate_credentials(config.provider, credentials or {})
        stored_provider, stored = store.load_credentials(self.tls_dir, cryptor)
        merged = {**stored, **fresh} if stored_provider == config.provider else fresh
        if not merged:
            raise AcmeError(f"enter the {providers.get(config.provider).name} credentials")
        info = self._run(cryptor, config, merged)
        store.save_config(self.tls_dir, config)
        store.save_credentials(self.tls_dir, cryptor, config.provider, merged)
        return info

    def renew(self) -> CertInfo:
        cryptor = require_unattended_key(self._vault)
        config = store.load_config(self.tls_dir)
        if config is None:
            raise AcmeError("nothing is configured yet")
        stored_provider, credentials = store.load_credentials(self.tls_dir, cryptor)
        if stored_provider != config.provider or not credentials:
            raise AcmeError("no DNS credentials are stored for the configured provider")
        return self._run(cryptor, config, credentials)

    def _run(self, cryptor: Cryptor, config: AcmeConfig, credentials: dict[str, str]) -> CertInfo:
        if not self._lock.acquire(blocking=False):
            raise AcmeBusy("a certificate request is already running")
        try:
            info = lego.issue(self.tls_dir, cryptor, config, credentials)
        except AcmeBusy:
            # The CLI holds the lock. Not a failure, so no back-off.
            raise
        except AcmeError as exc:
            self.last_error = str(exc)
            self._last_failure = datetime.now(timezone.utc)
            raise
        finally:
            self._lock.release()
        self.last_error = None
        self._last_failure = None
        try:
            self.reload_if_changed()
        except AcmeError as exc:
            # The certificate is issued and stored; only serving it failed.
            # Raising here would make the caller discard a good issuance.
            self.last_error = str(exc)
            logger.error("%s -- it will be served after a restart", exc)
        return info

    def maybe_renew(self) -> None:
        """One housekeeping pass. Never raises for an expected failure."""
        try:
            info = store.stored_cert_info(self.tls_dir)
            if info is None or store.load_config(self.tls_dir) is None:
                return
            if not store.renewal_due(info):
                self.reload_if_changed()
                return
            if self._last_failure and datetime.now(timezone.utc) - self._last_failure < RENEW_RETRY_AFTER:
                return
            logger.info("certificate expires in %d day(s); renewing", info.days_left)
            self.renew()
        except AcmeError as exc:
            logger.error("automatic certificate renewal failed: %s", exc)

    def remove(self) -> list[str]:
        return store.remove_all(self.tls_dir)

    # --- restart ---

    def request_restart(self, delay: float = 1.0) -> None:
        """Replace the process so a newly issued certificate is served.

        The delay lets the response that asked for it reach the browser first.
        """
        if not store.has_material(self.tls_dir):
            raise AcmeError("there is no certificate to switch to yet")
        require_unattended_key(self._vault)
        if self._server is None:
            raise AcmeError(
                "this process was not started by backend.serve, so it cannot restart "
                "itself -- restart the container instead"
            )
        self.restart_requested = True
        loop = asyncio.get_running_loop()
        loop.call_later(delay, setattr, self._server, "should_exit", True)

    # --- reporting ---

    def status(self) -> dict:
        """Everything the Admin panel shows. Names stored settings, never their values."""
        config, info, stored_problem = self._stored_state()
        unavailable, stored_provider, stored_names, credentials_problem = self._credential_state()
        return {
            "serving_https": self.serving,
            "serving_fingerprint": self._loaded_fingerprint,
            "available": unavailable is None,
            "unavailable_reason": unavailable,
            "config": self._config_view(config),
            "stored_provider": stored_provider,
            "stored_credentials": stored_names,
            "certificate": info.as_dict() if info else None,
            "restart_needed": bool(info) and not self.serving and unavailable is None,
            "busy": self._lock.locked(),
            "last_error": self.last_error or stored_problem or credentials_problem,
            "lego_version": providers.lego_version(),
            "default_validation_delay": store.DEFAULT_VALIDATION_DELAY,
        }

    def _stored_state(self) -> tuple[AcmeConfig | None, CertInfo | None, str | None]:
        try:
            return store.load_config(self.tls_dir), store.stored_cert_info(self.tls_dir), None
        except AcmeError as exc:
            return None, None, str(exc)

    def _credential_state(self) -> tuple[str | None, str, list[str], str | None]:
        """(why unavailable, stored provider, stored setting names, problem)."""
        try:
            cryptor = require_unattended_key(self._vault)
        except AcmeError as exc:
            return str(exc), "", [], None
        try:
            provider, values = store.load_credentials(self.tls_dir, cryptor)
        except AcmeError as exc:
            return None, "", [], str(exc)
        return None, provider, sorted(values), None

    @staticmethod
    def _config_view(config: AcmeConfig | None) -> dict | None:
        if config is None:
            return None
        return {"domain": config.domain, "email": config.email, "staging": config.staging,
                "provider": config.provider, "provider_name": providers.get(config.provider).name,
                "validation_delay": config.validation_delay}
