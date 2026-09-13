"""`python -m backend.tls`: built-in HTTPS from inside the container.

The Admin panel does all of this. The CLI is the way that keeps DNS credentials
off the network -- they are typed into the container, not sent to it:

    docker compose exec -it pcap-server python -m backend.tls providers
    docker compose exec -it pcap-server python -m backend.tls issue \\
        --domain pcap.example.com --email you@example.com --provider cloudflare
    docker compose exec pcap-server python -m backend.tls status
    docker compose exec pcap-server python -m backend.tls renew

`issue` prompts for each of the provider's credentials, without echoing them.
Blank keeps a value already stored for that provider. Credentials are never
command-line arguments: argv is visible in `ps` to every process on the host.
Piped instead of typed (`exec -T ... < creds.env`), stdin is read as NAME=value
lines; a variable the provider reads as a file takes NAME=@/path/in/container.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
from pathlib import Path

from backend.tls import providers, store
from backend.tls.errors import AcmeError
from backend.tls.manager import TlsManager


def _drop_to_app_user() -> None:
    """`docker compose exec` runs as root; files written as root would be
    unreadable to the app, which runs as appuser."""
    if os.geteuid() != 0:
        return
    import pwd
    try:
        entry = pwd.getpwnam("appuser")
    except KeyError:
        return
    os.setgroups([])
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)


def _manager() -> TlsManager:
    from backend.database import Database
    from backend.vault import CaptureVault, StartupRefused

    data_dir = Path(os.environ.get("DATA_DIR", "/app/data"))
    captures_dir = Path(os.environ.get("CAPTURES_DIR", "/app/captures"))
    db_path = data_dir / "pcap-server.db"
    if not db_path.exists():
        raise AcmeError(f"no database at {db_path}. Run this inside the pcap-server container.")
    try:
        vault = CaptureVault(dict(os.environ), Database(db_path), captures_dir)
    except StartupRefused as exc:
        raise AcmeError(str(exc)) from exc
    return TlsManager(data_dir / "tls", vault)


def _read_file_value(name: str, path: str) -> str:
    try:
        return Path(path).expanduser().read_text()
    except OSError as exc:
        raise AcmeError(f"{name}: cannot read {path}: {exc}") from exc


def _prompt_credentials(provider: providers.Provider, stored: set[str]) -> dict[str, str]:
    print(f"\n{provider.name} -- {provider.docs}")
    print("Blank skips a setting" + (" (and keeps the stored value)." if stored else "."))
    values = {}
    for var in provider.variables:
        if var.group != "credentials":
            continue
        mark = " [stored]" if var.name in stored else ""
        label = f"{var.name}{mark} -- {var.description}"
        if var.kind == "file":
            path = input(f"{label}\n  path to the file, inside the container: ").strip()
            if path:
                values[var.name] = _read_file_value(var.name, path)
        elif var.kind == "secret":
            values[var.name] = getpass.getpass(f"{label}\n  (not echoed): ")
        else:
            values[var.name] = input(f"{label}\n  : ").strip()
    return values


def _read_piped_credentials(provider: providers.Provider) -> dict[str, str]:
    values = {}
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        name = name.strip()
        if not sep:
            raise AcmeError(f"expected NAME=value, got {name!r}")
        var = provider.variable(name)
        if var is not None and var.kind == "file" and value.startswith("@"):
            value = _read_file_value(name, value[1:])
        values[name] = value
    return values


def _print_status(st: dict) -> None:
    cfg = st["config"]
    print(f"serving:     {'HTTPS' if st['serving_https'] else 'this process is not serving'}")
    if not st["available"]:
        print(f"unavailable: {st['unavailable_reason']}")
    if cfg:
        print(f"domain:      {cfg['domain']}")
        print(f"email:       {cfg['email']}")
        print(f"provider:    {cfg['provider_name']} ({cfg['provider']})")
        print(f"staging:     {'yes' if cfg['staging'] else 'no'}")
        print(f"wait:        {cfg['validation_delay']}s before validation")
    else:
        print("domain:      (not configured)")
    print(f"credentials: {', '.join(st['stored_credentials']) or 'none stored'}")
    cert = st["certificate"]
    if cert:
        print(f"certificate: {', '.join(cert['names'])} -- expires {cert['not_after'][:10]} "
              f"({cert['days_left']} days), issuer {cert['issuer']}")
    else:
        print("certificate: none")
    if st["last_error"]:
        print(f"last error:  {st['last_error']}")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m backend.tls",
        description="Obtain and renew pcap-server's own Let's Encrypt certificate (DNS-01, via lego).",
    )
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="show the stored settings and certificate")
    prov = sub.add_parser("providers", help="list DNS providers, or one provider's settings")
    prov.add_argument("code", nargs="?")
    iss = sub.add_parser("issue", help="request a certificate (credentials are prompted for)")
    iss.add_argument("--domain", required=True)
    iss.add_argument("--email", required=True)
    iss.add_argument("--provider", required=True, help="a code from `providers`, e.g. cloudflare")
    iss.add_argument("--validation-delay", default="",
                     help="seconds to wait after creating the DNS record before Let's Encrypt "
                          "checks it (default 30)")
    iss.add_argument("--staging", action="store_true",
                     help="Let's Encrypt staging: untrusted certificates, generous limits")
    sub.add_parser("renew", help="request a new certificate now with the stored settings")
    return p.parse_args(argv)


def _list_providers(code: str | None) -> int:
    if not code:
        for p in providers.all_providers():
            print(f"{p.code:20} {p.name}")
        return 0
    p = providers.get(code)
    print(f"{p.name} ({p.code}) -- {p.docs}")
    for group in ("credentials", "additional"):
        print(f"\n{group}:")
        for v in p.variables:
            if v.group == group:
                print(f"  {v.name:40} {v.description}" + ("  [file contents]" if v.kind == "file" else ""))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        if args.command == "providers":
            return _list_providers(args.code)
        _drop_to_app_user()
        manager = _manager()
        if args.command == "status":
            _print_status(manager.status())
            return 0
        if args.command == "renew":
            info = manager.renew()
        else:
            provider = providers.get(args.provider)
            store.validate_domain(args.domain)
            store.validate_email(args.email)
            st = manager.status()
            stored = set(st["stored_credentials"]) if st["stored_provider"] == provider.code else set()
            values = (_prompt_credentials(provider, stored) if sys.stdin.isatty()
                      else _read_piped_credentials(provider))
            store.validate_validation_delay(args.validation_delay)
            info = manager.issue(args.domain, args.email, provider.code, values, args.staging,
                                 args.validation_delay)
    except (AcmeError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"\ncertificate for {', '.join(info.names)} stored, expires {info.not_after:%Y-%m-%d}.")
    print("If pcap-server is still on plain HTTP, switch it over with:\n"
          "    docker compose restart pcap-server\n"
          "A server already on HTTPS picks up a renewed certificate within the hour, "
          "without a restart.")
    return 0
