#!/usr/bin/env python3
"""Regenerate backend/tls/lego_providers.json from a lego source checkout.

    gh api repos/go-acme/lego/tarball/v5.4.1 > lego.tgz
    mkdir lego-src && tar xzf lego.tgz -C lego-src --strip-components=1
    python scripts/gen_lego_providers.py lego-src 5.4.1

Run it whenever LEGO_VERSION in the Dockerfile moves, and review the diff: it
is the allowlist of every environment variable an admin can hand to lego.

Each provider directory in lego carries a TOML file describing its
configuration -- the same data `lego dnshelp` prints. From it this keeps, per
provider, the variables that are real names (not prose), minus aliases, and
classifies each one:

  secret  a credential -- shown as a password field
  text    anything else -- an endpoint, a zone, a timeout
  file    a variable lego reads as a *path*. The admin pastes the file's
          contents instead, and the app writes them somewhere of its own
          choosing; a path an admin could set would let lego read any file the
          app can, and some providers send what they read to a URL the admin
          also chooses.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

# Providers that cannot work here, or must not.
EXCLUDED = {
    "exec": "runs an arbitrary program with the challenge -- code execution by configuration",
    "manual": "waits for someone at a terminal to create the record by hand",
    "acmedns": "keeps its account in a file that has to outlive each run",
}

# Single settings left out of otherwise-supported providers. Each one is a file
# whose *contents* can reach further than a credential should.
EXCLUDED_VARIABLES = {
    "AWS_SHARED_CREDENTIALS_FILE":
        "an AWS credentials file can carry credential_process, which runs a command; "
        "route53 and lightsail take AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY instead",
    "OCI_CONFIG_FILE":
        "an OCI config names a key_file path lego would then read; "
        "oraclecloud takes OCI_PRIVATE_KEY_PATH as pasted contents instead",
    "DNSUPDATE_TSIG_GSS_KEYTAB_FILE":
        "a Kerberos keytab is binary and cannot be pasted as text",
}

# Settings that turn off certificate verification for the provider's API. With
# them, anyone on the path to a self-hosted DNS panel can read the credentials
# lego sends it. A panel needs a certificate lego can verify.
SKIP_VERIFY_NAME = re.compile(r"INSECURE|SKIP_VERIFY|SSL_VERIFY|TLS_VERIFY|VERIFY_SSL", re.IGNORECASE)

ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
FILE_NAME = re.compile(r"(_FILE|_PATH|_LOCATION|_EDGERC)$")
FILE_NAMES = {"INFOBLOX_CA_CERTIFICATE"}
SECRET_NAME = re.compile(r"KEY|SECRET|TOKEN|PASSWORD|PASSWD|_PASS$|CREDENTIALS?$|SIGNATURE|HMAC",
                         re.IGNORECASE)


# Secrets the name pattern does not catch: a service account's JSON key, a TOTP seed.
SECRET_NAMES = {"GCE_SERVICE_ACCOUNT", "NICMANAGER_API_OTP"}


def classify(name: str) -> str:
    """Only decides how the field is drawn. Every value is sealed at rest alike."""
    if FILE_NAME.search(name) or name in FILE_NAMES:
        return "file"
    return "secret" if SECRET_NAME.search(name) or name in SECRET_NAMES else "text"


def variables(table: dict | None) -> list[dict]:
    out = []
    for name, description in (table or {}).items():
        if not ENV_NAME.match(name) or name.upper().startswith("LEGO_") or name in EXCLUDED_VARIABLES:
            continue
        if SKIP_VERIFY_NAME.search(name):
            continue
        if re.match(r"\s*alias", description, re.IGNORECASE):
            continue
        out.append({"name": name, "description": description.strip(), "kind": classify(name)})
    return out


def main(src: Path, version: str) -> int:
    providers = []
    for toml_path in sorted((src / "providers" / "dns").glob("*/*.toml")):
        data = tomllib.loads(toml_path.read_text())
        code = data["Code"]
        if code in EXCLUDED:
            continue
        config = data.get("Configuration", {})
        providers.append({
            "code": code,
            "name": data["Name"],
            "url": data.get("URL", ""),
            "docs": f"https://go-acme.github.io/lego/dns/{code}/",
            "credentials": variables(config.get("Credentials")),
            "additional": variables(config.get("Additional")),
        })
    providers.sort(key=lambda p: p["name"].lower())
    out = Path(__file__).resolve().parents[1] / "backend" / "tls" / "lego_providers.json"
    out.write_text(json.dumps({
        "lego_version": version,
        "excluded": EXCLUDED,
        "excluded_variables": EXCLUDED_VARIABLES,
        "providers": providers,
    }, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {len(providers)} providers to {out}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(Path(sys.argv[1]), sys.argv[2]))
