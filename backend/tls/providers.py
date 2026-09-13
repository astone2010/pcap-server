"""The DNS providers lego can prove a domain with, and what each one may be given.

lego_providers.json is generated from lego's own provider metadata by
scripts/gen_lego_providers.py, for the lego version the Dockerfile installs.
It is the allowlist: an admin can hand lego exactly the environment variables
listed for the provider they chose, and nothing else. That matters because
lego reads more from its environment than provider settings -- LEGO_* variables
include hooks that run commands, and any variable NAME_FILE makes lego read
NAME's value from a file. Neither can be named here.

Variables lego reads as a path ("file" kind) are never given a path by the
admin. The admin supplies the file's contents; backend/tls/lego.py writes them
into its own scratch directory and points the variable there.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from backend.tls import destinations

_CATALOG = Path(__file__).with_name("lego_providers.json")

MAX_VALUE_BYTES = 4096
MAX_FILE_BYTES = 64 * 1024
MAX_VARIABLES = 40


@dataclass(frozen=True)
class Variable:
    name: str
    description: str
    kind: str  # "secret" | "text" | "file"
    group: str  # "credentials" | "additional"


@dataclass(frozen=True)
class Provider:
    code: str
    name: str
    url: str
    docs: str
    variables: tuple[Variable, ...]

    def variable(self, name: str) -> Variable | None:
        return next((v for v in self.variables if v.name == name), None)


@lru_cache(maxsize=1)
def _load() -> tuple[str, dict[str, Provider]]:
    raw = json.loads(_CATALOG.read_text())
    providers = {}
    for p in raw["providers"]:
        variables = tuple(
            Variable(v["name"], v["description"], v["kind"], group)
            for group in ("credentials", "additional")
            for v in p[group]
        )
        providers[p["code"]] = Provider(p["code"], p["name"], p["url"], p["docs"], variables)
    return raw["lego_version"], providers


def lego_version() -> str:
    return _load()[0]


def get(code: str) -> Provider:
    provider = _load()[1].get(code)
    if provider is None:
        raise ValueError("unknown DNS provider")
    return provider


def all_providers() -> list[Provider]:
    return list(_load()[1].values())


def catalog_for_ui() -> list[dict]:
    """The picker's data. Names and descriptions only -- never a stored value."""
    return [
        {
            "code": p.code, "name": p.name, "docs": p.docs,
            "variables": [
                {"name": v.name, "description": v.description, "kind": v.kind, "group": v.group}
                for v in p.variables
            ],
        }
        for p in all_providers()
    ]


def validate_credentials(code: str, values: dict, *, resolve: bool = False) -> dict[str, str]:
    """Keep only non-empty values for variables this provider lists.

    Raises on a name the provider does not list rather than dropping it: a
    silently ignored credential is a request that fails later for no stated
    reason. URL and address settings are checked by destinations.py; resolve
    adds the DNS lookup, which lego.py asks for immediately before it runs.
    """
    provider = get(code)
    if not isinstance(values, dict):
        raise ValueError("credentials must be an object of name/value pairs")
    if len(values) > MAX_VARIABLES:
        raise ValueError("too many credential fields")
    clean: dict[str, str] = {}
    for name, value in values.items():
        variable = provider.variable(name) if isinstance(name, str) else None
        if variable is None:
            raise ValueError(f"{name!r} is not a setting of the {provider.name} provider")
        if value is None or value == "":
            continue
        if not isinstance(value, str):
            raise ValueError(f"{name} must be text")
        limit = MAX_FILE_BYTES if variable.kind == "file" else MAX_VALUE_BYTES
        if len(value.encode()) > limit:
            raise ValueError(f"{name} is longer than {limit} bytes")
        if "\x00" in value:
            raise ValueError(f"{name} contains a NUL character")
        if variable.kind != "file":
            destinations.check(name, value, resolve=resolve)
        clean[name] = value
    return clean
