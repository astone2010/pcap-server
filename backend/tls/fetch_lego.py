"""Build-time only: download one lego release, verify it, install the binary.

    python fetch_lego.py <version> <sha256> <arch> <dest>

Used by the Dockerfile's lego stage. The slim Python base image has no curl, and
a checksum pinned in the Dockerfile is the whole point: a release asset that
changes under the same version fails the build instead of being installed.
"""

from __future__ import annotations

import hashlib
import io
import sys
import tarfile
import urllib.request


def main(version: str, sha256: str, arch: str, dest: str) -> int:
    url = (f"https://github.com/go-acme/lego/releases/download/"
           f"v{version}/lego_v{version}_linux_{arch}.tar.gz")
    with urllib.request.urlopen(url, timeout=120) as resp:
        blob = resp.read()
    actual = hashlib.sha256(blob).hexdigest()
    if actual != sha256:
        print(f"checksum mismatch for {url}\n  expected {sha256}\n  got      {actual}", file=sys.stderr)
        return 1
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        member = tar.getmember("lego")
        if not member.isfile():
            print("lego in the archive is not a regular file", file=sys.stderr)
            return 1
        data = tar.extractfile(member).read()
    with open(dest, "wb") as out:
        out.write(data)
    print(f"installed lego {version} ({arch}) to {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:5]))
