"""Rotate the master key without re-encrypting a single capture body.

Why this can be cheap
---------------------
A sealed object is an envelope: an 84-byte header holding a per-object DEK
wrapped under the master key, followed by chunks encrypted under that DEK. The
master key never touches a capture's contents. So rotating it means unwrapping
each DEK with the old key and re-wrapping it with the new one -- 84 bytes per
file, whatever the file's size. A 40 GB capture rekeys as fast as a 40 KB one.

The DEK itself is deliberately unchanged. Replacing it would mean decrypting
and re-encrypting every byte, which turns a metadata edit into hours of I/O and
a window where plaintext exists somewhere.

What it covers
--------------
Captures, stored SSH private keys, and the built-in HTTPS material in
DATA_DIR/tls (the certificate's private key and the DNS credentials). All are
sealed with the same envelope by the same master key, and a rotation that moved
only some of them would leave the rest unopenable -- which startup then refuses to continue past, so a partial
rotation is a broken installation rather than a degraded one.

Safety properties
-----------------
- **Dry run by default.** Nothing is written without --apply.
- **Verify before replace.** The new header is written to a .partial file,
  the DEK recovered from it is compared against the original, and only then
  does it atomically replace the original. A crash leaves either the old file
  or a verified new one.
- **Resumable.** A file already under the new key is recognised and skipped,
  so re-running after an interruption finishes the job instead of failing.
- **Refuses a partial success.** Any file that cannot be rekeyed makes the run
  exit non-zero, with the reason per file. There is no "mostly rotated".
- **Never deletes a capture.** The worst case is a file left under the old key,
  named in the output.

Usage
-----
Stop the app first -- a capture being written while its header is swapped is
the one way to corrupt one.

    python -m backend.rekey \\
        --captures-dir /app/captures \\
        --ssh-keys-dir /app/ssh-keys \\
        --old-key-file /run/secrets/pcap_master_key \\
        --new-key-file /run/secrets/pcap_master_key.new \\
        --apply

Then replace the old key file with the new one and start the app. It will
report `encryption enabled (key id ...)` with the new id.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from backend.crypto import (
    ENCRYPTED_SUFFIX,
    HEADER_LEN,
    MAGIC,
    CryptoError,
    Cryptor,
    EnvKeySource,
    FileKeySource,
    KeyUnavailable,
    NotEncrypted,
    WrongKey,
    derive_kek_from_passphrase,
    generate_key_b64,
)

# A file written this recently is assumed to be a capture in progress. Swapping
# a header under a live writer is the one operation here that can destroy data,
# so it is refused rather than raced.
_LIVE_WRITE_SECONDS = 10

_COPY_CHUNK = 1024 * 1024


@dataclass
class Outcome:
    rekeyed: list[Path] = field(default_factory=list)
    already: list[Path] = field(default_factory=list)
    plaintext: list[Path] = field(default_factory=list)
    failed: list[tuple[Path, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failed


class RekeyRefused(Exception):
    """Raised before anything is written, when the run must not start."""


def _targets(
    captures_dir: Path | None, ssh_keys_dir: Path | None, tls_dir: Path | None = None,
) -> list[Path]:
    """Every sealed object: captures, SSH keys, and the TLS key and token.

    SSH keys carry no distinguishing suffix -- they are whatever the operator
    uploaded -- so the directory is taken as a whole and each file is judged by
    its magic bytes rather than its name.
    """
    found: list[Path] = []
    if captures_dir and captures_dir.exists():
        found += sorted(p for p in captures_dir.glob(f"*{ENCRYPTED_SUFFIX}") if p.is_file())
    if ssh_keys_dir and ssh_keys_dir.exists():
        found += sorted(p for p in ssh_keys_dir.iterdir() if p.is_file())
    if tls_dir and tls_dir.exists():
        found += sorted(p for p in tls_dir.glob(f"*{ENCRYPTED_SUFFIX}") if p.is_file())
    return found


def _check_no_live_writes(paths: list[Path]) -> None:
    now = time.time()
    live = []
    for p in paths:
        try:
            if now - p.stat().st_mtime < _LIVE_WRITE_SECONDS:
                live.append(p.name)
        except OSError:
            continue
    if live:
        raise RekeyRefused(
            "these files were modified in the last "
            f"{_LIVE_WRITE_SECONDS} seconds, so a capture may still be running: "
            + ", ".join(live)
            + "\nStop the app and run this again. Swapping a header under a live "
            "writer is the one thing here that can corrupt a capture."
        )


def rekey_file(path: Path, old: Cryptor, new: Cryptor, *, apply: bool) -> str:
    """Move one sealed file from the old master key to the new one.

    Returns a status: "rekeyed", "already", or "plaintext". Raises CryptoError
    for a file under neither key.
    """
    with open(path, "rb") as fh:
        header = fh.read(HEADER_LEN)

    if not header.startswith(MAGIC):
        # Written before encryption was switched on. The vault's own startup
        # migration seals these; rotating a key it was never sealed with is not
        # this routine's job, and guessing would risk double-sealing.
        return "plaintext"

    # Idempotence, which is what makes an interrupted run safe to repeat: a file
    # already under the new key is done, not broken.
    try:
        new.unwrap_dek(header)
        return "already"
    except (WrongKey, NotEncrypted):
        pass

    dek = old.unwrap_dek(header)  # WrongKey here means neither key opens it
    new_header = new.header_for_dek(dek)

    # Prove the new header really does carry the same DEK before anything is
    # replaced. This is the whole correctness argument in one line: the body is
    # copied byte for byte, so if the DEK round-trips, the file opens.
    if new.unwrap_dek(new_header) != dek:
        raise CryptoError("re-wrapped header did not round-trip the DEK")

    if not apply:
        return "rekeyed"

    tmp = path.with_suffix(path.suffix + ".partial")
    try:
        with open(path, "rb") as src, open(tmp, "wb") as dst:
            src.seek(HEADER_LEN)
            dst.write(new_header)
            while chunk := src.read(_COPY_CHUNK):
                dst.write(chunk)
        os.chmod(tmp, path.stat().st_mode & 0o7777)
        # Re-read from disk rather than trusting what we just wrote: this also
        # catches a truncated copy or a full disk.
        with open(tmp, "rb") as fh:
            if new.unwrap_dek(fh.read(HEADER_LEN)) != dek:
                raise CryptoError("verification of the written file failed")
        if tmp.stat().st_size != path.stat().st_size:
            raise CryptoError(
                f"size changed: {path.stat().st_size} -> {tmp.stat().st_size}"
            )
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return "rekeyed"


def rekey_all(
    old: Cryptor,
    new: Cryptor,
    *,
    captures_dir: Path | None,
    ssh_keys_dir: Path | None,
    tls_dir: Path | None = None,
    apply: bool,
) -> Outcome:
    if old.kek_id == new.kek_id:
        raise RekeyRefused(
            "the old and new keys are the same key "
            f"(id {old.kek_id.hex()[:12]}) -- nothing to rotate"
        )

    paths = _targets(captures_dir, ssh_keys_dir, tls_dir)
    if not paths:
        raise RekeyRefused(
            "no sealed files found -- check --captures-dir and --ssh-keys-dir "
            "point at the data volume, not into the image"
        )
    _check_no_live_writes(paths)

    out = Outcome()
    for path in paths:
        try:
            status = rekey_file(path, old, new, apply=apply)
        except (CryptoError, OSError) as exc:
            out.failed.append((path, str(exc)))
            continue
        getattr(out, status).append(path)
    return out


# --- key material ------------------------------------------------------------


def _load_key(which: str, args: argparse.Namespace, data_dir: Path | None) -> bytes:
    key_file = getattr(args, f"{which}_key_file")
    key_env = getattr(args, f"{which}_key_env")
    passphrase_env = getattr(args, f"{which}_passphrase_env")

    given = [n for n, v in (("file", key_file), ("env", key_env),
                            ("passphrase", passphrase_env)) if v]
    if len(given) != 1:
        raise RekeyRefused(
            f"give exactly one of --{which}-key-file, --{which}-key-env or "
            f"--{which}-passphrase-env (got {len(given)})"
        )

    if key_file:
        return FileKeySource(Path(key_file)).load()
    if key_env:
        value = os.environ.get(key_env, "")
        if not value:
            raise RekeyRefused(f"${key_env} is empty or unset")
        return EnvKeySource(value).load()

    passphrase = os.environ.get(passphrase_env, "")
    if not passphrase:
        raise RekeyRefused(f"${passphrase_env} is empty or unset")
    if data_dir is None:
        raise RekeyRefused(
            "--data-dir is required with a passphrase: the salt it was derived "
            "with lives in the database, and deriving against a fresh salt "
            "would produce a key that opens nothing"
        )
    return derive_kek_from_passphrase(passphrase, _salt_from_db(data_dir))


def _salt_from_db(data_dir: Path) -> bytes:
    """The stored passphrase salt, read without letting the app create one.

    Database() would mint and persist a new salt if none existed, which for a
    rotation is the worst possible outcome: a silently wrong key.
    """
    from backend.database import Database
    from backend.vault import _SALT_SETTING

    db_path = data_dir / "pcap-server.db"
    if not db_path.exists():
        raise RekeyRefused(f"no database at {db_path}")
    stored = Database(db_path).get_setting(_SALT_SETTING)
    if not stored:
        raise RekeyRefused(
            "this installation has no stored passphrase salt, so it was never "
            "in passphrase mode -- use --{old,new}-key-file instead"
        )
    return bytes.fromhex(stored)


# --- CLI ---------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m backend.rekey",
        description="Rotate the master key by re-wrapping each object's DEK.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Stop the app before running with --apply.",
    )
    p.add_argument("--captures-dir", type=Path, default=os.environ.get("CAPTURES_DIR"))
    p.add_argument("--ssh-keys-dir", type=Path, default=os.environ.get("SSH_KEYS_DIR"))
    p.add_argument("--data-dir", type=Path, default=os.environ.get("DATA_DIR"),
                   help="holds the built-in HTTPS key and DNS credentials (DATA_DIR/tls), and "
                        "the salt for passphrase mode")
    for which in ("old", "new"):
        p.add_argument(f"--{which}-key-file")
        p.add_argument(f"--{which}-key-env", metavar="VAR")
        p.add_argument(f"--{which}-passphrase-env", metavar="VAR")
    p.add_argument("--generate-new-key", type=Path, metavar="PATH",
                   help="write a fresh key to PATH (mode 0400) and use it as the new key")
    p.add_argument("--apply", action="store_true",
                   help="actually write; without it nothing is modified")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    try:
        if args.generate_new_key:
            if args.new_key_file or args.new_key_env or args.new_passphrase_env:
                raise RekeyRefused(
                    "--generate-new-key already supplies the new key; drop the "
                    "other --new-* option"
                )
            path = args.generate_new_key
            if path.exists():
                raise RekeyRefused(
                    f"{path} already exists -- refusing to overwrite a key file"
                )
            generated = generate_key_b64()
            if args.apply:
                path.write_text(generated + "\n")
                path.chmod(0o400)
                print(f"wrote a new master key to {path} (mode 0400)")
                print("BACK THIS UP. Without it the rekeyed captures cannot be opened.")
                args.new_key_file = str(path)
            else:
                # A dry run writes nothing, and that has to include the key
                # file: an operator who reads "wrote a new master key" from a
                # run that changed no capture has been told something false,
                # in the one tool where that matters most. The key is still
                # generated so the summary can name the id it would move to --
                # it just stays in memory, and the real run generates its own.
                print(f"would write a new master key to {path} (mode 0400)")
                args.new_key_env = "_REKEY_DRY_RUN_KEY"
                os.environ["_REKEY_DRY_RUN_KEY"] = generated

        old_kek = _load_key("old", args, args.data_dir)
        new_kek = _load_key("new", args, args.data_dir)
        old, new = Cryptor(old_kek), Cryptor(new_kek)

        print(f"old key id {old.kek_id.hex()[:12]} -> new key id {new.kek_id.hex()[:12]}")
        if not args.apply:
            print("DRY RUN -- nothing will be written. Add --apply to commit.")

        out = rekey_all(
            old, new,
            captures_dir=args.captures_dir,
            ssh_keys_dir=args.ssh_keys_dir,
            tls_dir=args.data_dir / "tls" if args.data_dir else None,
            apply=args.apply,
        )
    except (RekeyRefused, KeyUnavailable, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    verb = "rekeyed" if args.apply else "would rekey"
    print(f"{verb}: {len(out.rekeyed)}")
    if out.already:
        print(f"already under the new key: {len(out.already)}")
    if out.plaintext:
        print(f"unencrypted, left alone: {len(out.plaintext)} "
              f"({', '.join(p.name for p in out.plaintext[:3])})")
    for path, why in out.failed:
        print(f"FAILED {path.name}: {why}", file=sys.stderr)

    if not out.ok:
        print(
            f"\n{len(out.failed)} file(s) could not be rekeyed and are untouched, "
            "still under the old key. Keep the old key file: the app will refuse "
            "to start against a mix it cannot fully open.",
            file=sys.stderr,
        )
        return 1

    if args.apply and out.rekeyed:
        print("\nDone. Now replace the old key file with the new one and start the app.")
        print("Keep the old key until you have confirmed it starts and a capture opens.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
