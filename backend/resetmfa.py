"""Clear an account's second factor from the host, when nobody can sign in.

Why this exists as well as the Admin button
-------------------------------------------
`POST /api/admin/users/{id}/totp/reset` handles the ordinary case: somebody
lost their phone and an admin fixes it in the UI. It deliberately refuses to
reset the *caller's own* account, which leaves one case it cannot cover -- the
only admin on the installation has lost their authenticator. Reaching any API
route means already being past the second factor, so there is no signed-in
answer to "I cannot sign in".

The answer has to come from outside the app, at a bar that is higher than a
stolen cookie and not lower: access to the host running the container. That is
the same bar as reading the master key or the database directly, so this grants
nothing an operator at that level did not already have -- it just means they do
not have to edit SQLite by hand to get it.

What it does
------------
Exactly what the route does, minus the route:

  * NULLs the TOTP secret and clears the confirmed flag, so the account enrols
    again -- with a fresh secret -- at its next login. The old secret is
    destroyed rather than merely unconfirmed, because whoever still holds that
    authenticator could otherwise confirm the account straight back.
  * Deletes every session belonging to that user, so a session that already
    carries both factors cannot outlive the reset.
  * Deletes every trusted device belonging to that user. A trusted device is a
    second factor in its own right -- skipping TOTP is the entire point of one
    -- so leaving them would exempt precisely the devices with the most access.

What it does NOT do
-------------------
Change or reveal a password, create a user, or grant admin. A forgotten
password is a different problem and is not solved by a tool that can be run by
anyone who can reach the host.

Usage
-----
Dry run by default -- nothing is written without --apply:

    docker compose run --rm --entrypoint python pcap-server \\
        -m backend.resetmfa alice

    docker compose run --rm --entrypoint python pcap-server \\
        -m backend.resetmfa alice --apply

`--list` names the accounts and says which have MFA confirmed, for when the
exact username is the thing that has been forgotten.

The app does not have to be stopped: this touches three rows of the metadata
database and no capture file. Any session it deletes is meant to be deleted.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from backend.database import Database

# Resolved exactly as backend/main.py resolves it, so this reaches the database
# the app is using rather than creating an empty one beside it -- which would
# "succeed" at resetting an account that does not exist there.
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
DB_PATH = DATA_DIR / "pcap-server.db"


def _resolve(db: Database, username: str) -> dict | None:
    """Looked up by name, because a UUID is not what a locked-out operator has."""
    return db.get_user_by_username(username)


def _list_users(db: Database) -> int:
    users = db.list_users()
    if not users:
        print("no accounts")
        return 0
    width = max(len(u["username"]) for u in users)
    for u in sorted(users, key=lambda u: u["username"].lower()):
        flags = []
        if u["is_admin"]:
            flags.append("admin")
        flags.append("MFA confirmed" if u["totp_confirmed"] else "MFA NOT set up")
        print(f"  {u['username']:<{width}}  {', '.join(flags)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m backend.resetmfa",
        description=(
            "Clear an account's two-factor authentication so it enrols again at "
            "next login. For the case the Admin panel cannot reach: the only "
            "admin has lost their authenticator."
        ),
    )
    parser.add_argument("username", nargs="?", help="the account to reset")
    parser.add_argument("--list", action="store_true",
                        help="list accounts and their MFA state, and do nothing else")
    parser.add_argument("--apply", action="store_true",
                        help="actually write the change (default is a dry run)")
    args = parser.parse_args(argv)

    if not DB_PATH.exists():
        print(
            f"no database at {DB_PATH}. Set DATA_DIR, or run this inside the "
            "container where /app/data is mounted.",
            file=sys.stderr,
        )
        return 2
    db = Database(DB_PATH)

    if args.list:
        return _list_users(db)

    if not args.username:
        parser.error("give a username, or --list to see them")

    user = _resolve(db, args.username)
    if not user:
        print(f"no account called {args.username!r}. Try --list.", file=sys.stderr)
        return 2

    sessions = db.count_sessions_for_user(user["id"])
    state = "confirmed" if user["totp_confirmed"] else "not set up"
    print(f"{user['username']}: MFA {state}, {sessions} live session(s)")

    if not args.apply:
        print(
            "\nDry run. Nothing was changed. Re-run with --apply to:\n"
            "  - clear the TOTP secret, so a NEW one is issued at next login\n"
            f"  - sign {user['username']} out of every session\n"
            f"  - forget every trusted device belonging to {user['username']}"
        )
        return 0

    db.reset_totp(user["id"])
    signed_out = db.delete_sessions_for_user(user["id"])
    db.delete_trusted_devices(user["id"])

    print(
        f"\nDone. {user['username']} has no second factor and no live session "
        f"({signed_out} deleted).\n"
        "The next sign-in with their password will show a new enrolment code.\n"
        "\nIf that account did not belong to whoever is now about to enrol it, "
        "the password is the only thing standing in the way -- change it too."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
