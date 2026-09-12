# Dev Skills gate state
Track: release sequence (version bump only — Ship/tag stays the user's)
Version: 0.1.0-dev.15
Updated: 2026-09-12
Branch: claude/api-rate-limiting-10cf7m

## What's in dev.15

Three work commits since the v0.1.0-dev.14 tag, all already pushed:

- `8a64990` — `SlidingWindowLimiter` (backend/auth.py): per-user rate limits
  on packet listing (30/min) and capture start (10/min), admin-configurable.
  Neither endpoint was throttled before; login was the only one with a cap.
- `44d2996` — `ServerAuth.hostname` now shares `validate_ssh_hostname` with
  `KnownHostEndpoint.hostname`, closing a gap where `$`, backtick, backslash,
  `\n`, `\r` reached asyncssh and the known_hosts store unvalidated.
- `db4749c` — CHANGELOG.md: added the dev.15 heading and Security entries for
  the two commits above.

Plus, this turn: the version bump itself (`backend/main.py` APP_VERSION,
`docker-compose.yml` image tag, CHANGELOG heading date) — not yet committed.

Explicitly **not** part of this turn: no tag, no GitHub release, no PR. The
user asked for the version bump, not a ship — Gate 6 stays theirs alone, as
it has all session (tag pushes are never executed by Claude, Section 5.7).

## Gates

🔢 VERSION    ✅ APP_VERSION (backend/main.py) and docker-compose.yml's image
                tag both read 0.1.0-dev.15; CHANGELOG heading dated
                2026-09-12 (was "unreleased"). release_notes_url in main.py
                is built from APP_VERSION, so it points at the new tag
                automatically once it exists. v0.1.0-dev.14 confirmed tagged
                on the remote (`git ls-remote --tags origin`) — no gap.
                grepped for every other "0.1.0-dev.14" string in the repo:
                none remain outside CHANGELOG's own dev.14 heading, which is
                history and correctly unchanged.
🔨 BUILD      ✅ ./scripts/check.sh: 517 passed, no skips, at 0.1.0-dev.15.
                Container image not built here — CI builds and pushes it on
                the tag push, same as every prior release.
🔒 SECURITY   ✅ pip-audit against backend/requirements.txt: no known
                vulnerabilities. Reviewed the full diff since v0.1.0-dev.14
                (`git diff v0.1.0-dev.14..HEAD` — backend/auth.py,
                database.py, main.py, models.py, frontend/js/app.js) as one
                pass on top of the two commits' individual reviews: no
                dangerous pattern, no new dependency, no secret, nothing that
                changes across the combined diff that wasn't already true of
                each piece alone.
📄 DOCS       ✅ CHANGELOG has a dated dev.15 entry covering both commits.
                README settings table already carries the two new rate-limit
                settings (added same session as the commit). No stale
                version or feature references found for dev.14.
📦 RELEASE    ➖ N/A — no PR: the default branch is out of scope by the
                user's standing decision from earlier sessions, so there is
                nothing to merge into. Matches dev.14's precedent.
🚀 SHIP       ⬜ not started, and not this turn's job. Tag push is always the
                user's own action (Section 5.7) — hand them the block when
                they're ready to ship, same three-line form used for dev.14.

## Still open, unrelated to this bump

- dev.14's own release body compares against dev.8 instead of dev.13
  (cosmetic). No GitHub MCP tool exists to edit a release, and `gh` isn't
  installed here, so this was handed to the user directly as a `gh release
  edit` command / UI steps. Not resolved yet as of this update.
