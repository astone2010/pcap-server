# Dev Skills gate state
Track: work commit (API hardening — item 3 rate limiting, then ServerAuth.hostname)
Version: 0.1.0-dev.14 (no bump owed — work commit track)
Updated: 2026-09-12
Branch: claude/api-rate-limiting-10cf7m (harness-designated branch for this task)

## Session start re-derivation

Resuming from a prior session's handoff. Re-derived, not assumed:

- Branch `claude/api-rate-limiting-10cf7m` at 1013f51, tree clean, matches
  `origin` (git status confirms local == remote).
- v0.1.0-dev.14 confirmed tagged on remote (`git ls-remote --tags origin`),
  alongside dev.1 through dev.13. No unfinished release gap.
- `backend/main.py:62` reads `APP_VERSION = "0.1.0-dev.14"` — unchanged, as
  expected for a work-commit track.
- Prior branch `claude/admiring-wright-k20ptf` (21 commits behind this one)
  was the previous session's home; this session's designated branch is
  `claude/api-rate-limiting-10cf7m`, per this session's task instructions.
  Not resolved by guessing — the task description assigns this branch
  explicitly, unlike last session's ambiguity between two branches.

## API hardening — work commits since dev.14 (carried from prior session)

Done (already committed, on this branch's history):
- Item 1: `limit_request_body` — refuses oversized body on Content-Length
  before parsing. (commit 1013f51)
- Item 2: `KnownHostEndpoint` model replaces hand-written body parsing for
  the two host-key routes. (commit in this branch's history)
- Item 3: `SlidingWindowLimiter` throttles packet listing (30/min) and
  capture start (10/min) per user, admin-configurable. (commit 8a64990,
  pushed)
- Item 4 (this session's second task): `ServerAuth.hostname` tightened to
  match `KnownHostEndpoint.hostname` — both now call the shared
  `validate_ssh_hostname`, which rejects `$`, backtick, backslash, `\n`, `\r`
  in addition to the space/`;`/`|`/`&` `ServerAuth` already rejected. Not yet
  committed — see implementation summary below.

- CHANGELOG.md: added a "0.1.0-dev.15 — unreleased" heading with Security
  entries for the rate-limiting and hostname-tightening commits. Docs only —
  no version bump: APP_VERSION, docker-compose's image tag, etc. stay at
  dev.14 until dev.15's own release sequence runs all six gates.

Open:
- dev.14's release body compares against dev.8, not dev.13 (cosmetic,
  `gh release edit`, user's to run).

## Environment

Remote container. Claude executes git after approval (Section 5.7); tag
pushes and ref deletions always go to the user as a presented block.
`gh` is not installed — GitHub MCP tools stand in.

🔢 VERSION    ⬜ not owed — work commit track
🔨 BUILD (item 3, shipped)  ✅ ./scripts/check.sh: 506 passed, no skips.
                Both new 429 checks verified to fail without the fix before
                being trusted as real coverage.
🔨 BUILD (hostname fix)     ✅ ./scripts/check.sh: 517 passed, no skips (506 +
                11 new). The 5 previously-unvalidated cases ($, backtick,
                backslash, \n, \r) verified to fail against the old looser
                validator before being trusted as real coverage.
🔒 SECURITY   ✅ item 3: SlidingWindowLimiter is pure in-memory bookkeeping,
                no new I/O/dependency/secrets. Quality note, not blocking:
                like RateLimiter._attempts, _hits is keyed per user id and
                never purged for inactive users — same pre-existing shape as
                the login limiter, not a new risk.
              ✅ hostname fix: pure validation tightening, strictly narrows
                accepted input, no new dependency or I/O. Extracted into one
                shared function (validate_ssh_hostname) rather than
                duplicating the character set a second time, matching the
                existing validate_ssh_username pattern in the same file.
📄 DOCS       ➖ N/A for these commits (work commits; changelog entries
                deferred to dev.15 release, tracked above). README settings
                table and admin panel's SETTING_LABELS updated for item 3's
                two new settings, per
                test_every_setting_the_backend_defaults_is_editable_in_the_admin_panel.
📦 RELEASE    ⬜ not owed — work commit track
🚀 SHIP       ⬜ not owed — work commit track

## Item 3 implementation summary (this session)

User's decisions (AskUserQuestion): per-user global scope, packet listing
30/min + capture start 10/min, admin-configurable.

- `SlidingWindowLimiter` (backend/auth.py) — sliding 60s window, `.allow(key)`
  records-and-checks in one call, no lockout/reset semantics (unlike
  RateLimiter, every allowed call counts and there's nothing to clear).
- Two new settings in `Database.DEFAULTS`: `rate_limit_packets_per_min` (30),
  `rate_limit_captures_per_min` (10).
- Two module-level limiter instances in backend/main.py, built from those
  settings at startup; `admin_update_setting`'s existing if/elif now also
  routes these two keys to `.update_config(...)`.
- `list_packets` and `start_capture` each call `.allow(user["id"])` first
  thing and return 429 before any tshark spawn / SSH connect happens.
- Frontend: SETTING_LABELS in app.js, README settings table.
- Tests: 6 unit tests for SlidingWindowLimiter (test_auth.py), 3 endpoint
  tests (test_main.py) — the two 429 tests assert the expensive call
  (capture_manager.start / capture_manager.get) was never reached, and the
  admin-settings test proves the new if/elif branches actually wire up
  (not just that the setting round-trips through the DB).

## ServerAuth.hostname tightening (this session, second task)

- `backend/models.py`: new module-level `validate_ssh_hostname`, same
  character set KnownHostEndpoint already enforced (rejects space, `;`, `|`,
  `&`, `$`, backtick, backslash, `\n`, `\r`). Both `KnownHostEndpoint.hostname`
  and `ServerAuth.hostname` now call it instead of each carrying its own copy
  — mirrors how `validate_ssh_username` is already shared between
  `UsernameRequest` and `ServerAuth.username` in the same file.
- Removed the stale docstring claim that ServerAuth.hostname was
  "deliberately" looser — it no longer is.
- Tests (tests/test_servers.py): a parametrized rejection table for
  ServerAuth mirroring the existing KnownHostEndpoint one, plus one
  acceptance case. Verified the 5 new characters ($, backtick, backslash,
  \n, \r) fail against the pre-fix validator and pass against the fix.
- No test file previously covered ServerAuth.hostname's rejected-character
  set at all; this closes that gap as well as the looseness itself.
