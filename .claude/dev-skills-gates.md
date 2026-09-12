# Dev Skills gate state
Track: work commit (API hardening item 3 — rate limiting)
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

Open:
- **Item 3 (this session's focus):** rate limiting covers login only
  (`rate_limiter` at `backend/main.py:488,496,506,526`, all inside `login`,
  plus `:622` for config). `RateLimiter` is `backend/auth.py:19`. Packet
  listing (spawns tshark) and capture start (opens SSH) are unthrottled per
  user. Needs a decision on limits and whether they join the admin-configurable
  settings (defaults at `backend/database.py:504`, README settings table)
  before coding.
- `ServerAuth.hostname` (`backend/models.py:69`) allows `$`, backtick,
  backslash, newline, CR — looser than `KnownHostEndpoint.hostname` (`:106`).
  Not yet touched.
- dev.15's CHANGELOG needs entries for the two hardening commits.
- dev.14's release body compares against dev.8, not dev.13 (cosmetic,
  `gh release edit`, user's to run).

## Environment

Remote container. Claude executes git after approval (Section 5.7); tag
pushes and ref deletions always go to the user as a presented block.
`gh` is not installed — GitHub MCP tools stand in.

🔢 VERSION    ⬜ not owed — work commit track
🔨 BUILD      ✅ ./scripts/check.sh: 506 passed, no skips (497 + 9 new tests).
                The two new 429 checks were verified to fail without the fix
                (temporarily reverted the throttle checks, reran, got the
                expected failures, restored) before being trusted as real
                coverage.
🔒 SECURITY   ✅ SlidingWindowLimiter (backend/auth.py) is pure in-memory
                bookkeeping — no new I/O, no new dependency, no secrets, no
                shell/SQL/serialization surface. Mirrors RateLimiter's
                existing shape (same file, same class of state).
                Quality note, not blocking: like RateLimiter._attempts, the
                new _hits dict is keyed per user id and never purged for
                users who stop being active — unbounded in principle, same
                pre-existing shape as the login limiter, not a new risk this
                change introduces.
📄 DOCS       ➖ N/A for this commit (work commit; changelog entry deferred to dev.15 release, tracked above) — README settings table and the admin panel's SETTING_LABELS were both updated so the two new settings aren't invisible, per test_every_setting_the_backend_defaults_is_editable_in_the_admin_panel
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
