# Dev Skills gate state
Track: WORK COMMIT in progress (browser test suites), then the 0.1.0-dev.14
       RELEASE SEQUENCE
Version: 0.1.0-dev.13 (shipped) -- dev.14 not yet bumped
Updated: 2026-09-12

## 0.1.0-dev.13 -- shipped and verified

🔢 VERSION ✅  🔨 BUILD ✅  🔒 SECURITY ✅  📄 DOCS ✅  📦 RELEASE ✅  🚀 SHIP ✅

Ship verified against four independent checks: tag v0.1.0-dev.13 -> 1573e0b on
the remote, Release run 34714750294 success, the "Build and push image" step
success, and the published Release (id 387682986).

## Work committed since, all on claude/admiring-wright-k20ptf

Each was a work commit: 🔒 SECURITY reviewed, approval given, no version bump.

- bb61fa6 floating image tag cannot move backward (release.yml guard)
- e9b9cd1 Enter submits the server form (the reported "cannot add a username")
- f456052 one capture per interface per server (+ interface column, migration)
- 195eb9a master key rotation routine (backend/rekey.py, 20 tests)
- 16d1190 deployment instructions (compose header, README quick start)
- e687ca0 filter library moved into the Capture tab, Filters tab removed
- 4f0a2cf CSP hash pinned by a test

455 tests pass, no skips. Tool-dependent suites really ran.

## Uncommitted work: browser test suites, plus two fixes they justified

Track: work commit. No version bump, no artifact, no publish.
Branch: claude/admiring-wright-k20ptf -- the user chose it this session.

Contents: tests/browser (31 tests), a favicon, and Enter submitting every
single-field form via data-enter-submits on the container. 486 tests, no skips.

🔒 SECURITY   ✅ reviewed. New dev-only dependency playwright==1.62.0 (official
                Microsoft package, exact name, actively maintained, not in
                requirements.txt so it never reaches the shipped image;
                pip-audit: no known vulnerabilities). Test server binds
                loopback only, throwaway master key per run, temp dirs removed
                on teardown. --no-sandbox only when running as root, headless,
                own-origin pages.
📋 APPROVAL   ⬜ not yet given. Do not commit until the user says so.

The two fixes were asked for explicitly. Both are covered by browser tests that
were verified to fail without them: stripping data-enter-submits from index.html
fails 6 tests, and removing the icon puts the /favicon.ico 404 back in the
console assertions.

Still on the old id list in app.js: display-filter, login-password, reg-password,
totp-confirm-code, login-totp. Left alone deliberately -- the display filter's
Enter needs a loaded capture to test, and an untested migration is how this bug
class started.

Pre-existing finding, NOT from this change, for dev.14's Gate 3: pytest 8.3.4
carries PYSEC-2026-1845 (predictable /tmp/pytest-of-{user}; local DoS or
privilege gain), fixed in 9.0.3. Dev-only. A major pytest bump is its own
change, not a rider on this one.

## Next: 0.1.0-dev.14 release sequence -- ALL SIX GATES APPLY

🔢 VERSION    ⬜ bump backend/main.py:61, docker-compose.yml image tag, and the
                CHANGELOG heading together. v0.1.0-dev.13 is confirmed tagged.
🔨 BUILD      ⬜ 483 tests, no skips. The browser suites are now IN the repo
                (tests/browser, 28 tests) and run in CI, so the browser pass is
                part of the suite rather than a separate manual step.
🔒 SECURITY   ⬜ pip-audit, plus review of this release's new input paths.
📄 DOCS       ⬜ CHANGELOG entry for dev.14.
📦 RELEASE    ⬜ PR ➖ N/A -- no branch to merge into.
🚀 SHIP       ⬜ the tag is the user's to push, always.

## Session notes

- Environment: remote container. Claude executes git after approval; tag and
  ref-deleting pushes are always handed to the user as a block.
- Branch: claude/admiring-wright-k20ptf is canonical. Work was briefly put on
  claude/dev13-ship-verify-n3cr2c (the harness-designated branch) and moved by
  fast-forward; that branch has since been deleted. The default branch
  (claude/hopeful-allen-qmo0ch) is explicitly out of scope -- do not raise it.
- tshark/tcpdump/capinfos are now installed by .claude/hooks/session-start.sh
  on remote sessions. No manual apt-get needed; if it ever is, the line needs
  DEBIAN_FRONTEND=noninteractive or wireshark-common's debconf prompt hangs it.
- ghcr.io :dev may currently point at dev.8's image -- dev.8 was tagged after
  dev.13, and dev.8's own copy of release.yml predates the guard. dev.14's
  release run will correct it. Worth confirming after dev.14 ships.
- v0.1.0-dev.8 is now tagged; the unfinished Gate 6 from earlier is closed.
- The browser suites use playwright's ASYNC api deliberately. The sync api
  installs an event loop on the main thread and holds it, and pytest-asyncio
  (this repo runs asyncio_mode=auto) then fails on every async test that
  follows: 30 failed / 106 errors in a full run, while each suite passed alone.
- The harness designated branch claude/pcap-server-dev14-release-3tokl4 for
  this session; it and claude/admiring-wright-k20ptf both point at de46241.
  Ask before pushing -- do not resolve this by guessing.
