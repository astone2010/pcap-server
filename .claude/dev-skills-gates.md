# Dev Skills gate state
Track: work commits complete; a 0.1.0-dev.14 RELEASE SEQUENCE is next
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

## Next: 0.1.0-dev.14 release sequence -- ALL SIX GATES APPLY

🔢 VERSION    ⬜ bump backend/main.py:61, docker-compose.yml image tag, and the
                CHANGELOG heading together. v0.1.0-dev.13 is confirmed tagged.
🔨 BUILD      ⬜ 455 tests plus a browser pass. The browser suites are NOT in
                the repo -- they caught five bugs across dev.11-14 that the
                Python suite could not see. Either rebuild them or decide
                explicitly to ship on tests alone.
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
