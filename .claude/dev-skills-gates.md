# Dev Skills gate state
Track: release sequence — 0.1.0-dev.16
Version: 0.1.0-dev.16
Updated: 2026-09-12
Branch: claude/nifty-lamport-aul3v3 (branched from origin/claude/admiring-wright-k20ptf @ 0e7649e)

## What is in the working tree

Full audit of the codebase, three user-reported/requested UI items, and the
audit fixes worth making. Nothing committed yet — awaiting approval.

- Saved filtered views (new feature): capture_views table, 5 routes, streaming
  filtered pcap export, viewer tab strip.
- Display-filter autocomplete over protocol/field names.
- Capture filter library scroll fix (.panel overflow:hidden was clipping it).
- Audit fixes: per-capture monitor timeout, constant-cost login for an unknown
  username, packet-detail rate limit, chunk-length bound, shared
  is_relative_to path check, hourly housekeeping sweep.
- README restructured into install -> first capture -> target host -> capture
  -> read -> secure -> operate -> develop. New Requirements and Development
  sections. No prose lost (verified line-by-line against HEAD).

## Gates

🔢 VERSION    ✅ APP_VERSION (backend/main.py:68) and the docker-compose image
                tag both read 0.1.0-dev.16; the CHANGELOG "Unreleased" heading
                became "0.1.0-dev.16 — 2026-09-12". release_notes_url in
                main.py is built from APP_VERSION, so it points at the new tag
                as soon as it exists. Grepped for every other "0.1.0-dev.15"
                string: the only one left is CHANGELOG's own dev.15 heading,
                which is history. v0.1.0-dev.15 confirmed tagged on the remote
                (git ls-remote --tags origin) — no gap behind this release.
🔨 BUILD      ✅ ./scripts/check.sh, re-run AFTER the version bump: 550 passed,
                21 skipped, 2m34s. Up from 517 (496 passed + 21 skipped) —
                33 new tests. The 21 skips are tshark and capinfos, which are
                not installable in this container (apt repos 403/unsigned);
                they run on a machine that has them. The browser suites DID
                run here — chromium is present — including 20 new ones.
🔒 SECURITY   ✅ Full read of every backend module and the frontend against
                SECURITY_REFERENCE.md and QUALITY_REFERENCE.md. pip-audit:
                runtime deps (backend/requirements.txt) clean; two findings in
                non-runtime packages — pytest 8.3.4 (PYSEC-2026-1845, fix
                9.0.3, dev-only) and setuptools 79.0.1 (PYSEC-2026-3447, a venv
                build tool the project never declares). Both reported to the
                user, neither fixed here: pytest 9 is a major bump that also
                drags pytest-asyncio and needs its own run.
📄 DOCS       ✅ CHANGELOG has an "Unreleased" section covering every change.
                README restructured and re-checked: no broken internal anchors,
                the stale "Filters library is a tab" claim fixed, saved views
                and autocomplete documented.
📦 RELEASE    ➖ N/A — no PR. The default branch is out of scope by the user's
                standing decision from earlier sessions.
🚀 SHIP       ⏳ commits and the branch push done from this container. The tag
                is NOT — a tag push is always the user's own action (Section
                5.7), handed over as a block. Stays ⏳ until
                `git ls-remote --tags origin v0.1.0-dev.16` answers.

## Reported, deliberately not changed

- Dockerfile base image is not digest-pinned; docker-compose has no cap_drop /
  no-new-privileges. Snippets handed to the user — untestable here (no Docker).
- GitHub Actions pinned to major tags, not commit SHAs. softprops/action-gh-
  release runs with contents: write.
- No LICENSE file, while README says "See repository for license details".
  A 1.0 blocker, and the licence is the user's choice to make.
- Any authenticated user can use any admin-uploaded SSH key against any host
  they name. A design decision, not a defect — surfaced for a 1.0 call.
- docker-compose ships COOKIE_SECURE=false with the port published on all
  interfaces. Documented in the file, but it is the insecure default.
- dev.14's release body still compares against dev.8 (carried over, cosmetic).

## Branch note for the next session

The container cloned the repo's HEAD, which is claude/hopeful-allen-qmo0ch —
the ORIGINAL single "Add pcap-server" commit, not the current work. There is no
main/master on origin. claude/nifty-lamport-aul3v3 was created here from
origin/claude/admiring-wright-k20ptf (0e7649e, = v0.1.0-dev.15), which is the
real tip. A session that trusts the default checkout audits a dead ancestor.
