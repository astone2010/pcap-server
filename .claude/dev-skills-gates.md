# Dev Skills gate state
Track: release sequence — 0.1.0-dev.17
Version: 0.1.0-dev.17
Updated: 2026-09-13
Branch: claude/admiring-wright-k20ptf — CANONICAL, and the only one to push to.
        The harness assigns a fresh claude/* branch every session; that
        assignment is NOT the branch this project uses. Three sessions running
        have now pushed to the harness name first and had to be corrected.
        Fast-forward onto admiring-wright-k20ptf instead.

## What is in 0.1.0-dev.17

Three commits, all pushed, each green on CI before the bump:

- f148595 Delete a running capture the way Stop stops one (Check #43)
- fc727c9 Prefer a trusted host's strongest key (Check #44)
- 60acfe7 Refuse a host whose keys are not trusted (Check #45) — BREAKING

BREAKING in this release: a server whose host has never been scanned stops
working until an admin trusts it. Accepted by the user; the project is still
in development.

## Gates — release sequence, 0.1.0-dev.17

🔢 VERSION    ✅ APP_VERSION (backend/main.py:68) and the docker-compose image
                tag both read 0.1.0-dev.17; the CHANGELOG "Unreleased" heading
                became "0.1.0-dev.17 — 2026-09-13". release_notes_url is built
                from APP_VERSION so it follows automatically. Grepped: no
                0.1.0-dev.16 left outside CHANGELOG history. v0.1.0-dev.16
                confirmed tagged on the remote — no gap behind this release.
🔨 BUILD      ✅ ./scripts/check.sh re-run AFTER the bump: 591 passed, 0
                skipped, 2m43s. The session-start hook installs tshark and
                capinfos, so the 21 that skip in a bare container ran too.
                Browser suites ran (chromium present).
🔒 SECURITY   ✅ Each of the three commits was reviewed against
                SECURITY_REFERENCE.md as it was written; the bump itself adds
                no code. pip-audit re-run this session: backend/requirements.txt
                clean, no known vulnerabilities. Two findings remain in the dev
                toolchain only (pytest 8.3.4 PYSEC-2026-1845, setuptools 79.0.1
                PYSEC-2026-3447) — neither ships in the container. dev.17 is
                itself mostly a security release: it closes a fail-open host
                key default and a stale-row/remote-file leak on capture delete.
📄 DOCS       ✅ CHANGELOG dated, with a Changed section marking the breaking
                change rather than burying it under Fixed. README summary line,
                first-capture ordering and Security section all updated in
                60acfe7; the Known Hosts panel hint too.
📦 RELEASE    ➖ N/A — no PR. The default branch is out of scope by the user's
                standing decision from earlier sessions.
🚀 SHIP       ⏳ version-bump commit pushed from this container. The tag is NOT
                and is the user's own action — handed over as a block. Stays ⏳
                until `git ls-remote --tags origin v0.1.0-dev.17` answers.

## The plan for what is left before 1.0

Ordered by value, with the reasoning, so a later session does not re-derive it.
Agreed with the user on 2026-09-13.

1. LICENSE. README says "See repository for license details" and there is no
   licence file. A true 1.0 blocker, one file, and blocked ONLY on the user's
   choice of licence. Nothing else can be called 1.0 while the repo makes a
   claim it does not honour.
2. Pin GitHub Actions to commit SHAs. softprops/action-gh-release@v2 runs in
   the release job holding contents: write, and actions/checkout@v4,
   docker/*-action@v3/v6 are all floating tags. A moved tag on any of them
   rewrites releases and publishes images. This is the supply-chain item that
   already has write access to the repo — it outranks the pip-audit rows.
   Mechanical and verifiable from here.
3. /api/ssh-keys authorization. It is get_current_user, not require_admin: any
   authenticated user can use any stored SSH key against any host they name.
   Same family as the fail-open dev.17 just closed — trust is now enforced on
   WHICH host, but not on WHO may use which key against it. Needs a decision
   from the user on the intended model before code.
4. Dockerfile digest pinning, plus cap_drop and no-new-privileges in compose.
   Minimal caps for the entrypoint are CHOWN, FOWNER, SETUID, SETGID. Cannot
   be verified in this container (no Docker) — do it where it can be run, or
   unverified hardening ships an image that will not start.
5. pytest 8 -> 9 (PYSEC-2026-1845). LAST, and its own session.
   pytest-asyncio 0.25.2 requires pytest<9, so this is a forced coordinated
   bump into pytest-asyncio 1.x, which changed fixture-loop semantics and
   dropped the event_loop fixture. pyproject sets asyncio_mode = "auto" across
   591 mostly-async tests: expect a broad reshuffle, not a version string.
   Dev-only — it does not ship.
   setuptools PYSEC-2026-3447 rides along or is ignored: the project never
   declares setuptools, it is the venv's bootstrap tool.

Also open, smaller: dev.14's release body still compares against dev.8
(cosmetic). docker-compose ships COOKIE_SECURE=false with the port published
on all interfaces — documented in the file, but it is the insecure default.

Stale branch on origin that is the USER'S to delete, never Claude's:
claude/nifty-lamport-aul3v3 (a duplicate of 45cf119).

## Branch note — READ THIS FIRST

The container clones the wrong tip. origin/HEAD is claude/hopeful-allen-qmo0ch,
the ORIGINAL single "Add pcap-server" commit — no README, no tests. There is no
main or master on origin. This session's clone landed on f1dc65b (dev.12).
Start with:
    git fetch origin claude/admiring-wright-k20ptf
    git checkout -B <work> origin/claude/admiring-wright-k20ptf
