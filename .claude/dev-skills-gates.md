# Dev Skills gate state
Track: release sequence — 0.1.0-dev.19
Version: 0.1.0-dev.19
Updated: 2026-09-13
Branch: claude/admiring-wright-k20ptf — CANONICAL, and the only one to push to.
        The harness assigns a fresh claude/* branch every session; that
        assignment is NOT the branch this project uses. Three sessions running
        have now pushed to the harness name first and had to be corrected.
        Fast-forward onto admiring-wright-k20ptf instead.

## 0.1.0-dev.17 — RELEASED AND VERIFIED

Verified from the container on 2026-09-13:
- tag v0.1.0-dev.17 -> 1bf079b on the remote
- release published, prerelease, body compares dev.16...dev.17
- the user confirmed it deployed: pcap.nscriven.net shows v0.1.0-dev.17

Contents: f148595 (capture delete), fc727c9 (host key ordering),
60acfe7 (fail-closed host trust, BREAKING), 1bf079b (bump).
All six gates closed for dev.17. Do not re-run them.

## 0.1.0-dev.18 — RELEASED (tag pushed by the user, 2026-09-13)

One fix: f7d05b0, the Trust host button wiring. Cut on its own because the
deployed dev.17 carries a dead button, and a fix nobody can run is not a fix.

🔢 VERSION    ✅ APP_VERSION (backend/main.py) and the docker-compose image tag
                both read 0.1.0-dev.18; CHANGELOG heading dated 2026-09-13. No
                0.1.0-dev.17 left outside changelog history. v0.1.0-dev.17
                confirmed tagged on the remote — no gap behind this release.
🔨 BUILD      ✅ ./scripts/check.sh re-run AFTER the bump: 594 passed, 0
                skipped, 2m48s. CI Check run #48 green on f7d05b0 before the
                bump commit.
🔒 SECURITY   ✅ dev.18 contains one event-handler registration change. No new
                routes, no new input, no change to what is trusted or when.
                pip-audit unchanged from dev.17: backend/requirements.txt
                clean; the two findings are dev-toolchain only.
📄 DOCS       ✅ CHANGELOG dated.
📦 RELEASE    ➖ N/A — no PR. Default branch out of scope by standing decision.
🚀 SHIP       ✅ tag pushed by the user and confirmed deployed —
                pcap.nscriven.net shows v0.1.0-dev.18.

## 0.1.0-dev.19 — RELEASED (tag pushed by the user, 2026-09-13)

One fix: 4818f22, the caching and tab-refetch pair below. Cut immediately
rather than held, because dev.18 structurally CANNOT deliver its own frontend
fix to a browser that has already loaded the page — that is the bug.

🔢 VERSION    ✅ APP_VERSION (backend/main.py) and the docker-compose image tag
                both read 0.1.0-dev.19; CHANGELOG heading dated 2026-09-13. No
                0.1.0-dev.18 left outside changelog history. v0.1.0-dev.18
                confirmed tagged at 85d7c89 — no gap behind this release.
🔨 BUILD      ✅ ./scripts/check.sh re-run AFTER the bump: 601 passed, 0
                skipped, 2m59s.
🔒 SECURITY   ✅ Cache-Control: no-cache is a weakening of CACHING only. No
                change to auth, to input handling, or to what is served; the
                CSP and its hash-pinned inline theme script are untouched.
                pip-audit unchanged: backend/requirements.txt clean.
📄 DOCS       ✅ CHANGELOG dated.
📦 RELEASE    ➖ N/A — no PR. Default branch out of scope by standing decision.
🚀 SHIP       ✅ tag v0.1.0-dev.19 -> 4b34837 confirmed on the remote.

## RESOLVED — the untrusted-host contradiction

Both halves are explained, and neither was the connection path.

The user's decisive observation: add a server, trust it from Admin, come back
to Servers — still "Host not trusted", and Test connection succeeds. So the
host WAS trusted; /api/servers was not lying, the page was showing stale data.

1. The Servers tab never refetched. initTabs() refreshed only the admin tab on
   activation; the server list was loaded at boot and after add/edit/remove.
   Trusting in Admin and returning rendered activeServers as captured before
   the trust existed. Fixed: the tab refetches on activation, and the open
   server keeps its highlight (selection had lived only as a class on the
   element the re-render replaces).

2. The Trust host button stayed dead in dev.18 even though dev.18 contained
   the wiring fix -- because the browser was still running dev.17's app.js.
   StaticFiles sends ETag and Last-Modified and NO Cache-Control, so browsers
   fall back to heuristic freshness (~10% of the file's age since
   Last-Modified) and reuse app.js without revalidating. Fixed: frontend files
   are served Cache-Control: no-cache, which is revalidate-not-restore -- the
   ETag still stands, so a reload is a 304 with no body.

The second one is the important finding and is not about this button: until
now EVERY frontend fix in this project could silently fail to reach users, and
the symptom is always "you shipped it and it still does not work."

Note for the next session: anyone testing a frontend change against a
deployment made before dev.19 should hard-reload once (Ctrl+Shift+R, or
long-press reload on mobile). The no-cache header only governs fetches made
after it ships.

## Reported by the user, NOT yet designed or built

**Trusting a host is blind acceptance.** Pressing "Trust keys" runs
ssh-keyscan and stores whatever comes back, in one step. The operator never
sees what they accepted. Real ssh shows you the fingerprint and makes you type
yes; this shows nothing.

Proposed two-step flow (asyncssh API confirmed working in this container):

    asyncssh.import_public_key(f"{key_type} {blob}").get_fingerprint()
      -> 'SHA256:pqouMGbr5CNceb8hwojaPMFisestRVqpjUsaV14FfeE'

That is OpenSSH's own format, so it compares directly against
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` run on the target — which
is the whole point, and the detail that makes the feature usable rather than
decorative.

1. POST /api/admin/known-hosts/scan becomes NON-MUTATING: scans, returns each
   key with its type and SHA256 fingerprint, stores nothing.
2. The UI lists them and says where to compare them against the host. Accept
   or Cancel.
3. A new POST /api/admin/known-hosts/confirm carries back the exact key blobs
   the operator saw, and stores those.

Step 3 must store what was DISPLAYED, not re-scan. Re-scanning on confirm
reopens the hole the review was meant to close: a swap between display and
acceptance would be pinned without anyone seeing it.

## Decided, do not re-open

- **Non-admins cannot establish host trust, and there is no request queue.**
  They see "Ask an admin to trust it under Admin > Known Hosts" where an admin
  sees the Trust host button. The alternative considered and rejected was a
  "this server needs its host trusted" flag an admin approves; it adds a queue
  for a workflow that is rare and already has a clear human path. Decided by
  the user on 2026-09-13. This is the behaviour already shipped — no code
  change follows from it.
- **The trust RECORD stays admin-owned and endpoint-scoped; only the state and
  the action surface on the server page.** active_servers rows are per-user and
  known_hosts rows are not; several servers share one endpoint's decision
  (pinned by test_servers.py); and re-pinning a host decides what every user's
  connections are checked against. The server page shows trust and offers an
  admin the button — it does not own the data.

## Asked by the user on 2026-09-13, answered, not yet built

Three things raised at the end of the session. Each was investigated; none
were started. Two are "the data already exists and the UI discards it".

**1. Multiple BPF selectors.** Cannot be done from the UI today. Both insertion
paths REPLACE the box rather than append:
    useLibraryFilter(expr)    -> box.value = expr   (app.js:1149)
    useFilterSuggestion(expr) -> box.value = expr   (app.js:2314)
So a second pick wipes the first. Typing `tcp port 22 and host 10.0.0.5` by
hand works fine — BPF has and/or/not and the backend passes the expression
through untouched.

The code change is small; the DESIGN question is not, and should be settled
before building. Appending with " and " is right most of the time and silently
wrong the rest: `port 80 and port 443` matches nothing, where the user meant
`or`. Recommended shape — append with " and " when the box is non-empty, but
surface the combined expression for editing before it runs, rather than
quietly composing a filter that captures zero packets. The user has NOT
decided this yet.

**2. OS distro is detected and then thrown away.** prereq_check reads
/etc/os-release on the target and the API returns it:
    "os": result["facts"]["os_release"].get("PRETTY_NAME", "")
    — main.py:932 (saved server) and main.py:1054 (add-form probe)
renderPrereqs (app.js:536) never reads res.os. Zero hits for it in the
frontend. It is not stored on the server record and not set at creation; it is
discovered live per check.

Two separate asks, worth keeping apart:
  a. Show it in the prereq output. Free — the data is already in the response.
  b. Store it on the server row and show it at a glance. A real feature: it is
     a cache that goes stale when a host is upgraded, so it needs a "last
     seen" qualifier rather than being presented as current fact.
Recommended: do (a) now, treat (b) as its own piece of work.

**3. App version on the login page.** The slot EXISTS and is deliberately left
empty. index.html:92 has <span id="auth-version">, applyBuildLinks fills it
from status.version, and the API refuses to supply it:
    "version": APP_VERSION if user else ""            — main.py:510
    "release_notes_url": ... if user else ""          — main.py:511
That is an intentional choice, not an oversight: an unauthenticated visitor is
not told the exact version, because a version plus a public changelog names
precisely which fixes an instance does not have.

Genuine trade-off both ways. For: diagnosing "did my deploy land?" from the
login page is exactly what the user was doing repeatedly, it is a self-hosted
tool usually on a private address, and a build can be fingerprinted from asset
hashes regardless. Against: free reconnaissance on the most exposed page.
Middle option worth considering: show it when authenticated OR when the
deployment opts in via an env flag, so a private instance can show it and a
public one need not. NOT decided.

## The plan for what is left before 1.0

Ordered by value. Agreed with the user on 2026-09-13.

0. The two items above: the untrusted-host contradiction (a correctness bug in
   a security control, so it outranks everything) and then the fingerprint
   review.
1. LICENSE. README says "See repository for license details" and there is no
   licence file. A true 1.0 blocker, one file, blocked ONLY on the user's
   choice of licence.
2. Pin GitHub Actions to commit SHAs. softprops/action-gh-release@v2 runs in
   the release job holding contents: write; actions/checkout@v4 and the
   docker/* actions are floating tags too. A moved tag rewrites releases and
   publishes images. This is the supply-chain item that already has write
   access to the repo — it outranks the pip-audit rows. Mechanical.
3. /api/ssh-keys authorization. It is get_current_user, not require_admin: any
   authenticated user can use any stored SSH key against any host they name.
   Same family as the fail-open dev.17 closed. Needs a decision from the user
   on the intended model (keys owned per-user? admin-assigned per-server?
   admin-only?) before any code.
4. Dockerfile digest pinning, plus cap_drop and no-new-privileges in compose.
   Minimal caps for the entrypoint: CHOWN, FOWNER, SETUID, SETGID. Cannot be
   verified in this container (no Docker).
5. pytest 8 -> 9 (PYSEC-2026-1845). LAST, and its own session.
   pytest-asyncio 0.25.2 requires pytest<9, so it is a forced coordinated bump
   into pytest-asyncio 1.x, which changed fixture-loop semantics and dropped
   the event_loop fixture. pyproject sets asyncio_mode = "auto" across 594
   mostly-async tests. Dev-only; it does not ship. setuptools
   PYSEC-2026-3447 rides along or is ignored — the project never declares it.

pip-audit as of 2026-09-13: backend/requirements.txt CLEAN. Both findings are
dev-toolchain only.

Also open, smaller: dev.14's release body still compares against dev.8
(cosmetic). docker-compose ships COOKIE_SECURE=false with the port published
on all interfaces — documented in the file, but it is the insecure default.

Stale branch on origin that is the USER'S to delete, never Claude's:
claude/nifty-lamport-aul3v3 (a duplicate of 45cf119).

## Environment notes

- Remote container: Claude executes branch pushes after approval. Tag pushes
  and ref deletions are ALWAYS handed to the user as a block. No `cd` in those
  blocks — the user's preference.
- `gh` is absent. Use the GitHub MCP tools.
- The session-start hook installs tshark, tcpdump and capinfos, so the 21
  tests that skip in a bare container DO run here. A full run is ~2m45s.
- Commits only on the user's explicit word. A stop hook is not approval; it
  fired three times this session and was correctly ignored each time.

## Branch note — READ THIS FIRST

The container clones the wrong tip. origin/HEAD is claude/hopeful-allen-qmo0ch,
the ORIGINAL single "Add pcap-server" commit — no README, no tests. There is no
main or master on origin. This session's clone landed on f1dc65b (dev.12).
Start with:
    git fetch origin claude/admiring-wright-k20ptf
    git checkout -B <work> origin/claude/admiring-wright-k20ptf
