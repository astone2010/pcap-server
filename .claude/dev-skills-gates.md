# Dev Skills gate state
Track: work commit (0.1.0-dev.17 is released; unreleased work on top)
Version: 0.1.0-dev.17 (shipped)
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

## 🚨 UNRESOLVED — start here

**An untrusted host connected successfully.** On the deployed dev.17, the
Servers tab showed "Host not trusted — connections to it are refused" for
serveradmin@10.0.0.230:22 while **Test connection on that same server returned
"Connection successful / Host key: ssh-ed25519"**. Both cannot be true:

- /api/servers sets host_trusted from bool(db.get_known_hosts(hostname, port))
  (main.py, list_servers)
- _connect refuses when _get_known_hosts_file(hostname, port) returns None,
  which is exactly when get_known_hosts returns no rows (ssh_manager.py)

Same table, same key, opposite answers. The deployed image definitely contains
the refusal — the tag, the release and the version badge all agree — so this is
not a stale deployment. Ruled out already: testServer() overwrites its result
element before each request, so it is not stale DOM text.

Resolve it with one query against the live database before writing any code:

    docker exec -it <container> sqlite3 /data/pcap.db \
      "SELECT hostname, port, key_type FROM known_hosts;
       SELECT name, hostname, port FROM active_servers;"

- Rows present for 10.0.0.230/22 -> the connection was correct and
  /api/servers is misreporting. Suspect the hostname/port values differing
  between the stored known_hosts row and the active_servers row (whitespace,
  or a port stored as text).
- No rows -> the refusal did not fire, and the next check is whether the
  running code actually contains it:
      docker exec <container> python -c "import backend.ssh_manager as m, \
        inspect; print('no trusted host keys' in inspect.getsource(m))"

Whichever way it lands, it needs a test that pins the two answers together:
host_trusted and the connect decision must be derived from ONE function, not
from two call sites that can drift.

## What is in the working tree now

The Trust host button fix. Nothing committed yet — awaiting approval.

- frontend/js/app.js: "trust-server-host" moved from
  delegate("admin-known-hosts") to delegate("server-list"). The button renders
  in #server-list; delegate() bails on !container.contains(el), so every click
  was silently dropped. My regression, shipped in dev.17 with the button.
- tests/browser/test_server_form.py: 3 new. The wiring test asserts on the
  confirm() dialog, which fires on click before any network, so it pins the
  wiring rather than ssh-keyscan's behaviour against an unroutable address.
  Verified to fail (assert []) against the old wiring.
- CHANGELOG.md: Unreleased / Fixed entry.

## Gates

🔢 VERSION    ⬜ not owed on a work commit
🔨 BUILD      ✅ tests/browser/test_server_form.py 14 passed (was 11). FULL
                ./scripts/check.sh NOT yet re-run for this change — do that
                before the commit if it has not happened.
🔒 SECURITY   ✅ event-handler registration only; no new routes, no new input,
                no change to what is trusted or when.
📄 DOCS       ✅ CHANGELOG Unreleased/Fixed.
📦 RELEASE    ➖ N/A — no PR. Default branch out of scope by standing decision.
🚀 SHIP       ⬜ not owed on a work commit.

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
