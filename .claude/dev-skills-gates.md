# Dev Skills gate state
Track: work commit
Version: 0.1.0-dev.16 (shipped) — unreleased work on top, no bump yet
Updated: 2026-09-13
Branch: claude/admiring-wright-k20ptf — CANONICAL, and the only one to push to.
        The harness assigns a fresh claude/* branch every session; that
        assignment is NOT the branch this project uses. Three sessions running
        have now pushed to the harness name first and had to be corrected.
        Fast-forward onto admiring-wright-k20ptf instead.

## 0.1.0-dev.16 — RELEASED AND VERIFIED, nothing outstanding

Verified from this container on 2026-09-13:
- tag v0.1.0-dev.16 -> 55ad719 on the remote, exactly the branch head
- Release workflow run #16 success; image pushed to
  ghcr.io/darthrater78/pcap-server:0.1.0-dev.16 and :dev moved forward
- GitHub release published, prerelease, body compares dev.15...dev.16
- Check runs #41, #42 and #43 all success

All six gates for dev.16 closed. Do not re-run them.

## Committed since dev.16, pushed, CI green

- f148595 "Delete a running capture the way Stop stops one". delete() awaits
  the cancelled monitor before touching the row (it was resurrecting the row
  via the monitor's finally -> _persist -> INSERT OR REPLACE), interrupts
  tcpdump, clears the remote pcap over the capture's own connection, closes
  the session, and returns what it did. Frontend gained a running-aware
  prompt, a busy button, an error path and a remote-path fallback message.
  Check run #43 success.

## What is in the working tree now

Option 1 (fail closed) on host key trust, approved by the user for a
development-stage project. Nothing committed yet — awaiting approval.

- backend/ssh_manager.py: _connect refuses before opening a socket when no
  keys are stored, naming the host and where to trust it. known_hosts is never
  None now (that is asyncssh's "disable validation" value). The
  HostKeyNotVerifiable message no longer says "scan the host key first" — it
  could only ever fire for a MISMATCH, never for the no-keys case it named.
- backend/main.py: /api/servers reports host_trusted per row.
- frontend/js/app.js: the server list shows "Host not trusted — connections
  are refused", with an inline Trust host button for admins and an ask-an-
  admin line otherwise. trustServerHost() rather than adminTrustHost(),
  because the latter reports into the Admin tab's message element.
- frontend/index.html + README.md: the "an unverified host still connects"
  claim is now false and is corrected in both. README's first-capture steps
  reordered so trusting the host comes BEFORE Test connection, which can no
  longer run without it. The Security section explains the asyncssh
  known_hosts=None trap and why trust is endpoint-scoped and admin-owned.
- tests: 7 new (3 fail-closed in test_ssh_manager.py, 4 host_trusted in
  test_servers.py, including one pinning that two servers on one host share a
  single decision and one that port 22's keys do not vouch for port 2222).

BREAKING for any deployment with servers whose hosts were never scanned: they
stop working until an admin trusts them. Accepted by the user — still in
development.

## Gates

🔢 VERSION    ⬜ not owed on a work commit; a bump to dev.17 is the user's call
🔨 BUILD      ✅ ./scripts/check.sh — 591 passed, 0 skipped, 2m39s. tshark and
                capinfos are installed by the session-start hook, so the 21
                that skip in a bare container ran here too.
🔒 SECURITY   ✅ This IS the security change: it closes a fail-open default.
                Reviewed for the obvious own-goal — no chicken and egg, since
                scan_host_keys() uses ssh-keyscan as a subprocess and never
                goes through _connect(). host_trusted on /api/servers reveals
                only whether a host the caller already configured is trusted,
                which Test connection would tell them anyway; establishing
                trust is still require_admin.
📄 DOCS       ✅ CHANGELOG (a Changed section, marked breaking), README summary
                + first-capture order + Security section, and the Known Hosts
                hint in index.html.
📦 RELEASE    ➖ N/A — no PR. Default branch out of scope by standing decision.
🚀 SHIP       ⬜ not owed on a work commit.

## Raised this session, not changed

- An unverified host still connects, unverified. _get_known_hosts_file returns
  None when no keys are stored, and asyncssh treats known_hosts=None as
  "disable host key validation" -- not "use the default file". So a host that
  has never been scanned gets no verification at all and is handed the SSH
  key. Documented behaviour (README line 127, and the Known Hosts hint say so
  out loud) and a deliberate TOFU-on-demand design, but it is fail-open in the
  one place the security rules say fail closed. A 1.0 call for the user.
- The HostKeyNotVerifiable message says "Scan the host key first via Admin >
  Known Hosts", but that exception can only fire when keys ARE stored and do
  not match -- the no-keys case never raises it. The message describes the one
  situation it is never shown for.
- README line 56 says "SSH host keys are verified per host", which line 127
  then qualifies. The summary overstates the default.

## Carried over from dev.16, still open

- No LICENSE file, while README says "See repository for license details".
- Dockerfile base image not digest-pinned; compose has no cap_drop /
  no-new-privileges. Needs a real Docker host to verify.
- Actions pinned to @v4/@v3, not SHAs; softprops/action-gh-release holds
  contents: write.
- pytest 8.3.4 PYSEC-2026-1845 — dev-only; fix is pytest 9, a major bump that
  drags pytest-asyncio.
- /api/ssh-keys is get_current_user, not require_admin: any user can use any
  stored key against any host they name. Design decision, worth a 1.0 call.
- dev.14's release body still compares against dev.8 (cosmetic).

Stale branches on origin that are the USER'S to delete, never Claude's:
claude/nifty-lamport-aul3v3 (duplicate of 45cf119).

## Branch note — READ THIS FIRST

The container clones the wrong tip. origin/HEAD is claude/hopeful-allen-qmo0ch,
the ORIGINAL single "Add pcap-server" commit — no README, no tests. There is no
main or master on origin. This session's clone landed on f1dc65b (dev.12).
Start with:
    git fetch origin claude/admiring-wright-k20ptf
    git checkout -B <work> origin/claude/admiring-wright-k20ptf
