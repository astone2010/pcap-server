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
- tag v0.1.0-dev.16 -> 55ad719 on the remote (git ls-remote --tags origin),
  which is exactly the branch head
- Release workflow run #16 completed success; image pushed to
  ghcr.io/darthrater78/pcap-server:0.1.0-dev.16 and :dev moved forward
- GitHub release published, prerelease, body compares dev.15...dev.16
- Check run #42 (the tag ref) completed success, as did #41 on the same SHA

All six gates for dev.16 closed. Do not re-run them.

## What is in the working tree now

Delete-a-running-capture fix, reported by the user: a delete had to perform the
same termination, remote file removal and session close a stop performs.
Nothing committed yet — awaiting approval.

- backend/capture.py: delete() awaits the cancelled monitor before touching the
  row (it was resurrecting the row via the monitor's finally -> _persist ->
  INSERT OR REPLACE), interrupts tcpdump, clears the remote pcap, closes the
  session, and returns what it did.
- backend/ssh_manager.py: RemoteCapture.remove_remote_file() — rm -f over the
  connection the capture is already on, before it is closed.
- backend/main.py: the DELETE route returns that result instead of a bare ok.
- frontend/js/app.js: a running capture gets its own prompt, a busy button, an
  alert on failure, and the remote path to clear by hand if that half failed.
- tests/test_capture.py: 7 new tests, including a regression test that fails
  against the old delete() (verified by reverting the await and watching it go
  red with error='cancelled').

## Gates

🔢 VERSION    ⬜ not owed on a work commit; a bump to dev.17 is the user's call
🔨 BUILD      ✅ ./scripts/check.sh — 557 passed, 21 skipped, 2m37s. Up from
                550. The 21 skips are tshark and capinfos, not installable in
                this container (apt repos 403/unsigned); browser suites DID run.
🔒 SECURITY   ✅ reviewed the diff against SECURITY_REFERENCE.md. rm -f path is
                _shell_quote'd and server-generated (/tmp/pcap_<uuid>.pcap),
                never user input; the command is timeout-bounded and check=True;
                authorisation is unchanged (_require_own_capture still gates
                the route); the response carries two booleans and no internal
                state; the frontend uses CSS.escape in the button selector and
                alert() text, so no new injection surface.
📄 DOCS       ✅ CHANGELOG "Unreleased" section covers both fixes.
📦 RELEASE    ➖ N/A — no PR. The default branch is out of scope by the user's
                standing decision from earlier sessions.
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
