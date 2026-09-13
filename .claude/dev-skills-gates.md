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

Host key ordering fix, reported by the user: forgetting a host's keys and
rescanning made the handshake settle on RSA. Nothing committed yet — awaiting
approval.

- backend/ssh_manager.py: _get_known_hosts_file writes entries strongest first
  by host_key_strength. asyncssh derives its acceptable server-host-key-alg
  list by walking the file in order and SSH takes the first the server holds,
  so line one was deciding the algorithm on the strength of ssh-keyscan's
  print order (rsa before ed25519). Verified directly against asyncssh's own
  match_known_hosts: rsa line first -> prefers rsa-sha2-256; ed25519 line
  first -> prefers ssh-ed25519.
- tests/test_ssh_manager.py: 6 new tests, including one asserting the result
  is independent of scan order, and one that every stored key is still
  written (a key absent from the file cannot verify a rotation).

## Gates

🔢 VERSION    ⬜ not owed on a work commit; a bump to dev.17 is the user's call
🔨 BUILD      ✅ ./scripts/check.sh — 584 passed, 0 skipped, 2m49s. The
                session-start hook installed tshark and capinfos, so the 21
                tests that skip in a bare container RAN for the first time
                here and pass. Browser suites ran too.
🔒 SECURITY   ✅ The ordering change is a strengthening: it makes the client
                prefer ed25519 over RSA where both are trusted, and it changes
                nothing about WHICH keys are trusted — every stored key is
                still written, so a rotation still verifies. No new input
                reaches a shell; the file is still built from stored key types
                and written to the data dir as before.
📄 DOCS       ✅ CHANGELOG "Unreleased" covers both fixes.
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
