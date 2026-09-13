# Dev Skills gate state
Track: release sequence — 0.1.0-dev.23 CLOSED. All six gates done.
Version: 0.1.0-dev.23
Updated: 2026-09-13 (session: live-streaming-packet-filter-6irysx)
Branch: claude/admiring-wright-k20ptf — CANONICAL, re-confirmed by the user
        this session.

## Branch hygiene — read this at session start

The harness assigns a fresh claude/* branch every session. This session was
given claude/live-streaming-packet-filter-6irysx; the user confirmed AGAIN that
the canonical branch is claude/admiring-wright-k20ptf. That has now been
confirmed in three consecutive sessions, so treat it as settled and do not ask
a fourth time — just checkout the canonical branch and carry on.

Two traps, both hit this session:

1. **The local canonical ref was 39 commits stale on checkout.** The container
   clones the harness-assigned branch; the canonical one comes down as a stale
   local ref. `git pull --ff-only origin claude/admiring-wright-k20ptf` after
   checkout, and confirm the log before trusting the working tree.
2. **There is a second branch on the remote, claude/hopeful-allen-qmo0ch**
   (eb4502e). It is the repo default, and every GitHub release's
   `target_commitish` names it — dev.22's and dev.23's alike. That field is
   default-branch metadata and NOT where the tag points; both tags resolve
   correctly to their own commits. Cosmetic, matches the previous release, do
   not "fix" it.

## 0.1.0-dev.23 — RELEASED (tag pushed by the user, 2026-09-13)

Three commits: 2d7468e (backend pipeline), 298295d (frontend + chip size),
a3e1408 (bump).

🔢 VERSION    ✅ APP_VERSION (backend/main.py:74) and the docker-compose image
                tag both read 0.1.0-dev.23; CHANGELOG heading dated
                2026-09-13. v0.1.0-dev.22 confirmed tagged at a0e91d7.
🔨 BUILD      ✅ ./scripts/check.sh re-run AFTER the bump and after the final
                comment edits: 890 passed, 0 skipped, 4m25s. 872 before this
                work; the 18 new tests are the record walk, the two limits,
                the live routes, and read_at against a real SFTP server.
🔒 SECURITY   ✅ pip-audit clean; NO dependency change at all — the whole
                feature is stdlib plus the asyncssh and tshark already here.
                Notes under SECURITY, below.
📄 DOCS       ✅ CHANGELOG dated; README gained a "Streaming a capture live"
                section, three settings rows, a capture-form note and a
                known-limits entry; docs/architecture.md gained a module row,
                a design section and a known-limits entry.
📦 RELEASE    ➖ N/A — no PR. Default branch out of scope by standing decision.
🚀 SHIP       ✅ verified from the container, not assumed: tag v0.1.0-dev.23 ->
                a3e1408 on the remote, matching the branch head exactly; Check
                run #62 green on that commit BEFORE the tag went up; Release
                run #23 success; release published as a prerelease with a body
                comparing dev.22...dev.23. No assets, same as dev.22 — that is
                this repo's norm, not a failure.
                NOT yet confirmed deployed.

### DECIDED by the user, 2026-09-13 — do not re-open

1. **Display filters ARE in a live view.** The plan written at the end of
   dev.22 recommended shipping without them ("no display filter in v1, All
   packets only, and say so in the UI"). The user overruled it: "a live stream
   without packet filter is kind of useless". Settled, and it turned out cheap
   rather than expensive because the live routes reuse get_packet_list.
2. **The cap freezes the PREVIEW, not the capture.** Past the byte cap the live
   view stops advancing and says so; tcpdump runs on and the saved pcap is
   complete. Rejected: a rolling window (renumbers frames, breaks the detail
   pane and the append-only list) and stopping the capture at the cap (silently
   truncates a capture the operator asked to run for five minutes).
3. **The cap of two is on CAPTURES, not viewers.** Enforced in start().
4. Branch: claude/admiring-wright-k20ptf.

### THE TWO FACTS THAT DECIDED THE ARCHITECTURE — do not re-derive

Verified in the container during dev.22 and now pinned by tests.

1. **A partially written SEALED capture cannot be read at all.**
   Cryptor.open_stream raises "truncated: incomplete chunk" rather than
   yielding the chunks it holds. Deliberate truncation detection, NOT
   weakened. It kills the obvious "read the partial stored file" design
   outright, which is why this is a pass-through that never writes plaintext
   to the data volume.

2. **tshark exits non-zero on a capture cut mid-packet** — and a non-zero exit
   with a display filter present is exactly how get_packet_list detects a
   filter tshark refused. A live read lands mid-record constantly, so without
   intervention EVERY poll with a filter applied would have reported the
   operator's valid filter as invalid. backend/livestream.py walks the pcap
   record headers and hands tshark only whole records.

   tests/test_livestream.py::test_tshark_accepts_what_the_buffer_hands_it is
   the load-bearing test: it puts the same bytes through real tshark both ways
   and asserts the difference. Its failure message says that if tshark ever
   stops objecting, the trimming is no longer load-bearing and livestream.py
   can be simplified.

### What was built

backend/livestream.py (new)  LiveBuffer + BytesSource: the record walk and the
                             cap. Pure parsing, no asyncio, unit-tested alone.
                             feed() enforces the cap itself rather than
                             trusting the caller — a test caught that it did
                             not, and a buffer that only stays within its cap
                             when asked nicely is not a cap.
backend/capture.py           -U when live; live_count() and the
                             max_live_streams check inside start()'s await-free
                             stretch; live_poll() with a per-capture lock;
                             buffer dropped on every capture-end path.
backend/ssh_manager.py       RemoteCapture.read_at() over the capture's OWN
                             connection; SFTP client closed in close().
backend/main.py              two live routes + their own rate limiter.
backend/models.py            live_stream on CaptureRequest and CaptureInfo.
backend/database.py          live_stream column + migration, three settings.
frontend                     Capture-screen checkbox, the live bar, the
                             append-only list, the finish-and-reopen handover,
                             the capture-list badge and Watch live button.

### SECURITY

- No new dependencies. pip-audit clean.
- Two new routes, both GET, both behind get_current_user (which enforces TOTP)
  and _require_own_capture (404, never 403, on someone else's — a 403 would
  confirm the id exists). offset/limit are bounded Query params; view flags are
  checked against ALLOWED_VIEW_FLAGS; the display filter goes through the
  existing validate_display_filter. The read-only-over-HTTP middleware treats
  them exactly as the stored /packets routes, because they return the same kind
  of data.
- Their own rate limiter (rate_limit_live_polls_per_min, 90). Sharing the
  packet-list budget would have left two live streams unable to open a packet.
- remote_path is server-generated (/tmp/pcap_<uuid>.pcap), never user input,
  and reaches SFTP rather than a shell.
- LiveBuffer parses a file sitting on a host under investigation. It bounds a
  claimed record length (MAX_RECORD_BYTES), refuses an unrecognised magic
  rather than guessing, and the walk provably advances, so a crafted file
  cannot spin it.
- An SFTP error can carry text from the target host: truncated to 200 chars and
  rendered with textContent, the same treatment the existing capture-failure
  message already gets.
- The one SQL change is a hardcoded ALTER TABLE with no interpolation.
- NEW EXPOSURE, written into both README and architecture.md: a live stream
  holds up to live_stream_buffer_mb of UNENCRYPTED packet data in process
  memory while the capture runs. Packets already pass through memory on the way
  to tshark; what changes is volume and duration. Bounded by that setting and
  by max_live_streams, never written to the data volume, discarded when the
  capture ends.

### The chip size

.view-tab was 0.75rem — 12px, smaller than everything around it, for
operator-typed labels read at a glance while packets scroll. Now 0.875rem, the
app's own content size, with padding and the action glyphs scaled to match; the
three action buttons on a chip were a few pixels of click target side by side.
The browser test asserts the chip is no smaller than a capture's name rather
than hard-coding a number alone, so the guard says what it is guarding.

### Deliberately NOT done

- No WebSocket or SSE. Polling with a frame-number cursor matches
  refreshRunningCaptures, adds no transport, and shares its cadence so the two
  cannot disagree about one capture's count. Revisit only if 3s proves visibly
  laggy in real use.
- No long-lived `tshark -T ek` NDJSON stream. It would remove the O(n) re-parse
  per poll, but it changes the parser model substantially and would not share
  the stored viewer's code path — which is the property that keeps one filter
  language rather than two.

### NOT VERIFIED — the first thing to check in real use

**Live streaming has never run against a real remote host.** This container has
no SSH target and self-capture is refused by design. What IS covered by real
tools rather than fakes: the record walk and the filter behaviour against real
tshark, and read_at against a real asyncssh SFTP server serving a file that
grows under the reader (tests/test_ssh_manager.py, an in-process server added
this session — there was no SSH-server harness before).

The untested seam is tcpdump -U's actual write cadence on a real target: how
quickly the remote file grows, and therefore whether a 3s poll feels live or
laggy. Point a real capture at something before trusting the feature.
