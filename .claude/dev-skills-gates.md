# Dev Skills gate state
Track: release sequence — 0.1.0-dev.23
Version: 0.1.0-dev.23
Updated: 2026-09-13 (session: live-streaming-packet-filter-6irysx)
Branch: claude/admiring-wright-k20ptf — CANONICAL, re-confirmed by the user
        this session. The harness assigned claude/live-streaming-packet-filter-6irysx;
        that is NOT where this project's work goes. Both were at f6901ed at
        session start, and the local canonical ref was 39 commits stale until
        fast-forwarded.

Environment: REMOTE CONTAINER. Claude executes git here after approval; the tag
push is handed to the user as a block (Section 5.8).

## 0.1.0-dev.23 — AWAITING COMMIT APPROVAL

🔢 VERSION    ✅ APP_VERSION (backend/main.py:74) and the docker-compose image
                tag both read 0.1.0-dev.23; CHANGELOG heading dated 2026-09-13.
                v0.1.0-dev.22 confirmed on the remote at a0e91d7.
🔨 BUILD      ✅ ./scripts/check.sh re-run AFTER the bump and after the final
                comment edits: 890 passed, 0 skipped, 4m25s. Was 872 before
                this work; +18 are the new live-stream tests.
🔒 SECURITY   ✅ pip-audit clean; NO dependency changes at all. Diff scanned
                for the Section 4.2 categories — notes below.
📄 DOCS       ✅ CHANGELOG dated; README gains a "Streaming a capture live"
                section plus three settings rows and a known-limits entry;
                docs/architecture.md gains a module row, a design section and
                a known-limits entry.
📦 RELEASE    ➖ N/A — no PR. Default branch out of scope by standing decision.
🚀 SHIP       ⬜ tag block to hand to the user once the commit is approved.

### DECIDED by the user, 2026-09-13 — do not re-open

1. **Display filters ARE in v1.** The dev.22 plan recommended against them
   ("no display filter in v1, All packets only"). Overruled: "a live stream
   without packet filter is kind of useless". Settled.
2. **The cap freezes the PREVIEW, not the capture.** Past the byte cap the live
   view stops advancing and says so; tcpdump runs on and the saved pcap is
   complete. Rejected: a rolling window (renumbers frames, breaks the detail
   pane and the append-only list) and stopping the capture (silently truncates
   a capture the operator asked to run for five minutes).
3. **The cap of two is on CAPTURES, not viewers.** Enforced in start().
4. Branch: claude/admiring-wright-k20ptf.

### The two things that decided the architecture

Both were verified in the container during the dev.22 session and re-verified
by tests here. Do not re-derive them.

1. **A partially written SEALED capture cannot be read.** Cryptor.open_stream
   raises "truncated: incomplete chunk" rather than yielding the chunks it
   holds. That is deliberate truncation detection and it was NOT weakened. It
   kills the "just read the partial stored file" design outright, which is why
   this is a pass-through that never writes plaintext to the data volume.

2. **tshark exits non-zero on a capture cut mid-packet** -- and a non-zero exit
   with a display filter present is exactly how get_packet_list detects a
   filter tshark refused. A live read lands mid-record constantly, so without
   intervention EVERY poll with a filter would have reported the operator's
   valid filter as invalid. backend/livestream.py walks the pcap record headers
   and hands tshark only whole records.

   tests/test_livestream.py::test_tshark_accepts_what_the_buffer_hands_it is
   the load-bearing test: it puts the same bytes through real tshark both ways
   and asserts the difference, and it says in its message that if tshark ever
   stops objecting, the trimming is no longer load-bearing.

### Security notes on this diff

- No new dependencies. pip-audit clean.
- Two new routes, both GET, both behind get_current_user (which enforces TOTP)
  and _require_own_capture (404, never 403, on someone else's). offset/limit
  are bounded Query params; view flags are checked against ALLOWED_VIEW_FLAGS;
  the display filter goes through the existing validate_display_filter. They
  are treated exactly as the stored /packets routes are by the read-only-over-
  HTTP middleware, because they return the same kind of data.
- Their own rate limiter (rate_limit_live_polls_per_min, 90). Sharing the
  packet-list budget would have left two live streams unable to open a packet.
- remote_path is server-generated (/tmp/pcap_<uuid>.pcap), never user input,
  and reaches SFTP rather than a shell.
- LiveBuffer parses a file on a host under investigation. It bounds a claimed
  record length (MAX_RECORD_BYTES) and refuses an unrecognised magic rather
  than guessing; the walk provably advances, so a crafted file cannot spin it.
- An SFTP error message can carry text from the target host. Truncated to 200
  chars and rendered with textContent, the same treatment the existing capture
  failure message already gets.
- The one SQL change is a hardcoded ALTER TABLE with no interpolation.
- NEW, and written into both README and architecture.md: a live stream holds up
  to live_stream_buffer_mb of UNENCRYPTED packet data in process memory while
  the capture runs. Packets already pass through memory on the way to tshark;
  what changes is volume and duration. Bounded by that setting and by
  max_live_streams, never written to the data volume, discarded when the
  capture ends.

### What was built

backend/livestream.py (new)  LiveBuffer + BytesSource: the record walk and the
                             cap. Pure parsing, no asyncio, unit-tested alone.
backend/capture.py           -U when live; live_count() and the max_live_streams
                             check in start()'s await-free stretch; live_poll();
                             buffer dropped on every capture-end path.
backend/ssh_manager.py       RemoteCapture.read_at() over the capture's OWN
                             connection, with the SFTP client closed in close().
backend/main.py              two live routes + the live poll limiter.
backend/models.py            live_stream on CaptureRequest and CaptureInfo.
backend/database.py          live_stream column + migration, three settings.
frontend                     the Capture-screen checkbox, the live bar, the
                             append-only list, the finish-and-reopen handover,
                             the capture-list badge and Watch live button.

### The chip size

.view-tab was 0.75rem (12px) -- smaller than everything around it, for
operator-typed labels. Now 0.875rem, the app's own content size, with padding
and the action glyphs scaled to match. The browser test asserts it is no
smaller than a capture's name rather than hard-coding a number alone, so the
guard says what it is guarding.

### Deliberately NOT done

- No WebSocket or SSE. Polling with a frame-number cursor matches
  refreshRunningCaptures, adds no transport, and shares its cadence so the two
  cannot disagree about the same capture's count. Worth revisiting only if the
  3s cadence proves visibly laggy in use.
- No long-lived `tshark -T ek` NDJSON stream. It would remove the O(n) re-parse
  per poll but changes the parser model substantially and would not share the
  stored viewer's code path -- which is the property that keeps one filter
  language rather than two.

### NOT yet verified

Live streaming has not been run against a real remote host: this container has
no SSH target, and self-capture is refused by design. What IS covered by real
tools rather than fakes: the record walk and the filter behaviour against real
tshark, and read_at against a real asyncssh SFTP server serving a file that
grows under the reader (tests/test_ssh_manager.py). The untested seam is
tcpdump -U's actual write cadence on a real target.
