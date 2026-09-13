# Dev Skills gate state
Track: release sequence — 0.1.0-dev.24 CLOSED. All six gates done.
Version: 0.1.0-dev.24 (RELEASED 2026-09-13)
Updated: 2026-09-13 (session: local CLI, Fedora, bash)
Branch: claude/admiring-wright-k20ptf — canonical, in sync with origin at
        27287cd. Working tree clean.
Environment: LOCAL Claude Code CLI — Claude PRESENTS git commands, the user
        runs them (SKILL.md 5.8). Not a container; nothing is lost at session
        end, but nothing is auto-committed either.

## DECIDED by the user, 2026-09-13 (this session) — do not re-open

1. **Ship 0.1.0-dev.24 first**, then start dev.25 for the batch below. The
   user chose this over folding everything into one release.
2. **Custom filter entries are PRIVATE to each user.** Same model as saved
   views. Not shared, and no admin-publish step. Asked and answered.
3. **The server check before a capture is a CONFIRM DIALOG**, not the existing
   prereq check and not inline detail. Start capture names the server, its
   hostname, the interface and the filter, and asks for confirmation before
   tcpdump runs on that host.

## QUEUED for 0.1.0-dev.25 — asked for mid-session, not yet started

- Custom entries in the BPF capture-filter library AND in the viewer's display
  filter list. Per-user (decision 2).
- ~~Capture screen server dropdown~~ NOT NEEDED. updateServerDropdown() in
  app.js already renders `${srv.name} - ${srv.hostname}`. Asked the user
  2026-09-13: "the server dropdown is working correctly". Closed, do not
  reopen or "improve" it.
- Require the operator to name the capture before it can be started (today
  naming is Rename-after-the-fact only).
- The confirm dialog (decision 3).
- README: rewrite **Quick start** around getting the published container image
  up. The user's words: "no one would be gonna cloning anything".
- README: a section on running WITHOUT a reverse proxy, explaining the risks.
- **Capture list should show what a capture was filtered with.** Two parts,
  asked for together:
  1. A **badge** on a BPF-filtered capture, the same way `live_stream` already
     gets one (`.badge-live` in renderCaptures). Same treatment, different fact.
  2. The filter rendered **readably**, not as raw ports. The user's words:
     "not just port numbers, list protocols if possible, ports when not."
     So `tcp port 443` reads as HTTPS, `port 88` as Kerberos, and an expression
     with no known service name falls back to the port. FILTER_LIBRARY in
     app.js already pairs expressions with human labels and is the obvious
     source for that mapping -- but it is keyed by whole expression, not by
     port, so a port->service table is probably still needed. Do NOT invent
     names for ports that have none; fall back to the raw expression.
  The capture already stores `command`, which contains the filter after `--`.
  Prefer storing/reading the filter itself over re-parsing the command string
  -- capture.py's own comments warn that re-parsing the command is how the
  per-interface rule would have broken.
  CHECKED: `bpf_filter` lives on CaptureRequest only. It is NOT on CaptureInfo
  and NOT persisted. So this needs a `bpf_filter` column plus a migration,
  exactly the shape `live_stream` got in dev.23 (backend/database.py). Captures
  taken before the column exists will have it empty -- render those as
  "unknown", never as "no filter".

## Current session tracker — 0.1.0-dev.24, release sequence

🔢 VERSION    ✅ APP_VERSION (backend/main.py:75) and the docker-compose image
                tag both read 0.1.0-dev.24; CHANGELOG heading dated
                2026-09-13. v0.1.0-dev.23 confirmed tagged on the remote.
🔨 BUILD      ✅ ./scripts/check.sh on this host: 905 passed, 0 failed,
                0 SKIPPED, 2m26s, exit 0. The project's own workflow, not a
                substitute. Baseline at dev.23 was 890; +15 = the tests added
                this session exactly.

                Two false greens were caught getting here, BOTH of which
                reported success while silently excluding the entire browser
                suite: the 3.12 container under --userns=keep-id (93 skips),
                and check.sh before playwright had a chromium (93 skips again).
                ALWAYS read the skip count. 905/0 is the number that means
                the browser tests ran.
🔒 SECURITY   ✅ pip-audit: "No known vulnerabilities found". NO dependency
                change at all. Notes under SECURITY below.
📄 DOCS       ✅ CHANGELOG dated; README gained "A live stream has to be
                pointed at something", a line in the four-controls table and a
                clause in the preview-limit settings row;
                docs/architecture.md gained a design section and a
                known-limits entry.
📦 RELEASE    ✅ f659269 on the remote. No PR: default branch out of scope by
                standing decision.
🚀 SHIP       ✅ VERIFIED from the remote, not assumed: tag v0.1.0-dev.24 ->
                f659269, matching the branch head exactly. Release run
                34762829528 success; published as a prerelease
                "v0.1.0-dev.24 (Dev)"; image pushed to
                ghcr.io/darthrater78/pcap-server:0.1.0-dev.24 AND :dev moved
                to it. 0 assets, same as dev.22/.23 -- this repo's norm.
                Check run 34762586063 on the branch push also passed (4m45s),
                so a clean checkout verified this commit independently.
                NOT yet confirmed deployed.

### scripts/check.sh CANNOT RUN ON THIS HOST — read before trusting Gate 2

This machine's `python3` is 3.14 (Fedora 44). check.sh builds its venv with
bare `python3`, and the pinned pydantic-core has no 3.14 wheel, so it falls
back to building from source and dies in PyO3:

    error: the configured Python interpreter version (3.14) is newer than
    PyO3's maximum supported version (3.13)

The project targets 3.12 (Dockerfile `FROM python:3.12-slim`, check.yml
`python-version: '3.12'`). Gate 2 was therefore run in a rootless-podman
container on python:3.12-slim with tshark+tcpdump+chromium, running the same
`pytest` check.sh would run. Containerfile is in the session scratchpad.

Three traps if you rebuild that container:
1. `requirements-dev.txt` starts with `-r requirements.txt`, so BOTH files must
   be COPYed or the install fails on a path that is not in the image.
2. `--userns=keep-id` makes the whole browser suite SKIP (93 skips) -- chromium
   is installed under root's HOME and is unreadable as the mapped user. It
   looks like a pass. It is not. Run as root; conftest.py already adds
   --no-sandbox when geteuid()==0.
3. Do NOT run two containers over the same tree at once. Doing so produced
   scattered browser failures in BOTH runs that vanished when each ran alone.
   The first "failure" of this session was entirely that.

### check.sh — FIXED THIS SESSION, and now in the dev.24 commit

The user reversed the earlier "commit dev.24 first" call: "I do want to make
sure we fix sh issue as well and include it in this commit and push". So the
fix ships in dev.24, not later.

python3.12.14 is installed on this host (the user ran the dnf install).
scripts/check.sh now selects the interpreter itself -- see the CHANGELOG entry
and the README Development section. All three failure paths were tested before
the real run: PYTHON= out of range, PYTHON= nonexistent, and a stale 3.14
.venv being rebuilt.

Original decision, kept for the record: the user chose **install python3.12 on
the host** over containerising check.sh.

So, after dev.24 is committed, in dev.25 or as its own tooling commit:

1. The user runs `sudo dnf install python3.12` themselves. Not Claude's to run.
2. **check.sh still needs fixing even after that**, because it calls bare
   `python3` -- which stays 3.14 on this host. Make it:
   - honour a `PYTHON=` env override first;
   - otherwise search python3.12 / python3.13 / python3.11 / python3 and take
     the first whose version is inside the supported range;
   - validate an EXISTING .venv was built by a supported interpreter and
     rebuild it if not -- today a bad .venv is reused forever and every later
     run fails identically;
   - fail with ONE line naming the range and what was found, instead of a
     200-line cargo/PyO3 dump that never mentions Python versions.
3. The supported range is **3.11-3.13**, set by `pydantic==2.10.3`: its
   pydantic-core wheels stop at cp313, and the source fallback needs PyO3
   <= 3.13. Dockerfile and check.yml both use 3.12; keep the range honest
   against the pins rather than guessing.

REJECTED, and why: bumping pydantic so 3.14 works. CI and the Dockerfile stay
on 3.12, so local would test a stack the project does not ship -- the exact
drift check.sh exists to prevent -- and a dependency bump drags the security
gate into a tooling problem.

The container path (python:3.12-slim, rootless podman) was NOT chosen and is
not to be committed. It stays a session workaround; its Containerfile and the
three traps are documented above.

Everything below this line is the RECORD of 0.1.0-dev.23, which shipped
cleanly. Carry-forward knowledge, not current state.

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


### SECURITY — 0.1.0-dev.24

- No new dependencies, no new routes, no new database columns. pip-audit clean.
- The new refusal is a pure read of the request: `req.interface`, and
  `req.bpf_filter.strip()`. Nothing is executed, and the message interpolates
  only ANY_INTERFACE, a module constant -- no user input reaches it.
- The 400 body is fixed policy text. It discloses no server state, and says
  nothing an unauthenticated caller could not read in the README.
- The frontend notice is static markup in index.html. No interpolation, so no
  new XSS surface; it is toggled with `.hidden`, never innerHTML.
- Net security GAIN, and it is the point of the change: two live streams on
  `-i any` could previously pin 2 x live_stream_buffer_mb of unencrypted packet
  data in container memory and burn CPU re-parsing the whole buffer every poll.
  The rule bounds an authenticated resource-exhaustion path that was reachable
  by ticking one box.

### QUALITY — reviewed, and the one thing worth knowing

The rule is stated TWICE: `start()` in backend/capture.py and
`liveStreamIsTargeted()` in app.js. Deliberate and commented at both ends --
the server is the authority, the client copy exists so the form can answer
while it is being filled in. Sharing one definition would need a codegen step
this repo does not have and should not grow for one predicate. If the rule ever
changes, both move; the browser test asserting the request is never sent is
what fails if only one does.

### DECLINED by the user 2026-09-13 — do not raise again

Rewiring CI so release.yml calls check.yml as a gate (workflow_call + needs),
and narrowing check.yml's triggers. The user said "lets skip all that".

The finding behind it stands and is worth knowing, but is NOT to be acted on:
check.yml and release.yml are independent, so a tag push publishes an image to
ghcr whether or not the suite ever passed -- and release.yml runs no tests of
its own. Clean-checkout verification is therefore entirely absent from this
project's CI by choice. Local runs are the only gate.


### CI fires THREE runs per release — measured, not theorised

Observed on the dev.24 tag push:

  34762586063  Check    branch push  success  <- useful
  34762829509  Check    TAG push     duplicate of the above, same commit
  34762829528  Release  TAG push     the publish

check.yml uses bare `on: push:` with no filter, and **a tag push is a push**,
so every tag runs the suite a second time against a commit already tested.

The duplicate is not even protective: it starts the same second as the Release
run and RACES it. On dev.24 the Release finished first. It cannot gate a
publish it runs alongside.

An earlier diagnosis in this session was WRONG and is corrected here: the
duplication is not `push` + `pull_request` overlapping. This repo uses no PRs
at all, so `pull_request` never fires.

One-line fix, OFFERED and not yet accepted (distinct from the larger
workflow_call rewiring the user declined -- do not conflate them):

    on:
      push:
        branches: ['**']   # '**' matches branches only, never tags
      pull_request:
