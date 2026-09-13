# Dev Skills gate state
Track: RELEASE SEQUENCE — 0.1.0-dev.25. Gates 1-4 PASSED, 5 awaiting the
       user's push, 6 awaiting the user's tag.
Version: 0.1.0-dev.25 (NOT yet released)
Updated: 2026-09-13 (session: local CLI, Fedora 44, bash)
Branch: claude/admiring-wright-k20ptf — canonical. Was in sync with origin at
        0b98c8e; this release adds one commit on top.
Environment: LOCAL Claude Code CLI — Claude PRESENTS git commands, the user
        runs them (SKILL.md 5.8). Not a container.

## 0.1.0-dev.25 tracker

🔢 VERSION    ✅ 0.1.0-dev.25 in FIVE places, not three. backend/main.py:78,
                docker-compose.yml:72, CHANGELOG heading, AND README.md:113
                (Quick start curl) + README.md:147 (version table) +
                README.md:163 (Upgrading curl).
                ⚠️ THE README ONES ARE NEW AS OF THIS RELEASE. The no-clone
                Quick start fetches docker-compose.yml from a TAG-pinned raw
                URL, so the README now carries release tags. Any future bump
                that misses them ships a Quick start pointing at the previous
                release. `grep -rn "0\.1\.0-dev\.<prev>"` excluding .git,
                .venv and CHANGELOG is the check.
                v0.1.0-dev.24 confirmed tagged on the remote (ls-remote).
                pyproject.toml is pytest config only, no [project] table, so
                the repo-link requirement lands on backend/main.py REPO_URL +
                release_notes_url, which exist.
🔨 BUILD      ✅ ./scripts/check.sh on this host: 972 passed, 0 failed,
                0 SKIPPED, 2m37s, exit 0. Python 3.12.14 selected by the
                script itself. Baseline dev.24 was 905; +67 = the tests added
                this session.
                NOTE: check.sh RUNS FINE LOCALLY NOW. The dev.24 interpreter
                fix works. The container workaround documented lower down is
                no longer needed and should not be reached for by default --
                see "Local vs container" below.
🔒 SECURITY   ✅ 0 Critical, 0 High. Detail under SECURITY below.
                📝 1 Medium SURFACED, awaiting the user's call: pytest 8.3.4
                PYSEC-2026-1845. Dev-only, never shipped. See SECURITY below.
📄 DOCS       ✅ CHANGELOG dated 2026-09-13; README gained "Filters that would
                capture nothing", the rewritten Quick start, "Choosing a
                version", "Upgrading", and "Running it without a reverse
                proxy"; docs/architecture.md gained the bpf.py module row and
                a "Filters that cannot match anything" design section.
📦 RELEASE    ⏳ commit + push presented to the user, not yet run.
                No PR: default branch out of scope by standing decision.
🚀 SHIP       ⏳ tag block presented to the user. NOT ✅ until
                `git ls-remote --tags origin v0.1.0-dev.25` confirms it and
                the release run is green.

### SECURITY detail — 0.1.0-dev.25

NO runtime dependency change. backend/requirements.txt untouched.

pip-audit: pytest 8.3.4, PYSEC-2026-1845, fixed in 9.0.3. "pytest through
9.0.2 on UNIX relies on /tmp/pytest-of-{user} directories, allowing local
users to cause DoS or possibly gain privileges."
  * DEV-ONLY. pytest lives in backend/requirements-dev.txt; the Dockerfile
    installs backend/requirements.txt ONLY, so it never ships in the image.
  * Local attack vector on a developer or CI machine, not a production
    exposure. Graded Medium and surfaced; the user's call.
  * Fix would be 8.3.4 -> 9.0.3, a major bump needing pytest-asyncio
    compatibility work. dev.24 set the precedent of keeping dependency bumps
    out of a release's security gate; same call here.
  * NOT present in dev.24's audit -- this advisory is new since then.

New attack surface reviewed line by line (backend/bpf.py runs a subprocess):
  * argv list via asyncio.create_subprocess_exec. NO shell, no shell=True.
  * `--` before the expression. LOAD-BEARING, and verified by experiment:
    without it `-r /etc/passwd` made tcpdump OPEN that file; with it the same
    string is a syntax error. There is a test asserting the path never
    appears in the response.
  * binary from shutil.which("tcpdump"), a module constant -- never request
    input.
  * `-d` compiles and exits: no interface opened, no privilege needed, no
    network touched.
  * Auth required (Depends(get_current_user)) and rate limited
    (filter_check_rate_limiter, sharing rate_limit_packets_per_min).
  * Query length caps: bpf_filter 2000, interface 64.
  * Only tcpdump's FIRST stderr line is returned, with the "tcpdump:" prefix
    stripped. No stack traces, no paths.
  * Frontend warning text set with textContent, never innerHTML.
  * FIXED DURING THE GATE: asyncio.wait_for stops waiting but does not stop
    the process, so a timed-out tcpdump was left running and unreaped -- once
    per call on a keystroke-reachable endpoint. Now killed and awaited, same
    shape as packet_parser's tshark teardown. Test covers it.

Quality review of the changed code: worst-case CPU for the structural search
measured at 6ms (64 candidate ports, unsatisfiable, which is the case that
cannot short-circuit or hit the candidate guard). 200-port and deep-nesting
inputs bail on the guard in ~1-6ms. No N+1, no blocking I/O on the loop, no
unbounded cache, no nesting over 3 levels.

### Local vs container — SETTLED 2026-09-13, do not re-litigate

check.sh works locally. Verified this session: picks python3.12.14 itself,
finds tshark/tcpdump/capinfos/docker/chromium, 972 collected, exit 0.

Run the tests LOCALLY. What the container costs:
  1. The skip count stops meaning anything -- and 0 SKIPPED is this repo's
     signal that the browser suite actually ran. BOTH dev.24 false greens
     were container artifacts that dropped all 93 browser tests silently.
  2. Diagnosis speed. This session's one failure took ~3 minutes to isolate
     locally by injecting a temporary test that hooked console messages,
     dialogs and every fetch URL. Each such iteration is a rebuild in a
     container, and the temptation is to guess instead.
  3. Documented browser flakiness when two containers share the tree.
The container's ONLY real advantage -- python fidelity to the Dockerfile --
is what the dev.24 check.sh fix already provides, and the clean-room check is
what CI does on every branch push for free. Keep the container recipe as a
once-in-a-while tool for suspected host contamination, nothing more.

### THIS SESSION'S REGRESSION — read before touching browser waits

`page.wait_for_function("<bare expression>")` is a landmine in this repo.
Playwright can only evaluate a bare expression string by building it into a
function INSIDE the page, and this app's CSP is `script-src 'self'` with no
'unsafe-eval'. It only bites when the predicate is FALSE on the first look and
real polling begins.

Three call sites had it and were passing purely because their condition was
already true. Adding a filter-check round trip ahead of the capture POST made
one of them poll, and it failed with a CSP error that said nothing about the
real cause. All three now pass `"() => ..."` instead. Use the arrow form.

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

## Current session tracker — 0.1.0-dev.25, NOT STARTED

Nothing has been changed in this session yet. All six gates are ⬜ pending and
none of dev.24's ✅ carries forward: a passed gate is a statement about a diff
that no longer exists.

🔢 VERSION    ⬜
🔨 BUILD      ⬜
🔒 SECURITY   ⬜
📄 DOCS       ⬜
📦 RELEASE    ⬜
🚀 SHIP       ⬜

Session-start checks, 2026-09-13 (this session):
- Environment: LOCAL Claude Code CLI, Fedora 44, bash. Claude PRESENTS git.
- Remote: https://github.com/darthrater78/pcap-server
- In sync: local head 0b98c8e == origin/claude/admiring-wright-k20ptf.
- Unfinished-release check: CLEAN. Every CHANGELOG version through
  0.1.0-dev.24 has a tag on the remote (v0.1.0-dev.24 confirmed via
  git ls-remote). No stranded Gate 6.
- CI: release.yml (tag push) + check.yml (build check). Local dev: scripts/check.sh.
- NOTE: this state file is TRACKED in git, not gitignored. That is a deliberate
  deviation from SKILL.md's local-session guidance and it is why the knowledge
  below survives across sessions. Leave it tracked.

## IN PROGRESS this session — 0.1.0-dev.25, uncommitted

DONE (working tree, not committed, gates not yet run):
- README **Quick start** rewritten around the published image. No clone: the
  compose file is curl'd from a TAG-pinned raw.githubusercontent URL, which
  keeps the file and the image version it names in step. Added "Choosing a
  version" (pinned vs the floating `:dev`), "Upgrading", and an "If you would
  rather clone" pointer to Development.
  ⚠️ **NEW VERSION-CARRYING REFERENCE — Gate 1 must now update README.md.**
  The Quick start curl URL and the Upgrading curl URL both name a release tag.
  Version refs are now: backend/main.py APP_VERSION, docker-compose.yml image,
  CHANGELOG heading, AND these two README URLs.
- README **Running it without a reverse proxy**, placed before "Behind a
  reverse proxy". Cross-linked from Requirements, Quick start, Traffic in
  transit, and the proxy section itself.
- frontend/js/app.js: **live-stream checkbox clears after a successful start.**
  Cleared on success only (a failed start keeps the intent for the retry), and
  updateLiveTargetNotice() is called by hand because a programmatic checkbox
  change fires no `change` event. viewCapture still keys off body.live_stream,
  which was read before the clear -- do not "simplify" that to read the box.

### VERIFIED BY EXPERIMENT this session — the loopback exemption

`_is_secure_transport` (backend/main.py:296) treats loopback as secure. On a
containerised install with a PUBLISHED PORT this never fires. Ran the published
image under rootless podman, `-p 18080:8080`, curled 127.0.0.1:18080:

    secure_transport: false, read_only: true
    container log peer: 10.0.0.56  (the gateway, not 127.0.0.1)

With `--network=host`, the same curl:

    secure_transport: true, read_only: false
    container log peer: 127.0.0.1

So browsing http://localhost:8080 ON the Docker host is still read-only. This
is now documented. Docker's bridge behaves the same way (gateway 172.17.0.1).

## QUEUED, asked for mid-session 2026-09-13 — not started

- **Reject unsatisfiable BPF filter combinations.** Real report from the user:
  `((port 88) and (port 464)) and (tcp port 445 or ... or tcp port 443) and
  (port 53)` -> tcpdump: "expression rejects all packets". Built by repeatedly
  choosing "...and this" in the capture filter library, which ANDs port-only
  expressions that cannot both be true.
  FINDINGS (verified with `tcpdump -d` in the published image):
  * `tcpdump -d -y <dlt> <expr>` compiles WITHOUT capturing and prints
    "expression rejects all packets" for the user's filter. Exit code and
    stderr are usable as a check. The server image HAS tcpdump.
  * BUT libpcap's optimizer is INCOMPLETE: `tcp port 80 and tcp port 443`
    compiles happily and is not flagged. So tcpdump alone is necessary, not
    sufficient.
  * So it needs TWO layers: a structural port-set check (catches the class
    libpcap misses, and can run in the frontend at combine time, before the
    bad expression is ever in the box), plus a `tcpdump -d` pre-flight on the
    server (catches syntax errors and everything libpcap CAN prove, on typed
    filters too, not just library-built ones).
  * applyBpfFilter/bpfMenuItems (frontend/js/app.js ~1217-1245) is where "and"
    is chosen. Its own comments ALREADY name this hazard -- "`tcp port 80 and
    tcp port 443` matches nothing at all" -- and the menu was the mitigation.
    The menu is not enough; it offers the wrong answer as an equal choice.
  * models.py validate_bpf (~line 374) only checks forbidden CHARACTERS.
    Semantic validation would be new.
  * DLT matters: the user's capture was `-i any` => LINUX_SLL2, the server's
    local tcpdump would default to something else. Decide whether to pass
    `-y LINUX_SLL2` for the any-interface case.

## Gate 2 baseline — carry forward, do not lose

The dev.24 run of `./scripts/check.sh` on this host: **905 passed, 0 failed,
0 SKIPPED, 2m26s, exit 0.** That is the number to beat; dev.23's was 890.

**ALWAYS read the skip count.** Two false greens were caught during dev.24,
BOTH reporting success while silently excluding the entire browser suite: a
3.12 container under `--userns=keep-id` (93 skips), and check.sh before
playwright had a chromium (93 skips again). `0 SKIPPED` is what means the
browser tests actually ran. A green with 93 skips is a failed gate.

Release-verification norm for this repo: a release publishes as a prerelease
"vX (Dev)", pushes `ghcr.io/darthrater78/pcap-server:<version>` and moves
`:dev` to it, with **0 assets** — dev.22, .23 and .24 all did. 0 assets is
correct here, not a broken upload.

## 0.1.0-dev.24 — RELEASED, closed record

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
