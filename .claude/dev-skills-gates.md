# Dev Skills gate state
Track: release sequence — 0.1.0-dev.22
Version: 0.1.0-dev.22
Updated: 2026-09-13 (session: dev-skills-loading-yow48d)
Branch: claude/admiring-wright-k20ptf — CANONICAL, confirmed by the user.

## 0.1.0-dev.22 — COMMITTED, awaiting the tag

Three commits: eaeb7ce (validator), 4cdbe11 (frontend), 0637263 (bump).

Four things, never committed separately because the first was still awaiting
approval when the rest were asked for:

1. The filter library stays open while you choose, with a live preview bar
   ("choose more than one value from the bpf library without leaving the
   screen").
2. Fragment filters in the capture library.
3. NTLMSSP: a display-filter protocol plus four fields, and a transports row
   on the capture side.
4. The Viewer's display filter moved below the capture name.

And the bug that fell out of (2) — see THE VALIDATOR, below.

🔢 VERSION    ✅ APP_VERSION (backend/main.py:69) and the docker-compose image
                tag both read 0.1.0-dev.22; CHANGELOG heading dated
                2026-09-13. v0.1.0-dev.21 confirmed tagged at 30ddcfb.
🔨 BUILD      ✅ ./scripts/check.sh re-run AFTER the bump: 825 passed, 0
                skipped, 3m51s. The jump is mostly parametrised: every library
                expression is now one test against the validator and one
                against tcpdump -d.
🔒 SECURITY   ✅ pip-audit clean, deps untouched. The preview writes with
                textContent, never innerHTML, which matters because the value
                is arbitrary operator-typed text. This release DOES change a
                security control — validate_bpf — deliberately and with the
                user's decision; reasoning under THE VALIDATOR below.
📄 DOCS       ✅ CHANGELOG dated; README's filter-library passage covers the
                stay-open behaviour and Clear.
📦 RELEASE    ➖ N/A — no PR. Default branch out of scope by standing decision.
🚀 SHIP       ⏳ committed and pushed; tag block handed to the user.

### THE VALIDATOR — a control was deliberately narrowed

validate_bpf banned `;` `|` `&` `$` backtick and backslash. `&` and `|` are
BPF's own bitwise operators, so the ban refused every tcpflags and
byte-offset filter — the entire TCP-behaviour group in the library (5 rows),
one of the Capture tab's worked-example chips, and both new fragment rows.
Eight filters the app offered and the API rejected. Each half was correct on
its own terms, which is why nothing caught it.

DECIDED by the user: allow `&` and `|`, keep `;` `$` backtick backslash.

Why that is safe: the expression never reaches the remote shell as bare text.
It is one argv element, quoted by _shell_quote (single quotes, embedded quotes
escaped) before the command string is assembled in run_tcpdump, and it sits
after `--` so it cannot be read as an option. assert_no_forbidden_flags guards
the dangerous tcpdump flags separately. The character check is the second line
under the quoting, not the only one.

The two alternatives put to the user and declined: drop the filters from the
library, or replace the blacklist with a `tcpdump -d` compile check (strongest
validation, but a subprocess per request and tcpdump must be present wherever
the API runs — NOT verified, and still worth considering later).

The real fix for the class of bug is tests/test_filter_library.py: it reads
FILTER_LIBRARY and BPF_SUGGESTIONS out of app.js and puts every expression
through BOTH gates. A guard test asserts the regex actually matched something,
so it cannot pass vacuously.

### Corrected as part of this

Three places asserted the old ban and are now false. All updated:
- the combineBpf comment in app.js
- test_the_composed_filter_never_uses_the_c_operators' docstring
- README's "rejects shell metacharacters" paragraph
The keyword composition STAYS, but the reason is now the weaker, honest one:
the library and the man page write BPF with the words.

### NTLMSSP — what was asked for vs what is possible

Asked for as a protocol in the capture library and the AD group. There is no
BPF filter for NTLMSSP: it has no port, and it rides inside SMB/RPC/LDAP/HTTP
at an offset that moves with the enclosing protocol, while BPF matches fixed
offsets. Delivered as: a display-filter protocol and four fields (where it
genuinely works, verified against `tshark -G fields`), plus an AD-group
capture row recording the transports, labelled so it does not read as an NTLM
capture filter.

### DECIDED by the user, 2026-09-13

Stay-open with a live preview, NOT checkboxes-and-Apply. Batch multi-select
was offered again here and declined again — the per-pick combinator menu from
dev.21 stays, because inferring one combinator for a whole batch is the
silent-wrong-filter risk that menu exists to avoid.

### Why the collapse existed, and what replaced it

The library closed itself on every pick deliberately: the field it fills sits
above the list, so the collapse was the only evidence the click had landed.
Removing it without replacing that feedback would have been a regression. The
preview bar is the replacement, and it READS the field rather than tracking
clicks, so a typed edit or a manual clear keeps it honest.

Also dropped: the focus jump into the field. Both it and the collapse moved
the page out from under someone part-way through choosing several filters.

### The friction, measured

tests/browser/test_capture_ui.py used to reopen the library between picks in
every composition test — the friction was plain from inside the test suite
before anyone complained about it. With the reopens gone the file runs in 77s
instead of 228s.

### Checked, not a bug

`.filter-preview { display: flex }` would normally outrank the `hidden`
attribute, which comes only from the UA stylesheet. style.css:82 already
carries `[hidden] { display: none !important }` with a comment about exactly
this trap, so hiding works and the test covering it passes for the right
reason.

## NEXT, DESIGNED NOT BUILT — live packet streaming in the viewer

Asked for as "is it possible to stream the packets live as they're captured in
the viewer". Answer: yes, but it is a capture-pipeline change, not a UI one.
Comparable in size to the fingerprint review or larger. Nothing is built.

### What happens today

tcpdump -w <remote_path> writes ON THE REMOTE HOST. No capture bytes come back
during the run. When it finishes: status -> TRANSFERRING, fetch_file SFTPs it
down in 64KB chunks sealing into the vault as it lands, then the viewer runs
tshark against the sealed file through PcapSource, which decrypts in flight so
no plaintext ever exists as a file.

The only live signal that exists is a COUNT: tcpdump -v reports packets-so-far
on stderr, _pump_stderr parses it into info.packet_count (capture.py:118, the
_LiveCount callback), and the UI polls every 3s via refreshRunningCaptures.
So the "something is happening" plumbing is there; the packets are not.

### Three things verified in the container on 2026-09-13 — do not re-derive

1. **tshark reads a growing pcap.** Truncated one mid-record: it emitted every
   COMPLETE packet on stdout, then warned "appears to have been cut short in
   the middle of a packet" and EXITED 2. So a live reader must accept exit 2
   with that message as normal. Cheap to do: packet_parser._run already
   returns (stdout, stderr, returncode) to its caller rather than raising —
   only the live path needs the carve-out. NOTE the strict path at
   packet_parser.py:324 raises DisplayFilterError on any non-zero.

2. **A partially written SEALED capture cannot be read at all.** Cryptor
   .open_stream raises `CryptoError: truncated: incomplete chunk` at 25%, 50%
   and 90% of a sealed file — it refuses rather than yielding the complete
   chunks it holds. That is deliberate truncation detection and should NOT be
   weakened casually. This kills the obvious "just read the partial file"
   design.

3. **-U is allowed.** FORBIDDEN_TCPDUMP_FLAGS is {-z, --postrotate-command,
   -W, -G, -C, -r, -F, -V, -Z}. Without -U tcpdump buffers, so the remote file
   lags a buffer behind — on a quiet link, many seconds.

### The recommended shape: a PASS-THROUGH, not a read of stored data

Do not try to read the partial stored file (finding 2). Instead:

    remote growing file --(incremental SFTP from a byte offset)--> tshark in
    flight --> rows --> browser

The authoritative pcap keeps accumulating remotely and is fetched and sealed
at the end EXACTLY as now. Storage model unchanged, no plaintext on the data
volume (which is the whole point of PcapSource's design), crypto keeps its
strict truncation check.

Keeping the remote file as the source of truth also preserves what the current
design deliberately buys: a dropped SSH connection mid-capture loses nothing.
A `tcpdump -U -w -` stdout stream would be simpler to plumb and would delete
the TRANSFERRING phase, but it throws that away — if the connection drops, the
capture is gone. Rejected for that reason, not for difficulty.

### Work breakdown

1. Add -U to build_command_args. One line, plus a test.
2. Incremental read: a method alongside fetch_file that SFTP-reads from a byte
   offset on a RUNNING capture and does not seal. Returns bytes + new offset.
3. A live source: feed (pcap global header + accumulated records) to tshark.
   The 24-byte global header must be sent ONCE at the front of every spawn —
   tshark needs it to know the link type.
4. The viewer's status gate: it opens COMPLETED captures only. Needs a defined
   live mode, and a decision about what happens when the capture ends (switch
   to the sealed file seamlessly, or make the operator reopen).
5. Transport: NO WebSocket exists anywhere. StreamingResponse is used twice
   (main.py:1260, 1390), so SSE is a short step. But polling with an offset
   cursor matches refreshRunningCaptures and adds no new transport at all —
   recommend starting there and only adding SSE if it is visibly laggy.

### Open decisions — put these to the user BEFORE building

- **Display filters in a live view at all in v1?** Either re-run tshark with
  the filter on every poll (simple, costs a tshark spawn per poll per viewer),
  or filter client-side over what has arrived (cheap, but the filter language
  is tshark's and reimplementing any of it in JS is a trap). Recommend: no
  display filter in v1, "All packets" only, and say so in the UI.
- **Re-running tshark over a growing file is O(n) per poll.** Fine for
  moderate captures, wasteful for large ones. The alternative is a long-lived
  `tshark -T ek` streaming NDJSON, which changes the parser model
  substantially. Recommend the simple version first with a packet cap.
- **How many concurrent live viewers?** Each costs an SSH channel and a tshark.
  max_concurrent_captures already exists as a precedent for capping this.

### What NOT to do

- Do not weaken Cryptor.open_stream's truncation check to make a partial
  sealed file readable. It is an anti-tamper property and the pass-through
  design does not need it.
- Do not write a plaintext partial capture to the data volume. PcapSource's
  module docstring exists precisely to say that never happens.

## 0.1.0-dev.21 — RELEASED (tag pushed by the user, 2026-09-13)

Multiple BPF entries: composing a second capture filter instead of replacing
the first. The design question left open at the end of the previous session is
now DECIDED by the user — see below.

🔢 VERSION    ✅ APP_VERSION (backend/main.py:69) and the docker-compose image
                tag both read 0.1.0-dev.21; CHANGELOG heading dated
                2026-09-13. v0.1.0-dev.20 confirmed tagged at 7320eae — no gap
                behind this release.
🔨 BUILD      ✅ ./scripts/check.sh re-run AFTER the bump: 625 passed, 0
                skipped, 2m51s. 10 of those are new.
🔒 SECURITY   ✅ pip-audit on backend/requirements.txt: no known
                vulnerabilities (deps untouched this release). The diff is
                frontend composition plus tests: no new route, no new input
                path, no change to what is trusted. The composed string lands
                in bpf_filter, which validate_bpf already checks, and
                openFilterMenu sets row.textContent rather than innerHTML.
📄 DOCS       ✅ CHANGELOG dated; README's filter-library passage now covers
                composition and says why neither combinator is defaulted.
📦 RELEASE    ➖ N/A — no PR. Default branch out of scope by standing decision.
🚀 SHIP       ✅ verified from the container: tag v0.1.0-dev.21 -> 30ddcfb on
                the remote; Check #57 green on the branch commit, Check #58 and
                Release run #21 green on the tag.

### DECIDED by the user, 2026-09-13 — do not re-open

Reuse the display filter's menu model for BPF picks: Replace / …and this /
…or this / Replace with NOT this. The three alternatives put to them and
rejected were a fixed " and " append, inferring the combinator from the
library group, and a multi-select compose-once flow.

The evidence that settled it: the library is mostly port and protocol rows,
where a second pick means `or` (`tcp port 80 and tcp port 443` matches
nothing), while a host row plus a protocol row means `and`. No fixed default
is safe, and a BPF filter matching nothing is silent — the capture runs to
its full duration and comes back empty.

### Two findings from building it

1. **The dismiss handler closed the menu on the click that opened it.** The
   document-level click handler at app.js:3534 closes #filter-menu on any
   click outside it, and at that instant the menu does not exist yet. The
   display filter never hit this because its menu opens from a contextmenu
   event, which fires no click. Fixed with stopPropagation on the opening
   click. Six browser tests caught it; it would have been invisible to every
   API test.
2. **A mislabelled item in the display filter's own menu.** "…and not
   selected" called combineFilter's `not` mode, which ignores the current
   expression and replaces it with the negation — Wireshark's "Not Selected".
   Relabelled to match the behaviour. Behaviour unchanged.

### Corrected mid-session, recorded so it is not re-derived

Parenthesised BPF filters are NOT broken. capture.py:310 joins the command
with no quoting, but that string is only the `command` field stored and
displayed on the capture record. The executed command is assembled separately
in ssh_manager.run_tcpdump (line ~453) and quotes every argument with
_shell_quote, so the filter arrives at tcpdump as one word. I claimed the
opposite mid-session before tracing the second path.

Real but minor, and NOT fixed: the displayed `command` is not shell-safe, so
it differs from what actually ran and would fail if pasted into a terminal.

## 0.1.0-dev.20 — RELEASED (tag pushed by the user, 2026-09-13)

The SSH host key fingerprint review: plan item 0, the last piece of the trust
work dev.17-dev.19 ran through.

🔢 VERSION    ✅ APP_VERSION (backend/main.py:69) and the docker-compose image
                tag both read 0.1.0-dev.20; CHANGELOG heading dated
                2026-09-13. No 0.1.0-dev.19 left outside changelog history.
                v0.1.0-dev.19 confirmed tagged at 4b34837 on the remote — no
                gap behind this release.
🔨 BUILD      ✅ ./scripts/check.sh re-run AFTER the bump: 615 passed, 0
                skipped, 2m29s. 14 of those are new.
🔒 SECURITY   ✅ pip-audit on backend/requirements.txt: no known
                vulnerabilities. Diff reviewed adversarially; one real finding
                in my own new code, fixed before the suite re-ran (the
                trailing-field cut, below). Residuals recorded.
📄 DOCS       ✅ CHANGELOG dated; README's "whatever answers is what gets
                pinned" replaced with the review and the ssh-keygen compare
                command; docs/architecture.md's stale fail-open paragraph
                corrected as well.
📦 RELEASE    ➖ N/A — no PR. Default branch out of scope by standing decision.
🚀 SHIP       ✅ verified from the container: tag v0.1.0-dev.20 -> 7320eae on
                the remote; Check run #54 green on that commit BEFORE the tag
                went up; Release run #20 success; release published,
                prerelease, body compares dev.19...dev.20. Image
                ghcr.io/darthrater78/pcap-server:0.1.0-dev.20 built and pushed
                by that run. NOT yet confirmed deployed by the user.

### The finding in my own diff, and why it mattered

asyncssh parses `<type> <blob> <anything>` as a key plus a comment, so a host
answering ssh-keyscan with a trailing field still produces a VALID
fingerprint. The old code took `split(None, 2)[2]` — the whole rest of the
line — and wrote it into a known_hosts line, where a space starts a new field.
The new confirm route's validator rejects whitespace, so the two halves would
have disagreed: a fingerprint displayed as fine, then a 422 on accept. Cut at
the parse instead, so display and storage agree. Covered by
test_a_trailing_field_on_a_scanned_key_is_cut_off.

### Residuals, recorded not fixed

- store_host_keys() loops add_known_host(), each committing on its own. Every
  fingerprint is validated before ANY key is stored, so the reachable failure
  is covered; a mid-loop sqlite error could still leave a partial pin. Would
  need a transaction in database.py to close properly.
- /confirm lets an admin pin an arbitrary well-formed key for an arbitrary
  endpoint. Not an escalation: host trust is admin-owned by design and the
  README says so. Worth knowing it is now reachable with a chosen key rather
  than only with whatever a host returned.

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
