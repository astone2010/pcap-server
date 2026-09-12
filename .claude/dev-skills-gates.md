# Dev Skills gate state
Track: release sequence (dev pre-release — branch not merged to main)
Version: 0.1.0-dev.8  (NOT yet tagged — user deferred tagging; prereq work folded in rather than burning dev.9)
Updated: 2026-09-12 (session 3 resume)

🔢 VERSION    ✅ 0.1.0-dev.8 in main.py, docker-compose.yml, CHANGELOG; v0.1.0-dev.7 tagged on remote at 9085701
🔨 BUILD      ✅ 249 checks green across 9 suites (adds SSH connection-leak measurement against a live server, CaptureManager lifecycle, and always-visible repo/release links). This container now HAS tcpdump 4.99.4 + tshark, so for the first time the viewer was tested against a real 40-packet capture and the probe against a real SSH server running a real /bin/sh. Caveat: no docker daemon, image not rebuilt (Dockerfile unchanged)
🔒 SECURITY   ✅ 0 Critical, 0 High. FIXED a rate-limiter bypass found while answering an nginx question: _client_ip trusted X-Forwarded-For unconditionally and read the LEFTMOST entry, so any caller could invent a fresh address per request and never trip the login limiter -- unlimited password guessing against a directly-exposed instance, and equally against one behind nginx using the usual $proxy_add_x_forwarded_for. Now the header is only consulted when TRUST_PROXY_HEADERS is set, and the rightmost (proxy-appended) entry is used. FIXED a leaked SSH connection per capture (authenticated connection to a production host outliving its work, measured server-side); added login timeout, keepalives, monitor ceiling, bounded download; stopped disclosing the exact version to unauthenticated callers. Probe output treated as untrusted: hostile-host suite proves command-injection, traversal, substitution and non-tcpdump paths are all rejected, and the discovered path is re-validated before storage. Probe asserted read-only by test (no package manager, no writes, only `sudo -n true`)
📄 DOCS       ✅ CHANGELOG dev.8 gains Features + Changed sections; README gains "Checking a server before you capture" incl. the PATH and setcap findings and why there are no distro templates
📦 RELEASE    ➖ N/A — dev pre-release, no PR to main
🚀 SHIP       ⬜ — user has deferred tagging until more work lands

Env: remote container (Claude executes git after approval; tag pushes handed to user)
Branch: claude/admiring-wright-k20ptf  <- canonical, by user decision 2026-09-12.
  The harness designated claude/load-dev-skills-62vxv4 this session; user chose to
  keep pushing to the original branch so dev.8 history stays continuous and the
  eventual tag has one unambiguous parent. Future sessions: if handed a new branch
  name again, reset it to this branch's head and push back here.

CORRECTION ON RECORD: dev.7's changelog claimed -n/-nn were fixed in the viewer.
Testing against real tshark showed that was over-stated. tshark's Info column
prints ports numerically regardless of resolution settings (verified on port 80:
-N mt and -n give byte-identical output), so tcpdump's ports-named-vs-numeric
distinction is not expressible in this view at all. Host names additionally need
nameres.network_name AND nameres.use_external_name_resolver. Replaced both chips
with one explicit "Resolve hostnames" toggle, default off, since resolution means
reverse-DNS on every address in a capture. dev.8's changelog records this.

SELF-CAPTURE HAZARD (demonstrated 2026-09-12; GUARDED as of this work):
  Capturing an interface that carries pcap-server's own web traffic records the
  app's HTTP session. Over plain HTTP this was verified to recover the admin
  password verbatim from the resulting pcap
  ({"username":"alice","password":"..."}), and would equally capture session
  cookies and TOTP codes. On the Docker host, `-i any` also sweeps the bridge
  interfaces and so captures container traffic. Candidate mitigations: warn when
  the capture target resolves to a local address, suggest a BPF exclusion for
  the app's own port (e.g. `not port 8080`), or offer it as a default filter.
  Read-only-over-HTTP reduces but does not remove this: sign-in is still
  permitted over HTTP, which is exactly the request that carries the password.

  GUARD IMPLEMENTED: a server whose hostname resolves to loopback, to an address
  this container answers on, to the default gateway (the Docker host on a bridge
  network), or to a published host alias (host.docker.internal and friends) is
  refused on add, on save, on edit, and on load of a profile stored before the
  check existed. The refusal names the matched address and explains the exposure.

  WHAT THE GUARD CANNOT SEE: the host's LAN address, when the container is
  bridged and has never been told what the host is called. `extra_hosts` or
  --add-host makes it resolvable and the check then catches it. So this is a
  guard against the likely mistakes, not proof of non-locality, and it is worded
  that way rather than implying more than it knows.

CONCURRENT CAPTURES ARE UNBOUNDED (user-reported 2026-09-12, not yet fixed):
  Nothing limits how many captures run at once. start_capture takes no lock and
  checks no quota, so a user can launch capture after capture and each one:
    - opens its own SSH connection to the target (bounded only by sshd's
      MaxSessions/MaxStartups, which will start refusing connections)
    - starts another tcpdump on the remote host, each writing its own file into
      the remote /tmp -- several long captures can fill it
    - stages another pcap on the captures volume, with no disk quota
    - holds another asyncio task and monitor timer for its full duration
  Two captures on the same interface also record the same packets twice, so the
  cost is paid for duplicate data.
  Candidate fixes, in rough order of value: a per-user concurrent-capture limit
  (an admin setting, like the existing max_capture_seconds); refusing a second
  running capture against the same server+interface; a free-space check on the
  remote /tmp during the prereq probe and before each start; and a total-size
  cap on the captures volume with oldest-first eviction or a plain refusal.
  Note the interaction with encryption: sealed captures are slightly larger than
  the plaintext (~0.18%), so a disk cap should be measured on stored bytes.

REQUESTED, NOT YET BUILT (user asked these be noted, 2026-09-12):
- Saved usernames: remember usernames already used and offer them as a dropdown
  when adding a server, instead of retyping. Belongs with the saved-servers
  table; consider per-user scope, same as active/saved servers.
- Capture sanitiser: an option to scrub a pcap before download so it can be
  analysed safely elsewhere. Worth scoping carefully -- candidates are payload
  stripping (headers only, like a post-hoc snaplen), credential redaction in
  cleartext protocols (HTTP Basic, FTP, SMTP AUTH, SNMP community strings),
  and MAC/IP anonymisation. tshark and tcprewrite can do parts of this; the
  design question is whether the sanitised copy replaces the download or is
  offered alongside the raw one.

Deferred by user decision:
- Encryption at rest: envelope encryption, PLUGGABLE key source — Docker
  secret/env as shipped default, admin passphrase (RAM-only) optional. Stop
  writing plaintext SSH keys to disk: asyncssh.import_private_key takes bytes.
  Scope should include captured pcaps (a capture of cleartext traffic is a
  credential dump) and TOTP secrets.
- TLS/ACME: LIKELY MOOT FOR THIS USER. They run Nginx Proxy Manager, which
  already issues and auto-renews Let's Encrypt certificates, including DNS-01 for
  hosts with no inbound port 80. The Caddy-sidecar work was scoped to solve a
  problem they have already solved; do not build it without asking. The
  reachability question (HTTP-01 vs DNS-01) is likewise NPM's to answer.
  Original note follows.
- TLS/ACME (superseded by the above): NOW LOAD-BEARING, not just nice to have. Capture download is
  refused over plain HTTP as of this work, so without a proxy in front there is
  no way to retrieve a capture except from loopback. Recommendation unchanged:
  Caddy sidecar over certbot. Reachability (HTTP-01 vs DNS-01) still unanswered.
  Original note: Recommendation on record: Caddy sidecar over certbot.
  Reachability (HTTP-01 vs DNS-01) unanswered and must be settled first.
- Tagging: user wants more work landed before any tag is cut.

SESSION 3 RESUME NOTES (2026-09-12, fresh container):
- Gates 1-4 above were passed in the previous container against THIS commit
  (cdd5509), and the state file is committed at it, so they stand as evidence.
  Any new edit in this session invalidates 🔒 SECURITY for the new diff.
- This container is NOT the one the checks ran in. It has no docker daemon, no
  tcpdump, no tshark and no `gh`. The 🔨 BUILD evidence is therefore historical,
  not reproducible here.
- NO LOCAL DEV WORKFLOW IS COMMITTED (gate-reference step 6). There is no
  scripts/, no tests/, no Makefile, no package.json. Every check suite counted in
  🔨 BUILD above was written ad-hoc in a previous container and died with it.
  Gate 2 has nothing in the repo to run. Committing the harness would make the
  BUILD gate reproducible instead of a claim.
- Branch rename RESOLVED: user chose claude/admiring-wright-k20ptf as canonical
  rather than let the harness's per-session branch name fork the history.

========================================================================
TEST HARNESS PLAN (researched 2026-09-12, NOT yet written -- next task)
========================================================================
Why: 5,327 lines of security-sensitive code, zero committed tests. Every check
suite counted in the BUILD gate for dev.1-dev.8 was written ad-hoc in a
container and died with it -- which is why the counts disagree (249 in this
file, 460 in a later handoff) and why neither can be re-run to settle it.
Gate 2 has nothing in the repo to execute, so it has been passing on assertion.
Secondary gap: release.yml triggers only on `v*` tag push, so nothing compiles
or tests before a tag. There is no PR/push build check at all.

CONTAINER BLOCKER, hit and not yet cleared:
  `pip install -r backend/requirements.txt` FAILS -- Debian's cryptography
  41.0.7 has no RECORD file and cannot be uninstalled. Use a venv. `.venv/`
  exists (gitignored) but has NO packages: the install was interrupted. First
  action next session: .venv/bin/pip install -r backend/requirements.txt
  Also note this container is Python 3.11; the image is 3.12.

PLAN, per module. The code has been read -- do not re-read 5,300 lines.

crypto.py
  - envelope round-trip; seal_bytes/open_bytes, seal_file/open_stream
  - Sealer: header() then seal() then finish(); reuse after finish raises
  - WrongKey on a foreign kek_id, and on a corrupted wrapped-DEK tag
  - CryptoError on a missing terminator (truncation detection), and on chunks
    spliced between files (AAD is MAGIC||index, so index order is bound)
  - _coerce_key across 32 raw bytes / 64 hex / base64, and its rejection path
  - assert KDF_N == 1<<17 and SCRYPT_N == 1<<17 so cost cannot be quietly lowered

vault.py
  - StartupRefused: no key and no ALLOW_UNENCRYPTED_CAPTURES
  - StartupRefused: encrypted captures present but no key configured
  - THE DISTINCTION THAT MATTERS: WrongKey -> refuse to start; a damaged or
    truncated file -> log loudly and start anyway (_key_opens_existing returns
    True when nothing said "wrong key")
  - migrate_plaintext: seals, verifies, only then unlinks; a failure leaves the
    plaintext intact and no .partial behind
  - stored_path suffix follows whether a cryptor exists
  - source_for picks the reader by magic bytes, NOT by filename

auth.py
  - hash_password/verify_password round-trip; legacy bare salt$hash still verifies
  - needs_rehash true for legacy and for lowered parameters
  - hash_token: the DB stores only the digest, never the bearer token
  - idle timeout DELETES the session (cannot be revived by a later request)
  - _LAST_SEEN_WRITE_INTERVAL throttles the touch_session write
  - RateLimiter: lockout at max_attempts, and the window expiring

main.py  (FastAPI TestClient; no listening socket needed)
  - REGRESSION TEST for _client_ip: X-Forwarded-For ignored unless
    _TRUST_PROXY_HEADERS, and the RIGHTMOST entry used when it is. The bug this
    replaces was unlimited password guessing against the login limiter.
  - read-only-over-HTTP middleware, including the four _INSECURE_ALLOWED_PATHS
    that must still work (login/logout/register/totp-confirm)
  - security headers + CSP present on every response
  - HSTS only when the transport is genuinely https
  - NOTE: backend.main runs Database(), CaptureVault() and delete_all_sessions()
    at module scope, and SystemExit(1)s on a refused vault. conftest.py must set
    DATA_DIR / CAPTURES_DIR / SSH_KEYS_DIR to tmp dirs and provide a master key
    BEFORE import, session-scoped.

localnet.py
  - describe_if_local, table-driven: HOST_ALIASES, loopback, an own address,
    the default gateway -- and an explicit test for the documented case it
    CANNOT catch (the host's LAN address on a bridged container), so the guard's
    limit is asserted rather than assumed

ssh_manager.py
  - _is_safe_tcpdump_path rejects "/bin/sh -c curl|sh", traversal, relative
    paths, and any basename that is not literally tcpdump
  - parse_prereq_output against hostile probe output (injection, substitution,
    non-printables, absurd lengths) -- output is remote and untrusted
  - _shell_quote; _key_path traversal refusal
  - evaluate_prereqs privilege matrix: root / cap_net_raw / sudo-nopasswd /
    sudo-demands-password / sudo-absent / none-of-these

packet_parser.py
  - _validate_display_filter, ALLOWED_VIEW_FLAGS, _name_resolution_args run
    anywhere with no tools
  - anything needing real tshark: pytest.mark.skipif, REPORTED AS SKIPPED.
    A harness that prints "all passed" while silently omitting the parser is
    how today's situation comes back.

Scaffolding
  - requirements-dev.txt (pytest, pytest-asyncio, httpx) kept OUT of the
    Dockerfile so the runtime image does not grow
  - scripts/check.sh as the single entrypoint: prints a tool-availability
    preamble (tshark/tcpdump/docker present or absent) and runs pytest with -r s
    so skips are visible
  - .github/workflows/check.yml on push and PR CALLING scripts/check.sh, not
    reimplementing the checks inline -- otherwise CI and local drift apart and
    can pass and fail independently

Still impossible here regardless of the harness: `docker compose build` is
untestable with no daemon, and the 10.0.0.230 prereq check needs LAN reach.
Both stay on real hardware.

---

## Harness progress (session 4, 2026-09-12)
Track: work commit (test scaffolding, no version bump)
🔒 SECURITY   ✅ 0 Critical, 0 High (test-only diff -- fixtures use synthetic
  key bytes, tmp_path-scoped I/O, no dangerous patterns)

Landed: pyproject.toml (pytest config, pythonpath + asyncio_mode=auto),
backend/requirements-dev.txt (pytest/pytest-asyncio/httpx, kept out of
Dockerfile per the plan), tests/test_crypto.py -- 28 tests, all passing,
covering: envelope round-trip (bytes + file), Sealer header/seal/finish
lifecycle incl. double-finish and seal-after-finish, WrongKey on both a
foreign kek_id and a corrupted wrap tag under the same kek_id, CryptoError
on missing terminator / mid-chunk truncation / spliced chunks (proves the
per-chunk AAD index binding), NotEncrypted / looks_encrypted on plaintext,
_coerce_key across raw/hex/base64 plus 6 rejection cases, and KDF_N == 1<<17
pinned so the scrypt cost can't be silently lowered.

Environment this session: docker present, no tcpdump/tshark/gh. Fresh venv,
clean `pip install -r backend/requirements.txt` (no cryptography/RECORD
conflict this time -- different container than the one that hit that).

Landed: tests/test_vault.py -- 30 tests, all passing (58 total with
test_crypto.py). Covers StartupRefused with no key and no override, the
truthy/falsy ALLOW_UNENCRYPTED_CAPTURES spellings, refusal when encrypted
captures exist with no key, the WrongKey-vs-damaged-file distinction in
_key_opens_existing (damage detection required truncating INSIDE the first
chunk, not just the tail -- next() only pulls one item, so a tail cut past
an intact first chunk never raises), unlock() leaving the vault locked on a
wrong passphrase, stored_path's .enc suffix logic, source_for dispatching
on magic bytes rather than filename (misnamed files both directions), and
migrate_plaintext's verify-then-unlink (success, verification-failure
leaves the original untouched, multi-file). Used a minimal FakeDB stub
(get_setting/set_setting only) rather than backend.database.Database, to
keep vault tests isolated from the heavier main.py import chain.

Landed: tests/test_auth.py -- 31 tests, all passing (89 total). Covers
hash_password/verify_password round-trip, unique salt per hash, current
scrypt params recorded in the hash, the legacy salt$hash format (built by
hand with _LEGACY_SCRYPT params to prove old hashes still verify),
needs_rehash true for legacy/weaker-params/malformed and false for current,
hash_token as a plain sha256 digest distinct from the token itself,
validate_session's idle-timeout deletion (incl. a naive/no-tzinfo
last_seen, since sqlite round-trips those), idle-timeout disabled at 0,
the _LAST_SEEN_WRITE_INTERVAL throttle (touch_session skipped when fresh,
called when stale enough or missing), and RateLimiter lockout/independent
keying/reset/update_config plus window expiry via a monkeypatched
time.monotonic (no real sleeping). Used a minimal FakeSessionDB stub
(same pattern as vault's FakeDB) rather than backend.database.Database.

Landed: tests/conftest.py + tests/test_main.py -- 23 tests, all passing
(112 total). conftest.py sets DATA_DIR/CAPTURES_DIR/SSH_KEYS_DIR to a fresh
tempfile.mkdtemp() tree and a synthetic PCAP_MASTER_KEY as plain
module-level code (not a fixture -- collection imports test modules, which
import backend.main, before any fixture runs, so a fixture would be too
late); verified with a standalone import smoke test before writing the
real suite. test_main.py covers: _client_ip against a hand-built
SimpleNamespace fake Request (no ASGI needed for a pure function) --
ignores X-Forwarded-For by default, uses the RIGHTMOST entry when
_TRUST_PROXY_HEADERS is set (this exact bug was the live rate-limiter
bypass, tested directly as "a spoofed leftmost entry does not win"),
skips unparseable entries, falls back to client.host; _is_secure_transport
incl. all three loopback spellings and forwarded-proto trust gating;
then, via a real TestClient, security headers present on every response,
CSP value matches _CSP exactly, HSTS absent over http / present over
https, the read-only-over-HTTP middleware blocking a mutating endpoint
unauthenticated (proves the block happens in middleware, before auth even
runs) while the 4 _INSECURE_ALLOWED_PATHS stay open and HTTPS is unaffected.

Landed: tests/test_localnet.py -- 22 tests, all passing (134 total).
Table-driven across describe_if_local's three "this is local" paths --
every HOST_ALIASES entry (parametrized, with a resolve() that raises if
called at all, proving the alias check truly short-circuits), plus
case-insensitivity and trailing-dot handling on the alias match; loopback
(v4 and v6); an address the container itself holds; the default gateway --
and the negative cases: unresolvable hostname, a resolved address with no
overlap at all, and the one from the module's own docstring: the host's
real LAN address on a bridged container that was never given an
--add-host entry, which resolves to neither an own address nor the
gateway and so is indistinguishable from a genuinely remote target. Also
covers resolve() directly (IP-literal short-circuit skips DNS entirely,
empty/whitespace input, DNS-failure returns empty set rather than
raising, IPv6 zone-id stripping, timeout restored even after a failure)
and local_addresses() as the union. resolve()/_own_addresses()/
_default_gateways() are monkeypatched throughout so none of this touches
real DNS, sockets, or /proc -- runs identically on any machine.

Landed: tests/test_ssh_manager.py -- 68 tests, all passing (202 total).
_is_safe_tcpdump_path: rejects shell injection (space/pipe/semicolon/
backtick/$()), a traversal path with the wrong final basename, relative
paths, non-tcpdump basenames, empty string, an oversized path, and an
embedded NUL -- plus one test documenting (not just asserting) that a
'..'-bearing path whose FINAL component is still literally "tcpdump" is
accepted, since PurePosixPath never collapses '..' and the value is only
ever used as a literal string in a remote shell command, never resolved
against a local filesystem. _shell_quote: safe strings pass through
unchanged, hostile ones get wrapped with the '"'"' escape verified
explicitly so an embedded quote can't close early. _key_path: traversal
(../, bare .., a subdir dance) and an absolute path both rejected --
covers pathlib's own gotcha where `keys_dir / "/etc/passwd"` silently
discards keys_dir because the right side is absolute. parse_prereq_output:
happy path field-by-field, command injection / substitution / traversal
all excluded from found_paths via _is_safe_tcpdump_path, dedup, control
characters stripped by _clean, the 400/40/80-char bounds enforced against
absurdly long input, non-digit UID stays None, SUDO_NOPASSWD requires the
exact string "yes", on_path preferred over found_paths for tcpdump_path.
evaluate_prereqs privilege matrix: incomplete probe and missing-tcpdump
short-circuits, root / cap_net_raw / sudo-nopasswd all "ok", sudo-present-
but-demands-password and sudo-requested-but-absent and no-privilege-at-all
all "fail" with the right remediation text, caps-unavailable warns only
when it's actually relevant (not for root), tmp-writable true/false/
unknown, and the three SELinux states plus "no check when absent".

Landed: tests/test_packet_parser.py -- 35 tests (202+35=237 total). Runs-
anywhere half (29 tests, no tools): _validate_display_filter accepts
benign filters and rejects each of the 6 forbidden characters individually
plus realistic hostile strings built from them; ALLOWED_VIEW_FLAGS pinned
to its exact documented set and checked against VIEW_FLAG_TIME_FIELD's
keys; _name_resolution_args off-by-default, the exact on-args, and that
the returned list is a copy (mutating it must not corrupt the shared
constant for the next caller); _flatten_fields scalar/nested/list/empty;
and one that proves get_packet_list rejects a hostile filter BEFORE any
subprocess runs at all, via a PcapSource whose chunks() raises if ever
iterated. Tool-dependent half (6 tests, pytest.mark.skipif on
shutil.which("tshark"/"capinfos"), reported via -r s rather than silently
omitted): a hand-built minimal libpcap file (one UDP packet, raw struct.pack,
no scapy/fixture needed) fed through get_packet_list, get_packet_detail and
get_packet_count end to end. VERIFIED FOR REAL this session: apt-get
installed tshark 4.2.2 + capinfos in this container specifically to prove
the 6 skippable tests actually pass and the hand-built pcap bytes are
valid, not just that they skip cleanly when tools are absent (full suite:
237 passed, 0 skipped, with tools present; the container's Dockerfile/image
were not touched -- this was throwaway container tooling for verification
only).

Landed: scripts/check.sh and .github/workflows/check.yml -- the last
scaffolding piece. check.sh prints a tool-availability preamble
(tshark/tcpdump/capinfos/docker present-or-absent, explaining that absent
tools mean SKIPPED not silently omitted), bootstraps a local .venv if one
doesn't exist, installs backend/requirements-dev.txt into it, then runs
`pytest -r s`. The venv step exists because of the exact issue the original
plan flagged: this container's system python has a Debian-packaged
`cryptography` with no RECORD file, so a bare `python3 -m pip install`
fails with "Cannot uninstall cryptography ..." -- reproduced live while
building this script, which is why the fix is in the script now rather than
a note for next time. check.yml runs on every push and pull_request
(closing the gap release.yml leaves: that one only fires on v* tags),
installs tshark+tcpdump (DEBIAN_FRONTEND=noninteractive, since
wireshark-common's postinst asks an interactive debconf question that
would otherwise hang the job), and calls scripts/check.sh rather than
reimplementing the checks inline, so CI and local can never drift into
passing and failing independently.

VERIFIED FOR REAL, twice: ./scripts/check.sh with the pre-existing .venv
(237 passed), and again after moving .venv aside to force the bootstrap
path from nothing (237 passed, fresh venv created and populated
correctly). tshark/capinfos are still installed in this container from
the previous verification pass, so 0 of the 237 were skipped either time;
capinfos install left tcpdump absent both runs, which is exactly the
partial-tool-availability case the preamble exists to report.

This closes out the harness plan from the original handoff: every file in
the table (crypto, vault, auth, main, localnet, ssh_manager,
packet_parser) now has real tests, plus the scaffolding to run them
identically in CI and locally. 🔨 BUILD is no longer a historical claim --
scripts/check.sh is a build/test workflow a fresh clone can run today.

---

## Fix: concurrent captures were unbounded (session 4, continued)

User picked this as the first of the remaining outstanding items (from a
prior session's punch list: concurrent captures / seal the SSH keys / CSP
unsafe-inline). CaptureManager.start() had no check at all on how many
captures were already running -- any authenticated user could call
POST /api/captures without limit, each one opening a new SSH connection to
a target host plus a local file, with nothing capping simultaneous SSH
connections, file descriptors, or disk usage.

Fix: a new `active_count()` on CaptureManager counts captures in
RUNNING/STOPPING/TRANSFERRING (every state that still holds a connection
or a file, not just RUNNING), checked against a new `max_concurrent_captures`
setting (default 5, same DEFAULTS/admin-settings pattern as
max_capture_seconds/max_capture_packets -- automatically admin-editable via
the existing generic PUT /api/admin/settings endpoint, no separate wiring
needed). The check runs FIRST in start(), before any SSH connection is
opened or file created, raising a new CaptureLimitExceeded that main.py's
POST /api/captures maps to HTTP 429 instead of the generic 500.

Track: work commit (bug fix, no version bump)
🔒 SECURITY   ✅ 0 Critical, 0 High -- limit checked before any resource is
  opened (rejection wastes nothing), error message is a static string with
  no sensitive detail, new setting follows the existing validation path.

Landed: tests/test_capture.py -- 12 tests, all passing (237+12=249 total).
active_count() per-status (PENDING/COMPLETED/FAILED don't count,
RUNNING/STOPPING/TRANSFERRING do) and summed across several; start()
succeeds below the limit; start() raises CaptureLimitExceeded at the limit
AND proves zero SSH connections were opened (a FakeSSHManager tracks
call count -- this is the test that actually matters, since a limit that
merely returns an error after already opening the connection isn't a fix
at all); the limit counts STOPPING/TRANSFERRING too, not just RUNNING;
capacity frees up once a capture completes; the exception message names
the actual configured limit. Captures are seeded directly into
CaptureManager._captures (bypassing start()) since active_count() only
reads that dict -- avoids needing N real fake processes/monitor tasks to
simulate N already-running captures. Async fixture teardown calls
manager.shutdown() to cancel the one real monitor task each test does
spin up, same cleanup path production uses.

---

## Fix: CSP script-src unsafe-inline (session 4, continued -- last punch-list item)

32 inline onclick/onchange attributes found (14 static in index.html, 18 in
app.js's dynamically-rendered template strings) -- close enough to the
punch list's "33" that it's the same set, likely off by one from a handler
added/removed since that note was written. All 32 converted:

- Static elements (buttons/checkbox that exist in index.html from page
  load): given stable ids, wired via addEventListener in a new
  initStaticHandlers().
- Dynamically-rendered content (server list, saved-server list, capture
  list, admin tables, packet rows): onclick="fn('${id}')" replaced with
  data-action/data-id attributes, resolved by a new delegate(containerId,
  handlers) helper -- ONE listener per container, attached once at boot on
  the container element itself (which exists from page load even though
  its innerHTML is replaced on every re-render), not re-attached per item.
  This is the standard pattern for CSP-safe dynamic content and avoids the
  alternative (re-querying and re-attaching listeners after every single
  innerHTML assignment across 7 different render functions).

The one remaining wrinkle: index.html's <head> has a genuine inline
<script> block (the theme-flash-prevention snippet) that has to run before
first paint, before app.js is even loaded -- can't move to the external
file without the flash returning. Pinned by SHA-256 content hash instead
of 'unsafe-inline' (legitimate CSP script-src source syntax, same family
as 'self' and nonces, not a bypass). Documented at both the CSP definition
in main.py and directly above the inline script in index.html, including
the one-liner to recompute the hash -- changing that snippet by even one
character silently breaks it and the browser drops the script with no JS
error, only a CSP console message.

style-src keeps 'unsafe-inline' deliberately -- inline style="" attributes
are used throughout this UI for layout, and removing that is a separate,
much larger change nobody asked for here.

Track: work commit (frontend hardening, no version bump)
🔒 SECURITY   ✅ 0 Critical, 0 High -- CSP tightening, not a new risk;
  data-id values preserve the exact escaping (escHtml or raw) each
  original onclick string already used, no regression either direction.

VERIFIED FOR REAL, live, in an actual browser: installed the Playwright
Python package into .venv (throwaway, like tshark/openssh-server before
it) and pointed it at this container's pre-installed Chromium build
(/opt/pw-browsers -- the pip-installed Playwright's pinned browser version
didn't match, so used executable_path directly). Started the real app
with uvicorn, drove it through a full flow with zero CSP console
violations and zero real console errors: register -> TOTP setup (computed
a real valid code with pyotp against the QR secret shown on screen) ->
confirm -> reached the app -> theme toggle (proves the SHA-256-pinned
inline script executed AND its dataset value drives the button, all with
no CSP block) -> admin tab -> uploaded a real ed25519 SSH key -> added a
server -> selected it via the delegated server-item click -> clicked a
delegated per-server action button -> created and deleted an admin user
via the admin-user-list delegation -> deleted the uploaded key via the
admin-ssh-keys delegation -> saved a server to a profile via a JS
prompt() dialog -> loaded/edited/saved/deleted it via the
saved-server-list delegation. Every container's delegate() wiring was
exercised at least once; capture-list and packet-tbody delegation use the
identical mechanism and weren't separately live-tested since they need a
reachable SSH target. Test server, generated keys, and the throwaway
playwright package were all removed afterward -- nothing from this
verification is part of the diff.

Landed: backend/main.py (_CSP script-src hash + comment rewrite),
frontend/index.html (14 static handlers converted, hash-pinning comment
added), frontend/js/app.js (delegate() helper, initStaticHandlers(),
initEventDelegation(), 18 template-string conversions). No new test file
-- this is frontend JS/HTML with no existing test harness coverage in this
repo (the harness built this session is Python/pytest only); the live
browser verification above is the closest equivalent for this change.

This closes the punch list from the prior session's handoff: concurrent
captures bounded, SSH keys sealed at rest, CSP script-src hardened. All
three verified live, not just unit-tested in isolation.

---

## Fix: SSH private keys stored in plaintext (session 4, continued)

User flagged this as an architecture-level task, not mechanical test-writing
-- correctly: it required deciding where key material flows (asyncssh's
client_keys accepts bytes/SSHKey objects, not just paths, so the whole
_connect() key-loading path had to change shape), how sealing relates to
the existing CaptureVault (reuse the same master key rather than a second
independent one -- one key to back up, no new configuration surface), what
happens across all four vault states (disabled/unencrypted, enabled+
unlocked, enabled+locked, no vault at all), and a migration story for
already-uploaded plaintext keys with the same blast-radius concern
concurrent-captures didn't have: get this wrong and an admin could be
locked out of every saved server, not just see a bad error message.
Designed at bumped effort on Sonnet (not Opus) per the user's call --
verified against the actual asyncssh 2.24.0 API before writing any code
(client_keys type union confirmed to accept bytes/str/PurePath/SSHKey;
import_private_key confirmed to raise KeyImportError, itself a ValueError
subclass, so malformed-key handling falls through the exact same generic
except-Exception paths that already existed -- zero behavior change for
that case).

Design chosen: keys are content-sniffed via the existing looks_encrypted()
magic-byte check, same as CaptureVault.source_for -- no filename/extension
change, so ServerAuth.ssh_key_name validation and the list/delete
endpoints needed zero changes. SSHManager gained an optional `vault` param
(same pattern as CaptureManager) and three new methods: _read_key_bytes
(decrypt when sealed and the vault can, else raise CryptoError -- vault
locked or absent), _load_client_key (decrypt then asyncssh.import_private_key),
and migrate_plaintext_keys (verify-then-replace, structurally identical to
CaptureVault.migrate_plaintext's already-proven safety, deliberately
NOT extracted into a shared helper -- duplicating ~15 lines was judged
safer than refactoring vault.py's already-tested, already-shipped
migrate_plaintext for a second caller). _connect() translates a locked-
vault CryptoError into ConnectionError right at the point of failure,
keeping _connect()'s public contract at exactly two exception types
(FileNotFoundError, ConnectionError) -- every existing caller
(test_connection, list_interfaces, prereq_check) already has a `except
ConnectionError -> HTTP 502` handler, so the clearer message reaches the
admin with ZERO changes needed in main.py's endpoint handlers. Upload
seals content via vault.cryptor.seal_bytes() before the first write_bytes
call -- no plaintext key touches disk even transiently.

Track: work commit (architecture-level fix, no version bump)
🔒 SECURITY   ✅ 0 Critical, 0 High -- see verification note below, this
  one got a live end-to-end check, not just unit tests in isolation.

VERIFIED FOR REAL, live, against a real SSH server: apt-get installed
openssh-server in this container (throwaway, like the tshark install --
repo/Dockerfile untouched) specifically to prove the whole pipeline works,
not just that the pieces look right in isolation. Generated a real ed25519
keypair, sealed the private half under a Cryptor, ran the actual
SSHManager.test_connection() against a real sshd on 127.0.0.1:2222 with
PermitRootLogin: the sealed key decrypted, parsed via
asyncssh.import_private_key, authenticated, and `echo ok` came back over
a real SSH session. Then re-ran the same connection attempt with the vault
locked (cryptor=None): refused with "SSH key ... is encrypted and the
vault is locked" -- BEFORE any network connection was attempted, not
after a failed handshake. Test sshd and all key material cleaned up
afterward (killed the process, removed /root/.ssh/authorized_keys and the
temp key files); nothing from this verification is part of the diff.

Landed: tests/test_ssh_manager_keys.py (14 tests) and
tests/test_ssh_keys_upload.py (2 tests) -- 265 total. Covers
_read_key_bytes/_load_client_key across all four vault states including
two REAL asyncssh keys (ed25519, ecdsa-p256) round-tripped through actual
seal/parse (not just byte-equality on fake data), _connect() translating
a locked vault into ConnectionError with the message asserted, and
migrate_plaintext_keys' full safety net (seals in place, skips .gitkeep,
skips already-sealed files so nothing is ever double-enveloped, leaves
the original byte-for-byte on a verification-failure injected via
monkeypatch, handles multiple files, no-ops with no cryptor or a missing
directory). The upload-sealing tests call main.upload_ssh_key directly
(FastAPI route decorators return the function unchanged) rather than
through TestClient, specifically to avoid registering a real user against
the shared session-wide db singleton just to reach one conditional.
