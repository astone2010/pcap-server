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

Next: tests/test_main.py -- the _client_ip regression test (ignores
X-Forwarded-For unless _TRUST_PROXY_HEADERS, takes the RIGHTMOST entry --
this is the actual vulnerability fixed in dev.8, so it's the highest-value
single test left), read-only-over-HTTP middleware incl. the 4
_INSECURE_ALLOWED_PATHS, CSP + security headers, HSTS only on real https.
Import note from the plan still applies: backend.main runs Database/vault/
delete_all_sessions at module scope and SystemExit(1)s on a refused vault,
so conftest.py must set DATA_DIR/CAPTURES_DIR/SSH_KEYS_DIR to tmp dirs and
a master key BEFORE import, session-scoped.
