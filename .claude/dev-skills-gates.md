# Dev Skills gate state
Track: 0.1.0-dev.28 OPEN — release sequence. dev.27 closed and shipped (below).
Version: 0.1.0-dev.28 (bumped). Previous tag v0.1.0-dev.27 confirmed on
         the remote: object b63c695, ^{} -> d70e47b.
Updated: 2026-09-13 (session: local CLI, Fedora 44, bash)
Branch: claude/admiring-wright-k20ptf — canonical. Head 39e48ee = origin.
Environment: LOCAL Claude Code CLI — Claude PRESENTS git commands, the user
        runs them (SKILL.md 5.8). Not a container.
Model: Opus 5, above the Sonnet ceiling; the user approved staying on it FOR
       dev.28 (2026-09-13).

## 0.1.0-dev.28 tracker

GATES RUNNING (user: "run the gates", 2026-09-13).

🔢 VERSION    ✅ 0.1.0-dev.28 in all seven refs: backend/main.py:83,
                docker-compose.yml:92, CHANGELOG heading, README.md:130/225/241,
                docs/reverse-proxy.md:110/274. grep for dev.27 outside CHANGELOG
                history and this file: none. Previous tag v0.1.0-dev.27 on
                remote (^{} d70e47b). Release-notes link built from APP_VERSION.
                pyproject.toml is pytest config only -- no app manifest.
🔨 BUILD      ✅ ./scripts/check.sh AFTER the bump: 1214 passed, 0 skipped,
                exit 0, 3m40s. Browser suites run the real app via
                backend.serve (golden path: sign-in, capture form, viewer,
                admin). CAVEAT CARRIED TO SHIP: Docker image not built here (no
                docker socket) and CI builds it only on tag push -- the user must
                `docker compose build` (lego stage is new) BEFORE tagging.
🔒 SECURITY   ✅ 0 Critical, 0 High. User: "fix all issues" -> every Medium/Low/
                quality item below was FIXED, not accepted, except one that is a
                standing user decision:
                  FIXED High (before): AWS_SHARED_CREDENTIALS_FILE (credential_
                    process RCE), OCI_CONFIG_FILE (key_file path read) excluded.
                  FIXED Medium: SSRF -- backend/tls/destinations.py refuses non-
                    http(s) URLs and loopback/link-local/unspecified/multicast,
                    literal at save and resolved just before lego runs. LAN
                    allowed by design. Residual (Low, documented): DNS rebinding
                    between our lookup and lego's.
                  FIXED Medium: *_INSECURE_SKIP_VERIFY / INFOBLOX_SSL_VERIFY no
                    longer offered (generator SKIP_VERIFY_NAME).
                  FIXED Low: base image pinned by index digest
                    sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
                    (verified: body hash matches, not e3b0, amd64+arm64), both
                    stages; .github/dependabot.yml (docker, weekly, 3.12 only).
                  FIXED Low: TLS routes call manager.status via to_thread.
                  FIXED Quality: manager.status split into helpers; tls.js
                    renderTls/tlsRequestForm split into single-purpose builders.
                  NOT CHANGED (user decision 2026-09-13, reaffirmed "understood
                    on the skip"): DNS credentials may cross plain HTTP; UI warns,
                    CLI offered. Only real fixes are refusing it or loopback-only.
                pip-audit clean. check.sh after fixes: 1243 passed, 0 skipped.
📄 DOCS       ✅ CHANGELOG dev.28 entry dated 2026-09-13 (now lists the
                excluded settings); README layout table gained backend/tls,
                serve.py, js/tls.js, scripts/; tls.md gained excluded settings +
                endpoint note; architecture/security/operating/filters/
                reverse-proxy consistent (grep: no certbot/backend.acme/Cloudflare-
                only/"Save this filter"/chip leftovers). Security-fix docs added
                (tls.md endpoints + cert checks, CHANGELOG, architecture,
                security). Final rebuild: check.sh 1243 passed, 0 skipped, exit 0.
📦 RELEASE    ⏳ branch in sync with origin (both 39e48ee); awaiting commit
                approval. PR ➖ N/A: no PR workflow in this repo (as dev.27).
🚀 SHIP       ⬜

### dev.28 scope
1. Built-in HTTPS -- backend/tls/ package (self-contained), lego 5.4.1.
2. DATA_DIR not-private startup warning (warn only).
3. Capture form: BPF example chips removed; Live stream option restyled;
   Save filter left of BPF field, hidden when empty.
4. Saved display filters: table custom_display_filters, /api/display-filters,
   Save filter button left of the Viewer's display filter, listed as "Your
   filters" at top of Filter help.

USER DECISIONS (2026-09-13):
- Passphrase mode + built-in TLS: REFUSE. File/env keys allowed.
- ACME setup allowed over plain HTTP, admin-only, plus a CLI path.
- memfd, not tmpfs -> docker-compose.yml unchanged.
- lego (not certbot), Proxmox-style provider picker, ~216 providers.
- "Self-contained" = all from web UI + no extra runtime + isolated package.
  HTTP-01 NOT wanted.
- Port: HTTPS on whatever host port compose publishes (container stays 8080).
- Stay on Opus for dev.28.

DESIGN (mine, surfaced):
- Provider allowlist generated from lego source TOML (scripts/gen_lego_providers.py)
  -> backend/tls/lego_providers.json; test pins its version to Dockerfile ARG.
  Excluded: exec, manual, acmedns. No LEGO_*, no *_FILE; path-type vars are
  "file" kind: admin pastes contents, app writes into /dev/shm scratch.
- lego runs with env = PATH/HOME/LANG + validated provider vars only; cwd =
  fresh /dev/shm dir (lego auto-loads .lego.yml from cwd).
- Credentials merge: blank keeps stored value for same provider; new provider
  starts empty.
- lego fetched in a Docker build stage via backend/tls/fetch_lego.py, SHA-256
  pinned for amd64 + arm64.

VERIFIED: real lego 5.4.1 parsed our exact argv (reached ACME directory fetch
against a closed local port). Real certbot was verified earlier but is gone.
NOT VERIFIED: image build; a real issuance end to end (needs user's domain).

## 0.1.0-dev.27 tracker

🔢 VERSION    ✅ 0.1.0-dev.27 in SEVEN places now, not five.
                ⚠️ TWO NEW REFS THIS RELEASE: docs/reverse-proxy.md carries the
                image tag TWICE (the Caddy sidecar compose and the NPM sidecar
                compose). Full list: backend/main.py:80, docker-compose.yml:92,
                CHANGELOG heading, README.md:127 (Quick start curl),
                README.md:222 (version table), README.md:238 (Upgrading curl),
                docs/reverse-proxy.md:105 and :269.
                Check: grep -rn "0\.1\.0-dev\.26" excluding .git, .venv and
                CHANGELOG. A bump that misses the docs ones ships sidecar
                examples pinned to the previous image.
🔨 BUILD      ✅ ./scripts/check.sh locally: 1063 passed, 0 failed, 0 SKIPPED,
                3m16s, exit 0. dev.26 baseline was 1055; +8 = the live-control
                and Admin-placement tests.
🔒 SECURITY   ✅ 0 Critical, 0 High. pip-audit: "No known vulnerabilities
                found" -- PYSEC-2026-1845 is CLOSED this release, not deferred
                again (see below).
📄 DOCS       ✅ CHANGELOG entry for dev.27; docs/reverse-proxy.md and
                docs/Caddyfile.example new; nginx-proxy-manager.md rewritten;
                architecture.md and security.md carry the directory-permissions
                fact; compose header rewritten.
📦 RELEASE    ✅ commit d70e47b, pushed to origin and VERIFIED by ls-remote:
                refs/heads/claude/admiring-wright-k20ptf = d70e47b = local
                HEAD, 0 unpushed. 21 files.
                EXECUTED BY CLAUDE, not presented -- the user was away from
                their desk and explicitly asked ("I want you to do the the
                commit and push"). That overrides SKILL.md 5.8's presentation
                DEFAULT for a local session; it does not touch the tag rule.
                ➖ PR — N/A: no PR workflow in this repo, `git log --merges` is
                empty across its whole history.
🚀 SHIP       ✅ tagged and published by the USER, verified from the remote:
                  * tag object b63c695; refs/tags/v0.1.0-dev.27^{} -> d70e47b,
                    which EQUALS the branch head. Both halves checked -- the
                    tag object sha is not the commit sha.
                  * Release workflow 34773044743 completed/success. "Build and
                    push image" and "Create GitHub Release" both green.
                  * GitHub Release v0.1.0-dev.27 (Dev) exists, prerelease,
                    published 2026-09-13T17:56:27Z.
                  * CI fired the expected THREE runs again: Check on the branch
                    push (success), then Check + Release on the tag push. Known
                    and declined -- see the standing constraints.

                  * BOTH IMAGE TAGS RESOLVE TO ONE MANIFEST. Run by the user
                    on their docker host (this sandbox cannot -- DNS for
                    pkg-containers.githubusercontent.com does not resolve, and
                    the gh token lacks read:packages):
                      :0.1.0-dev.27 -> 14974fbb4de5467ce7dbd9a2971cdbb1f7af3ae9
                      :dev          -> same
                    ALL FOUR POST-SHIP CHECKS DONE.

                ⚠️ TRAP WORTH REMEMBERING for the next release. Piping a FAILED
                `docker manifest inspect` into sha256sum yields
                e3b0c44298fc1c14... for every tag -- that is the hash of an
                EMPTY STRING. It looks exactly like a clean match and means the
                command produced no output. Check the hash is not e3b0c442
                before believing a digest comparison.

## 0.1.0-dev.27 — what changed

1. setLiveControls(live) gates .live-bar-actions. The live bar still shows on a
   saved live-streamed capture; its BUTTONS do not. Called from startLiveView
   (true), viewCapture's stored path (false), and settleFinishedCapture (false,
   BEFORE the completed/failed branch so a FAILED capture loses them too).
   Hidden not disabled: on a finished capture there is no "why" for a disabled
   button to invite. Reported by the user testing dev.26.
2. Admin is a TOOLBAR BUTTON (#admin-tab, .btn, data-tab="admin"), not a tab.
   activatePanel selects on `[data-tab], .tab`; initTabs attaches a direct
   listener because .tab-bar delegation cannot reach outside the bar.
   THREE test files referenced `.tab[data-tab='admin']` -> now `#admin-tab`.
3. docs/reverse-proxy.md + docs/Caddyfile.example, and the NPM guide rewritten
   for a SHARED, PRE-EXISTING NPM rather than one stood up for this app.
4. chmod 0700 in the Quick start and the compose header.
5. pytest 8.3.4 -> 9.0.3 AND pytest-asyncio 0.25.2 -> 1.4.0.

### SECURITY — 0.1.0-dev.27

- NO new routes, NO new database columns, NO schema change, NO new runtime
  dependency. The app's attack surface is unchanged by this release.
- The two code changes are both frontend visibility logic. setLiveControls
  toggles one element's `hidden`; the Admin move changes which element carries
  a class. Neither touches auth, capture data, or any request.
- THE ONE REAL SECURITY CONTENT IS DOCUMENTATION, and it is a live finding:
  the entrypoint chowns ssh-keys/, data/ and captures/ to appuser but sets NO
  MODE, so at a default umask they are world-readable. data/ holds the SQLite
  database, which stores totp_secret AS PLAIN TEXT (database.py:264 writes the
  raw secret; the app must compute codes from it). Any local account that can
  read that file can mint a valid second factor for every user, indefinitely.
  Password hashes are scrypt and sessions are SHA-256 digests, so those are an
  offline-cracking problem rather than an immediate one.
  Fixed for NEW installs via chmod 0700 in the Quick start + compose header,
  and written up in docs/security.md ("The data directory") and
  architecture.md. EXISTING INSTALLS ARE STILL 0755 -- see dev.28 queue.
  An earlier draft justified the chmod partly with "the encryption salt";
  that was WRONG and was corrected before commit. crypto.py:334 says outright
  the salt is not secret. The TOTP seeds are the reason.
- pip-audit clean. PYSEC-2026-1845 (pytest 8.3.4) is closed by the bump rather
  than carried. It was dev-only -- the Dockerfile installs requirements.txt --
  but an advisory nobody can close is one everybody learns to scroll past.
  pytest 9 required pytest-asyncio 1.4.0 because 0.25.2 pins pytest<9. BOTH
  SUITES were run against the pair before committing: 929 API + 134 browser,
  no failures, no new warnings. asyncio_mode="auto" and the function-scoped
  fixture loop in pyproject.toml are unchanged and still honoured.

### DECLINED this session — do not re-raise

Wiring the NPM management page into pcap-server's Admin tab. Three shapes were
considered and all refused:
  * iframe -- blocked by default-src 'self' anyway, but the real objection is
    that it trains people to type another app's credentials into a frame this
    app serves.
  * a link -- 127.0.0.1:81 resolves to the BROWSER's machine, not the host, so
    it is wrong in exactly the deployment that needs it.
  * pcap-server reverse-proxying NPM at /npm/ -- couples two trust domains (any
    pcap-server admin session becomes NPM admin), is SSRF by construction, and
    defeats the loopback bind that was the point.
The real need is answered in docs/reverse-proxy.md: SSH tunnel for setup, a
management-interface bind, or NPM behind itself with an Access List.

Also reverted this session: a `docs` URL map on /api/auth/status, added on a
MISREADING of "wire the page into the admin". backend/main.py is byte-identical
to HEAD. Do not re-add it unless asked.

## Queued for 0.1.0-dev.28

1. ACME/certbot integration. THE PLAN IS docs/acme-plan.md, committed with
   dev.27 -- read it first, it has the Termix findings and the decisions
   already taken. Headlines:
     * uvicorn terminates TLS; NO bundled nginx (we have one process).
     * SEAL THE TLS PRIVATE KEY under the master key -- the user's decision,
       2026-09-13. Termix leaves privkey.pem in plaintext on the volume; we do
       not. Implies decrypting to a tmpfs/-/run path at startup, which implies
       a compose-file change to the TAG-PINNED file people fetch.
     * DNS-01 is the documented default; a capture box is usually internal.
     * OPEN QUESTION 1: passphrase mode vs built-in TLS. A locked vault has no
       key to open at startup. Decide: loud HTTP fallback, or refuse the
       combination outright.
     * OPEN QUESTION 2, and the sharpest one: you configure ACME while still
       on plain HTTP, which is exactly when the app is read-only. The admin
       ACME routes would have to join _INSECURE_ALLOWED_PATHS. That needs its
       own justification and probably a local-connection restriction.
     * Validate domain and email HARD. Termix does not, and both land in argv
       after -d; a value starting with `-` is argument injection into
       certbot's parser.
2. Existing installs still have 0755 on data/. A startup check that warns when
   DATA_DIR is group- or world-readable would cover the installs the Quick
   start fix cannot reach. NOT YET RAISED WITH THE USER -- offer it.



1. The Stop capture button is offered on a SAVED capture. The live bar is
   shown for any capture with live_stream set, including completed ones, so
   Stop and Follow are both live on a finished capture -- and stopLiveCapture()
   returns early with no live capture id, so the button silently does nothing.
   Reported by the user after testing dev.26.
2. Move Admin off the tab bar and into the toolbar, beside the version link,
   the GitHub link and Logout. It is a destination, not a working tab.
3. Reverse-proxy setup: worked examples for Caddy, nginx AND Nginx Proxy
   Manager, written as a setup procedure rather than a config reference.
4. The NPM doc assumed you would stand NPM up FOR pcap-server, on a shared
   Docker network. Wrong: NPM is a proxy people already run, usually on
   another machine, and pcap-server is one more proxy host on it.
5. Link the author's own posts where they answer the prerequisite:
   NPM -> ramblingnonsense.nscriven.net/p/its-a-secret-to-everybody
   SSH keys -> ramblingnonsense.nscriven.net/p/stop-using-passwords-for-ssh

## 0.1.0-dev.26 — CLOSED AND SHIPPED 2026-09-13

All six gates ✅. Tag confirmed on the remote (above). What shipped:

Eight changes, from two batches the user queued in one session:

1. bpf_filter persisted on the capture record + migration; badged on the
   capture list under the FILTER_LIBRARY's own name where one exists.
2. Server, interface and capture filter shown on the viewer label.
3. Custom filter entries: custom_filters table, /api/filters CRUD, "Your
   filters" group at the top of the library, Save this filter on the form.
4. A capture name is required BY THE FORM (not by the API).
5. A pre-capture confirm dialog summarising the request.
6. OLED true-black dark theme.
7. Accent moved from teal to periwinkle blue (#6d9eff dark / #2b5fd9 light).
8. No standing Viewer tab; captures open as tabs of their own.

### SECURITY — 0.1.0-dev.26

- No new dependencies. pip-audit clean for everything in requirements.txt.
- THREE NEW ROUTES, all under /api/filters. Every one is
  Depends(get_current_user); there is no anonymous path. The mutating two are
  covered by enforce_read_only_over_http automatically -- they start with
  /api/ and are not in _INSECURE_ALLOWED_PATHS, which was checked rather than
  assumed.
- Per-user scoping is in the STATEMENT, not in a check beside it. Every
  custom_filters query carries `user_id = ?` in its own WHERE clause, so there
  is no window between an ownership check and the write. delete returns
  rowcount and the route turns 0 into a 404 -- not a 403, which would confirm
  the id exists.
- The saved expression goes through the SAME validator CaptureRequest uses
  (BPF_FORBIDDEN_CHARS). This is the point: /api/filters is a second door into
  the same argv, because a saved filter is replayed into a real capture. A
  test asserts a refused expression never reaches the database.
- The 409 body echoes the caller's OWN label back to them and nothing else. It
  reaches the DOM through textContent, never innerHTML.
- ONE new SQL migration, a hardcoded ALTER TABLE with no interpolation.
- New DOM: every interpolation in the filter badge, the viewer origin line and
  the capture tab strip goes through escHtml, including the title attributes.
  The badge title carries an operator-supplied BPF expression, which is the
  one genuinely attacker-adjacent string in the set.
- NO NEW EXPOSURE of packet data. Nothing here reads, moves or renders capture
  bytes; the filter is metadata about a capture, not its contents.

### Added after the first pass, at the user's direction

9.  README RESTRUCTURE. 1360 lines -> 598. Five subjects each became one
    document: docs/target-hosts.md, docs/filters.md, docs/live-streaming.md,
    docs/security.md, docs/operating.md. Nothing deleted -- the README keeps a
    short version of each and links the long one from a table at the top.
    A link checker over README + docs/*.md reports every internal link and
    anchor resolving; re-run it after any doc move.
10. PER-USER CAPS, both tables, in one change as the finding recommended:
    MAX_CUSTOM_FILTERS_PER_USER = 200 and MAX_VIEWS_PER_CAPTURE = 50, both in
    database.py. Enforced in add_custom_filter / add_capture_view, surfaced as
    409 with "limit" in the message.
11. MFA RESET. POST /api/admin/users/{id}/totp/reset, admin-only, plus
    backend/resetmfa.py as the host-side escape hatch.

    THE SECURITY DESIGN IS THE SPLIT, do not collapse it:
    - An admin may reset ANOTHER account over HTTP.
    - SELF-RESET IS REFUSED (400, code cannot_reset_own_totp). It cannot help
      a locked-out admin -- reaching any route means already being past the
      second factor -- and it IS a persistence path for a stolen session
      cookie: strip MFA, enrol your own authenticator, and a session that
      expires in hours becomes a login that does not.
    - The locked-out SOLE admin is answered out of band by
      `python -m backend.resetmfa <username> --apply`, at the bar of host
      access. Dry run by default. It never touches a password.

    A reset does THREE things and all three are load-bearing:
    - NULLs totp_secret, not just totp_confirmed. Otherwise whoever still
      holds the old authenticator can confirm the account straight back. This
      is also what makes /api/auth/totp/setup issue a FRESH secret, since it
      reuses a stored one if there is one.
    - delete_sessions_for_user -- a live session already carries both factors.
    - delete_trusted_devices -- a trusted device IS a second factor.
    18 tests in tests/test_mfa_reset.py cover all of it, including the refusal
    not being a partial reset and not signing the caller out.

### QUALITY — reviewed, and the one thing worth knowing
- FILTER_NAMES is derived from FILTER_LIBRARY at load rather than written out
  as a second table, so a filter cannot be offered under one name and listed
  under another. The reverse lookup is EXACT-MATCH ONLY and must stay that
  way: recognising `tcp port 443` inside a composed expression would name a
  capture after the broader half of its own filter, and working out how much
  narrower it really is means a second BPF model in the frontend.

### The migration's deliberate guess

An old capture row reads bpf_filter = '' and the UI shows no badge. The filter
IS recoverable from `command` -- it is the trailing argv -- and that is
refused on purpose: parsing it back means a second BPF parser picking an
expression out of an argv that also carries -i, -w and -s. Guessing
"unfiltered" loses a label on old captures; guessing a filter would be a false
claim about what is inside the file. test_a_capture_taken_before_the_column_
reads_as_unfiltered asserts both halves, including that the filter really is
sitting there in the command string.

## 0.1.0-dev.25 — CLOSED AND SHIPPED

All six gates ✅. Tag v0.1.0-dev.25 confirmed on the remote. The long-form
notes for dev.21–dev.25 were dropped from this file when dev.26 opened; the
CHANGELOG carries the user-facing record and git carries the rest. The
non-obvious constraints that outlive a release are below.

## Standing constraints — carry these forward

- **Version refs are FIVE places, not three.** The no-clone Quick start fetches
  docker-compose.yml from a TAG-pinned raw URL, so README.md carries release
  tags. A bump that misses them ships a Quick start pointing at the previous
  release.
- **backend/bpf.py and frontend/js/app.js (bpfCheckExpression) are one model in
  two copies**, kept honest by a parity browser test. Change both or neither.
- **page.wait_for_function needs "() => ..." here, never a bare expression.**
  CSP in this app blocks the bare form.
- **Custom filter entries are private per user. The server dropdown is closed** —
  do not touch it.
- **pyproject.toml is pytest config only** — no [project] table, so the
  repo-link requirement lands on backend/main.py REPO_URL + release_notes_url.
- **CI fires three runs per release** (check on branch push, a duplicate check on
  the tag push, and the release publish). check.yml uses bare `on: push:` and a
  tag push is a push. One-line fix OFFERED, not accepted:
  `on: push: branches: ['**']`. Do not re-raise unprompted.
- **DECLINED by the user 2026-09-13, do not raise again:** rewiring CI so
  release.yml calls check.yml as a gate (workflow_call + needs) and narrowing
  check.yml's triggers. The finding stands — a tag push publishes to ghcr
  whether or not the suite passed, and release.yml runs no tests — but local
  runs are the gate by choice.
- **Live streaming has still never run against a real remote host.** The
  untested seam is tcpdump -U's real write cadence, i.e. whether a 3s poll feels
  live. Covered by real tools: the record walk, filter behaviour against real
  tshark, and read_at against a real asyncssh SFTP server.

## Queued UI batch — the work dev.26 draws from

1. Capture list filter display: a badge on BPF-filtered captures plus readable
   protocol names. NEEDS a bpf_filter column + migration — it lives on
   CaptureRequest only today and is never persisted. THIS IS NEXT.
2. Server + BPF string shown during a live capture.
3. Custom filter entries.
4. Requiring a capture name.
5. The pre-capture confirm dialog.
