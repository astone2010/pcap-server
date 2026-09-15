# Dev Skills gate state

## Session opened 2026-09-15 #2 (local CLI, Debian 13, zsh, dev-skills 2.18.0)
Skill loaded as a REGISTERED skill this time (it is in the session skill list),
unlike the previous session which had to read SKILL.md by hand. Self-check: all
five reference files present in ~/.claude/skills/dev-skills/.

State re-derived from evidence (SKILL.md S2), not trusted from the entry below:
 - HEAD = 62cf182, branch claude/admiring-wright-k20ptf, 0 ahead / 0 behind
   origin after `git fetch`.
 - v0.1.0-dev.34 IS on the remote -> 62cf182, the exact HEAD commit. APP_VERSION
   (backend/main.py:100) reads 0.1.0-dev.34 and agrees with all seven refs.
   Released version == tagged version == HEAD: NO unfinished Gate 6, nothing
   stranded (GATE_REFERENCE step 7).
 - `git ls-remote --tags origin`: v0.1.0-dev.15 .. v0.1.0-dev.34, contiguous.
 - Working tree carries ONE modified file: this one (the dev.34 ship record,
   +48/-3, uncommitted). No source file touched this session yet.

Env: LOCAL CLI -> Claude PRESENTS git commands, the user runs them (S5.8).
Shell: zsh (Linux Terminal). Remote: https://github.com/darthrater78/pcap-server
Local dev workflow: ./scripts/check.sh. CI build check: check.yml (branches-only
push + pull_request, and it CALLS ./scripts/check.sh -- no CI/local drift).
CI release: release.yml on `v*` tag push. Plus lint-workflows.yml (actionlint).
gate-preflight.sh still NOT installed (.claude/hooks has only session-start.sh),
so the prose pre-flight is the only enforcement. This file remains tracked in
git rather than gitignored -- as the repo has always had it, not changed
unilaterally.

Model: Opus 5, above the Sonnet ceiling. Flagged to the user at session start;
no task approval yet this session (the dev.34 approval was task-scoped).

CARRIED FORWARD, still open: the lint-workflows.yml trigger defect logged for
dev.35 (see "Known defect" below) is CONFIRMED still present at HEAD -- `on:
push:` with a `paths:` filter and no `branches:` filter, so it still fires on
tag pushes.

Model approval: user said "opus is fine" (2026-09-15) for THIS task, after the
ceiling was flagged. Task-scoped, as every prior release has been.

## TASK — actively prevent capturing the box pcap-server runs on
User: "we really need to actively prevent captures to the same box the container
is installed on. major security issue."

WHAT ALREADY EXISTS (found before proposing anything, not rebuilt):
backend/localnet.py + _reject_self_target (main.py:1026), wired into add server
(1076), edit server (1166), probe test (1227), probe prereq-check (1242). It
refuses loopback, container-owned addresses, the default gateway and Docker's
host aliases with a 400 {"code":"self_capture"}, and app.js:56 turns that into
showBlockingAlert. So this is closing holes in a real guard, not adding a
missing one.

THE TWO HOLES:
 1. POST /api/captures (main.py:1529) never re-checks -- it does
    _require_server() then capture_manager.start(). A row added before the
    guard existed, or a hostname whose DNS answer has since moved to the host,
    captures with no check at all. The guard is add-time only.
 2. A bridged container cannot see its host's LAN address, which is exactly
    what a person types. localnet.py's docstring admits it and
    tests/test_localnet.py:114 ASSERTS the current behaviour
    (describe_if_local(host_lan_address) == ""). app.js's SELF_CAPTURE_WARNING
    tells the user this in prose because detection could not do it.

DECIDED WITH THE USER (AskUserQuestion, all three recommended options taken):
 - strictness: HARD BLOCK, no env override.
 - detection: shared-kernel boot_id probe over SSH *plus* a capture-start
   re-check. Containers share the host kernel, so an identical
   /proc/sys/kernel/random/boot_id proves the target IS this box regardless of
   network topology -- LAN IP, alias, VPN, macvlan all covered, which no
   address heuristic can do. World-readable (mode 444), no privilege needed.
 - existing rows: refuse on next use AND flag in the server list with the
   reason; do not delete anyone's configuration.

MUST VERIFY EMPIRICALLY, NOT ASSUME (this repo's standing practice): that a
container on this host actually reports the host's boot_id rather than a
virtualised one. Docker's default masked-paths list does not cover boot_id, but
gVisor/lxcfs-style runtimes virtualise /proc. If it were virtualised the probe
would silently never fire -- fail-open, so no false refusals, but no protection
either. Host boot_id read for the comparison:
70612579-dfd6-4521-a99b-5959f2ba5760. docker needs sudo in this session again,
so this goes to the user as a paste-able one-liner, as dev.34's smoke run did.

DESIGN NOTE, deliberate: the probe is a POSITIVE identification test. An
unreadable or absent boot_id (a BSD target, a masked /proc) proves nothing and
must not refuse -- absence of proof is not proof of locality, and failing closed
there would break every legitimate non-Linux target. The address checks still
apply underneath. This matches localnet.py's existing stance: "says what it
found rather than claiming more than it knows."

Track: RELEASE SEQUENCE 0.1.0-dev.35, chosen by the user via AskUserQuestion
(work commit was offered as the alternative). Same question swept in the
lint-workflows.yml trigger defect logged below, on the user's "yes, fix it
here".

IMPLEMENTATION DONE (uncommitted):
- localnet.py: BOOT_ID_PATH, _BOOT_ID_RE, BOOT_ID_MAX_CHARS, normalise_boot_id,
  own_boot_id (read each call, NOT cached -- a cached "" from an early call
  would disable the check for the process's life, silently and totally),
  describe_if_same_kernel, SelfCaptureRefused. Module docstring rewritten
  around the two layers.
- ssh_manager.py: BOOTID added to _PREREQ_SCRIPT + parsed through
  normalise_boot_id; read_boot_id(conn) helper; test_connection reports
  boot_id; run_tcpdump refuses BEFORE create_process on the very connection
  tcpdump would have used, and closes it.
- database.py: active_servers.self_target_reason + migration + setter; cleared
  on endpoint change via the same CASE pattern os_name uses.
- models.py: ServerInfo.self_target_reason (server-set; ServerAuth has no such
  field, so a client cannot clear it through the form -- tested).
- main.py: _refuse_self_target (one builder, because app.js keys off the code),
  _record_self_target, _reject_self_kernel; wired into prereq-check, test,
  both /api/probe routes, and START_CAPTURE, which had no check at all before.
  SelfCaptureRefused from the manager -> 400, recorded, not a 500.
- frontend: server-list flag (.server-warn-self, .self-target) + CSS; the Add
  form's standing warning no longer claims the LAN address cannot be detected.

🔢 VERSION    ✅ 0.1.0-dev.35 in all seven refs: backend/main.py:106,
                docker-compose.yml:107, README.md:231/332/348,
                docs/reverse-proxy.md:117/372. REPO_URL + release_notes_url
                (derived from APP_VERSION) present. v0.1.0-dev.34 confirmed on
                the remote -> 62cf182, so the previous release did ship.
🔨 BUILD      ✅ ./scripts/check.sh: 1477 passed, 0 failed, 0 skipped, 216s,
                exit 0. dev.34's baseline was 1424, so +53 are this change's
                (one more added after, during Gate 3: the recovery-path test).
                CONTAINER (user ran scratchpad/smoke35.sh under sudo; docker
                needs sudo in this session again, as in dev.34):
                 * THE CLAIM THE WHOLE DESIGN RESTS ON IS VERIFIED, NOT
                   ASSUMED: the app image run on this host reports boot id
                   70612579-dfd6-4521-a99b-5959f2ba5760 -- byte-identical to
                   the host's. Docker does not virtualise
                   /proc/sys/kernel/random/boot_id here, so the shared-kernel
                   check CAN fire. Had this come back NO MATCH the mechanism
                   would have needed replacing, not shipping.
                 * own_boot_id() in the image's own interpreter returns that
                   value; describe_if_same_kernel returns the finding for it
                   and '' for a made-up id.
                 * image builds; / and /js/app.js 200; /api/servers 401
                   unauthenticated; served app.js carries the new code
                   (self_target_reason x4, "same kernel" x1); 0 tracebacks.
                 * MIGRATION verified BOTH ways, after my first attempt proved
                   nothing: the script queried pcap.db, but main.py:200 names
                   it pcap-server.db, so sqlite created an empty file and the
                   PRAGMA returned [] with no error. Re-checked against the
                   container's REAL database: fresh DB carries
                   self_target_reason. Then wound a copy back to the dev.34
                   schema (DROP COLUMN) with a populated server row and opened
                   it with Database(): column added, existing row intact,
                   os_name preserved, new column defaults to '', setter works.
                 * /api/version 404 in the log is my script guessing a route
                   that does not exist -- not a defect.
🔒 SECURITY   ✅ 0 Critical, 0 High, 0 Medium. pip-audit: no known
                vulnerabilities. NO new third-party import (re, typing are
                stdlib; localnet is internal), so requirements and the
                Dockerfile are untouched -- no dependency drift.
                Diff grep for eval/exec/shell=True/os.system/subprocess/pickle/
                md5/sha1/verify=False/innerHTML/bare-except/assert-as-
                validation: 0 hits.
                Design points, deliberate:
                 - the remote boot id is UNTRUSTED INPUT: normalise_boot_id
                   (anchored UUID regex, bounded at 64 chars) before it is
                   compared, stored or logged. Flood, valid-id-plus-junk, and
                   valid-id-past-the-bound all normalise to ''. Tested.
                 - the stored reason for a KERNEL finding interpolates nothing
                   from the remote host -- describe_if_same_kernel returns a
                   constant. The ADDRESS reason does carry the hostname (the
                   user's own input), escHtml'd like every other value, with a
                   browser test asserting <img src=x id=pwn> renders as text.
                 - unknown never refuses, in BOTH directions: empty remote
                   value, and empty own value. Two empty strings must not
                   compare equal and refuse every target in existence; there
                   is a test named for that.
                 - _record_self_target cannot turn a refusal into a 500.
                 - ONE refusal builder, because app.js keys the blocking alert
                   off detail.code; a hand-phrased second refusal would be the
                   one that renders as a bare error.
                KNOWN LIMIT, stated not hidden: a target that LIES about its
                boot id defeats the kernel check. Not meaningful here -- the
                threat model is an operator pointing this at their own box by
                mistake, not an adversarial target -- and the address checks
                still sit underneath.
                FOUND AND FIXED DURING THIS GATE, not deferred: address-level
                findings at capture start were refused but NOT recorded, so
                the server list would not have explained them -- half of what
                the user asked for. start_capture now records before refusing.
                Also found: a flagged row could have been a dead end, so the
                recovery path was checked and is real (Test connection /
                Check prerequisites re-derive and clear) -- documented in
                architecture.md and pinned by a test.
                Quality: run_tcpdump's check sits inside the existing
                try/except so a refused connection is closed, not leaked
                (asserted). No nesting over 3 levels, no duplicated logic; the
                list flag reuses .server-warn rather than inventing a layout.
📄 DOCS       ✅ CHANGELOG dev.35 (Security/Fixed/Documentation). security.md,
                target-hosts.md, architecture.md rewritten around the two
                layers, with a table of where each check runs and the
                recovery path. README "Add the server" step says it must be a
                different machine. Stale-claim sweep for "cannot be
                detected"/"looks like any other target": the only hit is
                localnet.py's own docstring, correctly scoped to "no ADDRESS
                check" with the boot-id paragraph directly under it. app.js's
                standing warning no longer claims the LAN address is
                invisible, because it is not.
📦 RELEASE    ✅ branch synced before staging (git fetch; 0 ahead, 0 behind).
                PR ➖ N/A -- no PRs until 1.0, branch canonical (memory
                release-process; user 2026-09-15), as dev.27-34.
                Commit 2916f09, approved by the user ("commit and push") and
                executed by Claude at their explicit instruction rather than
                presented, as dev.34. 21 files, +1156/-70; staged list reviewed
                before commit (no keys, no .env, no capture data). Pushed;
                ls-remote -> 2916f09.
                Git identity was already set this time (the user's repo-scoped
                config from dev.34 survived), so no repeat of that failure.
                CI on the branch push: Check 34983013960 success (8m13s), Lint
                workflows 34983013974 success (8s). Both correct on a branch
                push -- lint fires because .github/workflows/** changed.
                Release notes drafted and shown; awaiting approval.
🚀 SHIP       ✅ SHIPPED 2026-09-15. Tag block handed to the user and run by
                them; never executed here (SKILL.md 5.8). Four post-ship
                checks, all verified:
                 * tag v0.1.0-dev.35 on the remote -> 2916f09, the same commit
                   branch Check passed on.
                 * Release run 34984099369 success (1m17s). GitHub release
                   v0.1.0-dev.35 (Dev), prerelease, published
                   2026-09-15T14:49:19Z. Approved notes applied with
                   gh release edit (2653 chars, replacing release.yml's auto
                   compare link).
                 * PR ➖ N/A -- no PRs before 1.0.
                 * Artifact is the image, not a release asset (0 assets is
                   correct here): ghcr :0.1.0-dev.35 and :dev share one real
                   digest sha256:fd6f20215301aac770252e2673116177523872c95b70
                   66636fcd0a9f57c0a41f. Cross-check: :0.1.0-dev.34 still
                   reads sha256:00738f77... exactly as this file recorded it
                   last session, so the digest lookup is sound.
                   NOTE for next time: `gh api /user/packages/...` returns 403
                   (token lacks read:packages). The digests above came from
                   the anonymous registry API instead -- get a pull token from
                   ghcr.io/token?scope=repository:<owner>/<repo>:pull, then
                   HEAD the manifest with an OCI/Docker Accept header and read
                   docker-content-digest. No extra scope needed.
                 * THE CI FIX IS PROVEN, and tag time was the only place it
                   could be: the v0.1.0-dev.35 tag push fired Release ONLY.
                   dev.34's tag push fired Release AND Lint workflows (run
                   34977747554 on ref v0.1.0-dev.34) -- both still visible in
                   gh run list, side by side.
                RELEASE SEQUENCE 0.1.0-dev.35 CLOSED AND SHIPPED.

## Uncommitted at close: this file's dev.35 ship record
Same as every prior release -- the ship record cannot be inside the commit it
describes. It gets swept into the next release's commit, as dev.34's was into
2916f09.

## Session opened 2026-09-15 (local CLI, Debian 13, zsh, dev-skills 2.18.0)
Re-derived from evidence (SKILL.md S2), not trusted from the prior entry below.

HEAD = 440f5f9, up to date with origin/claude/admiring-wright-k20ptf. 7 commits
sit on the branch past the v0.1.0-dev.33 tag (6121629..440f5f9, CI-trigger fix +
actionlint + dev-build docs/compose fixes) -- all CI plumbing/docs, no
APP_VERSION bump, no source-code behavior change. Check runs green on the two
most recent (34894226882, 34894777083).

v0.1.0-dev.33: tag on remote -> c3e43f6, GitHub release published (prerelease,
2026-09-14T17:01:10Z). APP_VERSION still reads 0.1.0-dev.33, matching its own
tag exactly -- no unshipped bump, no unfinished Gate 6. CLOSED AND SHIPPED,
confirmed again this session.

## 0.1.0-dev.34 — arrangeable packet-list columns (opened 2026-09-15)
Track: RELEASE SEQUENCE 0.1.0-dev.34, chosen by the user via AskUserQuestion
after being offered work-commit and review-first instead. Sweeps up the 7
CI/docs commits already sitting past the v0.1.0-dev.33 tag.

User's ask: "the view pane's column needs to be able to add and remove other
vakues as well as be moveable". Three scoping questions put to the user, all
answered with the recommended option: (1) curated presets PLUS any tshark
field validated against tshark's own registry; (2) stored per user and applied
to every capture, server-side, Wireshark-preference style -- not per saved
view, not localStorage; (3) inline (drag headings, right-click, Apply as
Column) PLUS a preferences dialog.

Model: Opus 5, above the Sonnet ceiling. The user set it deliberately with
/model immediately before the request; flagged in the first reply and treated
as approval for this task, consistent with the dev.31/32/33 approvals below.

Implementation DONE (uncommitted):
- models.py: BUILTIN_PACKET_COLUMNS, DEFAULT_PACKET_COLUMNS,
  CUSTOM_COLUMN_PREFIX, MAX_PACKET_COLUMNS, PACKET_FIELD_RE, PacketColumn
  (model_validator ties a custom column's id to its own field so the same
  field cannot become two columns), ColumnLayout. PacketSummary.values.
- packet_parser.py: get_packet_list(extra_fields=...) appends one -e per added
  column AFTER the MAC fields and reads their values from the END of the row
  (the Info column is free text mid-row; a tab in one shifts every forward
  position -- the built-ins still read forward, unchanged).
  validate_column_fields (pattern + cap + dedupe), unknown_packet_fields +
  _lookup_in_registry (streamed `tshark -G fields`, early break, kill rather
  than drain, positives-only memo bounded at 2000).
- database.py: column_layouts table (user_id PRIMARY KEY, columns JSON),
  get/set/clear. No row = default, deliberately, so a later change to the
  default reaches everyone who never customised.
- main.py: GET/PUT/DELETE /api/column-layout + /api/column-layout/default;
  packets route gains `columns`, re-validated per request.
- frontend: thead built by renderColumnHeaders from the layout; packetCellHtml
  per column id; drag/right-click headings; Columns dialog; Apply as Column on
  the detail menu; optimistic apply with rollback when the server refuses.

SECURITY notes made during the build, before any gate ran: a field name lands
in tshark's argv as `-e <name>`, so PACKET_FIELD_RE refuses anything that
could read as a flag (`-r` being the one that matters), applied at the model,
at the save route AND on every packet list -- the list's query string is the
caller's, not necessarily the saved layout's. Added-column values are escHtml'd
like every other capture-derived value.

BUG FOUND AND FIXED during self-review, pre-gate: an explicitly added MAC
column rendered empty, because the server keys the MAC fields off the -e view
flag and the chip was not lit. packetColumns now sends -e when the layout
needs it, without lighting the chip.

🚫 BLOCKED ON THE HOST, NOT ON THE CODE: this Debian 13 box has no
python3.13-venv (so scripts/check.sh cannot even build .venv), no tshark, no
tcpdump, no capinfos. Every prior entry below was written on a Fedora box that
had them. Install asked of the user:
  sudo DEBIAN_FRONTEND=noninteractive apt install -y python3.13-venv tshark tcpdump
Until then Gate 2 cannot run and the tshark-dependent tests report SKIPPED.

FINDING FOR THE USER, not changed unilaterally: docker-compose.yml at HEAD has
a DUPLICATE top-level `secrets:` key (commit 789dae9) -- the first names
/opt/docker/pcapserver/secrets/master.key, the second ./secrets/master.key.
Last key wins in a permissive parser, so the absolute path is silently
discarded; a strict one errors outright. The same commit hardcodes one
machine's /opt/docker/pcapserver paths into the file the README tells everyone
to curl at the tag, while the Quick start still says every relative path
resolves against the install directory. Raised, awaiting the user's decision.

🔢 VERSION    ✅ 0.1.0-dev.34 in all seven refs: backend/main.py:99,
                docker-compose.yml:100, README.md:230/331/347,
                docs/reverse-proxy.md:117/372. Historical mentions in
                architecture.md:108 and database.py:248 left as history, as
                dev.33 did. REPO_URL + release_notes_url (derived from
                APP_VERSION) present. v0.1.0-dev.33 confirmed on the remote
                (ls-remote -> c3e43f6), so the previous release did ship.
🔨 BUILD      ✅ ./scripts/check.sh: 1424 passed, 0 failed, 0 skipped, exit 0,
                211s. First run on this box with nothing skipped -- tshark
                4.4.18, tcpdump, capinfos and playwright's chromium all
                present (dev.33's baseline was 1371; +53 are this feature's).
                New suites all green: test_columns_ui 9, test_column_layout
                21, test_packet_parser 44. Browser suites drive the real app
                via backend.serve, so the golden path is exercised.
                CONTAINER: docker needs sudo in this session (the user added
                the group but it cannot reach an already-running shell), so
                the build+smoke ran as a one-line script the user pasted,
                writing to scratchpad/smoke.log for me to read. Results:
                image localhost/pcap-server:0.1.0-dev.34 builds; / and
                /js/app.js serve 200 with the new column code in the served
                bundle (8 matches); GET /api/column-layout and
                /api/column-layout/default 401 unauthenticated, PUT 403 --
                the plain-HTTP write refusal, so the write route is behind
                that policy too, not just auth; tshark in the image is
                4.4.18, the same build as the host; `tshark -G fields` knows
                tcp.srcport and does not know a made-up name; and
                unknown_packet_fields, run in the image's own interpreter,
                returns exactly ['definitely.not.a.real.field'] -- the save
                path proven in the container, which is the one thing the host
                could not answer for it. 0 tracebacks.
                FIRST SMOKE RUN FAILED, and the fault was the harness, not
                the app: the script let Docker create the bind-mount sources
                (root-owned, so appuser could not open the database) and did
                not set DATA_DIR/CAPTURES_DIR/SSH_KEYS_DIR, which is exactly
                what entrypoint.sh keys its chown off -- compose always sets
                them. Fixed in the script. Noted, NOT changed, as
                pre-existing and out of scope: entrypoint.sh silently does
                nothing when those three are unset and its `chown ... || true`
                swallows failures, so a hand-rolled docker run fails with
                "unable to open database file" and nothing pointing at
                ownership.
                NOTE FOR NEXT TIME: two runs were wasted by changing the tree
                under a running suite -- installing chromium mid-run (browser
                fixtures raced it, E not s) and editing app.js mid-run. A
                third died because `pkill -f pytest` matched its own shell.
                Start the suite, then leave the tree alone.
🔒 SECURITY   ✅ 0 Critical, 0 High, 0 Medium. pip-audit: no known
                vulnerabilities. No new third-party import (model_validator is
                pydantic, already a dependency), so requirements and the
                Dockerfile are untouched -- no dependency drift.
                Diff grep for eval/exec/shell=True/os.system/pickle/md5/sha1/
                bare-except/assert-as-validation/verify=False: the only hits
                are asserts inside tests (correct usage) and one
                create_subprocess_exec, which takes an argv list and no shell.
                Design point, not an afterthought: a column's field name lands
                in tshark's argv as `-e <name>`, so PACKET_FIELD_RE refuses
                anything that could read as a flag (`-r` being the one that
                matters) at the model, at the save route, AND on every packet
                list -- the list's query string is the caller's, not
                necessarily the saved layout's. test_main.py proves the
                capture is never even looked up first.
                FIXED DURING THIS GATE'S REVIEW, not deferred:
                 - prototype lookup: `values[field]` for a field named
                   __proto__ returned Object.prototype. Now
                   hasOwnProperty-guarded. The server refuses such a name, but
                   the table draws optimistically before that answer lands.
                 - the registry memo was unbounded -> capped at 2000, and only
                   positives are cached, so a name that was wrong once is
                   re-asked rather than pinned wrong past an image rebuild.
                 - `tshark -G fields` subprocess is killed rather than left
                   with a full pipe when the scan breaks early on a match
                   (the same finding this repo already had at dev.31).
                Quality: renderColumnDialogRows was ~55 lines building a row
                inline -> split into columnDialogRow(col, index, count). One
                renderer draws headings and cells together, so the two cannot
                drift. Added columns share one CSS width class rather than
                inventing a width per field.
📄 DOCS       ✅ CHANGELOG dev.34 (Added/Changed/Documentation), covering this
                feature AND the 7 CI/compose commits it sweeps up. README:
                "Choosing the columns", Apply as Column in the two-filters
                section. architecture.md: "The column layout" (storage, the
                no-row-means-default decision, why added fields go last in
                argv and are read from the end of the row, the argv boundary,
                the registry check) + the MAC-column paragraph updated for
                layouts.
                COMPOSE FIX, on the user's "keep mine": the duplicate
                top-level `secrets:` key introduced by 789dae9 is gone and the
                absolute /opt/docker/pcapserver paths are the shipped default.
                Three docs still named the old /opt/docker/pcap install dir
                (README Quick start + Upgrading, operating.md x2) and now
                match; the compose file says outright that its paths are
                absolute rather than relative to wherever it sits.
📦 RELEASE    ⏳ branch synced with origin (0 ahead, 0 behind at fetch).
                PR ➖ N/A -- user, 2026-09-15: "we're not doing any PRs until
                1.0", the branch is canonical, as dev.27-33. Saved to memory
                as release-process so it is not raised again.
                Commit 62cf182, approved by the user ("commit and push") and
                executed by Claude at their explicit instruction rather than
                presented; pushed. ls-remote -> 62cf182. 18 files, +1643/-65,
                staged list reviewed before commit (no keys, no .env, no
                capture data).
                Git identity was UNSET on this box -- the commit failed with
                "Author identity unknown". Not fixed unilaterally (SKILL.md:
                never update git config): the user ran a repo-scoped
                config command matching the six prior commits' author,
                darthrater78 <94141126+darthrater78@users.noreply.github.com>.
                Release notes drafted, shown, approved by the user ("goood").
🚀 SHIP       ✅ SHIPPED 2026-09-15. Tag block handed to the user and run by
                them; never executed here (SKILL.md 5.8). Four post-ship
                checks, all verified:
                 * tag v0.1.0-dev.34 on the remote -> 62cf182, the same
                   commit branch Check passed on.
                 * Release run #34 success. GitHub release v0.1.0-dev.34
                   (Dev), prerelease, published 2026-09-15T13:52:22Z.
                   Approved notes applied with gh release edit (1877 chars,
                   replacing release.yml's auto compare link).
                 * PR ➖ N/A -- no PRs before 1.0, see above.
                 * Artifact is the image, not a release asset (0 assets is
                   correct here): ghcr :0.1.0-dev.34 and :dev share one real
                   digest sha256:00738f77dc8e088dd1328dc6069e70fd7d5969b0eb
                   3d15da86a36b134b023ea2 -- a real header digest, not
                   e3b0c442.
                Check did NOT run on the tag push: only Lint workflows and
                Release did, so 6121629 works as designed.
                RELEASE SEQUENCE 0.1.0-dev.34 CLOSED AND SHIPPED.

## Known defect, found at ship time, NOT fixed in dev.34 -- for dev.35
lint-workflows.yml (added by 61e63fd, this release) has a bare `on: push:`
with only a `paths:` filter and NO `branches:` filter, so it fires on TAG
pushes too -- the exact bug 6121629 fixed for check.yml in this same release.
The user spotted it on the dev.34 tag push ("still dual workflows. are they
doing the same thing"): Release and Lint workflows both ran.

Harmless in effect -- actionlint, ~11s, reads the repo and publishes nothing
-- but it is the same class of bug, and the dev.34 changelog line about CI no
longer running twice on a release is narrower than it reads.

Deliberately NOT fixed mid-release: the tag was already pushed and Release #34
in flight, so a fix could not have been in the tag anyway. Fix in dev.35:
    on:
      push:
        branches: ['**']
        paths: ['.github/workflows/**']
Same reasoning as check.yml's comment. Check pull_request: needs no change.

## Session opened 2026-09-14 (local CLI, Debian 13, zsh, dev-skills 2.18.0)
Skill was NOT installed at session start -- no SKILL.md anywhere on this box,
only this state file survived. User supplied the v2.18.0 bundle as a GitHub
release asset; installed to ~/.claude/skills/dev-skills/ (6 md files,
documentation only, no scripts/executables in the archive). It is not in this
session's registered skill list -- skills register at session start -- so it was
loaded by reading SKILL.md + GATE_REFERENCE.md directly. A restart picks it up
as a real skill.

ENVIRONMENT CHANGED from every prior entry below: those all say Fedora 44 +
bash; this machine is Debian 13 + zsh. Treat older shell/path notes as stale.

STATE RE-DERIVED from evidence (SKILL.md S2), not trusted from this file.
What this file claimed vs what is actually true:
 - claimed actionlint "NOT committed yet -- presented, awaiting approval";
   it is in fact commit 61e63fd.
 - claimed dev.33 was "two commits, neither pushed/tagged"; v0.1.0-dev.33 IS
   on the remote at c3e43f6 and is an ancestor of origin's head.
   dev.33 CLOSED AND SHIPPED.
 - git ls-remote --tags: all versions tagged through v0.1.0-dev.33.
   No unfinished Gate 6.

Branch at open: local ec2acb7, origin 440f5f9 -- 0 ahead, 3 behind. Incoming
commits are the user's own from another machine (789dae9 volume paths/secrets,
2db7df8 README compose instructions, 440f5f9 compose filename); they touch only
README.md and docker-compose.yml. Clean fast-forward; sync block presented, not
executed (local session, SKILL.md S5.8).

7 commits now sit past the v0.1.0-dev.33 tag while APP_VERSION is still
0.1.0-dev.33. Not a gate violation -- unreleased work -- but Gate 1 hard-blocks
until it is bumped, so the next release is dev.34.

Model: Opus 5, above the Sonnet ceiling. User approved staying on it for THIS
task (2026-09-14), consistent with the dev.31/dev.32 approvals below.

Notes: hooks/gate-preflight.sh is NOT installed here (.claude/hooks carries only
session-start.sh), so the prose pre-flight is the only enforcement. This file is
tracked in git rather than gitignored, contrary to SKILL.md's local-session
default -- left as the repo has always had it, not changed unilaterally.

No files modified yet this session. All six gates pending.

🔢 VERSION    ⬜
🔨 BUILD      ⬜
🔒 SECURITY   ⬜
📄 DOCS       ⬜
📦 RELEASE    ⬜
🚀 SHIP       ⬜

## CI: actionlint added, workflow-file pushes skip the full suite (2026-09-14)
Chain: user kept pressing on "why the full suite for a workflow YAML edit"
across several turns, ending in "what is the standard" (answer: actionlint,
a purpose-built static linter for Actions workflows) then "yes" to adding it.

NOT committed yet -- presented, awaiting approval.

New file .github/workflows/lint-workflows.yml: downloads actionlint v1.7.12
from its GitHub release, SHA256-checksum verified against the value in the
release's own *_checksums.txt (fetched and compared directly, not trusted
from memory -- `gh api repos/rhysd/actionlint/releases/tags/v1.7.12` for the
asset list, `curl` the checksums file, `sha256sum -c` against the real
download). Ran the resulting binary against this repo's actual check.yml and
release.yml before writing anything: 0 findings, confirming both that the
tool works and that the existing files are already clean. Triggered only on
`.github/workflows/**` -- NOT the same download-and-pipe-to-tar script
actionlint's own README advertises for CI use, which does no checksum
verification at all; downloading+verifying directly matches this repo's own
fetch_lego.py pattern instead.

check.yml: `.github/workflows/**` moved from "deliberately excluded" (my own
prior reasoning, this same file, a few commits back) into paths-ignore, now
that lint-workflows.yml gives it real coverage. Flagged explicitly to the
user, not silently assumed equivalent: actionlint is static analysis, not
execution -- it would NOT catch a typo'd script path in the "Run tests" step,
only YAML/expression-level mistakes. User has not yet responded to that
caveat or to the dependabot gap also raised (github-actions ecosystem not
watched at all, dependabot.yml only has `docker`) -- offered, not added.

Track: work commit (no APP_VERSION bump). Required: SECURITY + approval.

🔒 SECURITY  ✅ actionlint fetched over HTTPS from GitHub's own release CDN,
               checksum-verified before extraction, exact version pinned
               (manually bumped, matching LEGO_VERSION's existing pattern in
               this repo -- not a new maintenance burden shape). New job
               declares `permissions: contents: read` explicitly (checkout
               only, nothing written) -- least privilege, and check.yml/
               release.yml were checked for what they currently declare
               before choosing this rather than copying either blindly.
📦 approval  ⬜ diff shown, not yet approved

## CI: check.yml no longer fires on a tag push (2026-09-14)
REVERSES a standing decision recorded further down this file under
"0.1.0-dev.25": "DECLINED by the user 2026-09-13, do not raise again:
...narrowing check.yml's triggers." That entry is left as-is below (historical
record of what was true then); this note is the current state. User asked
directly this session ("lets not duplicate the work in the process and fix
it") after I explained the tag push fires Check a second time (the branch
push already ran it) AND fires Release, which runs no tests at all and is not
gated on Check passing -- that second, larger finding (Release publishes to
ghcr regardless of Check's result) was NOT asked to be fixed and was not
touched; only the duplicate-Check-run trigger was.

Fix: .github/workflows/check.yml `on: push:` (bare, matched every ref
including tags) -> `on: push: branches: ['**']`. Tags carry no ref under
refs/heads, so this excludes them without needing to duplicate release.yml's
own `v*` pattern. pull_request: trigger untouched. YAML validated
(python3 -c "import yaml; yaml.safe_load(...)"). No test in the suite
references this file's contents, so nothing else to update.

Track: work commit (no APP_VERSION bump, no artifact, not part of the dev.33
feature set -- CI plumbing, not app CHANGELOG material, so not added there).
Required gates: SECURITY (below) + commit approval, not the full six.

🔒 SECURITY  ✅ one-line trigger-filter change to an existing, already-trusted
               workflow file. No new action, no new permission, no new
               secret, no change to what the job does once it runs -- only
               to which pushes cause it to run at all.
📦 approval  ✅ commit 6121629, approved by user ("yes"), executed by
               Claude, NOT pushed (not asked). Applies to the NEXT tag
               push, not v0.1.0-dev.33 (already tagged/shipped under the
               old trigger -- confirmed via gh: Check #92 branch push,
               Check #93 + Release #33 both on the tag push, all success).

## 0.1.0-dev.33, second commit — the recommended parity adds (2026-09-14)
User (after the first dev.33 commit, ebe5ac4): "lets commit only and do the
reccomended adds" -- the first half approved and executed already; this is a
SEPARATE, not-yet-approved batch, same open version (never tagged), so it
amends the same CHANGELOG entry rather than opening dev.34.

Scope: the four Wireshark-parity items recommended earlier and accepted --
Follow TCP/UDP Stream, Protocol Hierarchy, Conversations/Endpoints, Copy as
filter -- plus Export packet bytes (already built and committed in the first
dev.33 commit, listed here only because its CHANGELOG bullet was written in
this batch). Declined earlier and NOT built: colorization rules, Decode As,
IO Graph, full Statistics suite.

Implementation DONE (uncommitted):
- backend/packet_parser.py: get_protocol_hierarchy, get_conversations,
  get_follow_stream -- all built from one `-T fields` tshark pass aggregated
  in Python, NOT by parsing tshark's `-z io,phs`/`-z conv,ip` text reports
  (terminal-formatted, not fixed-width, wrong thing to screen-scrape).
  Follow Stream uses `follow,<proto>,raw,<index>` specifically -- verified
  empirically against a real capture that `,hex` merges consecutive
  same-direction frames' byte offsets (cannot split back apart) while `,raw`
  keeps them as separate lines; `,ascii` was ruled out for lossiness
  (non-printable bytes become `.`, wrong for something meant to be
  byte-exact). A nonexistent stream index doesn't error in tshark (exit 0,
  "Node 0: :0") -- verified, and is what the ValueError check is keyed on.
- get_packet_list gains tcp.stream/udp.stream columns (2 more -e fields,
  column indices shifted +2 -- full existing test suite re-run after the
  shift, all still passed with no index-specific test changes needed) so a
  packet ROW's own right-click can offer Follow Stream without first opening
  the detail pane -- matches Wireshark's actual workflow. get_packet_detail
  gains the same two fields from its PDML tree via a new _find_field_anywhere
  helper (tcp.stream lives under the "tcp" layer, not "frame").
- models.py: ProtocolHierarchyNode, Conversation, ConversationEndpoint,
  FollowStreamSegment, FollowStreamResult; PacketSummary + PacketDetail gain
  tcp_stream/udp_stream: int | None.
- main.py: three new routes (protocol-hierarchy, conversations,
  stream/{protocol}/{stream}), same auth/ownership/rate-limit pattern as the
  existing packet routes (_require_readable_capture, packet_rate_limiter).
  protocol path param validated against {tcp,udp} before anything else runs.
- frontend: three new <dialog>s (Protocol Hierarchy tree, Conversations two
  tables with per-row Filter buttons, Follow Stream with per-direction
  colouring + Set as display filter), two new toolbar buttons, Follow Stream
  wired into BOTH the packet-row context menu (via new data-tcp-stream/
  data-udp-stream on <tr>) and the detail-pane context menu (via
  currentDetail.tcp_stream/udp_stream) through a shared pushFollowStreamItems
  helper. Copy as filter added to filterMenuItems (the one menu-builder every
  right-click path already shares). Export packet bytes: client-side Blob
  from the hex the detail pane already holds, no new request.
SECURITY fix applied during this pass, before it ever reached a commit:
  get_follow_stream's `assert protocol in ("tcp","udp")` replaced with an
  explicit `if not in: raise ValueError` -- asserts strip under `python -O`,
  and the value was being f-string-interpolated straight into a `-z` tshark
  argument; the route already validates first, but the function itself had
  no defense if ever called from anywhere else. Re-ran the full diff grep
  for eval/exec/shell=True/os.system/innerHTML=/pickle/md5/sha1/bare-except/
  assert-as-validation after the fix: 0 further hits.
  XSS check done deliberately: reconstructed Follow Stream text is
  attacker-influenced (raw captured bytes) and is rendered via escHtml
  before insertion, same as every other interpolated value in these three
  dialogs (protocol names, addresses, error messages) -- checked one by one,
  not assumed.
Tests: packet_parser tests build a real 8-frame pcap (TCP handshake + HTTP
  exchange + unrelated UDP packet) via tests/packet_builders.py and run
  against REAL tshark -- hierarchy nesting incl. full-frame-bytes-at-every-
  layer semantics, conversation direction split, endpoint totals, follow
  reassembly byte-for-byte both directions, nonexistent-stream ValueError,
  tcp_stream/udp_stream on both PacketDetail and PacketSummary. test_main.py:
  429-before-tshark gate + bad-protocol-400 for all three routes. Browser:
  7 new tests (test_stats_dialogs_ui.py) with window.api stubbed per-path
  (the established pattern in this suite for API-backed dialogs -- no real
  capture pipeline available to browser tests here) -- tree rendering incl.
  percentage-against-root, pairs+endpoints rendering, Filter button applies
  the right expression and closes, stream colouring by direction, Set-as-
  filter uses the right field/index, server error surfaces verbatim, AND the
  row-context-menu trigger end to end (right-click -> menu item -> dialog
  opens). Plus test_packet_export_ui.py (3, from the first dev.33 commit)
  using page.expect_download to verify actual byte-exact file output, not
  just that a click ran.
  FULL SUITE, final run after this batch: 1371 passed, 0 failed, 0
  unexpectedly skipped, run twice clean.

🔢 VERSION    ➖ N/A for this commit -- still 0.1.0-dev.33, unshipped; no
                further ref bump needed
🔨 BUILD      ✅ podman build localhost/pcap-server:0.1.0-dev.33 ok (rebuilt
                after this batch). Rootless smoke test (ALLOW_UNENCRYPTED_
                CAPTURES=true, SELinux :Z + 0777 tmp mounts): 0 tracebacks,
                / and /js/app.js serve 200, served app.js contains the new
                dialog/menu code (grep count 10 across protocol-hierarchy/
                Follow TCP Stream/exportPacketBytes/Copy as filter), fresh-
                DB migration still drops live_stream cleanly. All three new
                routes verified 401 unauthenticated (auth gate wired, not
                skipped) with 0 server-side tracebacks in the log.
🔒 SECURITY   ✅ 0 Critical/High/Medium. One real finding (assert-as-argv-
                validation in get_follow_stream) found and fixed during this
                same pass, described above -- not deferred.
📄 DOCS       ✅ CHANGELOG dev.33 entry extended (Added: Follow Stream,
                Protocol Hierarchy, Conversations/Endpoints, Copy as filter,
                Export packet bytes; Documentation bullet added). README
                gains Export bytes note, "Follow a stream" and "Protocol
                Hierarchy and Conversations" sections, Copy-as-filter
                mentioned in "The two filters". architecture.md gains a full
                "Statistics: Protocol Hierarchy, Conversations, Follow
                Stream" section covering the three empirically-verified
                format choices (raw over hex/ascii for Follow Stream, Python
                aggregation over `-z` text parsing) and the tcp_stream/
                udp_stream plumbing.
📦 RELEASE    ⏳ commit c3e43f6, approved by user ("yes") after the diff and
                message were shown; executed by Claude, NOT pushed (not
                asked). PR ➖ N/A (branch canonical, as prior releases).
🚀 SHIP       ⬜ two commits on the branch (ebe5ac4, c3e43f6), neither
                pushed/tagged; 0.1.0-dev.33 still unshipped

## 0.1.0-dev.33, first commit — live streaming removed (2026-09-14)
Committed locally as ebe5ac4 (NOT pushed -- user asked to commit, not push).
See the detailed record below this line for what that commit covered.

## 0.1.0-dev.33 — opened 2026-09-14 (local CLI, Fedora 44, bash, dev-skills 2.18.0)
Track: release sequence 0.1.0-dev.33. Branch = origin cd2bda5 (tag v0.1.0-dev.32,
confirmed on remote). New session picked up capture-size-handoff.md.

Diagnosis (no code changes): user gave two same-interface (ens18) captures,
2000 packets each, 943KB vs 16.6MB. Pasted packet list from the 16.6MB one
showed repeated TCP payloads at len=32804/57920/48800 on one SSH flow --
impossible as real Ethernet frames. Root cause: TSO/GSO segmentation offload
on the target NIC (virtio-net/Proxmox), independent of live vs non-live --
tcpdump captures the kernel's pre-segmentation superframe. Not a pcap-server
bug; data content is correct, per-packet framing/size/timing is not.

User: "does this affect the actual readability/truth of the actual data" ->
answered: payload content is complete and correct, packet-level structure
(counts, sizes, timing, checksums on the coalesced frame) is not representative
of the wire.

User's scope (2026-09-14), all four accepted:
 1. "remove the feature entirely and explain in the release notes why" ->
    AskUserQuestion confirmed: LIVE STREAMING (the whole watch-as-it-records
    capability), not the GSO issue itself (which isn't a pcap-server feature).
 2. Filter in Viewer by interface when `any` is used.
 3. Every section right-clickable as a filter, Wireshark-style, in the frame
    viewer.
 4. Review tshark/wireshark for other reasonable parity gaps.

Research (general-purpose subagent, Sonnet, read-only) found #3 ALREADY FULLY
IMPLEMENTED: onDetailContextMenu/buildFieldFilter/filterMenuItems (Apply/Not/
And/Or/Prepare/Copy) on the packet-detail tree, plus row-level Conversation
filter -- confirmed by direct code read, not just the subagent's word. No work
needed there; user was not told anything was missing, was told it already
exists. Same research flagged #2 as the one real, cheap gap (col-iface has no
context-menu case though the cell's own tooltip already promises the filter),
and produced a prioritized Wireshark-parity list (D) for #4, NOT YET PRESENTED
to the user or scoped into this release -- to report next turn: Follow Stream
(highest value), interface right-click (built this session, see below),
Protocol Hierarchy, Conversations/Endpoints table, Copy as Filter, Export
Packet Bytes; explicitly recommended skipping colorization rules/Decode As/
IO Graph/full Statistics suite as disproportionate for this tool.

Implementation DONE (uncommitted):
- Live streaming removed: backend/livestream.py deleted; capture.py (_LiveCount
  progress-reporting infra KEPT -- unrelated, general to all captures, NOT
  live-stream-specific despite the name); ssh_manager.py RemoteCapture.read_at
  + _sftp slot removed; database.py live_stream column DROPPED via migration
  (SQLite supports DROP COLUMN >= 3.35; host 3.51.2, container Debian 13 --
  both qualify) + orphaned settings rows (max_live_streams, live_stream_buffer_mb,
  rate_limit_live_polls_per_min) deleted from the settings table on every
  startup (get_all_settings merges raw DB rows over DEFAULTS with no filter,
  so a customized value would otherwise persist as an unlabelled key forever);
  main.py routes/imports/rate limiter removed; models.py CaptureRequest/
  CaptureInfo.live_stream fields removed; frontend (app.js ~250 lines across
  the form, capture list, tabs, viewer, and the whole live-view polling
  module; index.html; style.css, keeping @keyframes live-pulse which
  .status-running::before still uses) fully swept, verified by exhaustive
  grep to zero remaining references.
  CAUGHT BY RUNNING TESTS, NOT BY GREP: backend/sanitizer.py imported pcap
  format constants (GLOBAL_HEADER_LEN, RECORD_HEADER_LEN, MAX_RECORD_BYTES,
  magic-byte tables) FROM livestream.py -- these are generic pcap-record-
  walking constants that happened to live there, unrelated to the live-stream
  feature itself. Moved into sanitizer.py (now sole consumer, before its
  first use at module scope -- NameError on load order was itself an early
  catch). BytesSource (PcapSource over an in-memory buffer) is genuinely
  reusable test/production infra, not live-stream-specific -- moved to
  pcapsource.py; tests/test_sanitizer.py import fixed.
- Interface filter (#2): packetRowHtml's .col-iface td gains data-ifindex/
  data-iface-name; onPacketRowContextMenu gains a col-iface branch producing
  buildFieldFilter("sll.ifindex", ifindex) through the SAME filterMenuItems
  Apply/Not/And/Or/Prepare/Copy menu every other column uses -- no new
  filter-building code. Tests added in test_interface_os_ui.py (right-click
  offers the filter; Apply sets #display-filter; no ifindex -> no ifindex
  item, though the row's own Conversation filter still offers -- test
  corrected once to reflect that pre-existing, unrelated behavior).
Tests: deleted tests/test_livestream.py, tests/browser/test_live_stream_ui.py
  (whole feature gone); trimmed the live-streaming sections out of
  test_main.py, test_capture.py (965-1371, including the "display filter over
  a running capture" tests, which exercised live_poll and are gone with it),
  test_ssh_manager.py (read_at/sftp_capture fixture); scrubbed live_stream
  fixture fields from test_capture_filter_record.py (schema fixture kept --
  it's testing bpf_filter's ADD COLUMN migration on an intentionally-legacy
  schema, live_stream there is historically accurate and my DROP COLUMN
  migration handles it fine, verified), test_interface_os_ui.py,
  test_sanitize_ui.py, test_capture_ui.py.
  FULL SUITE GREEN: 1346 passed (1207 API + 139 browser), 0 failed, 0 skipped
  reported as unexpected. Run twice, clean both times.
Docs: docs/live-streaming.md deleted. README (TOC, screenshot caption, three
  feature-description paragraphs, the whole "Streaming a capture live"
  section, the tab-dot claim now false, the Interface-column paragraph
  updated to describe right-click instead of hover-only), docs/filters.md,
  docs/operating.md (settings table), docs/security.md ("what this does not
  protect"), docs/architecture.md (module table, the whole "Streaming a
  capture live" section replaced with a "Removed" note explaining the dev.33
  decision and the real GRO/TSO cause, runtime settings table, Known limits
  gains a GRO/TSO-inflated-capture entry replacing the live-stream entries).
  CHANGELOG.md dev.33 entry written (Removed/Added/Documentation).
Version: 0.1.0-dev.33 in all seven refs (verified by grep after sed):
  backend/main.py, docker-compose.yml, README.md (x3), docs/reverse-proxy.md
  (x2). v0.1.0-dev.32 confirmed on remote (ls-remote).

Not yet done: formal Gate 3 security review (a self-review during
implementation found nothing -- no new routes, no new deps, the one new
filter-string path reuses existing buildFieldFilter/escHtml hardening, the
DB migration is a static DROP COLUMN + static-key DELETE with no
interpolation -- but this is not a substitute for running the gate itself).
Podman image not yet built (Gate 2 needs this, not just local pytest).
Commit approval not requested. Parity list (D) not yet put to the user.

🔢 VERSION    ✅ see above
🔨 BUILD      ✅ pytest 1346 passed. podman build localhost/pcap-server:
                0.1.0-dev.33 ok. Rootless smoke test (ALLOW_UNENCRYPTED_
                CAPTURES=true, SELinux :Z mounts): server starts, 0
                tracebacks, / and /js/app.js serve 200, app.js contains the
                new sll.ifindex filter code, 0 remaining live-stream markup
                in served HTML/JS. Fresh-DB migration verified directly:
                captures table has no live_stream column, settings table
                carries none of the three removed keys.
🔒 SECURITY   ✅ 0 Critical/High/Medium. Read full SECURITY_REFERENCE.md this
                session. Diff is overwhelmingly deletions; the one new
                client-built filter string (sll.ifindex) reuses the existing
                buildFieldFilter/FILTER_UNSAFE escaping, same as every other
                column's filter -- no new pattern. DB migration is a static
                DROP COLUMN + static-key-list DELETE, no interpolation. No
                new dependencies, no new routes, no new logging of anything
                sensitive. Grep across the diff for eval/exec/shell=True/
                os.system/innerHTML=/pickle/md5/sha1/bare-except: 0 hits
                outside test assertions.
📄 DOCS       ✅ see above (CHANGELOG + all affected docs)
📦 RELEASE    ⏳ commit about to be requested
🚀 SHIP       ⬜

## 0.1.0-dev.32 — opened 2026-09-14 (local CLI, Fedora 44, bash, dev-skills 2.18.0)
Track: release sequence 0.1.0-dev.32. Branch = origin 1478ff5 (tag v0.1.0-dev.31).
2026-09-14: user pushed README gallery 83d7783 + bc07bbc; 83d7783 carried sensitive
images. User: "I dont want the images from 83d7783 in the history". Rebuilt locally
as ONE commit 5e93b75 (tree == bc07bbc, parent 1478ff5, user as author); dev.32 work
reapplied uncommitted on top. Force push (with lease on bc07bbc) handed to the user.
User force-pushed 2026-09-14: ls-remote = 5e93b75; 83d7783 not in remote branch history.
Model: Opus 5 — user approved staying on it for dev.32 only.
Scope (user 2026-09-14):
 1. Prereq check offers file capabilities on sudo hosts (sudo-ok row gets an
    optional drop-sudo fix; caps set + sudo ticked -> suggest unticking; sudo
    hint in the server form mentions caps; upgrades drop caps note).
    User choice: GROUP-RESTRICTED setcap (pcap group, chgrp, chmod 750, setcap).
 2. OS distro (PRETTY_NAME) persisted on prereq check (os_name column, cleared
    on host edit), shown in details facts AND sidebar (user choice).
 4. ADDED (user 2026-09-14): interface names for "any" captures -- record host
    ifindex->name table at capture start, Interface column in the Viewer.
 3. Question answered, no change: interface picker = live SSH ls /sys/class/net
    on every loadInterfaces (page load, server dropdown change, loadServers,
    Capture from this server); no cache.

Implementation DONE (uncommitted): ssh_manager (probe NOEXEC/TDMODE, privilege
order sudo-first when ticked, info rows, _setcap_remedy group-limited,
interface_indexes + parse_interface_indexes), capture.py _record_interface_names
(start task + end in _collect), captures.interface_names + active_servers.os_name
migrations, prereq route persists OS (complete probes only), packet_parser
sll.ifindex/pkttype, PacketSummary interface/ifindex/direction, UI: OS in sidebar
+ facts, info status, Interface column, sudo hint, .prereq-row>div min-width fix.
Tests: test_ssh_manager (+caps/ifindex, real sh probe), test_packet_parser (SLL2),
test_servers (os), test_capture (names), browser/test_interface_os_ui.
Screenshots dark/light 1440/400 checked.
Docs + CHANGELOG dev.32 written.

🔢 VERSION    ✅ 0.1.0-dev.32 in all seven refs: backend/main.py:93,
                docker-compose.yml:96, README.md:206/307/323,
                docs/reverse-proxy.md:117/372. v0.1.0-dev.31 on remote -> 1478ff5.
                REPO_URL + release_notes_url present.
🔨 BUILD      ✅ pre-Gate-3-fix run: check.sh 1427 passed exit 0; podman build ok;
                in-image (Debian 13, dash, tcpdump 4.99.5, --cap-add NET_ADMIN,NET_RAW):
                printed remedy applied as root -> alice (pcap group) captures on any
                with no sudo, LINUX_SLL2 confirmed; bob gets NOEXEC fix; packets map
                to lo/in via recorded table. App image: new markup served, /api/servers
                401, fresh-DB migrations (interface_names, os_name), 0 tracebacks.
                dev.31-schema DB migrates cleanly.
                FINAL (after Gate 3 fixes): check.sh 1431 passed, exit 0; podman build
                localhost/pcap-server:0.1.0-dev.32 ok; in-image remedy/probe/capture
                re-verified, same results.
                FINAL after raw-only change: check.sh 1435 passed exit 0; podman build ok;
                in-image with --cap-add NET_RAW only: printed remedy (cap_net_raw=eip)
                -> alice captures any, bob NOEXEC fix, lo/in mapping.
🔒 SECURITY   ✅ 0 Critical, 0 High. User: "ok on the review" (2026-09-14).
                NET_ADMIN decision (user): cap_net_raw=eip default; cap_net_admin offered
                with the refuses-to-start caveat. Added _caps_refused -> fail row before
                root/sudo (verified: root exec EPERM with net_admin outside bounding set;
                raw-only runs). README gallery typos + orphan caption fixed. pip-audit clean, no new deps.
                Fixed in Gate 3: privileged-group advice guard (_PRIVILEGED_GROUPS),
                evaluate_prereqs split (_privilege_checks/_sudo_checks/_unrunnable_tcpdump),
                ifindex parsed once, getcap-hint "setcap works without it" was false.
                FINDING for user (not changed): cap_net_admin unnecessary -- cap_net_raw
                alone captured any + named iface (promisc) in-image; NET_ADMIN in file
                caps makes tcpdump unexecutable where the bounding set lacks it (EPERM
                seen in default rootless podman). User referenced net_admin+net_raw.
📄 DOCS       ✅ CHANGELOG dev.32 (Added/Changed/Fixed/Documentation). README: short
                version commands, Which interface a packet crossed. target-hosts.md:
                group-limited setcap, order, re-check after upgrade (removed false
                "survives upgrade" claim), OS recorded, sudo-first order. architecture.md:
                lifecycle diagram, Interface column section, known limits. security.md:
                target-side reads, group-limited setcap. Stale-claim grep clean.
📦 RELEASE    ✅ commit cd2bda5 approved by user ("commit"), executed by Claude; pushed on
                user's "push"; ls-remote = cd2bda5. PR ➖ N/A (branch canonical, as
                dev.27-31). Handoff notes excluded. CI Check run 34852170279 success on cd2bda5.
                Tag block (Termux, 3 lines) handed to user.
🚀 SHIP       ✅ user pushed tag 2026-09-14: ls-remote v0.1.0-dev.32 -> cd2bda5.
                Release run 34854429821 success; tag-push Check run 34854429920 success.
                GitHub release v0.1.0-dev.32 (Dev) published, prerelease; CHANGELOG dev.32
                notes applied via gh release edit (2452 chars, replacing the auto compare
                link) on user's "yes". ghcr :0.1.0-dev.32 and :dev share one digest
                sha256:5801c80a604e878b7dee855842945db3d34cb1c343db1db3b20c3f05e089bc83.
                RELEASE SEQUENCE 0.1.0-dev.32 CLOSED.

## 0.1.0-dev.31 (previous)

## Current session — opened 2026-09-13 (local CLI, Fedora 44, bash, dev-skills 2.18.0)
Track: release sequence 0.1.0-dev.31 — packet sanitizer. IMPLEMENTATION DONE
(uncommitted), gates not yet run. Version not bumped.
New: backend/anonymize.py (Crypto-PAn, matches 10 reference vectors; MAC; names),
backend/framewalk.py (header walker + RFC 1624 checksums), backend/sanitizer.py
(tshark JSON pass in lockstep, field rules, keys, install secret data/sanitize.key),
main.py GET /api/captures/{id}/sanitize (+ /sanitize/summary?ticket=),
vault.derived_key + crypto.derive_subkey, packet_parser spawn_tool/reap_tool
(stream_filtered_pcap refactored onto them). UI: Sanitize on capture card + viewer
toolbar, <dialog> options -> report stage. Tests: test_anonymize, test_framewalk,
test_sanitizer (real tshark + routes), browser/test_sanitize_ui, packet_builders.
Docs: README What it does + "Sanitizing a capture" + TOC, roadmap item removed;
architecture.md section/modules/storage/limits/roadmap; security.md paragraph.
Findings fixed during build: tshark skips retransmitted segments' payloads
(prefs added); -J misses nested NTLMSSP (dropped); line-by-line JSON read was
3/4 of runtime (chunked split: 50k fully-selected frames 38s -> 9.4s).
check.sh on final code: 1370 passed, exit 0 (was 1267 at dev.30).
Screenshots dark/light 1440/400 checked; dialog centring + button width fixed.
NOT YET VERIFIED: container tshark (Debian, 4.4.x) runs the sanitize pass --
do this in Gate 2 with a real sanitize inside the podman image.
Branch claude/admiring-wright-k20ptf = origin 212936f (fetched at session start).
All versions tagged on the remote through v0.1.0-dev.30.
Model: Opus 5 — user approved staying on it for the sanitizer (2026-09-13).
Decisions: defaults creds+IPs+MACs; mapping key = HKDF(capture DEK), plaintext
captures fall back to one random secret file in the data volume.
Uncommitted at start: this file (dev.30 ship record); untracked
.claude/audit-handoff.md, .claude/sanitizer-handoff.md.

User: "Run the gates" (2026-09-13). Not commit approval.

🔢 VERSION    ✅ 0.1.0-dev.31 in all seven refs: backend/main.py:93,
                docker-compose.yml:96, README.md:206/307/323,
                docs/reverse-proxy.md:117/372. test_live_stream_ui.py:85 names
                dev.30 as history, deliberately. v0.1.0-dev.30 on remote -> 212936f.
                REPO_URL + release_notes_url (derived from APP_VERSION) present.
🔨 BUILD      ✅ final check.sh (after Gate 3 fixes): 1372 passed, 0 skipped, exit 0.
                Earlier post-bump run: 1370 passed, exit 0. podman build
                localhost/pcap-server:0.1.0-dev.31 ok; in-container (tshark
                4.4.18) sanitize of 50k frames 12-13s, 0 unmasked, 0 bad checksums,
                NTLM case matches local; app serves dialog markup, route 401
                unauthenticated, encryption enabled, 0 tracebacks. Rebuilt and
                re-verified after Gate 3 fixes.
🔒 SECURITY   ✅ 0 Critical, 0 High (pending user sight of quality review).
                pip-audit clean. No shell/eval/pickle/innerHTML in diff.
                Fixed: client-visible data-dir path in sanitize.key error;
                unbounded AddressMapper/Pseudonyms caches (CACHE_LIMIT 200k);
                -G fields subprocess not killed on read error; CPU on event loop
                (yield every 64 frames; test proves 0 ticks without it).
                Documented: Crypto-PAn known-address weakness, length kept.
                Low, accepted-pending-user: UI summary poll has no time cap once
                started; small sync reads (DEK header, sanitize.key) in async
                route; no per-user concurrency cap beyond packet_rate_limiter.
                Quality: stream_sanitized_pcap split (_TsharkPass);
                download_sanitized_capture ~80 lines, mostly validation.
📄 DOCS       ✅ CHANGELOG dev.31 (Added/Documentation). README sanitizing section
                + TOC + What it does + limits sentence; architecture.md section,
                modules, storage, known limits, roadmap; security.md; operating.md
                rotation note. Roadmap sanitizer entries removed.
📦 RELEASE    ⏳ commit 1478ff5 approved by user ("Commit"), executed by Claude,
                pushed; ls-remote = 1478ff5. PR ➖ N/A (branch canonical, as
                dev.27-30). Low findings: user proceeded to commit without
                objection. Release notes drafted and shown. CI Check run
                34799467956 success on 1478ff5.
🚀 SHIP       ✅ checked 2026-09-14 (new session, local CLI, bash):
                * tag v0.1.0-dev.31 on remote -> 1478ff5 (user).
                * Release run 34800153617 success; tag Check run 34800153624
                  success. v0.1.0-dev.31 (Dev), prerelease, 2026-09-14T02:44:31Z.
                * GHCR :0.1.0-dev.31 and :dev -> sha256:c4b027be28909dcb13f551ad3ee2c873d954eda81eae51d6455df79ff88efa6b
                * PR ➖ N/A.
                * Notes applied via gh release edit 2026-09-14 (user: "yes").
                dev.31 CLOSED AND SHIPPED.

## 0.1.0-dev.30 tracker (previous session)
Track: 0.1.0-dev.30 CLOSED AND SHIPPED 2026-09-13 (UI refresh, HTTPS docs). Ship record uncommitted.
User decisions 2026-09-13: scope "Visual + flow"; stay on Opus 5 for this task only.
 Branch claude/admiring-wright-k20ptf = origin 8832614.
Next version would be 0.1.0-dev.30. All prior versions tagged (dev.25..dev.29).
Implementation DONE (uncommitted), gates not yet run: index.html (servers welcome,
usernames in sidebar, capture card/limits/footer, captures heading, flags explainer
after list), app.js (server dots/count/facts detail, captureFromServer, SERVERS_WELCOME,
capture stats chips/short id/error block, formatBytes, captureDuration, compact
self-capture warning, add-form clears selection), style.css (btn focus/quiet danger,
pills, logo mark, cards, phone toolbar fix), test_live_stream_ui alignment test now
compares against #cap-interface.
Docs (user request 2026-09-13): README HTTPS section high up (callout under intro,
TOC link, ## HTTPS before Quick start: ACME recommended, proxy real cert, proxy
self-signed; Quick start step 7 Turn on HTTPS; first-capture lead-in); roadmap
Windows targets (README + architecture.md); reverse-proxy.md new "No domain: a
self-signed certificate" (openssl w/ SAN+EKU, Caddy tls internal, nginx, NPM
Custom); tls.md + operating.md pointers. Anchor check: 0 broken.
HTTP warnings (user request): sign-in banner rebuilt (head/body/fix list/guide
link), read-only bar one line + admin "Set up HTTPS" -> Admin HTTPS (verified over
LAN IP 10.0.0.56), refusal panel restyled with action; _HTTPS_REMEDY + JS
HTTPS_REMEDY shortened (ACME recommended, proxy, self-signed); "restart the
container" -> docker compose up -d everywhere. BUG FIXED: /api/auth/status
cookie_secure now _cookie_secure() (built-in HTTPS + COOKIE_SECURE=false falsely
warned); test added in test_tls_routes. Recreate-not-restart note: README,
operating.md, reverse-proxy.md, nginx-proxy-manager.md, docker-compose.yml comment.
check.sh (all changes so far): 1265 passed, 0 failed, exit 0. Not yet a gate pass
(version not bumped).
Browser screenshots dark+light, 1440 and 400px:
no horizontal overflow. check.sh before fixes: 2 failed (both fixed, re-run passed).

TLS CLI hint now mirrors wizard fields (domain/email/provider/delay/staging,
shell-quoted, never credentials) + 2 browser tests; tls.md sentence.

🔢 VERSION    ✅ 0.1.0-dev.30 in all seven refs: backend/main.py:83,
                docker-compose.yml:96, README.md:199/300/316,
                docs/reverse-proxy.md:117/372. tls.md:245 names dev.28/dev.29
                deliberately. v0.1.0-dev.29 on remote -> 1d9e528.
🔨 BUILD      ✅ check.sh after bump: 1267 passed, 0 failed, exit 0. podman build
                localhost/pcap-server:0.1.0-dev.30 ok; container serves
                /api/auth/status, new UI markup, tls.js updateTlsCli, lego 5.4.1,
                encryption enabled, no errors. After Gate 3 refactor
                (captureActions): capture + live browser suites 89 passed.
🔒 SECURITY   ✅ 0 Critical, 0 High. pip-audit clean. Diff reviewed: every new
                innerHTML interpolation escaped (escHtml) or constant/numeric;
                banners/bar/refusal built with textContent; CLI command shell-
                quotes typed values, credentials never included; status
                cookie_secure now the applied flag (no new endpoint).
                Standing Medium (user decision): credentials over plain HTTP.
                Quality: renderCaptures split (captureActions). selectServer ~50
                lines, mostly one template -- accepted.
📄 DOCS       ✅ CHANGELOG dev.30 (Changed/Fixed/Documentation). README HTTPS
                section, step 7, roadmap Windows; reverse-proxy self-signed;
                operating/NPM/compose recreate note; stale "red banner" refs
                fixed; tls.md CLI prefill sentence.
📦 RELEASE    ✅ commit 212936f by Claude on the user's instruction ("do a commit
                and push and tag"), pushed; ls-remote = 212936f. CI Check run
                34795033974 success on 212936f. audit-handoff.md excluded.
                Notes drafted and shown with the tag block. PR ➖ N/A (as
                dev.27-29: branch is canonical).
🚀 SHIP       ✅ 2026-09-13, post-ship checks:
                * tag v0.1.0-dev.30 on remote -> 212936f (user).
                * Release run 34795624685: build+push image success, create
                  release success. v0.1.0-dev.30 (Dev), prerelease,
                  2026-09-14T01:21:52Z; notes applied via gh release edit.
                  Tag Check run 34795624644 success.
                * PR ➖ N/A.
                * GHCR :0.1.0-dev.30 and :dev -> sha256:7ef6d0954dc899d8b78da0f94bf693c07a09cf084aef59f8ddd81d9d4307822f

---
Track: 0.1.0-dev.29 CLOSED AND SHIPPED 2026-09-13. Ship record committed (8832614).
       0.1.0-dev.28 CLOSED AND SHIPPED 2026-09-13 (below).

## PENDING WORK — read before starting a session
- NEXT FEATURE (discussed, not started): packet sanitizer. See memory
  packet-sanitizer-design for the agreed shape and user decisions.
- Prepared, approved, NOT YET RUN: exhaustive security audit + operability + pentest.
  Full plan and locked user decisions in .claude/audit-handoff.md. Read-only
  investigation, carries no gates itself. Resume with "run the audit handoff".

Version: 0.1.0-dev.28 (bumped). Previous tag v0.1.0-dev.27 confirmed on
         the remote: object b63c695, ^{} -> d70e47b.
Updated: 2026-09-13 (session: local CLI, Fedora 44, bash)
Branch: claude/admiring-wright-k20ptf — canonical. Head 39e48ee = origin.
Environment: LOCAL Claude Code CLI — Claude PRESENTS git commands, the user
        runs them (SKILL.md 5.8). Not a container.
Model: Opus 5, above the Sonnet ceiling; the user approved staying on it FOR
       dev.28 (2026-09-13).

## 0.1.0-dev.29 tracker

Opened 2026-09-13 from the user's first real dev.28 issuance attempt.
Gates run on the user's instruction ("Run the gates And do the commit since I'm
away from my desk").

🔢 VERSION    ✅ 0.1.0-dev.29 in all seven refs (main.py:83, compose:92, README
                130/225/241, reverse-proxy.md 110/274); CHANGELOG heading dated
                2026-09-13. v0.1.0-dev.28 on remote -> 8fac667 = branch head.
                docs/tls.md:238 names dev.28 deliberately (troubleshooting row).
🔨 BUILD      ✅ check.sh after bump: 1264 passed, 0 skipped, exit 0. Image built
                with rootless podman; container serves /api/auth/status, ships
                tls.js wizard + admin-shell markup, lego 5.4.1, no log errors.
                (Afterwards: a comment fix in lego.py + architecture.md bullet;
                TLS suites re-run 179 passed.)
🔒 SECURITY   ✅ 0 Critical, 0 High. pip-audit clean. Diff since 8fac667 reviewed:
                argv gets --dns.propagation.wait from a validated int (5..600,
                bools refused); _ERROR_FIELD regex single-line, non-overlapping
                alternation; redaction runs after unescape; overview/wizard DOM
                built with textContent; localStorage page name allowlisted.
                Standing Medium (user decision): credentials over plain HTTP.
                Quality: loadAdminOverview ~45 lines (card builders split) -- ok.
📄 DOCS       ✅ CHANGELOG dev.29 (wait-not-poll, readable errors, Cloudflare one
                field, banner, CLI location, admin sections, HTTPS steps);
                tls.md (3-step setup, Wait before validation, why it waits,
                troubleshooting), architecture.md (wait bullet), README admin
                names. No stale "DNS servers that check"/public-resolver text.
📦 RELEASE    ✅ commit 1d9e528 by Claude (user authorized, away), pushed;
                ls-remote = HEAD. .claude/audit-handoff.md excluded (unseen).
                Notes: user tagged after being shown them with "when CI is green
                and you've approved the notes" -- applied on that basis; the user
                can edit them. PR ➖ N/A.
🚀 SHIP       ✅ 2026-09-13, post-ship checks:
                * tag v0.1.0-dev.29 on remote -> 1d9e528 (user, Termux).
                  NOTE: user tagged BEFORE the branch Check finished; it then
                  passed (success on 1d9e528).
                * Release workflow: build+push image success, create release
                  success. v0.1.0-dev.29 (Dev), prerelease, 2026-09-13T23:58:56Z;
                  notes applied via gh release edit.
                * PR ➖ N/A.
                * GHCR :0.1.0-dev.29 and :dev -> sha256:2b616e4b6c6cd95e811132f76e7ce83cf6c73d7e5bd5caa6c8109e24628a37bf
                  (real header digests, not e3b0c442).

### What the user hit on dev.28
- lego failed: "recursive nameservers: NS 127.0.0.11:53 returned NXDOMAIN for
  _acme-challenge.pcap.nscriven.net" after 2 min. Record WAS created via
  Cloudflare; Docker's resolver forwards to the host's LAN DNS, which answers
  for nscriven.net itself (split DNS). NPM works because certbot just sleeps.
- `docker compose exec` run outside the compose dir -> "no configuration file".
- Cloudflare showed 4 credential boxes; NPM needs only the API token.
- Asked that the plain-HTTP banner name ACME as an option (it did, third).
- Container lacks ping/curl/wget -- by design; lego doesn't need them.

### Fixes (dev.29)
1. lego --dns.resolvers default 1.1.1.1:53,8.8.8.8:53; configurable per install
   (acme.json "resolvers", UI "DNS servers that check the record", CLI
   --resolvers). IP[:port] only, max 4, no loopback/link-local. Old acme.json
   loads. Verified real lego 5.4.1 parses the flag.
2. lego errors: extract error="..." from the ERROR line, drop WARN HEADS UP,
   one hint (most specific first). Tested on the user's exact output.
3. providers.PRIMARY: cloudflare=[CF_DNS_API_TOKEN], route53, lightsail, gcloud,
   azuredns, ovh, gandiv5; others under "Other ways to authenticate".
4. Banner + _HTTPS_REMEDY: "two ways" -- built-in Let's Encrypt (ACME, DNS-01)
   first, reverse proxy second.
5. UI CLI hint says to run in the compose folder; docs give docker exec.

USER DECISIONS 2026-09-13:
- "We are not going to resolve on external resolvers." Public default reverted;
  compose `dns:` workaround withdrawn.
- User: "Proxmox npm termux. Everything else I use that has certbot in acme does
  not have this issue." All of those WAIT a fixed delay and never poll local DNS.
  -> FIX: lego --dns.propagation.wait=<delay>s (skips lego's recursive and
  authoritative checks entirely -- verified in lego source
  dns01.PropagationWait(wait, skipCheck=true)). "Wait before validation",
  default 30s like Proxmox, 5..600. The resolvers setting was REMOVED (never
  released); old acme.json "resolvers" key ignored. Real lego 5.4.1 accepts the
  flag. check.sh 1259 passed, 0 skipped.
- Corrected by the user: I asserted split DNS without evidence. Cause of the
  NXDOMAIN poll remains UNCONFIRMED; the fix does not depend on it.
- Record name _acme-challenge.pcap.<zone> is correct (RFC 8555 8.4).
- Admin panel "a mess ... too busy and confusing". USER CHOSE (AskUserQuestion):
  sidebar sections (Proxmox-like), one line + Learn more, HTTPS status first
  with setup as steps. BUILT: index.html admin-shell/nav/7 pages (Overview,
  HTTPS, Encryption, Users, SSH keys, Known hosts, Settings); app.js
  selectAdminPage (data-admin-page, NOT data-tab -- activatePanel clears
  [data-tab]), remembered page (localStorage, try/catch), Overview cards + nav
  attention dots; tls.js status-first + 3-step wizard (values survive Back/Next;
  failed request leaves wizard open). Screenshots checked desktop + 400px.
  Pre-existing, not touched: top toolbar overflows at 400px.
  check.sh 1264 passed, 0 skipped, exit 0.

## 0.1.0-dev.28 tracker

ALL SIX GATES ✅ + FOUR POST-SHIP CHECKS ✅.

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
📦 RELEASE    ✅ commit 1abc598 approved ("commit"), executed by Claude, pushed.
                The user ALSO ran the presented block: 368363e (same message,
                only .claude/dev-skills-gates.md differs) is the branch head;
                local fast-forwarded, ls-remote = 368363e = HEAD. TAG TARGET IS
                368363e. PR ➖ N/A (no PR workflow). Release notes APPROVED
                ("yes") -- to be applied with `gh release edit` after CI
                publishes (release.yml generate_release_notes = commits only).
🚀 SHIP       ✅ SHIPPED 2026-09-13, all four post-ship checks verified:
                * tag v0.1.0-dev.28 on remote -> 8fac667 (LIGHTWEIGHT: created by
                  the user's `gh api .../git/refs` from Termux; dev.27 was
                  annotated). The user's later `git tag` said "already exists".
                * Release workflow success: build and push image, create
                  GitHub Release. Release v0.1.0-dev.28 (Dev), prerelease,
                  published 2026-09-13T21:35:05Z. Approved notes applied with
                  gh release edit (replacing generate_release_notes).
                * PR ➖ N/A (no PR workflow).
                * GHCR: :0.1.0-dev.28 and :dev both ->
                  sha256:a117d7b534dd27b6af5cc73a73445fb2d7e4754147867852a5a15c157ee97fb2
                  (real registry header digests, not e3b0c442).
                Image also pre-verified locally with rootless podman (HTTP, HTTPS
                via memfd from a sealed cert, no plaintext key on the volume).
                History: Check on 368363e failed (bare-expression
                wait_for_function under CSP); fixed in 8fac667 + hygiene test.
                LESSON: the user on Termux wanted a MINIMAL paste block (fetch,
                tag, push) -- long guarded scripts caused frustration.

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
