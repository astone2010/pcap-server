# Dev Skills gate state
Track: release sequence — 0.1.0-dev.26 (OPEN, nothing done yet)
Version: 0.1.0-dev.25 is the last RELEASED version (tag v0.1.0-dev.25 -> dc65ae4,
         confirmed on the remote by ls-remote this session).
Updated: 2026-09-13 (session: local CLI, Fedora 44, bash)
Branch: claude/admiring-wright-k20ptf — canonical, in sync with origin at
        bf4a42a. Working tree clean at session start.
Environment: LOCAL Claude Code CLI — Claude PRESENTS git commands, the user
        runs them (SKILL.md 5.8). Not a container.
Model: session is on Opus 5, ABOVE the Sonnet ceiling (SKILL.md 5.2). Flagged to
        the user at session start; awaiting their call.

## 0.1.0-dev.26 tracker

🔢 VERSION    ✅ 0.1.0-dev.26 in all FIVE places: backend/main.py:80,
                docker-compose.yml:72, CHANGELOG heading, README.md:123
                (Quick start curl), README.md:201 (version table),
                README.md:217 (Upgrading curl).
                v0.1.0-dev.25 confirmed tagged on the remote (ls-remote ->
                dc65ae4).
🔨 BUILD      ✅ ./scripts/check.sh on this host: 1055 passed, 0 failed,
                0 SKIPPED, 5m48s, exit 0. Baseline dev.25 was 972; +83 = the
                tests added this session. Ran LOCALLY, no container.
                Run three times this session; 1055 is the final figure.
🔒 SECURITY   ✅ shipped code: 0 Critical, 0 High. Details below.
                RE-RUN after the MFA-reset and cap work landed; 1055 passed.
                ONE OPEN ITEM, dev-only: pip-audit reports PYSEC-2026-1845
                against pytest 8.3.4 (fix: 9.0.3). pytest is in
                requirements-dev.txt only and the Dockerfile installs
                requirements.txt, so it is NOT in the shipped image. Offered
                the bump; it is a major version jump and was not taken during
                the release. Re-raise at the start of dev.27.
📄 DOCS       ✅ CHANGELOG entry for 0.1.0-dev.26; README rewritten for the
                Quick start, the name requirement, the confirm dialog, saved
                filters, the filter badge, capture tabs and the theme;
                docs/architecture.md updated for the new tables, the per-user
                scoping rule and bpf_filter-on-the-record.
📦 RELEASE    ⬜
🚀 SHIP       ⬜

## 0.1.0-dev.26 — what shipped

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
