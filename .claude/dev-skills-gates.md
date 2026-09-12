# Dev Skills gate state
Track: release sequence
Version: 0.1.0-dev.11
Updated: 2026-09-12

🔢 VERSION    ✅ 0.1.0-dev.11 in backend/main.py, docker-compose.yml and the
                CHANGELOG heading. Previous version confirmed tagged on the
                remote: v0.1.0-dev.10 at c3df2cb, read with git ls-remote, not
                from a local tag list. Repo and release-notes links present in
                main.py.
🔨 BUILD      ✅ 399 tests green, no skips -- tshark, capinfos and tcpdump are
                all installed in this container, so the suites that need them
                ran rather than reporting SKIPPED. Booted under uvicorn (uvloop)
                with a seeded encrypted capture and driven end to end in
                Chromium across three suites: the viewer and capture rename, the
                filter UX, and the stored-username list. That browser pass is
                not optional here -- it caught a stale function name this
                session that every one of the 399 tests was blind to.
🔒 SECURITY   ✅ 0 Critical, 0 High. pip-audit clean, no dependency changes.
                Fixed this release: TOTP was enforced by the frontend only, so
                any client ignoring needs_totp_setup held a session with one
                factor and the whole API behind it -- the check now sits on
                get_current_user, which all 24 protected routes and require_admin
                share. Also bounded the tcpdump progress parser and its stderr
                buffer, both fed by the host under investigation.
                Deliberately loosened, with reasoning: the display filter now
                accepts & and |, because it reaches tshark through
                create_subprocess_exec as one argv element with no shell on the
                path. That property is asserted by a test that inspects argv
                rather than claimed in a comment. ; $ ` and backslash stay
                refused, a length cap was added, and the capture filter keeps
                the stricter rule because it does travel in a shell string.
📄 DOCS       ✅ CHANGELOG entry for 0.1.0-dev.11 with date, covering fixed,
                added, changed, security and documentation. docs/architecture.md
                written this release and linked from the README. README gains a
                two-filters comparison, the new feature lines, a roadmap, and no
                longer claims -v is refused.
📦 RELEASE    ✅ commit approved by the user, who also asked for the tag.
                PR step ➖ N/A -- the repo has no branch to merge into: the
                default branch is the initial commit and every release from
                dev.1 to dev.10 was tagged on a claude/* branch.
🚀 SHIP       ⏳ awaiting the tag. Tag pushes are always the user's to run.
                Stays ⏳ until `git ls-remote --tags origin v0.1.0-dev.11`
                confirms it, the release workflow (.github/workflows/release.yml,
                on: push tags v*) completes, and the ghcr.io image and the
                GitHub Release are verified.

Outstanding, needs the repository owner:
  * The repo's DEFAULT BRANCH is claude/hopeful-allen-qmo0ch, the initial
    commit, and every commit since sits on claude/admiring-wright-k20ptf.
    GitHub renders the landing page and README from the default branch, so
    none of this work is visible at the repository root. A settings change.
  * v0.1.0-dev.8 has a CHANGELOG entry but no tag on the remote. Every other
    version from dev.1 to dev.10 is tagged. An unfinished release predating
    this session.

Not started, agreed as next:
  * Full API hardening pass: per-route auth and authz audit, pydantic bodies in
    place of raw request.json(), rate limiting on the probe endpoints,
    consistent error shapes. The TOTP fix in this release is the first piece.
