# Dev Skills gate state
Track: release sequence
Version: 0.1.0-dev.12
Updated: 2026-09-12

🔢 VERSION    ✅ 0.1.0-dev.12 in backend/main.py, docker-compose.yml and the
                CHANGELOG heading. Previous version confirmed tagged on the
                remote with git ls-remote: v0.1.0-dev.11 at 77186a9. Repo and
                release-notes links present in main.py.
🔨 BUILD      ✅ 404 tests green, no skips -- tshark, capinfos and tcpdump are
                all present, so the suites needing them ran. Booted under
                uvicorn (uvloop) with a seeded encrypted capture and driven in
                Chromium across five suites: the viewer and capture rename, the
                filter UX, the stored-username list, the viewer layout, and a
                new one covering the theme name, the filter library and the
                local-time flag. That last runs the browser in America/Denver so
                a bug that silently rendered UTC would show up as a failure.
🔒 SECURITY   ✅ 0 Critical, 0 High. pip-audit clean; no dependency changes.
                The only new input path this release is the -tz view flag, which
                goes through the same ALLOWED_VIEW_FLAGS check that rejects an
                unknown flag with a 400 before tshark runs. The filter library
                is static data rendered through escHtml, and the expressions it
                inserts land in the capture-filter box and face the same
                server-side validation as a typed one. The extra tshark field
                (sll.src.eth) is a constant in the argument list.
                Carried from earlier in this session and still standing: TOTP is
                now enforced on get_current_user rather than by the frontend
                alone; the tcpdump progress parser and its stderr buffer are
                bounded; the display filter's character rule was loosened to
                allow & and | with a test that inspects argv to prove no shell
                is involved.
📄 DOCS       ✅ CHANGELOG entry for 0.1.0-dev.12 with date. README reordered
                around the reader -- what it does, quick start, first capture,
                the two filters, security, capture privilege, running it,
                reference -- with a contents line and a new Security section.
                docs/architecture.md corrected (it still described the TOTP gap
                as open after it had been closed) and extended with the
                display-filter rule, the timestamp decision and the MAC columns.
📦 RELEASE    ✅ commit approved by the user, who asked for the tag.
                PR step ➖ N/A -- the repo has no branch to merge into: the
                default branch is the initial commit, and every release from
                dev.1 to dev.11 was tagged on a claude/* branch.
🚀 SHIP       ⏳ awaiting the tag. Tag pushes are always the user's to run.
                Stays ⏳ until `git ls-remote --tags origin v0.1.0-dev.12`
                confirms it, the release workflow completes, and the ghcr.io
                image and GitHub Release are verified.

Outstanding, needs the repository owner:
  * The repo's DEFAULT BRANCH is claude/hopeful-allen-qmo0ch, the initial
    commit. Everything since sits on claude/admiring-wright-k20ptf. GitHub
    renders the landing page and README from the default branch, so none of
    this work -- the reworked README included -- is visible at the repository
    root. A settings change: Settings, Branches, switch the default.
  * v0.1.0-dev.8 has a CHANGELOG entry but no tag on the remote. Every other
    version from dev.1 to dev.11 is tagged.

Not started, agreed as next:
  * Full API hardening pass: per-route auth and authz audit, pydantic bodies in
    place of raw request.json(), rate limiting on the probe endpoints,
    consistent error shapes. The TOTP enforcement was the first piece of it.
