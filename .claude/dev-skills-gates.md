# Dev Skills gate state
Track: release sequence
Version: 0.1.0-dev.10
Updated: 2026-09-12

🔢 VERSION    ✅ 0.1.0-dev.10 in backend/main.py, docker-compose.yml and the
                CHANGELOG heading; v0.1.0-dev.9 confirmed tagged on the remote
                at 7637bce; repo and release-notes links present in main.py.
🔨 BUILD      ✅ 351 tests green via scripts/check.sh with real tshark and
                capinfos installed, so the capinfos suite ran rather than
                skipping. Booted on the upgraded stack (fastapi 0.141.1 /
                starlette 1.3.1) and the new lifespan shutdown handler was seen
                firing. UI driven end to end in Chromium via Playwright -- which
                is the only thing that caught the missing comma that left
                app.js unparseable while all 303 tests passed.
🔒 SECURITY   ✅ 0 Critical, 0 High. pip-audit clean (five starlette advisories
                cleared). Fixed this release: an unvalidated SSH username
                interpolated into the sudoers rule printed for an operator to
                run as root; that rule now installs through visudo rather than
                tee; a capture-slot leak on failed launch; one shared body
                validator for both host-key endpoints (a non-numeric port was
                a 500). Reviewed and cleared: the migration's SQL f-string
                interpolates one of two hardcoded literals chosen by a local
                PRAGMA, and every new frontend interpolation is escaped or is
                an own-API URL path.
📄 DOCS       ✅ CHANGELOG entry for 0.1.0-dev.10 with date; README feature list
                no longer advertises the removed saved-servers split; README
                sudo section contrasts blanket NOPASSWD:ALL with the scoped rule
                and explains why passwordless is required at all (SSH keys are
                the only auth method this app uses).
📦 RELEASE    ✅ commit approved by the user; release notes approved.
                PR step ➖ N/A -- this remote has no default branch to merge
                into (only claude/* branches exist), so the project releases by
                tagging the branch, as v0.1.0-dev.1 through dev.9 all did.
🚀 SHIP       ⏳ tag block handed to the user to run. Stays ⏳ until
                `git ls-remote --tags origin v0.1.0-dev.10` confirms the tag,
                the release workflow (.github/workflows/release.yml, on: push
                tags v*) completes, and the ghcr.io image and GitHub Release
                are verified.

Follow-ups requested by the user, not started:
  #1 full API hardening pass (auth/authz per route, pydantic bodies instead of
     raw request.json(), rate limiting on the probe endpoints, error shapes).
  #2 filter UX -- pattern suggestions and real documentation for both the BPF
     capture filter and the viewer display filter. Checked this session: the
     display filter has no help at all beyond its placeholder, and the BPF
     examples exist but are buried inside the "Where are the tcpdump flags?"
     explainer.
