# Dev Skills gate state
Track: work commit
Version: 0.1.0-dev.10 (unchanged -- this commit does not bump anything)
Updated: 2026-09-12

🔢 VERSION    ⬜ not owed on a work commit. No refs touched; main.py, the
                compose file and the CHANGELOG heading all still read
                0.1.0-dev.10.
🔨 BUILD      ✅ 384 tests green via the venv with real tshark, capinfos and
                tcpdump installed, so nothing skipped. The app was booted under
                uvicorn (uvloop) with a seeded encrypted capture and driven end
                to end in Chromium: viewer, packet detail, hex dump, display
                filter, capture rename, the capture-page host label, the server
                username picker and the Admin username list all verified in the
                browser, not just in tests.
🔒 SECURITY   ✅ 0 Critical, 0 High. pip-audit clean (no dependency changes).
                Found and fixed in this diff: the tcpdump progress parser
                matched an unbounded digit run from the captured host's stderr,
                handing int() a quadratic parse; and that stderr accumulated for
                the whole capture with no cap. Both are remote-influenced input
                from a host under investigation, so both are bounded now.
                Reviewed and cleared: every new SQL statement is parameterised;
                the one-off backfill uses literals only; the username endpoints
                validate through the same rule the sudoers line depends on and
                scope every read and write by user_id; the new mutating routes
                inherit the plain-HTTP read-only refusal from the existing
                middleware; all new frontend interpolation is escaped or set
                through textContent.
📄 DOCS       ⬜ not owed on a work commit. The in-app flags explainer was
                updated because -v now appears in every command string; the
                CHANGELOG has no entry for this work yet.
📦 RELEASE    ⬜ not owed on a work commit.
🚀 SHIP       ⏳ CARRIED OVER, NOT THIS SESSION'S WORK: v0.1.0-dev.10 was
                released and pushed last session but never tagged. Tag pushes
                are always the user's to run. Until
                `git ls-remote --tags origin v0.1.0-dev.10` shows it, dev.10 is
                an unfinished Gate 6.

Quality, surfaced and accepted:
  * CaptureManager._monitor is ~90 lines and now carries a nested live-count
    closure. Cohesive but large; left as known debt rather than split under an
    unrelated change.

Follow-ups requested by the user, not started:
  #1 full API hardening pass (auth/authz per route, pydantic bodies instead of
     raw request.json(), rate limiting on the probe endpoints, error shapes).
  #2 filter UX -- pattern suggestions and real documentation for both the BPF
     capture filter and the viewer display filter.
