# Dev Skills gate state
Track: work commit
Version: 0.1.0-dev.9 (tagged on remote; no bump in this session)
Updated: 2026-09-12

🔢 VERSION    ⬜ not owed — no version bump; changelog entries sit under "Unreleased"
🔨 BUILD      ✅ 351 tests green via scripts/check.sh, with real tshark + capinfos
                installed so the previously-skipped capinfos suite actually ran.
                App booted on the upgraded stack (fastapi 0.141.1 / starlette
                1.3.1) and the new lifespan shutdown handler was confirmed
                firing. UI driven end to end in Chromium via Playwright.
🔒 SECURITY   ✅ 0 Critical, 0 High. pip-audit clean (was 5 starlette advisories).
                Fixed this session: unvalidated SSH username interpolated into
                the sudoers rule printed for an operator to run as root; the
                printed rule now installs through visudo instead of tee; a
                capture-slot leak on failed launch; request-body validation
                shared between the two host-key endpoints (a non-numeric port
                was a 500).
📄 DOCS       ✅ CHANGELOG "Unreleased" covers every change; README feature list
                no longer advertises the removed saved-servers split; README
                sudo section contrasts blanket NOPASSWD:ALL against the scoped
                rule and explains why passwordless is required at all (SSH keys
                are the only auth method).
📦 RELEASE    ⬜ not owed — no PR for a work commit
🚀 SHIP       ⬜ not owed — no tag, no merge to main

Follow-up requested by the user, not started: full API hardening pass
(see task #1 — auth/authz per route, pydantic bodies instead of raw
request.json(), rate limiting on the probe endpoints, error-shape consistency).
