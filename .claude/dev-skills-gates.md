# Dev Skills gate state
Track: release sequence
Version: 0.1.0-dev.13
Updated: 2026-09-12

🔢 VERSION    ✅ 0.1.0-dev.13 in backend/main.py:61, docker-compose.yml:22 and
                the CHANGELOG heading. Previous version confirmed on the remote
                with git ls-remote: v0.1.0-dev.12 at f1dc65b, with a successful
                Release workflow run and a published GitHub Release.
🔨 BUILD      ✅ 423 tests green, no skips -- tshark, tcpdump and capinfos are
                installed, so every tool-dependent suite ran. Booted under
                uvicorn (uvloop) against a seeded encrypted five-frame capture
                (TCP handshake, an HTTP GET, a DNS query) and driven in
                Chromium: 21 checks covering the PDML tree labels, hidden
                generated fields, field-to-byte highlighting, byte-to-field
                selection, the Apply-as-Filter menu, TCP flag bit filtering,
                and the packet-row conversation filter. A second browser suite
                covers the server form: 14 checks on the blank SSH key picker,
                the refusal to add/test/probe without one, the standing
                self-capture warning, the backend still rejecting localhost, and
                the edit form keeping the server's own key. Zero JS errors.
🔒 SECURITY   ✅ 0 Critical, 0 High. pip-audit clean; no dependency changes.
                Two new input paths this release, both reviewed:
                - PDML parsing. Refused outright if the bytes carry a document
                  type declaration, matched case-insensitively, because expat
                  resolves internal entities and packet contents reach it.
                - Click-built filter values. Quoted before they are sent; a
                  value carrying any character _FILTER_FORBIDDEN rejects
                  degrades to an existence test. The validator was NOT relaxed.
                The new tree and hex rendering use textContent and
                createElement throughout -- no innerHTML carries packet data.
                Self-capture detection is unchanged and still enforced on both
                add and edit; the new warning covers the host-LAN-address case
                it is structurally unable to see, now pinned by a test.
📄 DOCS       ✅ CHANGELOG entry dated, with the Added/Changed/Security/Fixed
                split. README gained "Building a filter by clicking" and
                "Field and byte selection". docs/architecture.md gained the
                PDML and click-built-filter entries in its input-validation
                section.
📦 RELEASE    ⬜ awaiting commit approval. PR ➖ N/A -- the repo has no branch
                to merge into.
🚀 SHIP       ⬜ tag is the user's to push.

## Session notes

- Environment: remote container. Claude executes git after approval; tag and
  ref-deleting pushes are always handed to the user as a block.
- Branch: claude/admiring-wright-k20ptf, chosen by the user this session.
- tshark, tcpdump and capinfos are NOT preinstalled:
      apt-get update -qq && apt-get install -y -q tshark tcpdump
- The browser check is not in the repo. It caught the one real bug in this
  release (quoted address literals) that all 423 tests missed. Adding it would
  mean playwright in requirements-dev and chromium in CI -- offered, not done.
- The default branch is still claude/hopeful-allen-qmo0ch (the initial commit),
  so none of the work is visible at the repository root. Open, needs the user.
- v0.1.0-dev.8 has a changelog entry but no tag. Open, needs the user.
