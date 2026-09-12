# Dev Skills gate state
Track: release sequence — COMPLETE for 0.1.0-dev.13
Version: 0.1.0-dev.13
Updated: 2026-09-12 (ship verification session)

🔢 VERSION    ✅ 0.1.0-dev.13 in backend/main.py:61, docker-compose.yml:22 and
                the CHANGELOG heading. v0.1.0-dev.12 confirmed on the remote at
                f1dc65b with a successful Release run and a published Release.
🔨 BUILD      ✅ 423 tests green, no skips (tshark, tcpdump, capinfos present).
                49 browser checks across three Chromium suites (packet viewer,
                server form, users), zero JS errors. Verified from a fresh clone
                of the pushed branch, not a working tree.
🔒 SECURITY   ✅ 0 Critical, 0 High. pip-audit clean; no dependency changes.
                PDML parsing refuses any document type declaration (expat
                resolves internal entities and packet bytes reach it).
                Click-built filter values are quoted; a value carrying a
                character _FILTER_FORBIDDEN rejects degrades to an existence
                test. The validator was NOT relaxed. Tree and hex rendering use
                textContent/createElement throughout.
📄 DOCS       ✅ CHANGELOG entry dated with Added/Changed/Security/Fixed.
                README gained "Building a filter by clicking" and "Field and
                byte selection". docs/architecture.md gained the PDML and
                click-built-filter entries under input validation.
📦 RELEASE    ✅ committed and pushed. PR ➖ N/A — no branch to merge into;
                the default branch is out of scope by the user's instruction.
🚀 SHIP       ✅ verified this session, all four checks:
                - tag v0.1.0-dev.13 -> 1573e0b on the remote (git ls-remote)
                - Release run 34714750294 completed, conclusion success
                - "Build and push image" step success, so
                  ghcr.io/darthrater78/pcap-server:0.1.0-dev.13 and :dev exist
                - GitHub Release "v0.1.0-dev.13 (Dev)" published 19:39:45,
                  prerelease true, id 387682986
                Check run 34714750268 on the tag also green.

## Next work — work commit, in progress

Track: work commit (no version bump, no artifact, no publish).
Change: .github/workflows/release.yml — floating-tag guard.

🔒 SECURITY   ✅ reviewed below. No new permissions, no secrets read or printed,
                no new dependency. The tag name reaches the script through an
                env var instead of a ${{ }} template, so it is never expanded
                into script text; every use is quoted and nothing is eval'd.
                set -euo pipefail added, and a failed ls-remote now aborts the
                release rather than guessing at what is tagged.
🔢 VERSION    ⬜ not owed — no bump in a work commit. The guard ships in dev.14.
🔨 BUILD      ⬜ not owed. Verified by executing the step's own script across
                five tag scenarios against the real remote tag list, plus a
                YAML parse. The 423-test suite was NOT run: no Python changed,
                and it cannot exercise a workflow file.
📄 DOCS       ⬜ not owed. Checked anyway: no doc or compose file references
                :dev or :latest, so no claim is contradicted. docker-compose.yml
                pins an exact version.
📦 RELEASE    ⬜
🚀 SHIP       ⬜

## dev.8 plan — option B, chosen by the user

Tag v0.1.0-dev.8 at 3e34888 immediately BEFORE cutting dev.14. dev.8's run
executes dev.8's own copy of release.yml, which is byte-identical to the
pre-guard version, so it WILL repoint :dev at dev.8's image. dev.14's run,
which carries the guard and is the newest dev version, corrects :dev right
after. The regression window is the gap between the two runs; docker-compose
pins an exact version so only a manual `docker pull ...:dev` is exposed.

## Session notes

- Environment: remote container. Claude executes git after approval; tag and
  ref-deleting pushes are always handed to the user as a block.
- Designated branch this session: claude/dev13-ship-verify-n3cr2c, currently at
  1573e0b, not yet on the remote. The canonical published branch is
  claude/admiring-wright-k20ptf, also at 1573e0b.
- tshark, tcpdump and capinfos are NOT preinstalled:
      apt-get update -qq && apt-get install -y -q tshark tcpdump
- The three browser suites are NOT in the repo — they live only in a previous
  container's scratch and are gone. They caught four real bugs that 423 tests
  missed. Re-adding them means playwright in a dev requirements file and
  chromium in check.yml. Offered four times, never taken.
- v0.1.0-dev.8 has a CHANGELOG entry (line 449) and no tag on the remote.
  Unfinished Gate 6 from an earlier session. Needs the user; tags are theirs.
- The default branch is claude/hopeful-allen-qmo0ch (initial commit), so none of
  the work is visible at the repository root. Explicitly out of scope.
- Local dev workflow: ./scripts/check.sh. check.yml calls the same script, so
  CI and local have not drifted.
