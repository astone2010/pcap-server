# Handoff: pcap-server dev.40 (hardening)

Written 2026-09-17 10:12 EDT. Start a fresh session from this file. Read
`.claude/dev-skills-gates.md` first (the dev.40 section at the top). Re-check
`git status` / `git log` too: another session was editing this repo while this
was written.

**Goal:** Finish shipping 0.1.0-dev.40.

## Current state
**HEAD is `2e458b9`**, pushed to origin. It is the user's own commit, made from a
separate Sonnet session: "Untangle setup docs". It touched README.md,
docker-compose.yml and docs/operating.md, and **it swept in part of dev.40**:
- `docker-compose.yml` on the branch already has the hardening block (cap_drop
  ALL + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, read_only,
  tmpfs /tmp), and **its image is pinned to `0.1.0-dev.40`**.
- README on the branch already curls `v0.1.0-dev.40/docker-compose.yml`.
- 🚨 **Neither the tag nor the image exists yet.** Anyone following the README on
  the default branch right now gets a 404 from curl or a failed image pull. Ship
  dev.40 soon, or point those refs back at dev.39.

**Still UNCOMMITTED** (14 files, plus the untracked `.claude/hooks/gate-preflight.sh`
and this file):
- `backend/ssh_manager.py`: `_connect` checks host trust before loading the
  client key. There are 3 new tests in `tests/test_ssh_manager.py`, and the
  locked-vault test in `tests/test_ssh_manager_keys.py` now uses a trusted host.
- `release.yml`:
  - The tagged commit must be on the default branch (compare API; tested ahead/identical/behind).
  - `concurrency: release`, no cancel.
  - Timeouts on every job.
  - `persist-credentials: false`.
  - buildx v4.4.1 @f87e5991.
- `check.yml` / `lint-workflows.yml`: actions pinned to SHAs (checkout 3d3c42e5
  v7.0.1, setup-python 5fda3b95 v7.0.0), plus timeouts and persist-credentials.
  actionlint 1.7.12 is clean.
- `backend/main.py` APP_VERSION and `docs/reverse-proxy.md` at dev.40. The
  CHANGELOG dev.40 entry, a `docs/security.md` hardening paragraph, and a
  `docs/architecture.md` note on the `_connect` order.
- `.claude/settings.json`: the gate-preflight PreToolUse hook (upstream v2.23.0,
  read in full).
- ⚠️ **`README.md`: the working tree deletes the whole Quick start section
  (-132 lines).** This is NOT dev.40 work. It was being edited by another session
  at 10:11. Ask the user whether it is intentional before committing anything
  that includes README.md.

**Verified:** check.sh passes 1559 / 0 skipped. Image
`localhost/pcap-server:0.1.0-dev.40` is built locally. The hardened compose file
was brought up for real: the app is up, PID 1 has CapEff=0, rekey, resetmfa and
tls work, and mounts owned by root, 1000 and 1001 all boot. Dependabot alerts and
security updates are now enabled, with 0 alerts (SBOM: 22 packages).

## Gate status
🔢 VERSION ✅ · 🔨 BUILD ⏳ · 🔒 SECURITY ⏳ · 📄 DOCS ⏳ · 📦 RELEASE ⬜ · 🚀 SHIP ⬜
- **BUILD:** the handoff was offered and the user chose to try the image. No
  result has been reported yet.
- **SECURITY:** the user must sign off on three Medium items: DAC_OVERRIDE is
  kept, the Dockerfile's apt packages are unpinned, and there is no osv-scanner
  (the image's OS layer is unaudited).
- **DOCS:** re-check after the user's `2e458b9` rewrite and the in-progress
  README edit. Every version ref and the setup docs must agree.

## Decisions to respect
- Publishing intent (a bump or tag) makes a release. A plain push is a work
  commit. No PRs before 1.0 (Gate 5's PR step is ➖ N/A).
- Claude runs git after approval. The **user runs tag pushes** from
  `/home/serveradmin/pcap-server`.
- The gate-preflight hook needs a `handoff` annotation on the BUILD line
  (the repo has a Dockerfile).
- Opus is approved per task. Flag the Sonnet ceiling once.
- UI feedback about "Staged APKs" belongs to **adb-server**, not here (see
  adb-server/.claude/staged-apks-feedback-handoff.md).

**Shell environment:** a local Linux box. Claude uses bash, and the user runs
tag blocks on this box.

## Next step
Ask the user about the uncommitted README deletion, and how the dev.40 image
test went. Then close SECURITY and DOCS, commit, push, and hand over the tag
block. The branch already advertises dev.40, so this is urgent.
