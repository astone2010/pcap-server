# Handoff: pcap-server security audit → dev.37 shipped

Written 2026-09-15. Resume a fresh session from this file.

**Goal:** Run the queued audit/pentest, then fix findings. Done through shipping dev.37.

**Current state:** dev.37 **shipped and verified** — commit `d513564`, tag
`v0.1.0-dev.37` on remote, gate job passed before release, ghcr
`:0.1.0-dev.37` == `:dev` `sha256:65c85477…`, GitHub release published + notes
applied. Working tree has one uncommitted file: `.claude/dev-skills-gates.md`
(this session's ship record — swept into dev.38 next release, as always).

**What shipped in dev.37:** H1 (login memory-DoS → scrypt concurrency gate),
H2 (bootstrap admin race → atomic insert), L7 (version hidden from password-only
session), L2 (`Cache-Control: no-store`), L6 (crypto assert→raise), and the
reported host-key bug (**Scan & accept host key** button + probe transient-pin +
`host_not_trusted` code replacing the stale admin-only message).

**Gate status:** 🔢✅ 🔨✅ (1532 tests + container smoke) 🔒✅ (0 Crit/High/Med,
signed off) 📄✅ 📦✅ 🚀✅ — all closed.

## Open items (not started)

1. **CI bundle M2/M3/M4** — SHA-pin the 5 actions in `release.yml`, add
   `permissions: contents: read` to `check.yml`, add `github-actions`+`pip` to
   `.github/dependabot.yml`. Separate work commit (no version bump); kept out of
   dev.37 on purpose (edits the pipeline that ships releases). M4 open since
   2026-09-14.
2. **Redeploy `:0.1.0-dev.37` on the live box** — H1 is fixed in the image but
   the running container is still dev.36 until pulled. User's action.
3. **Deferred by design:** M5 (TOTP secrets plaintext at rest — needs migration),
   L1 (chunked-body cap), M1-code (limiter re-key — trades one DoS for another).
   Live install M1 is a non-issue (`trust_proxy_headers=true`).

## Reference

**Key files:** `backend/auth.py` (scrypt gate) · `backend/main.py`
(register/probe/auth_status) · `backend/ssh_manager.py:HostNotTrusted` ·
`frontend/js/app.js` (`scanAcceptKeys`) · `.claude/dev-skills-gates.md` (full
per-gate record).

**Decisions:** pre-1.0, no PRs (working branch canonical); tag pushes are the
user's to run; Opus approved above the Sonnet ceiling for this task; live
pentest scoped to `:8090` only.

**Shell/env:** local CLI, Debian 13, zsh; `sudo -n docker` works; `.venv`
present; branch `claude/admiring-wright-k20ptf`; remote
https://github.com/darthrater78/pcap-server

**Next step:** if continuing, start the CI bundle (M2/M3/M4) as a work commit.
Otherwise redeploy the box.
