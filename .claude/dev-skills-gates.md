# Dev Skills gate state
Track: release sequence (dev pre-release — branch not merged to main)
Version: 0.1.0-dev.8
Updated: 2026-09-12

🔢 VERSION    ✅ 0.1.0-dev.8 in main.py, docker-compose.yml, CHANGELOG; v0.1.0-dev.7 confirmed tagged on remote at 9085701
🔨 BUILD      ✅ 121 checks green across 5 suites (60 unit, 26 API incl. restart-signs-out, 22 session, 9 banner over a routable IP, 7 settings-validator over HTTP). Caveat: no docker daemon in this container, so the image was not rebuilt (Dockerfile unchanged by this diff)
🔒 SECURITY   ✅ 0 Critical, 0 High. This release IS the security work: session tokens hashed at rest (was plaintext bearer — anyone reading the db could replay sessions), sessions invalidated on restart, configurable idle timeout, cleartext-HTTP banner. Self-review of the diff caught and fixed 3 issues before commit: per-request SQLite write amplification, unreachable "0 disables", undocumented single-worker assumption
📄 DOCS       ✅ CHANGELOG dev.8 entry; README gains a "Sessions" section covering all three expiry paths and the single-process requirement
📦 RELEASE    ➖ N/A — dev pre-release, no PR to main
🚀 SHIP       ⏳ — commit approved by user; tag push v0.1.0-dev.8 is the user's to run

Env: remote container (Claude executes git after approval; tag pushes handed to user)
Branch: claude/admiring-wright-k20ptf

Deferred by user decision (2026-09-12):
- Encryption at rest: envelope encryption with a PLUGGABLE key source — Docker
  secret/env as the shipped default, admin passphrase (RAM-only) as an option.
  Plaintext SSH keys must stop touching disk: load into asyncssh from memory.
  Also covers TOTP secrets and, arguably, captured pcaps.
- TLS/ACME (Let's Encrypt): deferred entirely, "too much to add right now".
  Recommendation on record: Caddy sidecar over certbot; reachability question
  (HTTP-01 vs DNS-01) still unanswered and must be settled first.
- Distro templates: recommended AGAINST. tcpdump syntax is identical across
  distros (libpcap). Detect, don't template.

Next: prereq test + discovered tcpdump path (per user, after this commit).
