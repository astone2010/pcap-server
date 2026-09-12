# Dev Skills gate state
Track: release sequence (dev pre-release — branch not merged to main)
Version: 0.1.0-dev.8  (NOT yet tagged — user deferred tagging; prereq work folded in rather than burning dev.9)
Updated: 2026-09-12

🔢 VERSION    ✅ 0.1.0-dev.8 in main.py, docker-compose.yml, CHANGELOG; v0.1.0-dev.7 tagged on remote at 9085701
🔨 BUILD      ✅ 249 checks green across 9 suites (adds SSH connection-leak measurement against a live server, CaptureManager lifecycle, and always-visible repo/release links). This container now HAS tcpdump 4.99.4 + tshark, so for the first time the viewer was tested against a real 40-packet capture and the probe against a real SSH server running a real /bin/sh. Caveat: no docker daemon, image not rebuilt (Dockerfile unchanged)
🔒 SECURITY   ✅ 0 Critical, 0 High. FIXED a leaked SSH connection per capture (authenticated connection to a production host outliving its work, measured server-side); added login timeout, keepalives, monitor ceiling, bounded download; stopped disclosing the exact version to unauthenticated callers. Probe output treated as untrusted: hostile-host suite proves command-injection, traversal, substitution and non-tcpdump paths are all rejected, and the discovered path is re-validated before storage. Probe asserted read-only by test (no package manager, no writes, only `sudo -n true`)
📄 DOCS       ✅ CHANGELOG dev.8 gains Features + Changed sections; README gains "Checking a server before you capture" incl. the PATH and setcap findings and why there are no distro templates
📦 RELEASE    ➖ N/A — dev pre-release, no PR to main
🚀 SHIP       ⬜ — user has deferred tagging until more work lands

Env: remote container (Claude executes git after approval; tag pushes handed to user)
Branch: claude/admiring-wright-k20ptf

CORRECTION ON RECORD: dev.7's changelog claimed -n/-nn were fixed in the viewer.
Testing against real tshark showed that was over-stated. tshark's Info column
prints ports numerically regardless of resolution settings (verified on port 80:
-N mt and -n give byte-identical output), so tcpdump's ports-named-vs-numeric
distinction is not expressible in this view at all. Host names additionally need
nameres.network_name AND nameres.use_external_name_resolver. Replaced both chips
with one explicit "Resolve hostnames" toggle, default off, since resolution means
reverse-DNS on every address in a capture. dev.8's changelog records this.

Deferred by user decision:
- Encryption at rest: envelope encryption, PLUGGABLE key source — Docker
  secret/env as shipped default, admin passphrase (RAM-only) optional. Stop
  writing plaintext SSH keys to disk: asyncssh.import_private_key takes bytes.
  Scope should include captured pcaps (a capture of cleartext traffic is a
  credential dump) and TOTP secrets.
- TLS/ACME: deferred. Recommendation on record: Caddy sidecar over certbot.
  Reachability (HTTP-01 vs DNS-01) unanswered and must be settled first.
- Tagging: user wants more work landed before any tag is cut.
