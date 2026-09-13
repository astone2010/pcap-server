# Plan: built-in ACME / certbot certificates

*Working document for 0.1.0-dev.28. Not user documentation — delete or rewrite
as `docs/tls.md` when the feature ships.*

## The goal

pcap-server obtains and renews its own Let's Encrypt certificate, so a single
`docker compose up -d` gives you HTTPS with no reverse proxy at all. The proxy
guides stay — they are right for anyone already running one — but they stop
being the *only* way to get out of read-only mode.

## Prior art: Termix

`Termix-SSH/Termix`, `src/backend/database/routes/acme-ssl-routes.ts`. Worth
reading; it is a working implementation of exactly this.

**What they do:**

- certbot runs inside the container, `execFileSync("certbot", argv)` — argv
  array, never a shell string.
- Admin UI stores `{domain, email, challengeType, cloudflareToken}` where
  challenge is `http-webroot` | `dns-cloudflare` | `manual`.
- `--webroot -w <dir>` for HTTP-01; `--dns-cloudflare` with a credentials ini
  written at mode `0600` for DNS-01.
- Certs copied to `data/ssl/termix.{crt,key}`, key `0600`, cert `0644`.
- **nginx is bundled in their image** and terminates TLS;
  `reloadNginxWithSSL()` reloads it after issuance.

**Three things not to copy:**

1. **No validation of `domain` or `email`.** Only a presence check, and both go
   into argv after `-d`. There is no shell, so no shell injection — but a value
   beginning with `-` is argument injection into certbot's own parser. This repo
   already has that discipline (`assert_no_forbidden_flags`, the BPF and
   interface validators) and must apply it here.
2. **The Cloudflare token is stored as plain JSON in the settings table.** A DNS
   API token can edit the zone. That is master-key-class material and this repo
   already has the machinery to protect it.
3. **No renewal automation** that I could find — an admin-triggered endpoint
   only. Let's Encrypt certificates last 90 days.

## Decisions already taken

| | |
| --- | --- |
| **uvicorn terminates TLS**, not a bundled nginx | We have no nginx in the image and one process in the container. uvicorn takes `--ssl-certfile` / `--ssl-keyfile`. Cost: no hot reload, so renewal needs a restart — every ~60 days, and schedulable |
| **Seal the TLS private key** under the master key, like SSH keys | **Decided by the user.** Termix accepts a plaintext `privkey.pem` on the data volume; we do not. The app's whole claim is that no plaintext sensitive material lives there |
| **DNS-01 is the documented default** | A capture server is usually internal. DNS-01 needs outbound access only, so the host never has to be exposed |
| **Own release** | dev.28, against a clean dev.27 base |

### What sealing the key implies

This is the part that needs design rather than typing, because uvicorn wants a
**file path**, and the point of sealing is that no plaintext file exists.

Sketch to validate before building:

1. certbot writes `privkey.pem` under a certbot config dir.
2. We seal it with the existing envelope (`crypto.py`, the same path
   `ssh_manager` uses for keys) into `data/ssl/server.key.enc`, then shred the
   certbot copy. The certificate itself is public — no need to seal it.
3. At startup, `vault` opens the sealed key and writes it to a path that is
   **not on the data volume**: a `tmpfs` mount, or `/run` inside the container.
   uvicorn is pointed at that path. It exists only while the process runs.
4. If the vault is locked (`ENCRYPTION_MODE=passphrase`), there is no key to
   open at startup — so the app cannot serve TLS until an admin unlocks it,
   which is a chicken-and-egg problem worth thinking about before committing to
   this design. **Open question.** Possible answers: fall back to HTTP and say
   so loudly; or accept that passphrase mode and built-in TLS are incompatible
   and refuse the combination at startup with a clear message.

The `tmpfs` requirement means the compose file gains a mount, which means the
no-clone Quick start's compose file changes — and that is a version-pinned file
people fetch by tag. Worth calling out in the release notes.

## Shape of the work

**Backend**

- `backend/acme.py` — issuance, renewal, and the certbot argv builder. Nothing
  else shells out.
- Validators in `models.py`: a strict domain rule and an email rule. Neither may
  begin with `-`; a domain is labels of `[A-Za-z0-9-]` separated by dots, and
  nothing else. Test the rejection of `-d`, `--config-dir`, spaces and empties.
- Admin routes, `require_admin`, mutating ones therefore already covered by
  `enforce_read_only_over_http` — but note the bootstrap problem: **you are on
  plain HTTP when you configure this**, which is exactly when the app is
  read-only. `/api/admin/acme/*` will have to join `_INSECURE_ALLOWED_PATHS`,
  and that is a deliberate, documented exception needing its own justification
  in the security docs. **This is the single most security-sensitive decision in
  the feature.** Consider requiring it to be reachable only from a local
  connection, reusing whatever `_is_local_connection` already does.
- The DNS token sealed via the existing vault, decrypted only into the `.ini`
  for the duration of the certbot call, then removed. Never logged.
- Renewal in `_housekeeping()` (`main.py:114`) — it already runs a daily-ish
  loop. Check expiry with `openssl x509 -checkend`, renew under 30 days.

**Image**

- `certbot` plus one plugin package **per DNS provider**. This is the real
  dependency cost and why Termix hardcoded Cloudflare. Start with Cloudflare
  only and say so.

**Docs**

- A new `docs/tls.md`, and the proxy guides gain a line saying there is now a
  third option.

## Test plan

- Unit: the argv builder, given adversarial domains and emails. No network.
- Unit: seal/open round trip for the key, and that the plaintext file is gone.
- Integration: point it at Let's Encrypt **staging** — never production in a
  test — or stub the certbot binary with a fixture that writes known pems.
- The renewal check against a certificate generated with a short lifetime.

## What this does NOT change

The read-only-over-HTTP rule stays exactly as it is. This feature gives people a
way to *get* HTTPS; it does not relax what happens without it.
