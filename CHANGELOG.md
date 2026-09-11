# Changelog

## 0.1.0-dev.6 — 2026-09-11

### Features

- Move the flag picker from Capture to the Viewer, where the flags actually do
  something. A capture is always written with `tcpdump -w`, so tcpdump's display
  flags never changed the saved pcap; they now control how the packet list is
  rendered instead, mapped onto tshark: `-n`/`-nn` disable name resolution,
  `-e` adds MAC address columns, and `-t`/`-tt`/`-ttt`/`-tttt` pick the
  timestamp format. Flags that cannot affect a list view (`-v`, `-q`, `-A`,
  `-X`, `-XX`) are gone. Changing one re-renders immediately, and the
  timestamp and resolution flags are mutually exclusive.
- Flags are split into a "Standard" box (`-n`, `-nn`, with `-nn` on by default
  and dot-marked) and a "Niche" box for the situational rest. The buttons are
  larger and a selected one is clearly highlighted.
- Add a light theme alongside the dark one, with a toggle in the toolbar.
  Dark stays the default and the choice is remembered; the palette moves to
  neutral slate with a teal accent, and packet colours are tuned per theme.
- Persist capture history to SQLite. Captures, and the ability to download
  them, now survive a container restart; previously the list lived only in
  memory, so restarting orphaned every `.pcap` on disk. A capture that was
  running when the server stopped is marked failed, since its remote process
  is gone.
- Colour-code the packet list in the viewer the way Wireshark does: problems
  (retransmissions, duplicate ACKs, zero window, unreachable) in red, resets,
  session open/close, and a distinct colour per protocol — ARP, ICMP, DNS,
  HTTP, TLS/QUIC, UDP, TCP — with a legend above the table.
- Adapt the layout for phones. Panels stack into one column, the capture form
  reflows, the packet table scrolls sideways instead of being crushed, and the
  sign-in screen scrolls on short viewports.

### Fixes

- Don't pass `-n` twice when it is also picked as an extra flag, and drop it
  entirely when `-nn` is selected, since `-nn` supersedes it.

## 0.1.0-dev.5 — 2026-09-11

### Features

- Run tcpdump under `sudo -n` per server, for hosts where the SSH user is not
  root. Set on the server, so every capture against it inherits the choice.
- Edit a saved server after creation — name, host, port, username, SSH key and
  the sudo flag. Previously a key could only be chosen at creation time.
- Pick the capture interface from a dropdown populated by reading
  `/sys/class/net` on the target host, instead of typing a name blind.
- Every tcpdump flag in the picker now has a tooltip, and selected flags are
  explained in a list under the picker.

- Warn on the sign-in page when the cookie setting and the page's protocol
  disagree. Plain HTTP with `COOKIE_SECURE=true` shows a red banner saying
  sign-in cannot work and how to fix it; HTTPS with `COOKIE_SECURE=false`
  shows a yellow banner that the session cookie is unprotected. `localhost`
  is exempt, since browsers treat it as a secure context.
- `/api/auth/status` reports `cookie_secure` so the page can detect the
  mismatch.

### Fixes

- A failed capture now reports tcpdump's actual stderr instead of the fixed
  string "capture failed". The remote command no longer ends in `; true`, which
  was discarding tcpdump's exit status.

### Security

- Reject the tcpdump flags that become privilege escalation under sudo — `-z`
  and `--postrotate-command` run commands as root, `-W`/`-G`/`-C` enable the
  rotation that fires them, and `-r`/`-F`/`-V` read arbitrary files. The module
  refuses to import if any is ever added to the allowlist.
- Validate interface names against a strict character allowlist rather than
  blocking a handful of shell metacharacters.
- `escHtml` now escapes quotes, so interpolating a value into an HTML attribute
  cannot break out of it.

## 0.1.0-dev.4 — 2026-09-11

### Fixes

- Fix TOTP setup screen appearing to never load after creating the admin
  account — the `hidden` attribute was overridden by `.auth-container`'s
  `display: flex`, so all three screens rendered stacked and the QR code sat
  one full viewport below the register form

## 0.1.0-dev.3 — 2026-09-11

### Fixes

- Fix login/registration failing over plain HTTP — session cookie had
  `Secure` flag hardcoded, browsers silently dropped it on non-HTTPS

### Changes

- `COOKIE_SECURE` env var controls Secure cookie flag (default: true)
- Set `COOKIE_SECURE=false` in docker-compose for HTTP/LAN deployments

## 0.1.0-dev.2 — 2026-09-11

### Fixes

- Fix container crash on startup when bind-mount directories are not owned by
  UID 1000 — entrypoint now auto-fixes ownership before starting
- SSH keys managed via Admin GUI (upload/delete) instead of manual file placement

### Changes

- Remove `build.yml` CI workflow — builds only run on tag push
- ssh-keys volume no longer mounted read-only (app writes uploaded keys)
- Add `gosu` to container for privilege drop in entrypoint

## 0.1.0-dev.1 — 2026-09-11

Development build, not yet merged to `main`. Tagged directly from a feature
branch so the packaged build can be tested before a stable release is cut.

### Features

- Remote packet capture via SSH using tcpdump
- Wireshark-style web UI for packet list and detail views
- Multi-user authentication with scrypt password hashing
- TOTP-based two-factor authentication with QR code setup
- Trusted device cookies to skip MFA on recognized browsers
- Saved server profiles per user
- SSH host key verification using Trust On First Use (TOFU)
- Admin panel for managing users, settings, and known hosts
- GUI-configurable settings: capture duration, packet count, session length,
  device trust period, rate limiting
- Per-user capture isolation — users see only their own captures
- Automatic cleanup of remote tcpdump processes on shutdown
- Rate limiting on login with configurable lockout
- Docker deployment with non-root container user
- CI release workflow — builds and pushes Docker image to GHCR on tag push
- Bind-mount volumes for persistent data and captures
