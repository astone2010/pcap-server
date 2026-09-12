# Changelog

## 0.1.0-dev.8 — 2026-09-12

### Features

- Add a read-only prerequisite check per server (Servers → Check prerequisites).
  It probes the host for what a capture needs and reports a checklist: OS,
  whether tcpdump is installed and at what absolute path, whether it is on the
  SSH session's PATH, whether capture privilege exists (root, `cap_net_raw` on
  the binary, or passwordless sudo), whether /tmp is writable, and the SELinux
  mode. **Nothing is installed and nothing is elevated beyond `sudo -n true`.**
  On a miss it prints the command for the operator to run themselves, with the
  install hint matched to the detected distribution. `setcap` is offered ahead
  of sudo, since it removes the need for sudo altogether.
- Captures now invoke tcpdump by its discovered absolute path. tcpdump lives in
  `/usr/sbin`, which a non-login SSH session frequently omits from PATH for
  non-root users — so a bare `tcpdump` could fail with "command not found" on a
  host where it was plainly installed. The prerequisite check records the real
  path and captures use it.
- Everything the probe returns is treated as untrusted input. A discovered path
  must be absolute, free of shell metacharacters, and named `tcpdump`, and it is
  re-validated before it is stored — a hostile or compromised host answering
  with `/bin/sh -c ...` is discarded rather than executed.

### Changed

- Replace the viewer's `-n`/`-nn` chips with a single explicit
  **Resolve hostnames** toggle, default off. dev.7 claimed these flags were
  fixed; testing against real tshark showed that was over-stated, and the
  reason is structural rather than a bug in the mapping:
  tshark's Info column prints ports numerically whatever name resolution is set
  to — verified on a capture to port 80, where `-N mt` and `-n` produce
  byte-identical output — so tcpdump's "ports named vs numeric" distinction has
  nowhere to appear in this view. And host names need both
  `nameres.network_name` and `nameres.use_external_name_resolver`; `-N mnt`
  alone changes nothing, and the hosts file is only consulted when the external
  resolver is on. So the only resolution that alters this view is host lookup,
  and it costs a reverse-DNS query for every address in the capture. On a tool
  used to examine suspicious traffic that tells the resolver what is being
  investigated, so it is off by default and the control says what it does.

### Security

- Session tokens are no longer stored in the clear. The `sessions` table held
  the bearer token verbatim, so anyone able to read the database file could
  replay every live session; trusted-device tokens were already hashed, so the
  schema disagreed with itself. Sessions are now looked up by SHA-256 digest.
  Tokens issued before this are not recognised and are cleared on startup.
- A restart signs everyone out. Sessions live in SQLite on a persistent volume,
  so they outlived the container that issued them — including one restarted to
  apply a security fix. Every session is invalidated at startup.
- Add a configurable idle timeout, `Session idle timeout (minutes)` in
  Admin → Settings, default 60. `session_duration_hours` remains an absolute
  cap; the idle window closes a session that stops being used. An idle session
  is deleted rather than merely refused, so a later request cannot revive it.
  Set it to 0 to disable idle expiry and keep only the absolute cap.
- Warn when the app is served over plain HTTP with `COOKIE_SECURE=false`. The
  banner covered HTTP with Secure cookies required, and HTTPS with them
  disabled, but not the override itself — the one configuration where sign-in
  works normally and the session cookie, password and TOTP code all cross the
  network in cleartext. That case was silent. `localhost` stays quiet, since
  browsers treat it as a secure context.

### Fixes

- Throttle the `last_seen` write to once a minute. Stamping it on every
  authenticated request turned each API call into a SQLite write, which on a
  single-writer database is wasteful and risks lock contention. The interval is
  far shorter than any usable idle window, so timeouts are unaffected.
- Accept 0 for the idle timeout in Admin → Settings. The settings validator
  required every value to be >= 1, which made the documented "0 disables it"
  unreachable from the GUI.

## 0.1.0-dev.7 — 2026-09-11

### Features

- Servers added under **Servers** are now permanent. They were held in a
  process-global dictionary, so every one of them disappeared on restart and had
  to be re-added by hand; they are now rows in SQLite and last until you delete
  them. They are also scoped to the user who added them — previously every
  logged-in user could list, test, delete and capture from every other user's
  servers.
- A server can be given an optional name when it is added, shown in the server
  list in place of the bare hostname.
- Captures record the server they came from. The list used to resolve the
  capture's `server_id` against the servers loaded in the browser, which meant
  a bare UUID after any restart and for any server since deleted. Each capture
  now stores a label — `name (user@host)`, or `user@host` when unnamed — stamped
  when the capture starts, so it stays correct forever.

- Remove tcpdump's display flags from the capture API. `-v`, `-vv`, `-vvv`,
  `-q`, `-A`, `-X`, `-XX`, `-e`, `-n`, `-nn` and the `-t` family were still
  accepted on `POST /api/captures` even though dev.6 dropped them from the UI,
  and dev.6's changelog described them as gone when only the UI had lost them.
  A capture is always written with `tcpdump -w`, which makes tcpdump a writer
  rather than a printer: it emits no text, so none of those flags can change a
  byte of the pcap. `extra_flags` is gone entirely — what a capture contains is
  decided by the interface, packet count, snap length and BPF filter, all of
  which are structured fields. The Capture panel now carries an explainer
  covering why, and a BPF filter cheatsheet, since selecting specific traffic
  is the filter's job rather than a flag's.
- The refusal of `-z`, `-W`, `-G`, `-C`, `-r`, `-F`, `-V` and `-Z` moves from
  validating user-supplied flags to asserting against the fully-built tcpdump
  command, including the `sudo -n` prefix. Nothing user-supplied reaches the
  argument list any more, so the check should be unreachable — which is why it
  is checked rather than assumed.

### Fixes

- Stop appending `-n` to the capture command. It was inert under `-w` and only
  made the command string shown against each capture look like it did something.
- `-n` and `-nn` in the viewer did nothing. The packet list read `ip.src` and
  `ip.dst`, which tshark always renders numerically whatever name resolution is
  set to, so neither flag could change what you saw and the two were mapped onto
  the same tshark flag anyway. The list now reads the resolved Source and
  Destination columns, and the flags map the way tcpdump means them: `-nn`
  resolves nothing, `-n` keeps port names but not host names, and selecting
  neither resolves both. This also fixes ARP, IPv6 and other non-IP packets,
  which previously showed `N/A` for both addresses because they have no `ip.src`.
- `-tt` and `-tttt` worked but were invisible. The timestamp column is a fixed
  100px in a `table-layout: fixed` table with `text-overflow: ellipsis`, so an
  epoch or full date was clipped to roughly `Sep 11, 202…`. Each format now gets
  a column width that fits it, `-t` collapses the column instead of leaving a
  gap, and the timestamp, source and destination cells carry their full value as
  a tooltip.

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
