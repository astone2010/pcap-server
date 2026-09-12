# Changelog

## 0.1.0-dev.8 — 2026-09-12

### Security

- **Captures are encrypted at rest.** A packet capture routinely contains
  credentials in cleartext, so the stored pcap is now sealed with AES-256-GCM
  under a per-capture key, which is itself wrapped by a master key that never
  lives on the data volume. The plaintext never touches a filesystem at any
  point: the capture is sealed chunk by chunk as it streams off the remote host
  over SFTP, tshark and capinfos read it from stdin rather than a file, and a
  download is decrypted straight into the response. Truncation, tampering,
  chunk reordering and splicing between files are all detected rather than read
  as a short capture.
- The master key comes from one of three sources, chosen by configuration: a
  file (a Docker secret — the default, since an environment variable is
  readable via `docker inspect` and `/proc/<pid>/environ`), an environment
  variable, or a passphrase an admin types after each start, which exists only
  in memory. **Startup fails closed**: without a key the app refuses to start
  and prints the exact remedy, unless `ALLOW_UNENCRYPTED_CAPTURES=true` says
  otherwise. A key that does not open the existing captures also stops startup,
  since continuing would strand them while writing new ones under a different
  key. Captures written before this release are sealed at startup, verified,
  and only then is the plaintext removed.
- **Over plain HTTP the app is read-only.** Anything that changes state is
  refused — SSH key upload and deletion, adding or editing servers, starting
  captures, settings, user creation — as is downloading a capture. Sign-in
  remains possible, because refusing it would leave no way in rather than a
  degraded way in. The refusal is a structured response the UI explains in
  place, the sign-in banner announces the restriction and the remedies, and the
  Download button renders disabled rather than failing when clicked.
  `X-Forwarded-Proto` is honoured only when `TRUST_PROXY_HEADERS=true`, since
  any client can send it.
- **Fix a login rate-limiter bypass.** The client address was taken from
  `X-Forwarded-For` unconditionally, and from the leftmost entry — which the
  client controls. A caller could present a fresh address per request and never
  trip the limiter, giving unlimited password guessing against a directly
  exposed instance, and equally against one behind a proxy using the usual
  `$proxy_add_x_forwarded_for`. The header is now consulted only with a trusted
  proxy configured, and the rightmost (proxy-appended) entry is used.
- **Servers may no longer point at the machine pcap-server runs on.** Capturing
  an interface that carries its own traffic records its own sign-in; over plain
  HTTP the admin password is recoverable verbatim from the resulting pcap, which
  is then stored and browsable. Hostnames resolving to loopback, to an address
  the container answers on, to the default gateway (the Docker host on a bridge
  network), or to a published host alias are refused on add, save, edit, and on
  loading a profile stored before this check existed. The alert names the
  address it matched and explains the exposure.
- **Add a Content-Security-Policy and companion headers.** Output escaping is
  the first line of defence and is tested, but one missed escape among 38
  `innerHTML` sites would be an XSS. `connect-src`, `img-src` and `form-action`
  mean script running on the page cannot send anything to another host;
  `frame-ancestors` and `X-Frame-Options` stop clickjacking; `base-uri` stops an
  injected `<base>` re-pointing every relative URL. Also `nosniff`,
  `no-referrer`, a restrictive `Permissions-Policy`, COOP/CORP, and HSTS only
  where TLS is genuinely in use. `script-src` still needs `'unsafe-inline'`
  because the UI uses inline event handlers, which cannot carry a nonce.
- Session and device-trust cookies move from `SameSite=Lax` to `Strict`. Lax
  still sends the cookie on a top-level GET, and the capture download is a GET.
- **Password hashing records its parameters.** The stored format was
  `salt$hash` with the scrypt cost implicit, so it could never be raised without
  invalidating every existing password. Hashes are now
  `scrypt$N$r$p$salt$hash` at N=2^17 (current OWASP guidance), old hashes still
  verify, and a correct sign-in transparently re-hashes at the new cost. The
  passphrase-derived master key uses the same cost. Hashing runs in a worker
  thread: at this cost it would otherwise block the event loop for roughly half
  a second per sign-in and make the login endpoint an easy way to stall the app.
- Do not disclose the running version to unauthenticated callers.
  `/api/auth/status` needs no session, so publishing the build there tells
  anyone who can reach the login page which advisories to match.
- Update `cryptography` 41.0.7 → 50.0.1 and `asyncssh` 2.18.0 → 2.24.0. The
  former was pinned to whatever a build container happened to have and carries
  known CVEs; the latter is the SSH implementation itself.
- Close the SSH connection carrying a capture. `run_tcpdump` returned only the
  tcpdump process, leaving its connection with no owner and no close path: it
  stayed open after tcpdump had exited and was reclaimed only whenever the
  garbage collector reached it. Measured against a live SSH server, every
  capture stranded one authenticated connection to the target host, outliving
  the work it was opened for. The process and its connection are now bound
  together and closed as one unit from the monitor's `finally`, from delete and
  at shutdown — verified released after success, after failure, on delete, on
  shutdown, on early abandon, and across ten sequential captures with no
  accumulation. The five short-lived operations (connection test, interface
  list, prerequisite check, pcap download, remote cleanup) were already closed
  by their context managers and were confirmed clean by the same measurement.
- Bound the SSH login. Without `login_timeout` a host that accepted TCP but
  never completed the handshake held the request open indefinitely.
- Add keepalives and a monitor ceiling. A capture may run for minutes, so a peer
  that disappeared mid-capture left the server waiting on a dead socket.
  Keepalives now detect it, and the monitor gives up at the capture's duration
  plus a minute — the remote `timeout(1)` wrapper only helps when `timeout(1)`
  is present and behaves.
- Bound the pcap download at 300 seconds, and discard a partially transferred
  capture rather than leaving a truncated file on the volume.
- Do not disclose the exact running version to unauthenticated callers.
  `/api/auth/status` is reachable without a session, so publishing the build
  there tells anyone who can see the login page which advisories to match. The
  repo and releases links are public and remain; the precise version and its
  release-notes link appear only once signed in.
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

### Features

- Admin → Capture encryption shows whether captures are encrypted, the key
  source, the key fingerprint, and how many captures are encrypted or still
  plaintext. In passphrase mode it offers the unlock form. A banner outside the
  admin panel says when captures are unencrypted or when the vault is locked, so
  neither state is discoverable only by going looking for it.
- Guides for running behind a reverse proxy: `docs/nginx.conf.example` and
  `docs/nginx-proxy-manager.md`. Both call out `proxy_buffering off`, without
  which nginx spools a decrypted capture to its own disk and undoes encrypting
  captures at rest.
- Link the GitHub repository and release notes from every screen. Signed in, the
  toolbar carries a version badge pointing at the running version's release
  notes, served by the backend so it cannot drift from the code. Signed out, the
  sign-in screen footer links the repo and the releases index.
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
