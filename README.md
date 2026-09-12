# pcap-server

Remote packet capture and analysis tool with a Wireshark-style web interface.
Connect to remote servers via SSH, run tcpdump captures, and analyze packets
in your browser.

## Features

- **Remote capture** — run tcpdump on remote servers over SSH
- **Packet analysis** — Wireshark-style packet list and protocol detail views
- **Multi-user** — scrypt password hashing, TOTP two-factor auth, trusted devices
- **Admin panel** — manage users, configure settings, scan SSH host keys
- **SSH host key verification** — Trust On First Use (TOFU) with known hosts database
- **Persistent servers** — servers you add are scoped to your account and last until you delete them, surviving restarts
- **Saved servers** — store connection profiles per user, editable after creation
- **sudo support** — run tcpdump via `sudo -n` per server, for non-root SSH users
- **Interface discovery** — pick the capture interface from a list read off the target host
- **BPF filtering** — full Berkeley Packet Filter syntax selects the traffic, with an in-app cheatsheet
- **Prerequisite check** — read-only probe for tcpdump, privilege, PATH and SELinux; never installs anything
- **View flags** — MAC columns and timestamp format, each documenting what it does
- **Optional name resolution** — off by default, because resolving addresses from a capture queries DNS
- **Capture provenance** — every capture records the server it ran against, and keeps it even if that server is later deleted
- **Colour-coded packets** — Wireshark-style colouring by protocol, with problems and resets called out
- **Light and dark themes** — dark by default, toggled from the toolbar and remembered
- **Works on phones** — the layout adapts down to phone width
- **Configurable** — capture limits, session duration, rate limiting all adjustable from the GUI
- **Process safety** — remote tcpdump processes are always cleaned up on shutdown

## Quick Start

```bash
git clone https://github.com/darthrater78/pcap-server.git
cd pcap-server
docker compose up -d
```

Open `http://localhost:8080`. The first user to register becomes the admin.

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SSH_KEYS_DIR` | `/app/ssh-keys` | Directory for SSH private keys |
| `CAPTURES_DIR` | `/app/captures` | Directory for downloaded pcap files |
| `DATA_DIR` | `/app/data` | Directory for the SQLite database. Users, servers, known hosts, settings and capture history all live here, so keep it on a persistent volume. |
| `COOKIE_SECURE` | `true` | Require HTTPS for the session cookie. Set to `false` for plain-HTTP/LAN use, or sign-in will not work. |

### Admin Settings (GUI)

These are configurable from the Admin tab by the admin user:

| Setting | Default | Description |
|---|---|---|
| Max capture seconds | 300 | Maximum duration for a single capture |
| Max capture packets | 100000 | Maximum packets per capture |
| Max concurrent captures | 5 | Captures running or finishing up at once, across all users — each holds an SSH connection to a target host plus a local file |
| Session duration (hours) | 8 | Login session lifetime |
| Session idle timeout (minutes) | 60 | Idle window before a session is deleted, independent of the absolute duration above. `0` disables idle expiry |
| Device trust (days) | 30 | How long a trusted device skips MFA |
| Rate limit attempts | 5 | Failed login attempts before lockout |
| Rate limit lockout (minutes) | 15 | Lockout duration after too many failures |

## What changes a capture

A capture always runs as `tcpdump -w <file>`, so that a pcap comes back for
analysis. `-w` turns tcpdump from a printer into a writer: it stops formatting
text and writes raw packet records. tcpdump's display flags — `-v`, `-vv`,
`-vvv`, `-q`, `-A`, `-X`, `-XX`, `-e`, `-n`, `-nn`, `-t`/`-tt`/`-ttt`/`-tttt` —
format text that is never emitted under `-w`, so they cannot affect the capture
and are not accepted. The ones that describe how to *read* a capture live in the
Viewer instead, where they change the packet list.

Four things decide what a capture contains, and each is a field on the capture
form:

| Field | tcpdump | Effect |
| --- | --- | --- |
| Interface | `-i` | which link to read from |
| Max packets | `-c` | stop after this many packets |
| Snap length | `-s` | bytes kept per packet — lower it for headers only |
| BPF filter | expression | which packets are captured at all |

Capturing *specific* traffic is the filter's job, not a flag's, and the filter
takes full BPF syntax: `host 10.0.0.230`, `tcp port 443`,
`port 53 and not host 8.8.8.8`, `net 192.168.1.0/24`, `vlan 100`, `icmp or arp`,
`tcp[tcpflags] & tcp-syn != 0`, `less 128`.

Shell metacharacters are rejected in the filter, which is passed to tcpdump as a
single quoted argument after `--`. `-z`, `-W`, `-G`, `-C`, `-r`, `-F`, `-V` and
`-Z` are permanently refused: tcpdump may be running under `sudo`, and those turn
a capture into code execution or file reads as root.

## Checking a server before you capture

**Servers → Check prerequisites** probes a host for what a capture needs and
reports what it found. Every command it runs is a read; the one privileged call
is `sudo -n true`, which answers "would sudo work" without doing anything. **It
never installs or changes anything** — where something is missing it prints the
command for you to run yourself.

It checks the OS, whether tcpdump is installed and where, whether tcpdump is on
the SSH session's PATH, whether capture privilege exists, whether `/tmp` is
writable, and the SELinux mode.

Two findings are worth knowing about in advance:

- **tcpdump is usually in `/usr/sbin`, which a non-login SSH session often drops
  from PATH for non-root users.** A bare `tcpdump` then fails with "command not
  found" on a host where it is plainly installed. The check records the absolute
  path and captures use it, so this resolves itself once you have run the check.
- **`setcap` beats sudo.** `sudo setcap cap_net_raw,cap_net_admin+eip
  /usr/sbin/tcpdump` lets an unprivileged user capture with no sudo at all, and
  it works the same on every distribution. The check recommends this first.

There are no per-distribution templates, and deliberately so: tcpdump is libpcap
everywhere, so its flags and filter syntax are identical across distributions.
What differs is PATH, whether sudo exists and which group grants it (`wheel` on
RHEL-family, `sudo` on Debian-family), and SELinux — all of which the probe reads
off the host rather than guessing from a distribution label. The detected distro
is used for exactly one thing: printing the right install command.

## SSH connection lifetime

A capture uses two SSH connections, and both are released deterministically:

| Connection | Lifetime |
| --- | --- |
| The capture | Bound to the tcpdump process and closed with it — on success, failure, timeout, delete and shutdown alike |
| The pcap download | Its own short-lived connection, closed by its context manager, bounded at 300s |

Connection test, interface discovery, the prerequisite check and remote cleanup
each open and close their own connection for the single command they run.

Connections use a 15 second login timeout, so a host that accepts TCP without
completing the SSH handshake cannot hang a request, and keepalives every 30
seconds (three missed before the connection is dropped) so a peer that
disappears mid-capture is noticed rather than waited on. The capture monitor
gives up at the capture's duration plus 60 seconds regardless.

## Behind a reverse proxy

Over plain HTTP pcap-server is read-only — see [Sessions](#sessions) and the
banner the app shows. Putting it behind TLS restores full access. A worked nginx
config is in [`docs/nginx.conf.example`](docs/nginx.conf.example), and there is a
separate guide for **[Nginx Proxy Manager](docs/nginx-proxy-manager.md)**, which
generates its own config and needs different steps. Three settings are
load-bearing and easy to miss.

**1. Tell the app that TLS terminated at the proxy.**

```nginx
proxy_set_header X-Forwarded-Proto $scheme;
```

and set `TRUST_PROXY_HEADERS=true` in the container. Without both, pcap-server
sees a plain-HTTP request and stays read-only. The header is only trusted when
that variable is set, because anyone can send it.

**2. Do not publish the app port once you trust that header.**

Trusting `X-Forwarded-Proto` means anyone who can reach the app directly can
claim to be the proxy. Bind it to loopback, or drop `ports:` entirely and put
nginx on the same Docker network:

```yaml
    ports:
      - "127.0.0.1:8080:8080"   # not "8080:8080"
```

**3. Turn proxy buffering off.**

```nginx
proxy_buffering off;
```

A capture download is decrypted on the fly. With buffering on, nginx spools
large responses to `proxy_temp_path`, which writes an unencrypted copy of the
pcap onto the proxy's disk — undoing the point of encrypting captures at rest.

One more worth setting: `proxy_set_header X-Forwarded-For $remote_addr;` rather
than the usual `$proxy_add_x_forwarded_for`. The latter appends the real peer to
whatever the client sent, leaving attacker-supplied text in the header.
pcap-server reads the rightmost entry for exactly that reason, but sending only
the address nginx saw removes the ambiguity.

Caddy is an alternative worth knowing about: it obtains and renews Let's Encrypt
certificates itself, and needs about five lines. nginx is fine — it just needs
certbot alongside it.

## Sessions

Sessions are bearer tokens in an `HttpOnly` cookie, stored only as a SHA-256
digest so the database never holds anything replayable. Three things end a
session:

| Limit | Where | Default |
| --- | --- | --- |
| Absolute lifetime | Admin → Settings, `Session duration (hours)` | 8 hours |
| Idle timeout | Admin → Settings, `Session idle timeout (minutes)` | 60 minutes (0 disables) |
| Restart | automatic | every session is invalidated when the container starts |

Because sessions are cleared at startup, restarting the container signs everyone
out — including you. Trusted devices are separate and survive a restart; they
skip the TOTP prompt, not the sign-in.

Run pcap-server as a single process. Starting uvicorn with `--workers` would
clear sessions once per worker as each boots, signing users out repeatedly.

## SSH Keys

Upload private keys from the **Admin** tab. They are stored in the `ssh-keys/`
directory (mounted at `/app/ssh-keys`) and offered as options when connecting to
a remote server. Keys can be uploaded and deleted from the GUI; no manual file
placement is needed. When a master key is configured (`MASTER_KEY_FILE` in
`docker-compose.yml`), uploaded keys are sealed under it the same way
captures are — a key never exists as a plaintext file on disk, and one
uploaded before encryption was enabled is sealed in place automatically the
next time the container starts.

## Running tcpdump with sudo

tcpdump usually needs root to open a capture interface. If the SSH user is not
root, tick **Run tcpdump with sudo** on the server, and grant that user
passwordless sudo for tcpdump only:

```
# /etc/sudoers.d/pcap-server
pcapuser ALL=(root) NOPASSWD: /usr/bin/tcpdump
```

pcap-server invokes `sudo -n`, so a host that still demands a password fails
immediately with a clear error rather than hanging.

**Understand what this grants.** `tcpdump` can run arbitrary commands as root
via its `-z` flag and read any file via `-r`, so anyone who can open a shell as
`pcapuser` on that host effectively has root there. pcap-server never sends
those flags — `-z`, `-Z`, `-W`, `-G`, `-C`, `-r`, `-F` and `-V` are rejected by
a server-side allowlist that refuses to start if one is ever added to it, and
every argument is shell-quoted — but the sudoers grant itself is still a
privilege boundary you are choosing to open. Prefer a dedicated, unprivileged
account used only by pcap-server, and don't reuse it for anything else.

## Architecture

- **Backend** — Python/FastAPI with asyncssh for SSH connections
- **Frontend** — vanilla HTML/CSS/JS, no build step
- **Database** — SQLite with WAL mode
- **Container** — Docker with python:3.12-slim base, runs as non-root user

## Development

```bash
docker compose up --build
```

The Docker Compose file mounts `./data` and `./captures` as bind mounts for
persistent storage across container restarts.

## License

See repository for license details.
