# pcap-server

Run tcpdump on your servers over SSH and read the results in a Wireshark-style
web interface. Captures come back encrypted, are never written to disk in the
clear, and are browsable packet by packet in the browser.

Built for the case where the machine you need to capture on is not the machine
you want to analyse from: a firewall, a hypervisor, a container host, a box you
only reach over SSH.

**Contents** — [Quick start](#quick-start) · [HTTPS](#https) ·
[Your first capture](#your-first-capture) · [What it does](#what-it-does) ·
[Requirements](#requirements) · [Using it](#using-it) ·
[Security](#security) · [Operating it](#operating-it) ·
[Development](#development) · [Roadmap](#roadmap) ·
[Documentation](#documentation)

## Quick start

**There is nothing to clone and nothing to build.**

1. Go to
   [`docker-compose.yml`](https://github.com/darthrater78/pcap-server/blob/v0.1.0-dev.40/docker-compose.yml)
   and follow the setup steps at the top of it. They have you paste its
   service block into a file named `compose.yaml` on your Docker host.
2. **Back up the master key** it generates somewhere other than this machine.
   It is the only thing that can decrypt your captures.
3. Open `http://<host>:8080` and create the admin account. Have an
   authenticator app ready — TOTP is required to finish.
4. **Turn on HTTPS** — see [HTTPS](#https). Until you do, the app is read-only.

Container not starting, or want a different version or to upgrade? See
[Installing](docs/operating.md#installing) in the operating guide.

## HTTPS

**pcap-server does not work properly without HTTPS, and that is on purpose.**
Over plain HTTP you can sign in and read captures you already have, and nothing
else: no adding a server, no starting a capture, no uploading an SSH key, no
downloads. A capture holds whatever crossed the wire, credentials included, and
the app will not move one over a connection anyone on the path can read. There
is no setting that turns this off. ([Why](docs/security.md#traffic-in-transit).)

There are three ways to get it:

| | What you need | Browser warning | Guide |
| --- | --- | --- | --- |
| **1. Built-in Let's Encrypt** — **recommended** | A domain whose DNS is at one of about two hundred supported providers (Cloudflare, Route 53, DigitalOcean, Hetzner, Porkbun, Duck DNS, deSEC…) and an API token for it | None | [Built-in HTTPS](docs/tls.md) |
| **2. A reverse proxy with a real certificate** | Nginx Proxy Manager, Caddy or nginx | None | [Reverse proxy setup](docs/reverse-proxy.md) |
| **3. A reverse proxy with a self-signed certificate** | Nginx Proxy Manager, Caddy or nginx. **No domain needed** | Yes, until each browser trusts the certificate | [Self-signed certificate](docs/reverse-proxy.md#no-domain-a-self-signed-certificate) |

**The built-in route** needs no proxy and no inbound port — Let's Encrypt checks
a DNS record, not a connection, so a machine on a private LAN address still gets
a real certificate, and it renews itself:

1. Point a name at the machine (`pcap.example.com` → its address; a LAN address
   is fine).
2. Make an API token at your DNS provider, limited to DNS edits on that zone.
3. **Admin → HTTPS → Set up certificate**: enter the domain, an email, the
   provider and the token, then **Request certificate** and **Switch to HTTPS**.
4. Browse to `https://pcap.example.com:8080` and sign in again.

Typed into the Admin panel over plain HTTP, the token crosses your network
unencrypted; [docs/tls.md](docs/tls.md#from-the-docker-host) has a command-line
route that keeps it on the host, plus renewal, passphrase mode and
troubleshooting.

## Your first capture

HTTPS first — every step below changes something, and none of them work over
plain HTTP.

1. **Add an SSH key.** Admin → SSH keys. Upload the private key file or paste it
   in. It must have no passphrase: pcap-server connects unattended.
2. **Add the server.** Servers → + Add, with a name, a hostname and the login to
   use. It must be a *different* machine from the one pcap-server runs on.
3. **Accept the host's keys.** The first connection shows the host's SSH key
   fingerprints for you to accept. Compare them against the host before
   accepting — [Adding a server](docs/target-hosts.md#adding-a-server) shows how.
4. **Test connection** and **Check prerequisites**.
5. **Sort out capture privilege** if the check says it is missing — it prints
   the exact commands for that host. See
   [Preparing a target host](#preparing-a-target-host).
6. **Capture.** **Capture from this server** opens the Capture tab with it
   chosen. Name it, pick the interface, set a duration, add a filter, confirm.
7. **Read it.** **View** on the finished capture.

## What it does

**Capture.** Add a host once and it stays on your list. Pick its interface from
a list read off the machine itself, set a duration, a packet cap and a snap
length, and give it a BPF filter — or pick one from a library grouped by what
you are hunting (Kerberos, SMB, LDAP, DNS, database ports, TCP flags).

**Read it.** A Wireshark-style packet list with protocol colouring, a decoded
protocol tree and a hex dump. Full display-filter syntax with autocomplete,
right-click to filter, **Follow TCP/UDP Stream**, **Protocol Hierarchy** and
**Conversations**, custom columns, and saved views you can download as their own
pcap.

**Share it.** **Sanitize** downloads a copy with credentials masked and
addresses, hostnames and usernames replaced by consistent stand-ins.

**Keep it safe.** Captures are encrypted at rest under a key that never lives on
the data volume, and decrypted in flight. Passwords are scrypt-hashed, TOTP is
required, and a target host's SSH keys must be trusted before anything connects.

**Run it for a team.** Multi-user with an admin panel, per-account server lists,
SSH keys uploaded through the UI and sealed under the master key, and a
read-only prerequisite probe that never installs anything.

There is a true-black dark theme, a light one named Flashbang for reasons that
become clear at 2am, and a layout that works down to phone width.

<img width="2550" height="853" alt="Test connection and prerequisite check" src="https://github.com/user-attachments/assets/2f33e3e5-d2bb-4fa0-9d36-8f72687861fb" />
Validate SSH key with Test Connection and perform a prerequisite check

<img width="1333" height="388" alt="Capture page" src="https://github.com/user-attachments/assets/a24074a5-d314-4461-849d-7cbcda455cc5" />
Full capture page allows for viewing, pcap sanitization, and/or download.

<img width="2555" height="804" alt="Interface selection" src="https://github.com/user-attachments/assets/c2e58875-4cf1-413e-86e2-04c40b09e49a" />
Easily target any interface on the remote

<img width="2528" height="693" alt="BPF filter library" src="https://github.com/user-attachments/assets/c94b24f2-673a-4b6b-a27d-6b8060907e2c" />
Interactive BPF filter library on the capture screen.

<img width="2527" height="1254" alt="Packet viewer" src="https://github.com/user-attachments/assets/50f6039e-6c9d-4441-a9d5-8a367a3a37c4" />
Wireshark like actions in the browser for quick analysis.

<img width="1293" height="388" alt="Encryption" src="https://github.com/user-attachments/assets/c78d0b10-a470-46b5-92d4-06d0205e1cdb" />
Robust encryption and security for data moving and at rest

<img width="1293" height="459" alt="ACME integration" src="https://github.com/user-attachments/assets/dfb547f3-adcc-4f40-8567-63c1e2e15c71" />
ACME/Certbot Integration

<img width="2550" height="853" alt="Flashbang theme" src="https://github.com/user-attachments/assets/dbb3a01e-81ad-4f7c-9f96-b4f2779481f5" />
For those who hate eyes, a "Flashbang" theme.

## Requirements

**To run pcap-server:** Docker with the Compose plugin, and disk for your
captures. tshark, tcpdump and the SSH client are inside the image. It listens on
port 8080.

**On each machine you want to capture from:**

| | |
| --- | --- |
| SSH access | key-based — pcap-server never uses a password for a target host. Not there yet? [Stop Using Passwords for SSH](https://ramblingnonsense.nscriven.net/p/stop-using-passwords-for-ssh) |
| `tcpdump` | installed |
| Capture privilege | `cap_net_raw` on tcpdump, passwordless sudo scoped to tcpdump, or root — see [Preparing a target host](#preparing-a-target-host) |
| A writable `/tmp` | the capture is staged there and deleted after transfer |

**In the browser:** anything current. **HTTPS:** not needed to install, needed
before anything useful — see [HTTPS](#https).

## Using it

### Preparing a target host

The short version: **prefer a file capability over passwordless sudo**, on a
tcpdump only a `pcap` group can run:

```bash
sudo groupadd -f pcap && sudo usermod -aG pcap <ssh-user>
sudo chgrp pcap /usr/sbin/tcpdump && sudo chmod 750 /usr/sbin/tcpdump
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump   # last: chgrp clears it
```

**Check prerequisites** prints these with the real path and username for each
host, and never changes anything itself.
**[docs/target-hosts.md](docs/target-hosts.md)** covers the sudo alternative,
why `cap_net_admin` is not needed, host key trust, and why the machine
pcap-server runs on is refused as a target.

### Taking a capture

Give it a name, pick the interface, and set the limits — blank numbers fall back
to the server maximum an admin sets:

| Field | tcpdump | Effect |
| --- | --- | --- |
| Interface | `-i` | which link to read from |
| Max packets | `-c` | stop after this many packets |
| Snap length | `-s` | bytes kept per packet — lower it for headers only |
| BPF filter | expression | which packets are captured at all |

**Start capture** shows everything it is about to run and asks first, because
the server and filter persist between captures.

**Watch for filters that capture nothing.** `tcp port 80 and tcp port 443` is
valid and matches nothing — a packet has only one source and one destination
port. pcap-server warns about this, but an empty capture looks exactly like a
quiet network. **[docs/filters.md](docs/filters.md)** covers both filter
languages, saved filters, and these traps in full.

### Reading a capture

**View** opens a capture in its own tab: packet list, protocol tree and hex
dump, with a display filter across the top. Right-click anything to filter on
it, follow a stream, or add it as a column. Save a filter as a named view and
download just those packets.

**[docs/viewer.md](docs/viewer.md)** covers columns, the interface column on
`any` captures, Follow Stream, Protocol Hierarchy, Conversations and saved
views.

### Sanitizing a capture

**Sanitize** downloads a copy with credentials masked and IP addresses, MAC
addresses, hostnames and usernames replaced — the same stand-ins every time for
the same capture. It is best effort: read the summary it shows before sharing,
and use **Strip payload** for anything leaving your hands.
**[docs/sanitizing.md](docs/sanitizing.md)** lists every option and its limits.

## Security

A packet capture contains whatever crossed the wire, credentials included.

| | |
| --- | --- |
| Captures at rest | AES-256-GCM envelope encryption. No plaintext pcap ever touches disk, and the master key lives outside the data volume |
| In transit | Over plain HTTP the app is read-only and refuses to hand a capture over at all |
| Sign-in | scrypt passwords, mandatory TOTP, sessions stored only as digests, per-IP login throttling |
| Target hosts | SSH keys only, and a host must have its keys trusted before anything connects |
| On the target | One `tcpdump -w` per capture, no shell, and the privilege-escalating flags are refused |

**[docs/security.md](docs/security.md)** is the full account, including
[what it does not protect against](docs/security.md#what-this-does-not-protect-against).

## Operating it

**[docs/operating.md](docs/operating.md)** covers installing, troubleshooting,
upgrading, environment variables, admin settings,
[recovering a lost authenticator](docs/operating.md#if-you-lose-your-authenticator),
and rotating the master key.

One thing catches people out: after changing `COOKIE_SECURE` or
`TRUST_PROXY_HEADERS` in your `compose.yaml`, run `docker compose up -d`, not
`docker compose restart` — a restart keeps the old environment.

## Development

```bash
git clone https://github.com/darthrater78/pcap-server.git
cd pcap-server
./scripts/check.sh
```

Python/FastAPI and asyncssh on the backend, vanilla HTML/CSS/JS with no build
step on the front, SQLite for storage, in a non-root container.
**[docs/development.md](docs/development.md)** covers the test script, the
supported Python versions, the code layout, and running the container against
your own changes. **[docs/architecture.md](docs/architecture.md)** is how it is
built and why.

## Roadmap

- **Windows targets** — capture from Windows machines, likely via `dumpcap.exe`
  over Npcap.
- **MCP server** — expose servers, captures and packet queries to agents over
  the Model Context Protocol.

Details in [docs/architecture.md](docs/architecture.md#roadmap).

## Documentation

| | |
| --- | --- |
| [Built-in HTTPS](docs/tls.md) | Let pcap-server get and renew its own Let's Encrypt certificate |
| [Reverse proxy setup](docs/reverse-proxy.md) | Caddy, nginx or Nginx Proxy Manager, with a real or self-signed certificate |
| [Preparing a target host](docs/target-hosts.md) | SSH access, adding a server, host key trust, capture privilege |
| [Filters](docs/filters.md) | Capture and display filters, and the ways a filter records nothing |
| [Reading a capture](docs/viewer.md) | The packet viewer: columns, streams, statistics, saved views |
| [Sanitizing a capture](docs/sanitizing.md) | Every sanitize option, and what it cannot promise |
| [Security](docs/security.md) | Encryption at rest, transport policy, sign-in, and what is not protected |
| [Operating it](docs/operating.md) | Installing, upgrading, troubleshooting, settings, MFA recovery, key rotation |
| [Development](docs/development.md) | Tests, layout, building locally |
| [Architecture](docs/architecture.md) | How it is built, every validator, and why each exists |

## License

See repository for license details.
