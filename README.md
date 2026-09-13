# pcap-server

Run tcpdump on your servers over SSH and read the results in a Wireshark-style
web interface. Captures come back encrypted, are never written to disk in the
clear, and are browsable packet by packet in the browser.

Built for the case where the machine you need to capture on is not the machine
you want to analyse from: a firewall, a hypervisor, a container host, a box you
only reach over SSH.

**Start here** — [What it does](#what-it-does) · [Requirements](#requirements) ·
[Quick start](#quick-start) · [Your first capture](#your-first-capture)

**Using it** — [Preparing a target host](#preparing-a-target-host) ·
[Taking a capture](#taking-a-capture) ·
[Streaming a capture live](#streaming-a-capture-live) ·
[Reading a capture](#reading-a-capture)

**Running it** — [Security](#security) · [Operating it](#operating-it) ·
[Architecture](#architecture) · [Development](#development) ·
[Roadmap](#roadmap)

**The longer documents.** This page is the tour; each of these is one subject in
full, for when you need it.

| | |
| --- | --- |
| [Preparing a target host](docs/target-hosts.md) | SSH access, adding and checking a server, and the three ways to give tcpdump capture privilege |
| [Filters](docs/filters.md) | The two filter languages in full, building one by clicking, and the ways a capture filter records nothing |
| [Streaming a capture live](docs/live-streaming.md) | Why a live stream needs a target, what it costs, and the two limits on it |
| [Security](docs/security.md) | Encryption at rest, transport policy, sign-in, what runs on the target, and what is *not* protected |
| [Built-in HTTPS](docs/tls.md) | Letting pcap-server get and renew its own Let's Encrypt certificate — no proxy, no inbound ports, DNS-01 through about two hundred DNS providers |
| [Reverse proxy setup](docs/reverse-proxy.md) | Getting it behind TLS — Caddy, nginx or Nginx Proxy Manager, external or as a sidecar in this stack, with DNS challenges for hosts that are not exposed |
| [Operating it](docs/operating.md) | Environment variables, admin settings, sessions, MFA recovery, TLS, rotating the master key |
| [Architecture](docs/architecture.md) | How it is built: the envelope format, every validator, and why each exists |

## What it does

**Capture.** Add a host once and it stays on your list. Pick its interface from
a list read off the machine itself, set a duration, a packet cap and a snap
length, and give it a BPF filter. A running capture reports how many packets it
has taken so far.

You do not have to know BPF. A filter library sits under the field, grouping
common expressions by what you are hunting — Kerberos, SMB, LDAP, DNS, database
ports, TCP flag matching — and you can save your own alongside it.

**Watch it happen.** Tick **Live stream** and the Viewer opens on the capture as
it records, packets appearing as they arrive. Stop it when you have seen what
you were waiting for, and it is fetched, sealed and reopened as an ordinary
stored capture.

**Read it.** A Wireshark-style packet list with protocol colouring, a decoded
protocol tree and a hex dump. Full Wireshark display-filter syntax narrows the
list, with autocomplete as you type; a filter tshark cannot parse comes back
with tshark's own message rather than an empty list.

A filter worth keeping can be **saved as a view** — a named tab on that capture,
still there when you come back next week, and downloadable as its own pcap
containing only what it selects. Timestamps can be relative, epoch, delta, the
server's UTC, or your own time zone.

**Keep it safe.** Captures are encrypted at rest under a key that never lives on
the data volume, and decrypted in flight, so no plaintext pcap ever touches
disk. Passwords are scrypt-hashed, TOTP is required, sessions are stored only as
digests, and a target host must have its SSH host keys trusted before anything
connects. Over plain HTTP the app refuses to change anything or hand a capture
over.

**Run it for a team.** Multi-user with an admin panel, per-account server lists
and stored SSH usernames, SSH keys uploaded through the UI and sealed under the
same master key, a read-only prerequisite probe that never installs anything,
and adjustable capture and session limits.

There is a true-black dark theme that costs an OLED panel nothing to display,
a light one named Flashbang for reasons that become clear at 2am, and a layout
that works down to phone width.

## Requirements

**To run pcap-server:** Docker and Docker Compose, and somewhere to put about
as much disk as your captures will weigh. Nothing else — tshark, tcpdump and
the SSH client all live inside the image. It listens on port 8080.

**On each machine you want to capture from:**

| | |
| --- | --- |
| SSH access | key-based — pcap-server never asks for, stores or sends a password for a target host. Not there yet? [Stop Using Passwords for SSH](https://ramblingnonsense.nscriven.net/p/stop-using-passwords-for-ssh) |
| `tcpdump` | installed. The prerequisite check finds it and reports the path |
| Capture privilege | `cap_net_raw` on the tcpdump binary, passwordless sudo scoped to tcpdump, or root — see [Preparing a target host](#preparing-a-target-host) |
| A writable `/tmp` | the capture is staged there and deleted after transfer |

**In the browser:** anything current. There is no build step and no framework —
the UI is plain HTML, CSS and JavaScript served by the app itself.

**HTTPS is not required to start, but the app is read-only without it** — and
read-only is enough to block a first capture. pcap-server can
[get its own certificate](docs/tls.md), or sit behind a
[reverse proxy](docs/reverse-proxy.md). See also
[Traffic in transit](docs/security.md#traffic-in-transit) and
[Running it without a reverse proxy](docs/operating.md#running-it-without-a-reverse-proxy).

## Quick start

**There is nothing to clone and nothing to build.** The image is published, and
`docker-compose.yml` is the entire install — one file, fetched straight from the
release you intend to run.

On the machine that will run pcap-server you need Docker with the Compose plugin
(`docker compose`, v2 — not the older standalone `docker-compose`) and a user
who can talk to the Docker socket. Nothing else: tshark, tcpdump and the SSH
client are all inside the image.

**Before you start, have an authenticator app on your phone.** TOTP is not
optional here and it is enforced by the API, not just the login screen — the
account you are about to create cannot finish being created without it. See
step 6.

```bash
# 1. Pick the install directory. This directory IS the install: it will hold
#    your captures and the key that decrypts them, and every relative path in
#    the compose file resolves against it. Anywhere you control is fine.
sudo mkdir -p /opt/docker/pcap && sudo chown "$USER" /opt/docker/pcap
cd /opt/docker/pcap

# 2. Fetch the compose file for a specific release. Pinning it to the tag is
#    what keeps the file and the image version it names in step with each
#    other -- see "Choosing a version" below before substituting another tag.
curl -fsSLO https://raw.githubusercontent.com/darthrater78/pcap-server/v0.1.0-dev.28/docker-compose.yml

# 3. Create the four bind-mounted directories, and close them to other users
#    on this host. All four must exist before the first start: Docker would
#    otherwise create them owned by root.
#
#    0700 is not belt-and-braces. At the default umask these are world-readable,
#    and data/ holds the SQLite database -- which stores every user's TOTP
#    secret as plain text, because the app has to compute codes from it. Anyone
#    who can read that file can generate a valid second factor for any account,
#    for as long as the secret stands. Password hashes are scrypt and sessions
#    are stored as digests, so those are a slower problem; the TOTP seeds are
#    the immediate one.
mkdir -p ssh-keys data captures secrets
chmod 0700 ssh-keys data captures secrets

# 4. The master key. Generated once, before the first start -- the app refuses
#    to start without it rather than storing captures in the clear. It is the
#    one file that opens all the others, so it is owner-read-only.
openssl rand -base64 32 > secrets/master.key
chmod 0400 secrets/master.key

# 5. Start it, and check it actually came up.
docker compose up -d
docker compose ps                                      # State should read "running"
docker compose logs pcap-server | grep -i encryption   # encryption enabled (key id ...)
```

**About ownership.** On the first start the entrypoint hands `ssh-keys/`,
`data/` and `captures/` to the container's own non-root user — `appuser`, UID
1000 — because a bind mount arrives with whatever the host gave it. If your own
account is UID 1000, which it is on most single-user Linux installs, nothing
changes for you. If it is not, those three directories stop belonging to you
after the first start and you will need `sudo` to look inside them. That is the
chown's doing, not the `chmod`; the `chmod` only stops it being silently
readable by everyone in the meantime. `secrets/` is left alone — Docker's daemon
reads the key as root before the container starts.

Two things are worth reading rather than skipping. `docker compose ps` should
show the service **running**, not `restarting` — a container that is looping is
one that failed and is being restarted for you, and `up -d` returns success
either way. And the `grep` should print `encryption enabled (key id ...)`; if it
prints nothing at all, the app did not get its key, and
[If it does not come up](#if-it-does-not-come-up) below has the three things
that cause that.

**Back that key up somewhere else before you capture anything.** It is the only
thing that can decrypt your captures, and there is no recovery path without it.
Keep it out of `data/` and `captures/`.

Every relative path in `docker-compose.yml` is resolved against the directory
that file is in, so run later `docker compose` commands from this directory too.
Absolute paths are supported and documented in the comments at the top of
`docker-compose.yml`.

### 6. Open it and create the admin account

Open `http://<host>:8080`. The first user to register becomes the admin, and
registration runs straight into TOTP enrolment: you are shown a QR code and the
secret behind it, and the account is not usable until you have entered a code
back from your authenticator. The published compose file already sets
`COOKIE_SECURE=false`, which is what lets that sign-in work over plain HTTP at
all.

Scan the QR into an app you will still have next month. If it does go missing,
an admin can reset another account's MFA from **Admin → Users → Reset MFA**, and
a locked-out *sole* admin has a host-side way back in — see
[If you lose your authenticator](docs/operating.md#if-you-lose-your-authenticator).

Once you are in, expect the app to be **read-only** — that is intended rather
than broken, and it is enough to block a first capture. See
[Running it without a reverse proxy](docs/operating.md#running-it-without-a-reverse-proxy) for
what that allows, what it refuses, and what to do about it. Then
[Your first capture](#your-first-capture).

### If it does not come up

Three failures account for almost all of them. All three are visible in
`docker compose logs pcap-server`, which is worth reading in full before
anything else — the app says what it is refusing and why.

| What you see | What it is |
|---|---|
| `bind: address already in use` | Something else already has port 8080. Change the **left** half of the `ports:` mapping in `docker-compose.yml` — `"8081:8080"` publishes it on 8081 instead. The right half is the port inside the container and does not move |
| The container restarts in a loop, logs mention the master key | Step 4 did not happen, or it produced an empty file. `secrets/master.key` must exist and be non-empty *before* the first start. Check with `wc -c secrets/master.key` — you want 45 bytes, not 0 |
| `secrets/master.key` is a directory | The compose file was started before step 3 and 4 ran, so Docker created the bind-mount path itself. Remove the empty directory, then do step 4 properly |

If you started it before creating the directories, the quickest fix is
`docker compose down`, delete whatever Docker created in their place, and go
back to step 3. Nothing is lost — there is no data yet.

### Choosing a version

| Tag | What it is |
|---|---|
| `v0.1.0-dev.28` | A specific release. What the command above fetches, and what the compose file it fetches pins its image to. Reproducible: the same tag is the same bytes next month |
| `:dev` | A floating tag that is moved to each new dev release as it is published. Convenient for tracking along, but `docker compose pull` will change the running version underneath you without the compose file changing at all |

Pin a release unless you specifically want to track. The
[releases page](https://github.com/darthrater78/pcap-server/releases) lists what
is available; substitute that tag in the `curl` above and the compose file will
name the matching image.

### Upgrading

Re-fetch the compose file at the tag you are moving to, then pull and
recreate. The tag below is the current release; substitute a later one when
there is one:

```bash
cd /opt/docker/pcap
curl -fsSLO https://raw.githubusercontent.com/darthrater78/pcap-server/v0.1.0-dev.28/docker-compose.yml
docker compose pull && docker compose up -d
```

`data/`, `captures/`, `ssh-keys/` and `secrets/` are bind mounts and are
untouched by this — the database migrates itself on start. Re-fetching the file
does discard any local edits you made to it, so if you have customised it (an
absolute path, `TRUST_PROXY_HEADERS`, a different published port), diff before
overwriting rather than after.

### If you would rather clone

Cloning still works and is the right move if you intend to change the code —
the repo carries the same `docker-compose.yml` plus the test suite and the
Dockerfile. See [Development](#development). Running it needs nothing from the
repo but that one file.

## Your first capture

1. **Upload an SSH key.** Admin → SSH Keys. It is sealed under the master key
   the moment it lands, the same way captures are.
2. **Add the server.** Servers → + Add. Give it a name, a hostname and the login
   it should use.
3. **Trust the host's keys.** Admin → Known Hosts → Trust keys, or the **Trust
   host** button on the server itself. This has to happen before anything will
   connect: a host with no trusted keys is refused rather than connected to
   unverified, so **Test connection**, **Check prerequisites** and captures all
   fail until it is done.

   You are shown each key's SHA256 fingerprint and asked to accept before
   anything is pinned. Compare them against the host itself first — on the
   target, run:

   ```bash
   for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $f; done
   ```

   The fingerprints are printed in OpenSSH's own format, so the two lists
   should match character for character. Accepting without comparing pins
   whatever answered on that address, which is the one thing host key
   verification exists to prevent.
4. **Test connection** and **Check prerequisites**, now that they can run.
5. **Sort out capture privilege** if the check says it is missing. It prints the
   exact command for the host in front of you — see
   [Preparing a target host](#preparing-a-target-host).
6. **Capture.** Capture tab: name it, pick the server and interface, set a
   duration, add a filter. It shows you what it is about to do and asks; say
   yes and the packet count starts climbing.
7. **Read it.** View on a finished capture. Click a packet for its protocol tree
   and hex dump.

## Preparing a target host

Everything a machine needs before you can capture from it — SSH access, a
`tcpdump` binary, and the privilege to use it — is in
**[docs/target-hosts.md](docs/target-hosts.md)**, along with how to add a
server, how to check one before you rely on it, and the three ways to grant
capture privilege.

The short version: **prefer a file capability** —
`sudo setcap cap_net_raw,cap_net_admin+eip $(command -v tcpdump)` — over
passwordless sudo. It grants one binary the two capabilities it needs, rather
than granting a user the right to run a program as root. pcap-server's
prerequisite check prints the exact command for the host in front of you, and
never installs or changes anything itself.

## Taking a capture

**Give it a name.** It is the first field and the form will not start without
one. Everything else about a capture is on the record afterwards — the server,
the interface, the filter — but what you were looking for is not, and a list of
captures identified by UUID is a list nobody can read a week later. Renaming
afterwards still works.

Four fields decide what the capture *contains*:

| Field | tcpdump | Effect |
| --- | --- | --- |
| Interface | `-i` | which link to read from |
| Max packets | `-c` | stop after this many packets |
| Snap length | `-s` | bytes kept per packet — lower it for headers only |
| BPF filter | expression | which packets are captured at all |

Leave the numbers blank and each falls back to the server maximum, which an
admin sets. **Live stream** is the fifth control and changes nothing about the
contents — see [Streaming a capture live](#streaming-a-capture-live).

Capturing *specific* traffic is the filter's job, and it takes full BPF syntax:
`host 10.0.0.230`, `tcp port 443`, `port 53 and not host 8.8.8.8`,
`net 192.168.1.0/24`, `vlan 100`, `icmp or arp`,
`tcp[tcpflags] & tcp-syn != 0`, `less 128`. If that is not a language you
think in, the filter library under the field has eighty-odd expressions grouped
by what you are hunting.

**Start capture asks first.** It spells out the name, server, interface,
duration, packet cap, snap length and filter before anything runs on the target.
Three of those fields read as blank when they mean "the server maximum", and
both the server and the filter persist between captures — which is how the right
capture ends up run against the wrong host.

### Your own saved filters

**Save filter**, to the left of the BPF box once there is something in it, puts
the expression into a list of your own under a name you choose. It appears at
the top of the library as **Your filters**. The Viewer's display filter has the
same button: saved display filters are listed at the top of **Filter help**, for
use on any capture.

These are **private to your account** — a capture filter usually names the hosts
and ports you are investigating, so they are treated the way your servers and
stored usernames are. Deleting one does not touch any capture already taken with
it.

### What a capture says it captured afterwards

Each capture in the list carries a badge naming its filter: the library's own
name where there is one, so `tcp port 443` shows as **HTTPS**, and the
expression itself where there is not. The exact text is on hover either way.

This matters more than it sounds. An empty packet list from a filtered capture
and an empty packet list from a quiet network look identical, and they lead to
opposite conclusions. Captures taken before this existed carry no badge: their
filter was never recorded, and it is not guessed at from the command.

### Filters that capture nothing

Joining two library picks with **…and this** is the easy way to build one. A
packet has one source port and one destination port, so asking for two services
is one condition more than there are slots for it. The filter compiles, tcpdump
runs for the full duration, and the capture comes back empty — which looks
exactly like there having been no such traffic.

pcap-server warns in two places: in the library, the moment you open the
**…and this** menu, and again before a capture whose filter cannot match
anything starts. Both are warnings rather than refusals — an odd-looking filter
you mean is still yours to run.

**[docs/filters.md](docs/filters.md)** has the rest: why `tcp port 80 and tcp
port 443` is valid and still wrong, how filters are composed for you, and where
the tcpdump flags went.

## Streaming a capture live

Tick **Live stream** on the capture form and the Viewer opens on the capture as
it records, packets appearing as they arrive — the same display filter,
autocomplete and saved views as a finished capture, because it is the same
viewer running the same tshark. Stop it when you have seen what you were waiting
for and it is fetched, sealed and reopened as an ordinary stored capture.

It needs to be pointed at something: an interface other than `any`, or a BPF
filter, or both. The preview is a fixed-size buffer held in memory, and
everything on every link fills it in seconds.

**[docs/live-streaming.md](docs/live-streaming.md)** covers why that rule
exists, what a live stream costs, the two limits that bound it, and what
happens when the preview fills up. (The capture itself is never affected — it
keeps running and is saved in full.)

## Reading a capture

**View** on a finished capture opens it in the packet viewer: a Wireshark-style
list on top, the decoded protocol tree and hex dump below, and a display-filter
box across the top.

### Captures open as tabs

Each capture you open gets its own tab on the bar at the top, next to Servers,
Capture and Admin. Open two and you can click between them — comparing a
capture taken before a change with one taken after is what the packet list is
usually for, and it should not mean going back to the list each time. Close a
tab with the **×** on it; the capture itself is untouched, and it opens again
from the Capture tab.

There is no standing **Viewer** tab. It led to an empty panel for most of a
session, and a tab that is usually empty is one people learn not to press. The
Viewer exists while something is open in it and not otherwise.

Each tab says which capture it holds, and a capture still recording carries a
pulsing dot so one left running in a background tab still says so. Inside the
panel, the line above the filter box names the **server, the interface and the
capture filter** the packets are coming from — which is the question a packet
table cannot answer, and matters most during a live stream, when a filter
narrower than you remember looks exactly like a quiet network.

### The two filters

The one thing worth getting straight before you use either.

| | Where | When it runs | Syntax | Example |
| --- | --- | --- | --- | --- |
| **Capture filter** | Capture tab | tcpdump, on the remote host, as packets go past | BPF | `tcp port 443` |
| **Display filter** | Viewer | tshark, when the list is drawn | Wireshark display syntax | `tcp.port == 443` |

The capture filter decides **what is recorded**, and anything it excludes is
gone for good. The display filter decides **what you see** out of what was
already recorded, so it costs nothing to change your mind.

Most display filters do not need to be typed. **Right-click** anything in the
viewer — a field in the detail tree at any depth, a column in the packet list,
a single TCP flag bit — and the Wireshark menu appears, including a
**Conversation filter** for both endpoints of an exchange and nothing else.

A filter tshark cannot parse comes back with tshark's own message and the
position it objected to, so an empty packet list always means the filter was
valid and nothing matched it.

**[docs/filters.md](docs/filters.md)** covers both languages properly.

### Field and byte selection

The detail tree and the hex pane are two views of the same frame. Click a field
and its bytes light up in both the hex and ASCII columns; click a byte and the
innermost field covering it is selected, with every parent opened so the row is
on screen. This works because the dissection comes from tshark's PDML output,
which reports each field's byte offset and length — the JSON output does not.

### Saved views

A display filter you will want again is worth keeping. **Save view** turns
whatever is in the filter box into a named tab on that capture — "auth
traffic", "the retransmissions", "everything to the DC" — and the tabs are
still there the next time you open it, on any machine you sign in from.

| | |
| --- | --- |
| Switching | click a tab; its filter goes into the box and the list redraws |
| **All packets** | always first, always present. It is the unfiltered capture, not a saved row, so it cannot be renamed or deleted |
| Editing | the selected tab offers rename, and will take the filter currently in the box if you have refined it |
| Downloading | **↓** on the selected tab downloads *that view* as its own pcap, containing only the packets its filter selects |
| Leaving a view | typing over the filter deselects the tab, rather than leaving it claiming to show something it no longer does |

Views are stored server-side against your account and that capture, not in the
browser, and they go when the capture does. Two things follow from that: they
survive a different browser, and another user's views are not yours to see.

**A filtered download is still packet data**, and frequently the most sensitive
slice of a capture rather than a less sensitive one — so it is refused over
plain HTTP for the same reason the full download is.

## Security

A packet capture is one of the most sensitive files a machine can produce: it
contains whatever crossed the wire, credentials included.

| | |
| --- | --- |
| Captures at rest | AES-256-GCM envelope encryption. No plaintext pcap ever touches disk, and the master key lives outside the data volume |
| In transit | Over plain HTTP the app is read-only and refuses to hand a capture over at all |
| Sign-in | scrypt passwords, mandatory TOTP, sessions stored only as digests, per-IP login throttling |
| Target hosts | SSH keys only — never a password — and a host must have its keys trusted before anything connects |
| On the target | One `tcpdump -w` per capture, no shell, and the privilege-escalating flags are refused on the built argument list |

**[docs/security.md](docs/security.md)** is the operator's account of all of
that, including
[what it does not protect against](docs/security.md#what-this-does-not-protect-against).
**[docs/architecture.md](docs/architecture.md)** is the implementation detail —
the envelope format, every validator, and why each one exists.

## Operating it

Day-to-day running lives in **[docs/operating.md](docs/operating.md)**:
environment variables, the settings an admin can change, session lifetime,
SSH key management, [recovering an account whose authenticator is
gone](docs/operating.md#if-you-lose-your-authenticator), putting it behind TLS
— and what you give up by not — and rotating the master key.

Two things are worth knowing before you read any of it:

- **Over plain HTTP the app is read-only.** It will not start a capture, hand a
  capture over, or change any setting. This is intended, and it is enough to
  block your first capture. **[Built-in HTTPS](docs/tls.md)** fixes it with no
  proxy at all — pcap-server requests and renews its own Let's Encrypt
  certificate — or **[Setting up a reverse proxy](docs/reverse-proxy.md)**
  does, with Caddy, nginx or Nginx Proxy Manager each worked start to finish; and
  [Running it without a reverse proxy](docs/operating.md#running-it-without-a-reverse-proxy)
  covers what you can still do if you would rather not.
- **`COOKIE_SECURE=false` is already set** in the published compose file, which
  is what lets sign-in work over plain HTTP at all. Set it back to `true` once
  you are behind TLS.

## Architecture

- **Backend** — Python/FastAPI with asyncssh for SSH connections
- **Frontend** — vanilla HTML/CSS/JS, no build step
- **Database** — SQLite with WAL mode
- **Container** — Docker with python:3.12-slim base, runs as non-root user

**[docs/architecture.md](docs/architecture.md)** is the full account: how a
capture flows from the form to the viewer, how it is encrypted at rest and
decrypted in flight without ever becoming a plaintext file, what every input
validator is defending against, and where the honest limits are.

## Development

```bash
git clone https://github.com/darthrater78/pcap-server.git
cd pcap-server
./scripts/check.sh
```

`scripts/check.sh` is the whole test story. It builds a virtualenv, installs
`backend/requirements-dev.txt` into it, reports which of tshark, tcpdump,
capinfos and a chromium binary it found, and runs pytest with `-r s` so a
skipped test is printed with its reason rather than quietly dropped.
`.github/workflows/check.yml` runs that same script rather than reimplementing
the checks, so CI and a developer's machine cannot pass and fail independently
of each other.

**It needs Python 3.11–3.13, and it picks the interpreter itself.** The ceiling
is not a preference: `pydantic-core` ships no wheel above cp313, and pip's
source fallback needs PyO3 ≤ 3.13, so on a newer Python the install dies in a
Rust build that never mentions Python versions. Distributions have started
shipping 3.14 as `python3` — Fedora 44 does — which made the script unrunnable
on a current machine.

So it searches `python3.12`, `python3.13`, `python3.11`, then `python3`, and
uses the first one in range; 3.12 comes first because that is what the
Dockerfile and CI use. Set `PYTHON=/path/to/python3.12` to override the search,
and it will refuse rather than quietly pick something else. An existing `.venv`
is checked too, not trusted — one built by an out-of-range interpreter is
rebuilt, because otherwise a single bad run poisons every later one with the
same unreadable failure. If nothing suitable is installed it says so in one
line, with the range and what it found:

```
No supported Python found. This project needs 3.11-3.13; pydantic-core has no
wheel above 3.13 and its source build refuses to compile.
Found: python3 = 3.14.7
Install one (e.g. 'sudo dnf install python3.12'), or set PYTHON=/path/to/python3.12
```

**Missing tools skip, they do not fail.** The suites that need tshark,
capinfos or a browser report as SKIPPED with the remedy in the reason. That is
deliberate — but a green run with twenty skips is not the same as a green run,
so read the skip list.

| Tool | Needed by | Get it |
| --- | --- | --- |
| `tshark`, `capinfos` | packet list, detail and count suites | your distribution's `tshark`/`wireshark-cli` package |
| chromium | `tests/browser` | `python -m playwright install chromium`, or point `PCAP_TEST_CHROMIUM` at one you already have |
| `tcpdump` | reported for completeness; captures run on the remote host | your distribution's `tcpdump` package |

**Layout.**

| Path | What is in it |
| --- | --- |
| `backend/main.py` | every route, the middleware, and the app's wiring |
| `backend/models.py` | pydantic models and every input validator |
| `backend/capture.py` | a capture's life from start to a terminal status |
| `backend/ssh_manager.py` | connections, the prerequisite probe, key handling |
| `backend/crypto.py`, `vault.py`, `pcapsource.py`, `rekey.py` | encryption at rest, and reading it back without a plaintext file |
| `backend/resetmfa.py` | host-side second-factor reset, for when nobody can sign in to press the button |
| `backend/packet_parser.py` | everything that shells out to tshark or capinfos |
| `backend/database.py` | the SQLite schema and every query |
| `backend/serve.py` | the container's entry point: opens the vault, then starts uvicorn, over TLS when a certificate is stored |
| `backend/tls/` | built-in HTTPS, self-contained: DNS provider allowlist, sealed storage, the one place lego runs, renewal, Admin routes and `python -m backend.tls` |
| `frontend/` | `index.html`, `css/style.css`, `js/app.js`, `js/tls.js`. No build step |
| `scripts/` | `check.sh`, the test entry point; `gen_lego_providers.py`, which regenerates the provider allowlist when lego's version moves |
| `docs/` | one document per subject; the README links them all from the top |
| `tests/` | API and unit suites |
| `tests/browser/` | playwright suites driving the real UI |

**Running it against your own changes:**

```bash
docker compose up --build
```

The compose file bind-mounts `./data` and `./captures`, so state survives a
rebuild.

**A note on style.** Comments in this codebase explain *why*, and frequently
name the bug that made the code what it is. That is on purpose: a check with no
stated reason is a check the next person deletes. Keep it up in anything you
add.

## Roadmap

- **MCP server** — expose servers, captures and packet queries over the Model
  Context Protocol, so an agent can drive pcap-server as tools rather than by
  imitating a browser session. The open questions are authorisation, since an
  MCP client is not a browser session and should not inherit one, and how much
  of a capture should be allowed to cross that boundary.
- **Packet sanitizer** — produce a redacted copy of a capture that is safe to
  share outside the team: strip or mask payloads and cleartext credentials, and
  optionally rewrite addresses consistently so traffic patterns survive while
  identities do not. It pairs with the encryption already here — that protects
  what must not leave, this defines what may.

## License

See repository for license details.
