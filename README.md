# pcap-server

Run tcpdump on your servers over SSH and read the results in a Wireshark-style
web interface. Captures come back encrypted, are never written to disk in the
clear, and are browsable packet by packet in the browser.

Built for the case where the machine you need to capture on is not the machine
you want to analyse from: a firewall, a hypervisor, a container host, a box you
only reach over SSH.

> **HTTPS is not optional.** Over plain HTTP pcap-server is read-only: it will
> not add a server, start a capture or hand one over, so a fresh install cannot
> take its first capture until HTTPS is on. **The recommended way is built in** —
> pcap-server gets its own Let's Encrypt certificate, with no proxy and no open
> ports. No domain? A reverse proxy with a self-signed certificate works too.
> **[Choose one →](#https)**

**Start here** — [What it does](#what-it-does) · [Requirements](#requirements) ·
[**HTTPS**](#https) · [Quick start](#quick-start) ·
[Your first capture](#your-first-capture)

**Using it** — [Preparing a target host](#preparing-a-target-host) ·
[Taking a capture](#taking-a-capture) ·
[Reading a capture](#reading-a-capture) ·
[Sanitizing a capture](#sanitizing-a-capture)

**Running it** — [Security](#security) · [Operating it](#operating-it) ·
[Architecture](#architecture) · [Development](#development) ·
[Roadmap](#roadmap)

**The longer documents.** This page is the tour; each of these is one subject in
full, for when you need it.

<img width="2550" height="853" alt="image" src="https://github.com/user-attachments/assets/2f33e3e5-d2bb-4fa0-9d36-8f72687861fb" />
Validate SSH key with Test Connection and perform a prerequisite check

<img width="1333" height="388" alt="image" src="https://github.com/user-attachments/assets/a24074a5-d314-4461-849d-7cbcda455cc5" />
Full capture page allows for viewing, pcap sanitization, and/or download.

<img width="2555" height="804" alt="image" src="https://github.com/user-attachments/assets/c2e58875-4cf1-413e-86e2-04c40b09e49a" />
Easily target any interface on the remote

<img width="2528" height="693" alt="image" src="https://github.com/user-attachments/assets/c94b24f2-673a-4b6b-a27d-6b8060907e2c" />
Interactive BPF filter library on the capture screen. 


<img width="2527" height="1254" alt="image" src="https://github.com/user-attachments/assets/50f6039e-6c9d-4441-a9d5-8a367a3a37c4" />
Wireshark like actions in the browser for quick analysis. 

<img width="1293" height="388" alt="image" src="https://github.com/user-attachments/assets/c78d0b10-a470-46b5-92d4-06d0205e1cdb" />
Robust encryption and security for data moving and at rest

<img width="1293" height="459" alt="image" src="https://github.com/user-attachments/assets/dfb547f3-adcc-4f40-8567-63c1e2e15c71" />
ACME/Certbot Integration

<img width="2550" height="853" alt="image" src="https://github.com/user-attachments/assets/dbb3a01e-81ad-4f7c-9f96-b4f2779481f5" />
For those who hate eyes, a "Flash-bang" theme. 


| | |
| --- | --- |
| [Built-in HTTPS](docs/tls.md) | **Recommended.** Letting pcap-server get and renew its own Let's Encrypt certificate — no proxy, no inbound ports, DNS-01 through about two hundred DNS providers |
| [Reverse proxy setup](docs/reverse-proxy.md) | Getting it behind TLS — Caddy, nginx or Nginx Proxy Manager, with a real certificate or [a self-signed one](docs/reverse-proxy.md#no-domain-a-self-signed-certificate) when there is no domain |
| [Preparing a target host](docs/target-hosts.md) | SSH access, adding and checking a server, and the three ways to give tcpdump capture privilege |
| [Filters](docs/filters.md) | The two filter languages in full, building one by clicking, and the ways a capture filter records nothing |
| [Security](docs/security.md) | Encryption at rest, transport policy, sign-in, what runs on the target, and what is *not* protected |
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

**Read it.** A Wireshark-style packet list with protocol colouring, a decoded
protocol tree and a hex dump. Full Wireshark display-filter syntax narrows the
list, with autocomplete as you type; a filter tshark cannot parse comes back
with tshark's own message rather than an empty list. Right-click anything for
Apply/And/Or as filter, **Follow TCP/UDP Stream**, or one of the two
toolbar-level views — **Protocol Hierarchy** and **Conversations** — for the
shape of a capture without reading it packet by packet.

A filter worth keeping can be **saved as a view** — a named tab on that capture,
still there when you come back next week, and downloadable as its own pcap
containing only what it selects. Timestamps can be relative, epoch, delta, the
server's UTC, or your own time zone.

**Share it.** **Sanitize** downloads a copy of a finished capture — or of one
saved view — with credentials masked and IP addresses, MAC addresses, hostnames
and usernames replaced by stand-ins that stay the same every time you sanitize
that capture. It is built as it downloads, so no sanitized copy is stored, and
it ends with an account of what it replaced and what it could not.

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

**HTTPS.** Not needed to install, but needed before anything useful — see the
next section.

## HTTPS

**pcap-server does not work properly without HTTPS, and that is on purpose.**
Over plain HTTP you can sign in and read captures you already have, and nothing
else: no trusting a host's keys, no adding a server, no starting a capture, no
uploading an SSH key, no downloads. A capture holds whatever crossed the wire,
credentials included, and the app will not move one — or accept a private key —
over a connection anyone on the path can read. There is no setting that turns
this off. ([Why](docs/security.md#traffic-in-transit).)

So decide how you will get HTTPS **before you install**. There are three ways:

| | What you need | Browser warning | Guide |
| --- | --- | --- | --- |
| **1. Built-in Let's Encrypt (ACME)** — **recommended** | A domain whose DNS is at one of about two hundred supported providers — Cloudflare, Route 53, DigitalOcean, Hetzner, Porkbun and more — and an API token for it | None. A real certificate, renewed automatically | [Built-in HTTPS](docs/tls.md) |
| **2. A reverse proxy with a real certificate** | Nginx Proxy Manager, Caddy or nginx, getting a certificate for your domain | None | [Reverse proxy setup](docs/reverse-proxy.md) |
| **3. A reverse proxy with a self-signed certificate** | Nginx Proxy Manager, Caddy or nginx. **No domain, no DNS account** | Yes, until each browser is told to trust the certificate | [Self-signed certificate](docs/reverse-proxy.md#no-domain-a-self-signed-certificate) |

### Recommended: let pcap-server get its own certificate

This is the least to run and the least to expose. There is no proxy to maintain,
**no inbound port** — Let's Encrypt checks a DNS record, not a connection to the
machine, so a box on a private LAN address gets a real, browser-trusted
certificate — and it renews itself.

1. **Install it and create the admin account** — [Quick start](#quick-start),
   steps 1–6. That much works over plain HTTP.
2. **Point a name at the machine** — say `pcap.example.com` → its address. A
   private LAN address is fine.
3. **Make an API token at your DNS provider**, limited to DNS edits on that one
   zone. On Cloudflare: **My Profile → API Tokens → Create Token → Edit zone
   DNS**, with the zone set to yours. It is the same token Nginx Proxy Manager
   asks for.
4. **Admin → HTTPS → Set up certificate.** Enter the domain and a contact email,
   pick the provider and paste the token, then **Request certificate** (about a
   minute) and **Switch to HTTPS**.
5. **Browse to `https://pcap.example.com:8080`** and sign in again.

Two things to know. Typed into the Admin panel over plain HTTP, the token
crosses your network unencrypted — the
[command-line route](docs/tls.md#from-the-docker-host) keeps it on the host
instead. And it needs a master key the app can read unattended, so it is not
available in [passphrase mode](docs/tls.md#passphrase-mode).

**No domain of your own?** Free names from [Duck DNS](https://www.duckdns.org/)
and [deSEC](https://desec.io) are among the supported providers.

### No domain: a proxy with a self-signed certificate

If you do not own a domain, or would rather not set up a DNS provider account,
put **Nginx Proxy Manager, Caddy or nginx** in front of pcap-server with a
certificate you make yourself. The app never sees the certificate: the proxy
terminates HTTPS and tells the app the connection was encrypted, so everything
works exactly as it does with a real one.

The cost is the browser: it warns that it does not recognise the certificate
until you import it (or Caddy's local root) as trusted on each machine you
browse from. The proxy settings are the same as for a real certificate, and
they matter just as much: the app must be told to trust the proxy, and **nothing
but the proxy may be able to reach the app's port**.

**[Self-signed certificate](docs/reverse-proxy.md#no-domain-a-self-signed-certificate)**
has each of the three worked through, with the one command that makes the
certificate.

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
curl -fsSLO https://raw.githubusercontent.com/darthrater78/pcap-server/v0.1.0-dev.33/docker-compose.yml

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

Once you are in, expect the app to be **read-only**, with a bar across the top
saying so. That is intended rather than broken — and it is why the next step is not
optional.

### 7. Turn on HTTPS

**Admin → HTTPS → Set up certificate**, as in
[the recommended route](#recommended-let-pcap-server-get-its-own-certificate) —
or put a proxy in front, with a real certificate or a
[self-signed one](#no-domain-a-proxy-with-a-self-signed-certificate). When the
read-only bar is gone, go on to [Your first capture](#your-first-capture).

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
| `v0.1.0-dev.33` | A specific release. What the command above fetches, and what the compose file it fetches pins its image to. Reproducible: the same tag is the same bytes next month |
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
curl -fsSLO https://raw.githubusercontent.com/darthrater78/pcap-server/v0.1.0-dev.33/docker-compose.yml
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

HTTPS first — [step 7 of the Quick start](#7-turn-on-https). Every step below
changes something, and none of them work over plain HTTP.

1. **Upload an SSH key.** Admin → SSH keys. It is sealed under the master key
   the moment it lands, the same way captures are.
2. **Add the server.** Servers → + Add. Give it a name, a hostname and the login
   it should use.
3. **Trust the host's keys.** Admin → Known hosts → Trust keys, or the **Trust
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
6. **Capture.** **Capture from this server** on the server's page opens the
   Capture tab with it already chosen. Name the capture, pick the interface, set
   a duration, add a filter. It shows you what it is about to do and asks; say
   yes and the packet count starts climbing.
7. **Read it.** View on a finished capture. Click a packet for its protocol tree
   and hex dump.

## Preparing a target host

Everything a machine needs before you can capture from it — SSH access, a
`tcpdump` binary, and the privilege to use it — is in
**[docs/target-hosts.md](docs/target-hosts.md)**, along with how to add a
server, how to check one before you rely on it, and the three ways to grant
capture privilege.

The short version: **prefer a file capability over passwordless sudo**, on a
tcpdump only a `pcap` group can run:

```bash
sudo groupadd -f pcap && sudo usermod -aG pcap <ssh-user>
sudo chgrp pcap /usr/sbin/tcpdump && sudo chmod 750 /usr/sbin/tcpdump
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump   # last: chgrp clears it
```

It grants one binary the one capability capturing needs, rather than granting a
user the right to run a program as root, and the group keeps other accounts on the
host from capturing with it. pcap-server's prerequisite check prints these
commands with the real path and username for the host in front of you — on a
server already using sudo too — and never installs or changes anything itself.
Some guides add `cap_net_admin` as well; a capture does not need it, and where a
host does not allow it (many containers) tcpdump will not start at all — see
[docs/target-hosts.md](docs/target-hosts.md).

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
admin sets.

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

Each tab says which capture it holds. Inside the panel, the line above the
filter box names the **server, the interface and the capture filter** the
packets are coming from — which is the question a packet table cannot answer,
and matters most when a filter narrower than you remember looks exactly like a
quiet network.

### Which interface a packet crossed

A capture on `any` has an **Interface** column: the interface each packet went
through and which way — `eth0 out`, `docker0 in`, `bcast` for broadcast. The
file itself only numbers interfaces, so pcap-server reads the host's names when
the capture starts and again when it ends. Right-click a cell for **Apply as
filter** on `sll.ifindex`, the same menu every other column offers. An
interface that existed only in the middle of a capture shows as `#3`, and an
older tcpdump that writes the first cooked format records no interface at all,
so the column shows just the direction. Captures on a named interface have no
such column.

**The name does not survive a download.** The mapping lives only in
pcap-server's own database; the `.pcap` file itself — classic pcap, the same
format tcpdump always wrote — has nowhere to carry it. Opened elsewhere, a
downloaded capture still shows the raw interface **index** (`sll.ifindex`,
under *Linux cooked capture v2* in any real Wireshark's own packet detail —
no plugin needed), just not the name that went with it here. If you need a
specific interface's traffic to stay identifiable after download, filter to
it first — right-click the column, **Apply as filter**, then download that —
rather than downloading the whole `any` capture and losing the mapping.

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
a single TCP flag bit — and the Wireshark menu appears: Apply / Not / And /
Or / Prepare as filter, a **Conversation filter** for both endpoints of an
exchange and nothing else, **Copy value** for the raw reading, and **Copy as
filter** for the expression built from it.

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

**Export bytes**, in the detail toolbar once a packet is selected, saves that
packet's raw bytes as a `.bin` file — built client-side from the same hex the
detail pane already holds, so it costs no extra request.

### Follow a stream

Right-click a TCP or UDP packet — its row in the list, or anywhere in its
detail pane — for **Follow TCP Stream** / **Follow UDP Stream**: the whole
conversation, reassembled in the order it was sent, one colour per direction.
**Set as display filter** narrows the packet list to the same stream
(`tcp.stream eq N` / `udp.stream eq N`).

### Protocol Hierarchy and Conversations

Two toolbar buttons give the shape of a capture without reading it packet by
packet. **Protocol Hierarchy** breaks it down by layer — `eth` → `ip` → `tcp`
→ `http`, each with a frame count, a byte count and a share of the whole —
nested the way the protocols themselves nest. **Conversations** lists every
address pair's traffic, split by direction, and every address's own total;
either table's rows offer a one-click filter onto them. Both read the current
display filter's slice of the capture when one is set, and the whole thing
otherwise.

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

### Sanitizing a capture

**Sanitize** — on a finished capture's card, and in the Viewer's toolbar —
downloads `<name>-sanitized.pcap`: the same packets, the same sizes, with what
identifies people and places replaced. In the Viewer with a saved view open, it
sanitizes just that view's packets.

| Option | Ticked to start | What happens |
| --- | --- | --- |
| **Credentials** | yes | Masked with `*`: HTTP `Authorization` (the scheme word is kept), cookie values (names kept), FTP/POP passwords, IMAP and SMTP logins, SNMP communities, RADIUS passwords, NTLM and Kerberos responses, LDAP simple binds, MySQL, PostgreSQL and SQL Server passwords, VNC responses |
| **IP addresses** | yes | Replaced prefix-preserving ([Crypto-PAn](https://en.wikipedia.org/wiki/Crypto-PAn)): hosts that shared a subnet still share one. Headers, tunnels, ICMP errors, ARP, neighbour discovery, and addresses inside DNS, DHCP and routing protocols. Reverse lookups (`…in-addr.arpa`) go with them |
| ↳ Keep private ranges | no | 10/8, 172.16/12, 192.168/16, 100.64/10, link-local and fc00::/7 are left as they are |
| **MAC addresses** | yes | Replaced with locally administered addresses |
| ↳ Keep vendor prefix | no | Only the last three bytes are replaced |
| **Hostnames** | no | DNS names, TLS server name, HTTP `Host`, DHCP and NetBIOS names — label by label, with the last label (`.com`, `.local`) kept, so one host gets one stand-in wherever it appears |
| **Usernames** | no | Same-length stand-ins, in FTP, POP, IMAP, SMTP, NTLM, Kerberos, LDAP, RADIUS, SMB and database logins |
| **Strip payload** | no | Everything after the TCP or UDP header is cut off, as if captured with a short snap length |

Loopback, multicast, broadcast and group MAC addresses are never replaced: they
are the same on every network. Checksums are updated to match, so a sanitized
capture opens without a wall of checksum errors — and one that was already wrong
in the original, as outgoing packets captured before checksum offload are,
stays exactly as wrong.

**The same capture always gets the same stand-ins.** Sanitize it today and again
next month and the two files line up, address for address. The mapping is
derived from that capture's own encryption key, so it changes for nothing — not
even for a master-key rotation — and nothing about it is stored. A different
capture maps differently. (A capture stored before encryption was switched on
uses a random key created once in `data/sanitize.key` instead.)

**Read the summary before sharing.** When the download finishes, the dialog
lists what was replaced, and two things it could not vouch for:

- **Found but not replaced in place** — fields read from decoded, decompressed
  or reassembled data, which has no fixed position in a packet. NTLM inside an
  HTTP header is base64, for example; there the whole header is masked anyway,
  but not every carrier is.
- **Payload no dissector understood**, by port — traffic Wireshark could not
  read, and so could not search. A password on a custom port is invisible to
  every rule above.

Sanitizing is best effort by nature: it replaces what Wireshark can find, in the
places listed above, and a credential in a JSON body or a hostname in a URL is
not one of them. Replaced addresses keep their structure on purpose, and that
cuts both ways: someone who already knows the real address of a host or two in
the capture learns how their prefixes map, and with it part of every address
that shares them. Stand-in names keep their length. For anything leaving your hands, **Strip payload** is the
option that does not depend on recognising what is in a packet. Like every other
download, it needs HTTPS.

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
  block your first capture — see [HTTPS](#https) for the three ways out:
  **[built-in HTTPS](docs/tls.md)** (recommended), a
  **[reverse proxy](docs/reverse-proxy.md)**, or a proxy with a
  **[self-signed certificate](docs/reverse-proxy.md#no-domain-a-self-signed-certificate)**.
  [Running it without a reverse proxy](docs/operating.md#running-it-without-a-reverse-proxy)
  covers what you can still do on plain HTTP.
- **`COOKIE_SECURE=false` is already set** in the published compose file, which
  is what lets sign-in work over plain HTTP at all. Set it back to `true` once
  you are behind a reverse proxy (built-in HTTPS does not need it).
- **After changing `COOKIE_SECURE` or `TRUST_PROXY_HEADERS`, run
  `docker compose up -d`, not `docker compose restart`.** A restart — or a stop
  and start — keeps the environment the container was created with, so the
  change does nothing. `up -d` recreates the container with it.

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
| `backend/packet_parser.py` | everything that shells out to tshark or capinfos, including Protocol Hierarchy, Conversations and Follow Stream |
| `backend/sanitizer.py` | the sanitized-download pipeline: the tshark pass, field rules, pcap record walking |
| `backend/anonymize.py`, `framewalk.py` | keyed stand-ins for addresses and names, and the checksum updates that keep a sanitized frame valid |
| `backend/database.py` | the SQLite schema and every query |
| `backend/serve.py` | the container's entry point: opens the vault, then starts uvicorn, over TLS when a certificate is stored |
| `backend/tls/` | built-in HTTPS, self-contained: DNS provider allowlist, sealed storage, the one place lego runs, renewal, Admin routes and `python -m backend.tls` |
| `frontend/` | `index.html`, `css/style.css`, `js/app.js`, `js/tls.js`. No build step |
| `scripts/` | `check.sh`, the test entry point; `gen_lego_providers.py`, which regenerates the provider allowlist when lego's version moves |
| `docs/` | one document per subject; the README links them all from the top |
| `tests/` | API and unit suites |
| `tests/browser/` | playwright suites driving the real UI |

**Running it against your own changes.** `docker-compose.yml` as published has
no `build:` section — only `image:`, pointing at the release tag — so
`docker compose up --build` against it as-is builds nothing; it just starts
the same published image everyone else runs. Give it one locally with a
`docker-compose.override.yml` next to it — Compose picks this up
automatically, no `-f` needed:

```yaml
# docker-compose.override.yml
services:
  pcap-server:
    build: .
```

Then the same directory and master-key setup as [Quick start](#quick-start)
(steps 3–4 — you need `ssh-keys/`, `data/`, `captures/` and
`secrets/master.key`), and:

```bash
docker compose up --build
```

`./data` and `./captures` are bind-mounted, so state survives a rebuild.
Edit source and re-run the same command to rebuild and restart on top of it.

**A note on style.** Comments in this codebase explain *why*, and frequently
name the bug that made the code what it is. That is on purpose: a check with no
stated reason is a check the next person deletes. Keep it up in anything you
add.

## Roadmap

- **Windows targets** — capture on Windows machines as well as Linux and other
  Unix hosts. Windows' built-in OpenSSH server already covers the connection and
  the file transfer; what differs is everything run on the far end. Today that
  is `tcpdump` writing to `/tmp`, `sudo`, and interfaces read from
  `/sys/class/net`. The likely route is Wireshark's `dumpcap.exe` over Npcap,
  which takes the same interface, BPF filter, packet count, duration and snap
  length and writes a pcapng the Viewer already reads; `pktmon`, built into
  Windows, needs nothing installed but has no BPF filters and writes a format
  that has to be converted first. It would be a per-server platform choice, with
  its own prerequisite check.
- **MCP server** — expose servers, captures and packet queries over the Model
  Context Protocol, so an agent can drive pcap-server as tools rather than by
  imitating a browser session. The open questions are authorisation, since an
  MCP client is not a browser session and should not inherit one, and how much
  of a capture should be allowed to cross that boundary.

## License

See repository for license details.
