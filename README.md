# pcap-server

Run tcpdump on your servers over SSH and read the results in a Wireshark-style
web interface. Captures come back encrypted, are never written to disk in the
clear, and are browsable packet by packet in the browser.

Built for the case where the machine you need to capture on is not the machine
you want to analyse from: a firewall, a hypervisor, a container host, a box you
only reach over SSH.

**Contents**

*Getting going* — [What it does](#what-it-does) ·
[Requirements](#requirements) ·
[Quick start](#quick-start) ·
[Your first capture](#your-first-capture)

*Using it* — [Preparing a target host](#preparing-a-target-host) ·
[Taking a capture](#taking-a-capture) ·
[Reading a capture](#reading-a-capture)

*Running it* — [Security](#security) ·
[Operating it](#operating-it) ·
[Architecture](#architecture) ·
[Development](#development) ·
[Roadmap](#roadmap)

## What it does

**Capturing.** Add a host once and it stays on your list. Pick the interface
from a list read off that host, set a duration, packet cap and snap length, and
give it a BPF filter — typed, chosen from clickable examples, or picked out of
the capture filter library that sits under the field itself, which groups common
expressions by protocol (Kerberos, SMB, LDAP, DNS, database ports, TCP flag
matching and so on). A running capture reports how many packets it has taken so
far. Captures can be renamed, and each one remembers which server it came from
even after that server is deleted.

**Reading.** A Wireshark-style packet list with protocol colouring, a decoded
protocol tree and a hex dump. Full Wireshark display-filter syntax narrows the
list, with autocomplete over protocol and field names as you type, its own
cheatsheet and examples; a filter tshark cannot parse is reported with tshark's
own message rather than shown as an empty list. A filter worth keeping can be
**saved as a view** — a named tab on that capture that is still there when you
come back to it, and that downloads as its own pcap containing only what it
selects.

Timestamps can be relative, epoch, delta, the server's UTC, or **your own time
zone**. Name resolution is off by default, because resolving addresses out of a
capture tells a DNS server what you are investigating.

**Security.** Captures are encrypted at rest under a key that never lives on the
data volume, and decrypted in flight so no plaintext pcap ever touches disk.
Passwords are scrypt-hashed, TOTP is required, and sessions are stored only as
digests. Over plain HTTP the app refuses to change anything or hand a capture
over. SSH host keys are verified per host. See [Security](#security).

**Operating.** Multi-user with an admin panel, per-account server lists and
stored SSH usernames, SSH keys uploaded through the UI and sealed under the same
master key, a read-only prerequisite probe that never installs anything,
adjustable capture and session limits, a dark theme and a light one named
Flashbang for reasons that become clear at 2am, and a layout that works down to
phone width.

## Requirements

**To run pcap-server:** Docker and Docker Compose, and somewhere to put about
as much disk as your captures will weigh. Nothing else — tshark, tcpdump and
the SSH client all live inside the image. It listens on port 8080.

**On each machine you want to capture from:**

| | |
| --- | --- |
| SSH access | key-based. pcap-server never asks for, stores or sends a password for a target host |
| `tcpdump` | installed. The prerequisite check finds it and reports the path |
| Capture privilege | `cap_net_raw` on the tcpdump binary, passwordless sudo scoped to tcpdump, or root — see [Preparing a target host](#preparing-a-target-host) |
| A writable `/tmp` | the capture is staged there and deleted after transfer |

**In the browser:** anything current. There is no build step and no framework —
the UI is plain HTML, CSS and JavaScript served by the app itself.

**HTTPS is not required to start, but the app is read-only without it.** See
[Traffic in transit](#traffic-in-transit).

## Quick start

```bash
git clone https://github.com/darthrater78/pcap-server.git
cd pcap-server

# The bind-mounted directories, created next to docker-compose.yml.
# Only ssh-keys/ is in the repo; the rest hold your data and are not.
# Create them yourself so they belong to you rather than to root.
mkdir -p data captures secrets

# The master key. Generated once, before the first start -- the app refuses to
# start without it rather than storing captures in the clear.
openssl rand -base64 32 > secrets/master.key
chmod 0400 secrets/master.key

docker compose up -d
docker compose logs pcap-server | grep -i encryption   # encryption enabled (key id ...)
```

**Back that key up somewhere else before you capture anything.** It is the only
thing that can decrypt your captures, and there is no recovery path without it.
Keep it out of `data/` and `captures/`.

Every relative path in `docker-compose.yml` is resolved against the directory
that file is in, so run later `docker compose` commands from this directory too.
Absolute paths are supported and documented in the comments at the top of
`docker-compose.yml`.

Open `http://localhost:8080`. The first user to register becomes the admin.

## Your first capture

1. **Upload an SSH key.** Admin → SSH Keys. It is sealed under the master key
   the moment it lands, the same way captures are.
2. **Add the server.** Servers → + Add. Give it a name, a hostname and the login
   it should use. **Test connection** and **Check prerequisites** run against it
   before you commit to saving.
3. **Sort out capture privilege** if the check says it is missing. It prints the
   exact command for the host in front of you — see
   [Preparing a target host](#preparing-a-target-host).
4. **Trust the host key.** Admin → Known Hosts. Until you do, the connection
   still works but is not verified, and the UI says so.
5. **Capture.** Capture tab: pick the server and interface, set a duration, add
   a filter. Watch the packet count climb while it runs.
6. **Read it.** View on a finished capture. Click a packet for its protocol tree
   and hex dump.

## Preparing a target host

Everything in this section happens on the machine you want to capture
*from*, not on the machine running pcap-server. It is a one-time job per host,
and **Servers → Check prerequisites** prints the exact command for the host in
front of you rather than a generic one.

### Adding a server

The SSH key field starts empty and has to be chosen. Add, Test connection and
Check prerequisites all refuse until a hostname, a username and a key are
present, so a server is never created with a key nobody picked.

**Never add the machine pcap-server itself runs on.** Capturing from its own
host records pcap-server's own traffic — your session cookie and TOTP code, and
over plain HTTP your password — into a capture this UI then stores and serves
back, and on a Docker host the `any` interface sweeps every other container too.
The obvious cases are refused automatically: hostname aliases, loopback, the
container's own addresses, and the default gateway, which on a Docker bridge is
the host machine. The case that cannot be detected is the host's own LAN
address, because a bridged container has no knowledge of it — which is why the
form warns as well as checks. Capture this host from a different machine.

### Checking a server before you capture

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

### Capture privilege: what tcpdump needs

tcpdump needs a privilege to open a capture interface that a plain SSH user
doesn't have by default. There are two ways to grant it — try the first one
before reaching for sudo, since it grants far less.

#### Preferred: a file capability, no sudo at all

`cap_net_raw`/`cap_net_admin` on the tcpdump binary itself lets that one user
capture without being root or touching sudo at all:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/tcpdump   # use your host's real path
```

Run **Servers → Check prerequisites** in the UI first — it discovers the
actual tcpdump path on that host (it's `/usr/sbin/tcpdump` on some distros,
`/usr/bin/tcpdump` on others) and gives you the exact command to run, along
with whether the capability is already set. This is a one-time step per host
and survives a tcpdump package upgrade being reapplied by the package
manager's postinst on most distros; verify with `getcap $(which tcpdump)`
after a package update if you want to be sure.

#### If setcap isn't available: passwordless sudo, scoped to tcpdump only

Some hosts don't have `libcap2-bin`/`getcap` installed, or you'd rather use
sudo.

**Why it has to be passwordless.** pcap-server authenticates to your hosts with
SSH keys and nothing else — it never asks you for, stores, or transmits a login
password for a target host, and there is no prompt in a capture for one to be
typed into. Captures run over a non-interactive SSH session, so when `sudo`
asks for a password there is nobody there to answer and no password on hand to
send. That is why the grant has to be `NOPASSWD` — and exactly why it should be
scoped to one binary instead of the whole account. pcap-server invokes
`sudo -n` ("never prompt") to keep this honest: a host that still wants a
password fails immediately with a clear error rather than hanging until the
capture times out.

If you would rather not open a `NOPASSWD` grant at all, use the `setcap` route
above — it needs no sudo and no password, and it grants less.

**Scope the grant to tcpdump. Do not make the account blanket-passwordless.**
Searching for "passwordless sudo" turns up this rule almost everywhere, and it
is the wrong one here:

```
# DON'T: every command, as root, no password. Far more than capturing needs.
pcapuser ALL=(ALL) NOPASSWD: ALL
```

That grants unrestricted root for every purpose, permanently, to an account
whose private key is sitting in pcap-server's key store. What captures actually
need is one binary:

```
# DO: this one binary, nothing else.
pcapuser ALL=(root) NOPASSWD: /usr/sbin/tcpdump
```

Both let `sudo -n tcpdump` run unprompted, so pcap-server works either way —
the difference is entirely in what *else* becomes possible if that account is
ever compromised. Take the second one. The full steps:

```bash
# 1. Find the exact tcpdump path first -- use it below, not a bare "tcpdump".
#    A bare command name in a sudoers NOPASSWD rule can be satisfied by
#    anything earlier on $PATH, not just the real binary.
which tcpdump
#   e.g. /usr/sbin/tcpdump

# 2. Write the rule with visudo -f, which validates syntax before saving --
#    a malformed file dropped straight into /etc/sudoers.d/ with cat/tee can
#    break sudo entirely for everyone on the host until it's fixed manually.
sudo visudo -f /etc/sudoers.d/pcap-server
```

In the editor that opens, add one line (replace `pcapuser` with the actual
SSH username this server config uses, and the path with what step 1 printed):

```
pcapuser ALL=(root) NOPASSWD: /usr/sbin/tcpdump
```

Save and exit; `visudo` will refuse to write the file at all if the syntax is
wrong, rather than leaving a broken sudoers.d entry behind. Then lock down the
permissions, since sudoers.d files are ignored if they're group- or
world-writable:

```bash
sudo chmod 0440 /etc/sudoers.d/pcap-server
sudo chown root:root /etc/sudoers.d/pcap-server
```

To do it in one line without an editor — piping through `visudo` rather than
`tee`, so the file is still validated before it replaces anything:

```bash
echo 'pcapuser ALL=(root) NOPASSWD: /usr/sbin/tcpdump' \
  | sudo EDITOR='tee' visudo -f /etc/sudoers.d/pcap-server
```

Then tick **Run tcpdump with sudo** on the server in the UI to actually use it.

**Check prerequisites** prints this exact command for you, with the username and
the discovered tcpdump path already filled in. To grant it to a group instead
of a named account, create the group first — a rule naming a group that doesn't
exist matches nobody and captures keep failing with the same error:

```bash
sudo groupadd -f pcap && sudo usermod -aG pcap pcapuser
echo '%pcap ALL=(root) NOPASSWD: /usr/sbin/tcpdump' \
  | sudo EDITOR='tee' visudo -f /etc/sudoers.d/pcap-server
```

**Understand what this grants, even scoped this way.** `tcpdump` can run
arbitrary commands as root via its `-z` flag and read any file via `-r`, so
anyone who can open a shell as that user on that host effectively has root
there. pcap-server never sends those flags — `-z`, `-Z`, `-W`, `-G`, `-C`,
`-r`, `-F` and `-V` are rejected by a server-side allowlist that refuses to
start if one is ever added to it, and every argument is shell-quoted — but the
sudoers grant itself is still a privilege boundary you are choosing to open.
Use a dedicated, unprivileged account for this and nothing else — don't reuse
a login you use for other purposes on that host.

## Taking a capture

A capture always runs as `tcpdump -w <file>`, so that a pcap comes back for
analysis. `-w` turns tcpdump from a printer into a writer: it stops formatting
text and writes raw packet records. tcpdump's display flags — `-vv`, `-vvv`,
`-q`, `-A`, `-X`, `-XX`, `-e`, `-n`, `-nn`, `-t`/`-tt`/`-ttt`/`-tttt` — format
text that is never emitted under `-w`, so they cannot affect the capture and are
not accepted. The ones that describe how to *read* a capture live in the Viewer
instead, where they change the packet list.

`-v` is the exception, and pcap-server adds it to every capture itself, which is
why it appears in the command shown against each one. It still changes nothing
in the file. Under `-w` it makes tcpdump report its running packet total on
stderr once a second, which is what the live count on a running capture reads —
the pcap is on the remote host until the capture ends, so there is nothing else
to count.

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

## Reading a capture

**View** on a finished capture opens it in the packet viewer: a Wireshark-style
list on top, the decoded protocol tree and hex dump below, and a display-filter
box across the top.

### The two filters

The one thing worth getting straight before you use either.

| | Where | When it runs | Syntax | Example |
| --- | --- | --- | --- | --- |
| **Capture filter** | Capture tab | tcpdump, on the remote host, as packets go past | BPF | `tcp port 443` |
| **Display filter** | Viewer | tshark, when the list is drawn | Wireshark display syntax | `tcp.port == 443` |

The capture filter decides **what is recorded**, and anything it excludes is
gone for good. The display filter decides **what you see** out of what was
already recorded, so it costs nothing to change your mind.

Display filters name a protocol field with a dot and compare it with an
operator — `ip.addr == 10.0.0.1`, `frame.len > 1000`,
`http.request.method == "GET"` — or use a bare protocol name on its own, like
`dns`. Combine with `and`, `or`, `not`, or with `&&`, `||`, `!`.

Both boxes offer clickable examples. **Browse the capture filter library** sits
under the BPF field on the Capture tab — a searchable list grouped by protocol,
which fills the field above it when you choose one. The Viewer has a full
display-filter cheatsheet behind **Filter help**.

A display filter tshark cannot parse is reported back with tshark's own message
and the position it objected to. An empty packet list therefore always means the
filter was valid and nothing matched it.

### Building a filter by clicking

Most display filters do not need to be typed. **Right-click** anything in the
viewer and the Wireshark menu appears:

- **In the detail tree** — any field, at any depth, including a single TCP flag
  bit. Right-clicking `.... .... ..1. = Syn: Set` gives `tcp.flags.syn == 1`.
- **In the packet list** — the menu builds from the column under the cursor: an
  address, a protocol, a length, a frame number. It also offers a
  **Conversation filter**, which is both endpoints of that exchange and nothing
  else.

Each menu offers the same four combinators as Wireshark — apply the expression
on its own, negate it, or join it to whatever is already in the box with `&&`
or `||` — plus **Prepare as filter**, which fills the box without running it.

Addresses go into the filter bare and text values are quoted, because Wireshark
treats `192.168.1.50` as an address literal and rejects it in quotes. A value
containing a character the display filter does not accept falls back to testing
that the field is simply present.

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
contains whatever crossed the wire, credentials included. Every design decision
below follows from that.

**[docs/architecture.md](docs/architecture.md) is the full account.** This is
the summary.

### Captures at rest

Envelope encryption. A master key wraps a per-file data key, and the capture is
sealed in 64 KiB chunks with AES-256-GCM. Each chunk is bound to its position,
so chunks cannot be reordered within a file or spliced between files, and an
explicit terminator makes truncation detectable rather than looking like a short
capture.

The master key comes from outside the data volume — a Docker secret, an
environment variable, or derived from an admin passphrase with scrypt and held
only in RAM. Encrypting with a key stored beside the data would protect nothing.

**Startup fails closed.** A missing key with encrypted captures present, or a
key that does not open the captures already stored, stops the app rather than
silently writing new captures under a different key or in the clear. Running
unencrypted is possible but has to be asked for explicitly with
`ALLOW_UNENCRYPTED_CAPTURES=true`.

**No plaintext pcap ever reaches disk.** A capture is sealed as it arrives over
SFTP, not written and then encrypted. To read one, it is decrypted in flight and
streamed to tshark, so the only plaintext that exists is the few kilobytes in
transit between two processes.

Uploaded SSH private keys are sealed the same way, and a key uploaded before
encryption was switched on is sealed in place at the next start.

### Traffic in transit

**Browser to pcap-server** is yours to terminate, because a LAN appliance cannot
obtain its own certificates. Rather than pretend, the app degrades explicitly:
**over plain HTTP it runs read-only.** Anything that changes state, and anything
that exports a capture in bulk, is refused with an explanation rather than a
bare 403. Viewing is allowed. Sign-in, sign-out and enrolment stay open, because
refusing those would leave no way in at all rather than a degraded one.

Loopback counts as secure — a connection that never leaves the machine has no
wire to read. `X-Forwarded-Proto` is honoured only when `TRUST_PROXY_HEADERS` is
set, because any client can send it. See
[Behind a reverse proxy](#behind-a-reverse-proxy) for the three settings that
matter, including why proxy buffering must be off.

**pcap-server to the target** is SSH with keys only. `asyncssh.connect` is
called with `password=None` and `passphrase=None` explicitly, so there is no
path by which a password could be used.

Host keys are verified per host. A host answers with one key per algorithm and
whichever the two ends negotiate is the one checked, so all of a host's keys are
trusted or forgotten as a set. The negotiated algorithm is reported, and a
negotiation weaker than what the host offered is flagged.

### Signing in

| | |
| --- | --- |
| Passwords | scrypt, N = 2^17, r = 8, p = 1. Parameters stored in the hash, so cost can be raised later without invalidating anyone |
| Comparison | constant-time |
| Sessions | 48 random bytes; the database stores **only the SHA-256 digest**, so a leaked database hands over no live sessions |
| Cookie | `HttpOnly`, `SameSite=Strict`, `Secure` by default |
| Expiry | absolute and idle, both adjustable; an idle session is deleted, not merely rejected |
| Second factor | TOTP, enforced by the API and not only by the UI |
| Trusted devices | separate token, also stored as a digest, with its own expiry |
| Login throttling | per client IP, adjustable, default five attempts then fifteen minutes |

### What runs on the target host

One command: `tcpdump -w <file> -v` plus the interface, packet cap, snap length
and your filter, wrapped in `timeout`. Nothing is installed and nothing is
changed. The prerequisite probe is read-only; its one privileged call is
`sudo -n true`, which asks whether sudo would work without doing anything.

`-z`, `-Z`, `-W`, `-G`, `-C`, `-r`, `-F` and `-V` are refused on the fully built
argument list immediately before execution. Under sudo those turn a capture into
command execution or arbitrary file reads as root. Nothing user-supplied reaches
tcpdump as a flag, which is precisely why this is checked rather than assumed.

Filters are validated before they travel. The capture filter rejects shell
metacharacters and is passed after `--` as a single argument, so a filter can
never become part of the command. SSH usernames are constrained to characters
sudoers gives no meaning to, so a username can never widen the sudoers rule the
prerequisite check prints for you to paste as root.

**pcap-server refuses to capture from the machine it runs on.** Capturing an
interface carrying its own traffic would record your sign-in — over plain HTTP
that is your password verbatim, and on any connection your session cookie and
TOTP code — into a capture then stored and browsable in this UI. On a Docker
host, capturing `any` also sweeps the bridge interfaces and records every other
container.

### In the browser

Content-Security-Policy blocks script running on this origin from reaching any
other host, by fetch, image URL or form submission; `script-src` needs no
`unsafe-inline`. Also set: `nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and
same-origin COOP and CORP. HSTS is sent only where TLS is genuinely in use.

### What this does not protect against

- Anyone who can execute code inside the running container, or read its memory.
  The key has to be present for the app to run unattended. That is the honest
  limit of any at-rest scheme.
- The pcap exists in the clear in `/tmp` on the **target** host for the duration
  of the capture. Inherent to running `tcpdump -w` on a remote machine; it is
  deleted after transfer.
- Self-capture detection cannot see the host's LAN address from inside a bridged
  container, so it guards against the common mistakes rather than proving
  non-locality.
- Passwordless sudo on the target is a privilege boundary you are choosing to
  open. The `setcap` route avoids it entirely and is preferred.

## Operating it

Day-to-day running: what to set, what the admin can change, and how to put it
behind TLS.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SSH_KEYS_DIR` | `/app/ssh-keys` | Directory for SSH private keys |
| `CAPTURES_DIR` | `/app/captures` | Directory for downloaded pcap files |
| `DATA_DIR` | `/app/data` | Directory for the SQLite database. Users, servers, known hosts, settings and capture history all live here, so keep it on a persistent volume. |
| `COOKIE_SECURE` | `true` | Require HTTPS for the session cookie. Set to `false` for plain-HTTP/LAN use, or sign-in will not work. |

### Settings in the Admin tab

These are configurable from the Admin tab by the admin user:

| Setting | Default | Description |
|---|---|---|
| Max capture seconds | 300 | Maximum duration for a single capture |
| Max capture packets | 100000 | Maximum packets per capture |
| Max concurrent captures | 5 | Captures running or finishing up at once, across all users — each holds an SSH connection to a target host plus a local file. Separately, and not configurable: one capture at a time per interface per server, so `eth0` and `eth1` on the same host can run together but a second capture on either is refused |
| Session duration (hours) | 8 | Login session lifetime |
| Session idle timeout (minutes) | 60 | Idle window before a session is deleted, independent of the absolute duration above. `0` disables idle expiry |
| Device trust (days) | 30 | How long a trusted device skips MFA |
| Rate limit attempts | 5 | Failed login attempts before lockout |
| Rate limit lockout (minutes) | 15 | Lockout duration after too many failures |
| Packet list requests per minute | 30 | Per-user cap on `/api/captures/{id}/packets` calls, which spawn tshark |
| Capture start requests per minute | 10 | Per-user cap on `/api/captures` (POST), which opens an SSH connection |

### Sessions

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

### SSH keys

Upload private keys from the **Admin** tab. They are stored in the `ssh-keys/`
directory (mounted at `/app/ssh-keys`) and offered as options when connecting to
a remote server. Keys can be uploaded and deleted from the GUI; no manual file
placement is needed. When a master key is configured (`MASTER_KEY_FILE` in
`docker-compose.yml`), uploaded keys are sealed under it the same way
captures are — a key never exists as a plaintext file on disk, and one
uploaded before encryption was enabled is sealed in place automatically the
next time the container starts.

### Behind a reverse proxy

Over plain HTTP pcap-server is read-only — see
[Traffic in transit](#traffic-in-transit) and the banner the app shows. Putting it behind TLS restores full access. A worked nginx
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

### SSH connection lifetime

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

### Rotating the master key

If the master key is disclosed — pasted into a chat, caught in a screenshot,
committed by accident — it has to be replaced, and swapping the key file alone
will not do it: the app refuses to start against captures the new key cannot
open, which is the fail-closed behaviour above doing its job.

Rotate it properly instead. Because the master key only ever wraps per-file data
keys and never touches a capture's contents, a rotation rewrites 84 bytes per
file rather than re-encrypting anything — a 40 GB capture rotates as fast as a
40 KB one.

**Stop the app first.** A capture being written while its header is swapped is
the one way this can corrupt one; the tool refuses to touch a file modified in
the last 10 seconds, but a stopped app is the real guarantee.

```bash
docker compose stop pcap-server

docker compose run --rm --entrypoint python pcap-server -m backend.rekey \
    --captures-dir /app/captures \
    --ssh-keys-dir /app/ssh-keys \
    --old-key-file /run/secrets/pcap_master_key \
    --generate-new-key /app/data/master.key.new
```

That is a **dry run**: it reports what it would move and writes nothing, key
file included. Add `--apply` to commit it. Then put the new key where the old
one was and start up again:

```bash
cp /opt/docker/pcap/data/master.key.new /opt/docker/pcap/secrets/master.key
docker compose start pcap-server
docker compose logs pcap-server | grep -i encryption
```

The log will report `encryption enabled (key id ...)` with the new id.

**Keep the old key until that line appears and a capture opens in the viewer.**
Until then it is the only thing that can read your captures.

Notes on how it behaves, which matter if something goes wrong mid-run:

- It covers captures **and** stored SSH keys. Moving only one would leave the
  other unopenable, and startup refuses to continue past that.
- It is safe to re-run. A file already under the new key is recognised and
  skipped, so an interrupted run finishes on the second pass.
- Any file it cannot move is left untouched under the old key and the run exits
  non-zero. There is no partial success reported as success.
- A file sealed under some third key is named and skipped, never guessed at.
- It never deletes a capture. The worst case is a file still on the old key,
  named in the output.

There is no supported way to rotate while the app runs, and no way to recover
captures whose key is lost — that is the point of the design, not a gap in it.

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
| `backend/packet_parser.py` | everything that shells out to tshark or capinfos |
| `backend/database.py` | the SQLite schema and every query |
| `frontend/` | `index.html`, `css/style.css`, `js/app.js`. No build step |
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
