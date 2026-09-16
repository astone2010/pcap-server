# Operating it

*Part of the [pcap-server](../README.md) documentation.*

Day-to-day running: what to set, what the admin can change, and how to put it
behind TLS — or what you give up by not.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SSH_KEYS_DIR` | `/app/ssh-keys` | Directory for SSH private keys |
| `CAPTURES_DIR` | `/app/captures` | Directory for downloaded pcap files |
| `DATA_DIR` | `/app/data` | Directory for the SQLite database. Users, servers, known hosts, settings and capture history all live here, so keep it on a persistent volume. |
| `COOKIE_SECURE` | `true` | Require HTTPS for the session cookie. Set to `false` for plain-HTTP/LAN use, or sign-in will not work. |
| `HOST_ADDRESSES` | empty | Comma-separated IP addresses of the machine pcap-server runs on. Capturing from that machine is refused, but from inside a bridge network the container cannot see its host's LAN address — which is the address someone would type for their own Docker host. Naming it here closes that gap with no connection to the target needed, so it applies even to a host that is unreachable or not yet trusted. IP addresses only; anything else is logged and ignored. |

> **Changing `COOKIE_SECURE` or `TRUST_PROXY_HEADERS`? Recreate the container,
> do not restart it.** Edit `docker-compose.yml`, then run `docker compose up -d`
> from its directory. Compose reads the environment when it *creates* a
> container, so `docker compose restart` — and `docker compose stop` followed by
> `start` — carry on with the old value, and the app behaves exactly as before.
> `up -d` sees the change and recreates it. Everyone is signed out, as on any
> restart.

## Settings in the Admin tab

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

## If you lose your authenticator

TOTP is enforced by the API, not just the login screen, so an account without
its second factor cannot get in. There are two ways back, and which one applies
depends on whether anyone else can still sign in.

**Somebody else is an admin.** Admin → Users → **Reset MFA** on that row. The
account enrols again — with a **new** code, not the old one — at its next
sign-in. Nothing else about it is touched: its servers, stored usernames, saved
filters and captures all stay, which is the whole reason this exists rather than
deleting the user and making them again.

Three things happen together, and none of them is optional:

| | |
| --- | --- |
| The old secret is destroyed | not merely unconfirmed. Whoever still holds that authenticator could otherwise confirm the account straight back to where it was |
| Every session is ended | a live session already carries both factors, so leaving one alive would let the old authenticator's holder keep working until it expired on its own |
| Every trusted device is forgotten | a trusted device *is* a second factor — skipping TOTP is the point of one — so leaving them would exempt exactly the devices with the most access |

Until they enrol again, that account is protected by its password alone. Do it
when you know who is asking.

**An admin cannot reset their own**, and the refusal is deliberate rather than an
oversight. It would not help — reaching any API route means already being past
the second factor, so the admin who is actually locked out cannot call it — and
it would let anyone holding a stolen session cookie replace your second factor
with theirs, turning a session that expires in hours into a login that does not.

**Nobody can sign in at all.** The sole admin has lost their authenticator.
That one is answered from the host, at the same bar as reading the database
directly:

```bash
cd /opt/docker/pcapserver

# Which accounts exist, and which have MFA set up.
docker compose run --rm --entrypoint python pcap-server \
    -m backend.resetmfa --list

# Dry run first — nothing is written without --apply.
docker compose run --rm --entrypoint python pcap-server \
    -m backend.resetmfa alice

docker compose run --rm --entrypoint python pcap-server \
    -m backend.resetmfa alice --apply
```

It does exactly what the button does and nothing more: it does not change or
reveal a password, create a user, or grant admin. The app does not need to be
stopped — it touches three rows of the metadata database and no capture file.

## SSH keys

Add private keys from the **Admin** tab, either by uploading the key file or by
pasting the key in — the clipboard is where most people have it, and the two go
through exactly the same checks and the same storage. They are kept in the
`ssh-keys/` directory (mounted at `/app/ssh-keys`) and offered as options when
connecting to a remote server. Keys can be added and deleted from the GUI; no
manual file placement is needed. When a master key is configured
(`MASTER_KEY_FILE` in `docker-compose.yml`), keys are sealed under it the same
way captures are — a key never exists as a plaintext file on disk, and one
added before encryption was enabled is sealed in place automatically the next
time the container starts.

A key is parsed as it arrives rather than the first time something tries to use
it. Two mistakes that used to surface minutes later as an SSH failure on an
unrelated screen are refused at the point of adding:

- **a public key.** The easy one to get wrong: the two files sit side by side
  and differ by one suffix. It is the one *without* `.pub` that belongs here.
- **a key with a passphrase.** pcap-server connects unattended and has nowhere
  to ask for one, so such a key cannot work here however valid it is elsewhere.
  `ssh-keygen -p -f <keyfile>` removes it — on a copy.

The key you upload here is the one that has to be authorised on your target
hosts. If those are still on password authentication, the author's
**[Stop Using Passwords for SSH](https://ramblingnonsense.nscriven.net/p/stop-using-passwords-for-ssh)**
covers getting them onto keys — pcap-server has no password path to fall back
on, by design.

## Running it without a reverse proxy

You can run pcap-server with no proxy in front of it, and for a quick look at a
capture that is a perfectly reasonable thing to do. Be clear about what you get,
because it is a **degraded mode, not a normal one**, and the app will not
pretend otherwise.

**What still works over plain HTTP:** signing in, browsing the capture list,
opening a capture in the Viewer, the protocol tree and hex dump, display
filters, and saved views you already have.

**What is refused:** everything that changes state or exports in bulk. Starting
a capture. Adding or editing a server. Trusting a host's SSH keys. Adding an
SSH key, uploaded or pasted. Saving a view. Every admin setting. Downloading a capture. Each refusal
comes back as an explanation rather than a bare 403, and the app shows a banner
saying why.

In practice this means **a fresh plain-HTTP install cannot take its first
capture**: step 3 of [Your first capture](../README.md#your-first-capture) is trusting the
host's keys, and that is a state change. You can register the admin account and
then go no further.

**There is no flag to turn this off.** That is deliberate. A capture routinely
contains credentials in cleartext, so handing one over an unencrypted connection
puts the whole thing on the wire; and an SSH private key uploaded over plain
HTTP is simply given away. Neither is a risk the app will let you accept by
setting a variable.

### The one exception: a genuinely local connection

Loopback counts as secure, because a connection that never leaves the machine
has no wire to read. **This almost never fires for a containerised install**,
and the reason catches people out: with a published port (`8080:8080`), the
connection reaches the container from the Docker bridge gateway, not from
`127.0.0.1`. As far as the app can tell — correctly — that packet crossed a
network. Browsing `http://localhost:8080` **on the Docker host itself is still
read-only.**

Two ways to get a genuinely local connection, both without a proxy:

**1. An SSH tunnel.** The honest answer, and the one to reach for. It is real
encryption, not a bypass:

```bash
ssh -N -L 8080:localhost:8080 you@the-docker-host
```

Then browse `http://localhost:8080` on your own machine. Note this only helps if
the app sees loopback at the other end — pair it with host networking below, or
accept read-only.

**2. Host networking.** Drop `ports:` from the compose file and add
`network_mode: host`. The container then shares the host's network stack, a
connection from the host arrives as real loopback, and the app is fully
functional to anyone on that host. This also removes the container's network
isolation, so it is a trade, not a free win — and it means anyone who can reach
the host's port 8080 from elsewhere on the LAN still gets the read-only version,
which is the correct outcome.

### What you are risking if you expose it anyway

Putting a plain-HTTP pcap-server on a LAN and living with read-only is not
harmless, even though the destructive operations are blocked:

- **Session cookies cross the wire in the clear.** `COOKIE_SECURE=false` is
  required for sign-in to work at all over HTTP, and it does what it says.
  Anyone on the path can lift a session and read every capture you can read.
- **Your password crosses in the clear at sign-in.** Sign-in is deliberately
  allowed over HTTP, because refusing it would leave no way in at all rather
  than a degraded one. That is a trade the app makes knowingly and tells you
  about; it does not make the password any safer.
- **Capture contents are readable to anyone watching.** The Viewer works, so
  packet data — including whatever credentials the capture caught — is being
  served unencrypted.
- **TOTP does not save you here.** It authenticates the sign-in; it does nothing
  about the session cookie that is then sent in the clear on every request.

The short version: read-only over HTTP protects your *configuration and your
keys*, not your *captures* and not your *session*. If the captures matter, put
it behind TLS.

### What not to do

Do not set `TRUST_PROXY_HEADERS=true` to unlock the app without an actual proxy.
That variable does not mean "pretend this is secure" — it means "believe the
`X-Forwarded-Proto` header", and **any client can send that header**. Setting it
with the port published to a network hands full write access, key upload and
capture download to anyone who can reach the port and type one extra header. It
is strictly worse than the read-only mode it appears to fix, and it is why the
variable exists as an opt-in at all rather than being on by default.

If you want the app fully functional, the supported route is TLS in front of
it. Caddy, Nginx Proxy Manager and Traefik each obtain and renew certificates
themselves and need very little configuration — see below.

## Behind a reverse proxy

Putting pcap-server behind TLS is what restores full access — over plain HTTP it
is read-only. **No proxy is needed** if pcap-server gets its own certificate:
[Built-in HTTPS](tls.md). Otherwise, **[Setting up a reverse proxy](reverse-proxy.md)** is the whole
procedure, worked start to finish for
[Caddy](reverse-proxy.md#caddy), [nginx](reverse-proxy.md#nginx) and
[Nginx Proxy Manager](reverse-proxy.md#nginx-proxy-manager), with a
[checklist for confirming it worked](reverse-proxy.md#checking-it-worked).

The proxy does not have to be something external. Either Caddy or NPM can run
as a service in this stack's own compose file, so the install carries its own
TLS and pcap-server publishes no port at all — see
[Running the proxy in the same stack](reverse-proxy.md#running-the-proxy-in-the-same-stack),
which also covers DNS challenges, for a host with no inbound ports from the
internet. With no domain at all, a proxy can serve
[a self-signed certificate](reverse-proxy.md#no-domain-a-self-signed-certificate).

Three settings are load-bearing and easy to miss, whichever proxy you use:

1. **`X-Forwarded-Proto` from the proxy, plus `TRUST_PROXY_HEADERS=true` on the
   app.** Neither alone does anything, and without both the app stays read-only.
2. **Then stop anything else reaching the app directly** — publish no port, bind
   to loopback, or firewall it to the proxy. Trusting that header means whatever
   can reach the app can claim to be the proxy.
3. **No response buffering to disk.** A capture download is decrypted in flight;
   a proxy that spools it to a temp file leaves an unencrypted pcap behind.
   nginx and NPM buffer by default and must be told not to; Caddy does not.

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

## Rotating the master key

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

It re-wraps the [built-in HTTPS](tls.md) key and token in `/app/data/tls` too —
the compose file sets `DATA_DIR`, which is where the tool looks.

That is a **dry run**: it reports what it would move and writes nothing, key
file included. Add `--apply` to commit it. Then put the new key where the old
one was and start up again:

```bash
cp /opt/docker/pcapserver/data/master.key.new /opt/docker/pcapserver/secrets/master.key
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
- Sanitized downloads are unaffected. Their stand-ins come from each capture's
  own data key, which a rotation rewraps without changing, so a capture
  sanitized after rotating matches one sanitized before.

There is no supported way to rotate while the app runs, and no way to recover
captures whose key is lost — that is the point of the design, not a gap in it.
