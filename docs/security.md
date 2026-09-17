# Security

*Part of the [pcap-server](../README.md) documentation.*

A packet capture is one of the most sensitive files a machine can produce: it
contains whatever crossed the wire, credentials included. Every design decision
below follows from that.

**[architecture.md](architecture.md) is the full account.** This is
the summary.

## The data directory

Captures and SSH keys are encrypted. **The database is not**, and it is the one
thing on the volume whose file permissions you have to set yourself.

It stores each user's TOTP secret as plain text, because the app has to compute
codes from it. Anyone who can read `data/pcap-server.db` can therefore produce a
valid second factor for any account, indefinitely — the password is then all
that stands in the way. Password hashes are scrypt and sessions are kept only as
SHA-256 digests, so those are an offline-cracking problem rather than an
immediate one.

The shipped `docker-compose.yml` runs the container locked down (since dev.40):
all Linux capabilities are dropped except the five the root-owned entrypoint and
the `docker compose run` maintenance commands need, `no-new-privileges` is set,
and the root filesystem is read-only, with `/tmp` in memory. The app process
itself runs as `appuser` with no capabilities at all. Capturing happens on the
target host, so the container never needs `NET_RAW`. A compose file written
before dev.40 has none of this. Copy the `cap_drop` through `tmpfs` lines from
the block in the current `docker-compose.yml` into your `compose.yaml`.

The container's entrypoint chowns the bind mounts to its own non-root user but
does not set a mode, so a directory created at a default umask is world-readable
to every account on the host. Create them closed:

```bash
chmod 0700 ssh-keys data captures secrets
```

Existing installations were not created this way. Check with `ls -ld data` and
fix it in place if the mode is not `0700` — nothing in the app depends on those
directories being readable by anyone but the container's user. **The app checks
at startup** and logs `DATA DIRECTORY IS NOT PRIVATE` when group or other
accounts have any access to it. It warns rather than refusing to start, since one
`chmod` fixes it and nothing needs to restart. (A Docker *named* volume, rather
than the bind mount the compose file uses, is already closed off by
`/var/lib/docker`'s own permissions and can ignore the warning.)

## Captures at rest

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

**A sanitized download is built in flight too**, and is never stored. Its
address and name mapping is keyed by a key derived from the capture's own data
key, so anyone holding a sanitized file still cannot reverse the mapping without
access to the capture itself. Sanitizing is best effort — it replaces what
Wireshark can dissect, and says in its summary what it could not — so a
sanitized capture is refused over plain HTTP like any other download, and should
be checked before it is shared. Captures stored before encryption was switched
on are keyed by `data/sanitize.key` instead, which is as sensitive as the
captures it covers.

## Traffic in transit

**Browser to pcap-server** is TLS from either
[pcap-server itself](tls.md) — a Let's Encrypt certificate obtained over a DNS
challenge, so no inbound port is needed — or a [reverse proxy](reverse-proxy.md)
in front. Without either, the app degrades explicitly: **over plain HTTP it runs
read-only.** Anything that changes state, and anything that exports a capture in
bulk, is refused with an explanation rather than a bare 403. Viewing is allowed.
Sign-in, sign-out and enrolment stay open, because refusing those would leave no
way in at all rather than a degraded one.

**The certificate routes stay open over plain HTTP too**, admin-only. They are
how an install gets *off* plain HTTP without a proxy, so refusing them there
would leave the proxy as the only way out. The cost is stated in the Admin panel
when the page is on HTTP: the DNS provider credentials in that request cross the
network in the clear. `python -m backend.tls issue`, run inside the container,
does the same job with the credentials typed at a prompt and never sent anywhere.

**The certificate's private key is sealed** under the master key, like captures
and SSH keys, and is never a plaintext file: the ACME client (lego) works in
`/dev/shm` and its directory is removed when it finishes, and at startup the key
is opened into a memory-only file for the TLS library and closed. DNS credentials
are sealed the same way, and lego is passed only the settings its documentation
lists for the chosen provider — nothing that reconfigures lego itself or makes it
read a file. Provider URL settings cannot point at the container's own loopback
or at link-local space where cloud metadata services live, and settings that
switch off TLS verification of a provider's API are not offered. Built-in HTTPS
refuses passphrase mode, where a restart would leave the app unable to open its
own key. Details in [Built-in HTTPS](tls.md).

Loopback counts as secure — a connection that never leaves the machine has no
wire to read. `X-Forwarded-Proto` is honoured only when `TRUST_PROXY_HEADERS` is
set, because any client can send it. See
[Behind a reverse proxy](operating.md#behind-a-reverse-proxy) for the three settings that
matter, including why proxy buffering must be off, and
[Running it without a reverse proxy](operating.md#running-it-without-a-reverse-proxy) for
what the degraded mode actually allows — including why loopback does not rescue
a containerised install.

**pcap-server to the target** is SSH with keys only. `asyncssh.connect` is
called with `password=None` and `passphrase=None` explicitly, so there is no
path by which a password could be used.

Host keys are verified per host, and verification is not optional: a host with
no trusted keys is refused outright rather than connected to unverified. That
matters more than it sounds, because asyncssh reads "no known-hosts file" as
*skip validation*, not as *use the default one* — so the alternative to
refusing is offering the SSH key to whatever answers on that address.

A host answers with one key per algorithm and whichever the two ends negotiate
is the one checked, so all of a host's keys are trusted or forgotten as a set.
They are offered strongest first, so a host with both an ed25519 and an RSA key
is verified against the ed25519 one regardless of the order they were scanned
in. The negotiated algorithm is reported, and a negotiation weaker than what
the host offered is flagged.

Trust is stored per endpoint, not per server: several server entries can point
at one host and they share a single trust decision.

**Establishing trust and replacing it are different powers, and only the second
is admin-only.** Accepting the fingerprints of a host you are adding a server
for is part of adding a server, which every user can do — so any user can pin
keys for an endpoint that has none. Two rules bound that: the keys must be for
an endpoint the caller owns a server at, and an endpoint that already has keys
stored is refused outright. Without the second rule a user could add a server
pointing at a host an admin trusts, re-pin keys of their own choosing, and
stand in the middle of the admin's connections to it. Replacing and forgetting
keys for any endpoint at all remain admin operations, under **Admin → Known
hosts**.

Establishing it is a two-step review either way. Scanning a host asks it for
its keys and stores nothing; the fingerprints are displayed, and only the keys
you accept are pinned — the ones that were on screen, not the result of a
second scan, so a key cannot change between being read and being accepted.

**Keys are pinned as part of creating the server, and are rolled back with it.**
Adding a server pins the accepted keys, connects, checks that the target is not
the machine pcap-server runs on, and creates the row last. The invariant is
that stored keys survive if and only if a server row references them: an
abandoned form, a target that proves to be this machine, a key that will not
parse — each leaves the store exactly as it found it. Trust never outlives the
request that asked for it.

A host that answered the scan but could not then be connected to is the other
side of that same rule rather than an exception to it: the server *is* created,
so its keys are kept, and it is marked **Never checked** until something
connects. A host that could not be scanned at all can still be added
deliberately — nothing is trusted and nothing is checked, and captures are
refused until both are put right.

**Deleting the last server for an endpoint forgets that endpoint's keys.** Trust
used to outlive its subject, so re-adding a host silently inherited a pinning
nobody had re-verified. The count is across every user's servers, because the
keys are global: forgetting keys another user's server still verifies against
would break their connections to prove a point about this one. The consequence
runs the other way too — when the last server for an endpoint belongs to a
non-admin, deleting it drops a trust decision an admin may have made. Key sets
that no server references are listed as orphaned in **Admin → Known hosts**,
with an action to forget them all.

## Signing in

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

## What runs on the target host

One command: `tcpdump -w <file> -v` plus the interface, packet cap, snap length
and your filter, wrapped in `timeout`. Around it are reads that need no
privilege: the interface list from `/sys/class/net` for the picker, and for a
capture on `any` the interface index table, so the Viewer can name the
interface each packet crossed. Nothing is installed and nothing is changed. The prerequisite probe is read-only; its one privileged call is
`sudo -n true`, which asks whether sudo would work without doing anything.

`-z`, `-Z`, `-W`, `-G`, `-C`, `-r`, `-F` and `-V` are refused on the fully built
argument list immediately before execution. Under sudo those turn a capture into
command execution or arbitrary file reads as root. Nothing user-supplied reaches
tcpdump as a flag, which is precisely why this is checked rather than assumed.

Filters are validated before they travel. The capture filter rejects `;`, `$`,
a backtick and a backslash — none of which mean anything in BPF — and is passed
after `--` as a single shell-quoted argument, so a filter can never become part
of the command. `&` and `|` are allowed, because they are BPF's own bitwise
operators and every `tcpflags` or byte-offset filter needs them; the quoting is
what makes them safe, and the character check is the second line under it
rather than the only one. SSH usernames are constrained to characters
sudoers gives no meaning to, so a username can never widen the sudoers rule the
prerequisite check prints for you to paste as root.

**pcap-server refuses to capture from the machine it runs on.** Capturing an
interface carrying its own traffic would record your sign-in — over plain HTTP
that is your password verbatim, and on any connection your session cookie and
TOTP code — into a capture then stored and browsable in this UI. On a Docker
host, capturing `any` also sweeps the bridge interfaces and records every other
container.

The refusal is checked twice over, because addresses alone cannot answer it.
Loopback, the container's own addresses, its default gateway and Docker's host
aliases are refused before anything connects. A target reached by an address
that gives none of that away — a Docker host addressed by its own LAN IP — is
caught once something connects to it, by comparing the target's kernel boot id
(`/proc/sys/kernel/random/boot_id`) with ours: a container shares its host's
kernel, so an identical value means the target is this machine. The check runs
when a server is added, when it is probed or tested, when a capture starts, and
once more on the connection the capture itself is about to run on, which is the
one point with no window between the check and the capture. There is no
override. A target that cannot answer — a BSD host, a masked `/proc` — is not
refused on that basis: it has proved nothing, and the address checks still
apply.

## In the browser

Content-Security-Policy blocks script running on this origin from reaching any
other host, by fetch, image URL or form submission; `script-src` needs no
`unsafe-inline`. Also set: `nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and
same-origin COOP and CORP. HSTS is sent only where TLS is genuinely in use.

## What this does not protect against

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
  open. The `setcap` route avoids it entirely and is preferred — on a tcpdump
  limited to a `pcap` group, since a capability on a binary anyone can run lets
  every account on that host capture, and with `cap_net_raw` only, which is all
  a capture needs. The prerequisite check prints it that way.
