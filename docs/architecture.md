# Architecture and security

How pcap-server is put together, and what each security measure is actually
defending against. `README.md` covers installing and using it; this covers how
it works and why it is built the way it is.

---

## What the app does

An operator adds a remote host, runs `tcpdump` on it over SSH, and gets the
resulting pcap back to browse in a Wireshark-style viewer in the browser. Every
interesting design decision follows from one property of that job: **a packet
capture is one of the most sensitive files a machine can produce.** It contains
whatever crossed the wire, credentials included. So the capture is encrypted the
moment it lands, it is never written to disk in the clear, and it is not handed
over an unencrypted connection.

---

## The pieces

| Layer | What it is |
| --- | --- |
| HTTP API and static files | FastAPI on uvicorn, mounted at `/api/*`; the frontend is served from `/` |
| Frontend | Vanilla HTML, CSS and JavaScript. No build step, no framework, no bundler |
| Remote execution | `asyncssh`, one connection per running capture |
| Packet analysis | `tshark` and `capinfos` invoked as subprocesses |
| Storage | SQLite in WAL mode for metadata; capture files on a separate volume |
| Encryption | AES-256-GCM envelope encryption, master key from outside the data volume |
| Container | `python:3.12-slim`, runs as a non-root user (`appuser`, uid 1000) |

### Backend modules

| Module | Responsibility |
| --- | --- |
| `main.py` | Routes, middleware, transport policy, app wiring |
| `auth.py` | Password hashing, sessions, TOTP, trusted devices, login rate limiting |
| `database.py` | Every SQL statement, schema creation, and in-place migrations |
| `models.py` | Pydantic models and every input validator |
| `ssh_manager.py` | Connections, host-key verification, remote command execution, file transfer |
| `capture.py` | Capture lifecycle: start, monitor, progress, transfer, cleanup |
| `packet_parser.py` | Feeding captures to `tshark`/`capinfos` and parsing what comes back |
| `pcapsource.py` | How a capture's bytes reach a tool, plaintext or decrypting in flight |
| `livestream.py` | Holding a running capture's bytes, and walking pcap records so only whole ones reach tshark |
| `crypto.py` | The envelope format, sealing and opening |
| `vault.py` | Key resolution, startup policy, plaintext migration |
| `localnet.py` | Detecting that a capture target is the machine pcap-server runs on |

There is no ORM, no service layer and no dependency-injection container. Routes
call the managers directly, and `database.py` is the only module that writes
SQL. That is deliberate: the codebase is small enough that indirection would
cost more than it buys, and keeping SQL in one file means the parameterisation
rule can be checked by reading one file.

---

## The life of a capture

```
browser  ──POST /api/captures──▶  CaptureManager.start()
                                        │
                                        │  concurrency limit checked FIRST,
                                        │  before any connection is opened
                                        ▼
                                  SSHManager.run_tcpdump()
                                        │  tcpdump -w /tmp/<uuid>.pcap -v ...
                                        │  wrapped in timeout(1)
                                        ▼
                                  _monitor() task
                                    ├── reads stderr as it arrives  ──▶ live packet count
                                    ├── waits for exit (with its own backstop timeout)
                                    ├── SFTP fetch, sealed chunk by chunk on arrival
                                    ├── deletes the remote /tmp file
                                    └── counts packets with capinfos
                                        ▼
                                  status COMPLETED
```

Four things are worth pointing at.

**The concurrency limit is checked before anything is opened.** Each running
capture holds an SSH connection and a local file handle. Checking afterwards
would mean opening the connection and then tearing it down, which is both
wasteful and a way for a caller to exhaust descriptors regardless of the limit.

**A failed launch closes its own record.** Only `_monitor` ever ends a running
capture, and `_monitor` does not exist until the launch succeeds. Without an
explicit cleanup on the failure path, every unreachable host permanently
consumed a concurrency slot.

**The remote file is written to `/tmp` on the target and deleted after
transfer.** It exists in the clear there for the duration of the capture. That
is inherent to running `tcpdump -w` on someone else's machine, and worth knowing.

**The pcap is sealed as it arrives**, not written and then encrypted. There is no
window in which a plaintext capture exists on the data volume.

---

## Streaming a capture live

A capture started with **Live stream** runs the pipeline above unchanged — same
remote file, same transfer, same sealing — and adds a second, read-only path
alongside it that exists only while the capture runs:

```
tcpdump -U -w /tmp/<uuid>.pcap        (on the target; -U so it writes per packet)
        │
        │  SFTP read from a byte offset, over the capture's OWN connection
        ▼
  LiveBuffer                           (in memory, capped, append-only)
        │  walks pcap record headers; offers only whole records
        ▼
  BytesSource ──▶ the same get_packet_list() the stored viewer uses ──▶ browser
```

Three constraints shaped this, each verified against the real tools rather than
assumed.

**The partially written stored file is unreadable, by design.** `Cryptor
.open_stream` raises on an incomplete sealed file rather than yielding the
chunks it holds — that is the truncation detection described under *Data at
rest*, and it is an anti-tamper property worth more than a live view. So the
obvious design, reading the file the transfer is writing, is not available, and
weakening the check to make it available was rejected. The live path is a
pass-through: the bytes never become a file on the data volume.

**tshark rejects a capture cut mid-packet.** Fed a torn record it emits every
complete packet, warns that the capture "appears to have been cut short in the
middle of a packet", and exits 2 — and a non-zero exit with a display filter
present is precisely how `get_packet_list` detects a filter tshark refused. A
live read lands mid-record constantly, so without intervention every poll would
report the operator's valid filter as invalid. `LiveBuffer` therefore walks the
16-byte pcap record headers itself and hands tshark only whole records, which
exits 0 and leaves the filter path's meaning intact. It refuses rather than
guesses on an unrecognised magic or an implausible record length, since the
file sits on a host under investigation.

**The remote file is kept as the source of truth.** A `tcpdump -U -w -` stdout
stream would be simpler and would delete the transfer phase entirely, but a
dropped SSH connection would then lose the capture. Reading a file that
accumulates on the target costs a phase and buys a capture that survives the
connection.

There is one filtering implementation, not two: the live routes call the same
`get_packet_list` and `get_packet_detail` as the stored ones, differing only in
which `PcapSource` they are handed. A separate live filter path is how the two
halves of the app would end up disagreeing about what a filter means.

**A live stream must arrive narrowed.** `start()` refuses one whose interface
is `any` and whose BPF filter is empty (`LiveStreamNotTargeted` -> HTTP 400).
This is a precondition rather than a limit: the buffer below is a fixed size and
does not refill, so an untargeted stream does not degrade, it freezes seconds in
and stays frozen for the rest of the capture. Either an interface or a filter
satisfies it, because either one bounds the traffic and which is appropriate
depends on the question being asked. The check runs before the concurrency and
per-interface checks, so a full container answers an unacceptable request with
the reason it is unacceptable rather than with "too many captures" — a message
that would send the operator to stop something when the problem is the form.

The rule applies to live streaming alone. An ordinary capture on `any` with no
filter has no preview buffer to fill and remains the default.

The frontend enforces the same rule in `liveStreamIsTargeted()` and explains it
in place on the capture form. The server is the authority; the client copy
exists so the answer appears while the form is being filled in rather than after
a request that was never going to be accepted.

**Two limits, for two different costs.** `max_live_streams` (2) bounds
concurrent live captures — each holds an SFTP channel on the target and costs a
tshark run over the whole buffer per poll — and is checked in `start()` in the
same await-free stretch as the concurrency and per-interface checks, so two
simultaneous requests cannot both pass it. `live_stream_buffer_mb` (16) bounds
the buffer, which is both a memory ceiling and a CPU one. At the cap the buffer
**freezes**: the preview stops advancing and says so while the capture runs on
and is saved in full. A rolling window was rejected because dropping the oldest
packets renumbers frames, and a frame number that means something different on
each poll breaks both the detail pane and the append-only list that depends on
frame numbers being stable.

---

## How a capture reaches tshark

This is the part most likely to surprise a reader, so it gets its own section.

An encrypted capture is never decrypted to a file. It is decrypted in flight and
streamed to `tshark` on stdin, so the only plaintext that exists is the few
kilobytes in transit between the two processes:

```
capture.pcap.enc ──▶ EncryptedSource.chunks() ──▶ os.pipe() ──▶ tshark -r -
                     (decrypts 64 KiB at a time,
                      off the event loop)
```

The pipe is created explicitly with `os.pipe()` rather than by passing
`stdin=PIPE`. That is not a stylistic choice. Wiretap, the library beneath both
`tshark` and `capinfos`, accepts a regular file or a FIFO on stdin and rejects
anything else:

```
tshark: The standard input is a "special file" or socket or other non-regular file.
```

asyncio's `stdin=PIPE` is a real pipe and passes that check. **uvloop's is a Unix
socketpair and does not** — and `uvicorn[standard]` selects uvloop, so the
container runs uvloop and a development machine running the test suite on stock
asyncio does not. Creating the pipe directly makes the descriptor a FIFO under
either event loop. The regression test asserts the kind of descriptor rather
than the loop, so it holds for both.

Feeding runs as its own task while stdout is drained, because a capture larger
than the pipe buffer would otherwise deadlock: the writer blocks on a full pipe
while the reader waits for output that cannot come.

---

## Data at rest

Envelope encryption, `crypto.py`:

```
master key (KEK)          from outside the data volume, never stored beside it
    │
    └─ wraps ─▶ data key (DEK)     random 256-bit, one per capture file
                    │
                    └─ seals ─▶ 64 KiB chunks, AES-256-GCM
```

The file format is versioned and self-describing:

| Field | Size | Purpose |
| --- | --- | --- |
| magic | 8 bytes | `PCAPENC\x01` — format identification and version |
| kek_id | 16 bytes | `SHA-256(KEK)[:16]`, so a wrong key is named rather than guessed at |
| dek_nonce | 12 bytes | nonce for the wrapped data key |
| wrapped_dek | 48 bytes | `AES-256-GCM(KEK, DEK)`, AAD = magic ‖ kek_id |
| chunks | repeated | 4-byte length ‖ 12-byte nonce ‖ ciphertext+tag |
| terminator | — | a zero-length chunk marks a clean end |

Each chunk is sealed with AAD = magic ‖ chunk index, so chunks cannot be
reordered within a file or spliced between files. The explicit terminator makes
truncation detectable rather than indistinguishable from a short capture.

**Where the key comes from** is the whole point. Encrypting with a key stored
beside the data protects nothing. The master key arrives as a Docker secret file,
an environment variable, or is derived from an admin passphrase with scrypt
(N = 2^17, roughly 128 MB and 100 ms per attempt) and exists only in RAM.

**The startup policy fails closed.** A missing key with encrypted captures
present, or a key that does not open the captures already stored, refuses to
start rather than silently writing new captures under a different key or in the
clear. Running unencrypted is possible but requires
`ALLOW_UNENCRYPTED_CAPTURES=true` — it never happens by accident.

**What this protects against:** someone who reads the data volume, a stolen
backup, a discarded disk, a copied captures directory. **What it does not:**
someone who can execute inside the running container or read its memory. That is
the honest limit of any at-rest scheme whose key must be present for the app to
run unattended.

---

## Data in transit

Two different links, protected differently.

**Browser to pcap-server** is the operator's problem to terminate, because a LAN
appliance cannot obtain its own certificates. So instead of pretending, the app
degrades explicitly: **over plain HTTP it runs read-only.** Anything that changes
state, and anything that exports capture contents in bulk, is refused with a
structured error the UI renders in full rather than as a bare 403. Viewing is
allowed. The exceptions are the endpoints without which there is no way in at
all — login, logout, register, TOTP confirm — because refusing those would leave
no degraded mode, just a locked door.

Loopback counts as secure transport: a connection that never leaves the machine
has no wire to be read from. `X-Forwarded-Proto` is honoured only when
`TRUST_PROXY_HEADERS=true`, because an untrusted client can set it.

**pcap-server to the target host** is SSH, key-based only — `asyncssh.connect`
is called with `password=None` and `passphrase=None` explicitly, so there is no
path by which a password could be used. That is why passwordless sudo is
required on the target: there is no password to give it.

---

## Authentication

| Mechanism | Detail |
| --- | --- |
| Passwords | scrypt, N = 2^17, r = 8, p = 1, dklen 64. Parameters are stored in the hash so cost can be raised later without invalidating existing passwords; `needs_rehash` detects the old implicit format |
| Comparison | `hmac.compare_digest`, not `==` |
| Sessions | 48 bytes from `secrets.token_urlsafe`. **The database stores only the SHA-256 digest**, so a leaked database does not hand over live sessions |
| Cookie | `HttpOnly`, `SameSite=Strict`, `Secure` by default (`COOKIE_SECURE=false` for plain-HTTP deployments) |
| Expiry | Absolute expiry enforced in SQL, idle expiry enforced on read. An idle session is *deleted*, not merely rejected, so a later request inside the window cannot revive it |
| Second factor | TOTP with `pyotp`, one-step validation window either side of the current code |
| Trusted devices | Separate 48-byte token, also stored as a digest, with its own expiry |
| Login throttling | Per-client-IP, five attempts then a fifteen-minute lockout, both adjustable at runtime |

**TOTP is enforced by the API, not only by the frontend.** It used to be the
other way round: a first login returned `needs_totp_setup: true` and the UI
acted on it, but no route checked `totp_confirmed`, so a client that ignored the
flag held a session backed by a password alone with the whole API behind it. The
check now lives on `get_current_user`, the dependency every protected route
already shares, so a route added later cannot forget it. Enrolment opts out
visibly by depending on `get_session_user` instead — the same session lookup
without the second-factor requirement — and `/api/auth/status` stays open,
because a half-enrolled account has to be able to reach the screen that finishes
enrolment.

Session `last_seen` is written at most once a minute rather than on every
request. On a single-writer database, touching a row per API call is both
wasteful and a lock-contention risk; the write interval is far shorter than the
idle window, so throttling cannot meaningfully extend a session's life.

---

## Input validation

Every input has a validator in `models.py`, and each one exists for a specific
reason rather than as a general precaution.

**SSH usernames** are constrained to `[A-Za-z0-9_][A-Za-z0-9._@-]{0,63}`. The
prerequisite check prints a sudoers rule naming this user for an operator to
paste in as root. Everything sudoers gives meaning to — whitespace, `#`, `,`,
`=`, `(`, `)`, `:`, `!` — is excluded, so a username cannot extend that rule
into a broader grant than the one binary it names. The stored-username list uses
the same validator, because a name saved there is offered straight back into a
server.

**tcpdump flags** are checked against a refusal list — `-z`, `-Z`, `-W`, `-G`,
`-C`, `-r`, `-F`, `-V` — on the fully built argument list, immediately before
execution. `tcpdump` may be running under sudo, and those flags turn a capture
into command execution or arbitrary file reads as root. Nothing user-supplied
reaches tcpdump as a flag any more, which is exactly why this is checked rather
than assumed: a future change that routes input back into the argument list
fails here instead of quietly handing root a `-z`.

**BPF filters** reject shell metacharacters and are passed as a single argument
after `--`, so a filter beginning with a dash is read as an expression rather
than an option, and a filter can never become part of the command.

**Display filters** reject `;`, `$`, backtick and backslash, and are capped in
length. `&` and `|` are deliberately allowed: a display filter reaches tshark
through `create_subprocess_exec` as one argv element with no shell anywhere on
the path, so shell operators in it are text for tshark to reject as bad filter
syntax rather than commands — and Wireshark's own `&&`, `||` and bitwise
matching need them. A test runs a probe command and inspects `argv` to assert
that property rather than leaving it as a claim in a comment. The capture filter
keeps the stricter rule, because that one does travel inside a command string
over SSH where a shell parses it.

**PDML** is parsed only after the raw bytes are checked for a document type
declaration. tshark never emits one, so its presence means the input is not
tshark's output; expat resolves internal entity definitions, which is the single
route by which a captured packet's own contents could turn into an expansion
attack against this process. Nothing is fetched over the network during parsing
and no external entity is ever resolved.

**Click-built filters** are quoted before they are sent, and a value containing
any character the display filter rejects degrades to an existence test on the
field rather than an equality. The validator was deliberately not relaxed to
make click-to-filter more expressive: the filter language's own quoting is the
thing that was made correct instead.

**tcpdump paths** must be absolute and end in `/tcpdump`.

**SSH key names** must be plain filenames with no path separators and no `..`.

**Remote stderr is treated as hostile input**, because it comes from the machine
under investigation. The progress-count pattern is bounded to twelve digits, so
a flood of digits cannot hand `int()` a quadratic parse, and the retained buffer
is capped, so a chatty or malicious host cannot grow it without limit.

### MAC address columns

The `-e` view flag asks for `eth.src`, `eth.dst` and `sll.src.eth` together.
`tcpdump -i any` produces a Linux cooked capture, which has no Ethernet header
at all, so the Ethernet fields are empty on every frame of the captures taken
with the default interface. Whichever field the frame actually carries wins. A
cooked header records the sender's address but no destination, so that column is
genuinely empty there; on a capture from a named interface both are real, which
is where the flag earns its place.

### Timestamps

The viewer can render a packet's time in the reader's own time zone. tshark
cannot do this: `frame.time` is the capture host's local time, and this
container runs on UTC with no knowledge of where the person reading the capture
is. So the `-tz` flag asks tshark for `frame.time_epoch` and the browser formats
it, which is the only place the answer exists. The other timestamp modes are
unchanged, and `-tttt` still shows the server's UTC.

---

## SSH host key verification

Host keys are managed per endpoint, not per row. A host answers with one key per
algorithm — `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa` — and whichever the
two ends negotiate is the one checked. So all of a host's keys are stored,
trusted and forgotten as a set; deleting one row would have left the rest still
verifying the host, with the next scan restoring the deleted one.

An unverified host is refused rather than connected to unchecked, and the UI
says which hosts are in that state. (This paragraph described the old fail-open
behaviour, which 0.1.0-dev.17 replaced.) The negotiated algorithm is reported
after connecting, and a negotiation weaker than what the host had available is
flagged.

Keys are taken on in two steps. `POST /api/admin/known-hosts/scan` runs
ssh-keyscan and returns each key with its OpenSSH SHA256 fingerprint, storing
nothing; `POST /api/admin/known-hosts/confirm` pins the keys handed back to it.
Confirm deliberately does not re-scan: the keys it stores are the ones the
admin read, so nothing can change between the display and the acceptance.

---

## Not capturing yourself

Capturing an interface that carries pcap-server's own traffic records its own
web session: over plain HTTP that is the admin password verbatim, and on any
connection the session cookie and TOTP code — written into a capture that is
then stored and browsable in this UI. On a Docker host, capturing `any` also
sweeps the bridge interfaces and records every other container's traffic.

`localnet.py` checks a target before a server can be added, in decreasing order
of certainty: loopback and any address the container holds (unambiguous), the
default gateway (on a Docker bridge network, that is the host), and the names
Docker publishes for the host. What it cannot detect is the host's LAN address
when the container has never been told what the host is called. So it reports
what it found rather than claiming proof of non-locality.

---

## Browser-side defences

Content-Security-Policy is defence in depth behind output escaping, not instead
of it. `connect-src`, `img-src` and `form-action` mean script running on this
origin cannot send anything to another host, by fetch, by image URL, or by form
submission. `frame-ancestors` blocks clickjacking and `base-uri` stops an
injected `<base>` silently re-pointing every relative URL.

`script-src` does not need `unsafe-inline`: every inline handler was moved to
`addEventListener`, and the one remaining inline script — the theme-flash
snippet that must run before `app.js` loads — is pinned by content hash.

Also set on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options:
DENY`, `Referrer-Policy: no-referrer`, a `Permissions-Policy` denying camera,
microphone, geolocation and interest-cohort tracking, and same-origin COOP and
CORP. HSTS is sent
only where TLS is genuinely in use — sending it from a LAN deployment that later
cannot do TLS would lock operators out of their own tool.

---

## Storage layout

| Path | Contents | Notes |
| --- | --- | --- |
| `/app/data` | SQLite database | WAL mode, foreign keys on |
| `/app/captures` | Capture files | `<uuid>.pcap.enc` when encryption is on |
| `/app/ssh-keys` | SSH private keys | Uploaded through the Admin panel |
| `/run/secrets/…` | Master key | Deliberately **not** on a data volume |

Tables: `users`, `sessions`, `trusted_devices`, `active_servers`, `known_hosts`,
`known_usernames`, `captures`, `settings`.

Schema changes are applied in place at startup by `_migrate()`, guarded by
`PRAGMA table_info` checks so they are idempotent. One-shot data migrations are
flagged in `settings` rather than re-run, so a backfill cannot resurrect a row
the operator has since deleted.

Every SQL statement is parameterised. The two places that interpolate into SQL
at all interpolate hardcoded literals chosen by a local `PRAGMA`, never input.

Keeping metadata and captures on separate volumes matters: the database holds
the encryption salt, and a backup that contains both the salt and the captures
is a smaller step from plaintext than one that does not.

---

## Runtime settings

Adjustable from the Admin panel, applied without a restart:

| Setting | Default |
| --- | --- |
| `max_capture_seconds` | 300 |
| `max_capture_packets` | 100000 |
| `max_concurrent_captures` | 5 |
| `max_live_streams` | 2 |
| `live_stream_buffer_mb` | 16 |
| `session_duration_hours` | 8 |
| `session_idle_timeout_minutes` | 60 |
| `device_trust_days` | 30 |
| `rate_limit_max_attempts` | 5 |
| `rate_limit_lockout_minutes` | 15 |
| `rate_limit_packets_per_min` | 30 |
| `rate_limit_captures_per_min` | 10 |
| `rate_limit_live_polls_per_min` | 90 |

---

## Testing

`scripts/check.sh` is the single entry point, used by CI and locally so the two
cannot drift. It reports which of `tshark`, `tcpdump`, `capinfos` and `docker`
are present, then runs pytest with `-r s` so skipped tests appear in the report.
A suite that prints "all passed" while quietly dropping the tshark-dependent
tests is how a real regression ships unnoticed.

Tests alone are not sufficient here, and the history says so plainly. A missing
comma once left `app.js` unparseable and blanked the entire UI while every test
passed, and the uvloop socketpair failure passed every test on stock asyncio
while failing every capture in the container. Changes to the frontend or to
subprocess handling get driven in a real browser against a real server.

---

## Known limits

- The pcap exists in the clear in `/tmp` on the **target** host for the duration
  of the capture. Inherent to `tcpdump -w` on a remote machine.
- At-rest encryption cannot protect against code execution inside the running
  container.
- A live stream holds up to `live_stream_buffer_mb` of **unencrypted** packet
  data in process memory for as long as the capture runs. Packets already pass
  through memory in flight on the way to tshark; what is new is the duration and
  the volume, and it is bounded by that setting and by `max_live_streams`. It is
  never written to the data volume, and it is discarded when the capture ends.
- A live stream cannot be taken of everything at once. `any` with no filter is
  refused, because the fixed-size buffer above would freeze within seconds of a
  busy host and stay frozen. Ordinary captures are unaffected.
- Self-capture detection cannot see the host's LAN address from inside a bridged
  container.
- Passwordless sudo for `tcpdump` on the target is a privilege boundary the
  operator chooses to open. Use a dedicated account for it. The `setcap` route
  avoids sudo entirely and is preferred.
- The single-writer SQLite database is fine for the concurrency this tool sees
  and would not be for much more.

---

## Roadmap

**MCP server.** Expose pcap-server's capabilities over the Model Context
Protocol, so an agent can list servers, start a capture, and query the resulting
packets as tools rather than by driving the HTTP API. The interesting questions
are authorisation — an MCP client is not a browser session and should not
inherit one — and how much of a capture should be allowed to cross that boundary
at all.

**Packet sanitizer.** Produce a redacted copy of a capture that can be shared
outside the team: strip or mask payloads, credentials in cleartext protocols,
authentication headers, and optionally rewrite addresses consistently so traffic
patterns survive while identities do not. This is what makes a capture shareable
with a vendor or attached to a ticket, and it pairs directly with the at-rest
encryption already here — the encryption protects what must not leave, and the
sanitizer defines what may.
