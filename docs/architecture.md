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
| `sanitizer.py` | Sanitized downloads: the tshark pass, the field rules, walking pcap records, and keeping it in step with the frame walker |
| `framewalk.py` | Addresses and checksums in frame headers, and incremental checksum updates |
| `anonymize.py` | Keyed stand-ins: prefix-preserving IP addresses, MAC addresses, same-length names |
| `crypto.py` | The envelope format, sealing and opening |
| `vault.py` | Key resolution, startup policy, plaintext migration |
| `localnet.py` | Detecting that a capture target is the machine pcap-server runs on |
| `bpf.py` | Deciding whether a capture filter can match anything, before the capture runs |
| `resetmfa.py` | Host-side second-factor reset, for when nobody can sign in to press the button |
| `serve.py` | The container's entry point: opens the vault, then starts uvicorn — over TLS when a certificate is stored |
| `tls/` | Built-in HTTPS, self-contained: the DNS provider allowlist (`providers.py`), where URL settings may point (`destinations.py`), what is stored and sealed (`store.py`), the one place lego runs (`lego.py`), the running app's view (`manager.py`), the memfd hand-off (`serving.py`), and the Admin routes and `python -m backend.tls` CLI |

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
                                    ├── on `any`: reads the interface index table (again after exit)
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

## Removed: streaming a capture live (0.1.0-dev.33)

A **Live stream** option once opened the Viewer on a capture while it was
still running, reading the growing remote file over a second SFTP connection.
It was removed — see the dev.33 CHANGELOG entry — for a reason unrelated to
its own design: a capture taken with heavy TCP segmentation/generic receive
offload active on the target's NIC can contain frames tens of kilobytes wide,
because the kernel hands the capture point one coalesced buffer before (or
after) the real on-wire segmentation, not the ~1500-byte frames that actually
crossed the link. That distorts file size, packet count and per-packet timing
regardless of live streaming, but a live view made it easiest to catch mid-way
through a capture — making the feature look more implicated than it was.
Correctness of what a capture reports was judged more valuable than the
watch-as-it-records convenience, so the feature was cut rather than kept and
caveated. The pcap-format record-walking code it used (`GLOBAL_HEADER_LEN`,
record header parsing, the magic-byte table) moved into `sanitizer.py`, its
only remaining consumer; `BytesSource` (a `PcapSource` over an in-memory
buffer) moved into `pcapsource.py` as general-purpose test/production
infrastructure. Nothing about capture correctness for GRO/TSO-affected NICs
changed — the standard remedy, when it matters, is disabling offload on the
target's interface before capturing (`ethtool -K <iface> tso off gso off gro
off lro off`), which this app does not do on the operator's behalf.

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

## Statistics: Protocol Hierarchy, Conversations, Follow Stream

Three more views over a capture, `packet_parser.get_protocol_hierarchy` /
`get_conversations` / `get_follow_stream`, behind
`/api/captures/{id}/protocol-hierarchy`, `/api/captures/{id}/conversations`
and `/api/captures/{id}/stream/{protocol}/{stream}`. All three read-only,
rate-limited on the same budget as the packet list, and authorized the same
way as every other capture route: `_require_readable_capture`.

**The hierarchy and the conversations are built in Python, not by parsing
tshark's own `-z io,phs` / `-z conv,ip` reports.** Those are formatted for a
terminal — indentation carries the tree, column widths size themselves to
the addresses present — which makes them the wrong thing to screen-scrape
when the same totals can be read directly off one `-T fields` pass, the same
mechanism `get_packet_list` already uses:

```
get_protocol_hierarchy: -e frame.protocols -e frame.len   (one line per packet)
get_conversations:      -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e frame.len
```

`frame.protocols` is a colon-separated layer list (`eth:ethertype:ip:tcp:http`);
folding it into a tree by walking each packet's list once, accumulating
frames and bytes at every layer it passes through, reproduces tshark's own
Protocol Hierarchy Statistics exactly — including that a layer's bytes are
the packet's FULL length, not that layer's own share of it, verified against
a real capture. Conversations are keyed by the address pair sorted once, so
the same two addresses land in one bucket regardless of which was `src` on a
given packet; direction is tracked per packet against that sorted key, which
is what lets `packets_a_to_b` and `packets_b_to_a` come out right without a
second pass. Endpoint totals are folded in from the same rows, so all of
Conversations and Endpoints is one tshark spawn, not two.

**Follow Stream uses `-z follow,<proto>,raw,<index>`, not `,ascii` or `,hex`.**
All three were tried against a real capture before choosing:

- `ascii` replaces non-printable bytes with `.`, which is fine for a lossy
  preview but wrong for anything that has to be byte-exact.
- `hex` is byte-exact, but its offsets run continuously across consecutive
  same-direction frames — verified against a real capture with two frames in
  a row from the same side, which come back as one merged run, offsets
  0000000A picking up where 00000000 left off. There is no way to split that
  back into per-frame lines.
- `raw` is byte-exact AND keeps frame boundaries: the same two-consecutive-
  same-direction-frames capture comes back as two separate lines under
  `raw`, not one. Each line is a bare hex string, tab-prefixed for the
  second endpoint, and turns into a `FollowStreamSegment` directly.

A stream index that does not exist is not an error to tshark — it exits 0
and prints `Node 0: :0` / `Node 1: :0` with no data lines, rather than
failing. An empty address before the colon is the only signal that the
index was never real (checked against a real capture), so that is what
`get_follow_stream` raises `ValueError` on.

`PacketSummary` and `PacketDetail` both carry `tcp_stream` / `udp_stream`
(`None` when the packet is in neither) so the frontend can offer Follow
Stream from a packet's row in the list — Wireshark's own workflow — without
first opening its detail pane to find the index. The row's copy comes as two
more `-T fields` columns on the existing `get_packet_list` call; the detail
pane's comes from walking its PDML tree for the field, since PDML already
carries every field tshark dissected, hidden ones included.

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

**Browser to pcap-server** is TLS terminated either by pcap-server itself or by
a reverse proxy. Built-in HTTPS lives in its own package, `backend/tls`, and
touches the rest of the app only through what `backend/tls/__init__.py` exports.
It obtains a Let's Encrypt certificate with [lego](https://go-acme.github.io/lego/)
over DNS-01 — the only challenge that needs no inbound port, which a LAN capture
box rarely has — and uvicorn serves it directly; there is no bundled nginx and
still one process in the container. lego is a single static binary, fetched at
build time by pinned version and checksum.

Four details carry the security weight:

- **The key is never a file.** uvicorn and Python's `ssl` module only load a key
  from a path, so `serve.py` opens the sealed key into a `memfd` — an anonymous
  in-memory file reachable as `/proc/self/fd/N` — lets uvicorn build its context
  from it, and closes it. lego runs with a directory under `/dev/shm` as its
  working directory, `HOME` and `--path`, removed when it exits, so its ACME
  account key, the issued key and any credential file never reach disk either.
  This is also why `serve.py` exists: uvicorn's CLI builds the TLS context
  *before* importing the app, and only the app's vault can open the key.
- **lego's environment is an allowlist.** Provider settings reach lego as
  environment variables, and lego reads more than provider settings: `LEGO_*`
  variables include hooks that run commands, and any `NAME_FILE` makes lego read
  `NAME` from a file. `backend/tls/lego_providers.json`, generated from lego's own
  provider metadata by `scripts/gen_lego_providers.py`, lists the variables each
  provider documents; only those are passed, validated by name, with nothing
  from the app's own environment. Variables lego reads as paths are filled with
  files the app writes into the scratch directory from contents the admin
  pasted. `exec`, `manual` and `acmedns` are excluded outright, as are settings
  that disable TLS verification and file settings whose contents can run a
  command or name another path. URL and address settings go through
  `destinations.py`: `http(s)` only, and never loopback, link-local (cloud
  metadata), unspecified or multicast — checked as typed and again after
  resolution immediately before lego runs. The residual is DNS rebinding in the
  seconds between that lookup and lego's own; LAN addresses are allowed by
  design.
- **Renewal reloads in place.** `SSLContext.load_cert_chain` on the context the
  server is already using swaps the certificate for every later handshake, so a
  renewal needs no restart. Only the first switch from HTTP does, and `serve.py`
  handles that by `execv`-ing itself — same PID, so the container never stops.
- **lego's argv is built defensively.** It runs without a shell, but a domain of
  `--path=...` would still be read as a flag. The domain and email are validated
  to a plain hostname and address, every user value is passed as `--flag=value`,
  and the finished argv is checked once more before it runs. lego also loads a
  `.lego.yml` from its working directory if one exists; the fresh scratch
  directory has none.
- **lego waits instead of polling DNS.** It runs with
  `--dns.propagation.wait=<delay>s` (30 s by default, the admin's **Wait before
  validation**), which skips lego's own check that the challenge record is
  visible — a check made through the container's resolver, which failed on a
  network where certbot and Proxmox succeed. Neither of those polls local DNS;
  they wait and let Let's Encrypt look, and so does this.

The cipher list is narrowed to ECDHE with AEAD for TLS 1.2, with TLS 1.2 as the
floor. uvicorn's own default string, `TLSv1`, selects the TLS 1.0-era CBC/SHA-1
suites for a TLS 1.2 client.

Without TLS from either source, the app degrades explicitly: **over plain HTTP it
runs read-only.** Anything that changes
state, and anything that exports capture contents in bulk, is refused with a
structured error the UI renders in full rather than as a bare 403. Viewing is
allowed. The exceptions are the endpoints without which there is no way in at
all — login, logout, register, TOTP confirm — because refusing those would leave
no degraded mode, just a locked door. The built-in certificate routes under
`/api/admin/tls` are the other exception — they are how an install gets off
plain HTTP without a proxy — and stay admin-only; the DNS credentials they
carry are the cost, and the CLI is the way to avoid paying it.

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
| Second-factor reset | An admin may reset **another** account (`POST /api/admin/users/{id}/totp/reset`), which NULLs the secret, deletes every session that account holds and forgets its trusted devices. Self-reset is refused: reaching a route means already being past the second factor, so it cannot help a locked-out admin, and it would let a stolen session strip MFA and enrol the thief's own authenticator. The locked-out sole admin is answered out of band by `python -m backend.resetmfa`, at the bar of host access |
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
than an option, and a filter can never become part of the command. The same
validator guards `/api/filters`, where an operator saves a filter under a name
of their own: a saved filter is replayed into a real capture later, so an
expression refused at the Capture form must not become runnable by arriving
through a different box. `&` and `|` are deliberately allowed — they are BPF's
own bitwise operators and every `tcpflags` expression needs them.

**A capture's filter is stored on its record**, in `captures.bpf_filter`, and
not recovered from the command string. Both are true of `interface` for the
same reason: re-parsing a shell command that also carries `-i`, `-w` and `-s`
would mean a second BPF parser in the codebase, and a rule that depends on
re-parsing a command breaks the first time the command changes shape. Captures
written before the column existed read as empty, and the UI treats empty as
"says nothing" rather than as "no filter" — guessing unfiltered loses a label,
guessing a filter would be a claim about what is inside the file.

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

### The column layout

Which columns the packet list shows, in what order, under what titles, is a
preference of the account rather than markup. It is stored server-side, in
`column_layouts` (one row per user, the columns as JSON), so it follows the
operator between browsers and applies to every capture — the way a Wireshark
column preference does, and unlike a saved view, which belongs to one capture.

**No row means the default.** An account that has never arranged its columns
has nothing stored, rather than a stored copy of the built-in list, so a later
change to the default reaches everyone who never customised. The Reset control
deletes the row for the same reason.

A column is one of two things. The **built-ins** (`number`, `time`, `source`,
`destination`, `interface`, `src_mac`, `dst_mac`, `protocol`, `length`, `info`)
are rendered from `PacketSummary`'s own fields, some with behaviour of their
own — a timestamp that follows the view flags, an interface cell that also
carries its index for the filter menu. An **added column** is any tshark field,
identified as `field:<name>`, fetched as one more `-e` on the pass
`get_packet_list` already runs and returned in `PacketSummary.values` keyed by
field name. One pass, so a column costs no extra round trip; the built-in
fields are fetched whether or not they are displayed, which keeps Follow Stream
and the conversation filter working from a row whose address columns were
removed.

Two details about that pass are load-bearing:

- **Added fields go last in the argv**, after the MAC fields, so a column the
  operator added never shifts the positions the built-in ones are read from.
- **Their values are read from the end of the row**, not by counting forward.
  The Info column is free text in the middle of the row and a tab inside one
  would shift every position after it; the built-in columns have always read
  forward and are left as they were, but the added ones can be read from the
  side of the row that nothing shifts.

**A field name is an argv boundary.** It reaches tshark as `-e <name>`, so a
name beginning with `-` would arrive as a flag instead — `-r`, with a path of
the caller's choosing behind it. `PACKET_FIELD_RE` refuses anything that is not
a dotted field name, and it is applied at the model, at the save route, and
again on every packet list, because the query string on a list request is the
caller's and not necessarily the saved layout's.

**A field tshark does not know is refused when the layout is saved**, by a
streamed pass over `tshark -G fields` — its dissector registry, the same list
Wireshark's own Custom column type offers. The check runs on save, never on a
packet list, because the registry is a multi-megabyte stream and the list is
the hot path; confirmed names are memoised, bounded, and only positives are
kept, so a name that was wrong once is re-checked rather than pinned as wrong
past the next image build. Protocol names count as fields: `-e tcp` is what
Wireshark's own protocol columns are built from.

### MAC address columns

The `-e` view flag asks for `eth.src`, `eth.dst` and `sll.src.eth` together.
`tcpdump -i any` produces a Linux cooked capture, which has no Ethernet header
at all, so the Ethernet fields are empty on every frame of the captures taken
with the default interface. Whichever field the frame actually carries wins. A
cooked header records the sender's address but no destination, so that column is
genuinely empty there; on a capture from a named interface both are real, which
is where the flag earns its place. The flag remains a quick toggle: it inserts
the two columns where they sat before layouts existed, without editing the
stored layout. Adding **Src MAC** or **Dst MAC** from the Columns dialog puts
them in the layout instead, and they are then shown whether or not `-e` is on.

### Interface column

`tcpdump -i any` writes Linux cooked v2 on current tcpdump, and that header
records, for each packet, the index of the interface it crossed
(`sll.ifindex`) and the kernel's packet type (`sll.pkttype`: in, out,
broadcast, multicast, to another host). It does not record a name, and an index
means nothing off the host that assigned it. So a capture on `any` also reads
`/sys/class/net/*/ifindex` from the target — no privilege needed — once as it
starts and once after tcpdump exits, merged, because an interface created during
the capture (a container's veth) only exists in the second reading. The table is
stored in `captures.interface_names` as JSON and the Viewer shows `eth0 out`
rather than `2`. Neither reading can fail a capture: without the table the
column shows `#2`. Where one index was reused by a different interface between
the two readings, the later name wins.

Remote output is hostile input here as well: a line must be an ASCII index and
an interface-name-shaped name of at most 15 characters, and the table stops at
4,096 entries. Cooked v1, which older tcpdump writes, has a packet type but no
index, so the column shows only the direction. The column is hidden for a named
interface, where it would repeat one name on every row.

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

Keys are taken on in two steps. A scan runs ssh-keyscan and returns each key
with its OpenSSH SHA256 fingerprint, storing nothing; a confirm pins the keys
handed back to it. Confirm deliberately does not re-scan: the keys it stores
are the ones the operator read, so nothing can change between the display and
the acceptance.

There are two scan routes and they differ only in who may call them.
`POST /api/admin/known-hosts/scan` is admin-only and pairs with
`/api/admin/known-hosts/confirm`. `POST /api/host-keys/scan` is the same
non-mutating scan open to any signed-in user, because the add-server form has
to show fingerprints before the server exists — scanning cannot change what
this install trusts, so widening it costs nothing but an ssh-keyscan spawn
against a caller-chosen address, which is rate limited on the same budget as
the filter check.

The confirm half is where the powers separate. `POST /api/servers` carries the
accepted keys with the create; `POST /api/servers/{id}/trust-host` does the
same for a server that already exists. Both are open to the server's owner, and
both refuse an endpoint that already has keys stored — they establish trust
where there is none and never replace it. Replacing and forgetting stay on the
admin pair.

**Ordering, and why it was inverted.** The kernel check below needs a
connection; a connection needs pinned host keys; pinning was once only offered
for a server that already existed. A server pointing at this very machine was
therefore always created and only refused later. `add_server` now pins, probes,
checks and creates in that order, with one invariant enforced in a `finally`:
keys pinned by a request survive only if that request creates a row. So the
flow manufactures no orphans of its own.

**Lifetime.** `known_hosts` carries no reference to a server row, so deleting a
server used to leave its keys behind for the next person to add that hostname.
`count_servers_for_endpoint` — deliberately unscoped by user, unlike every
other `active_servers` query, because the table it guards is global — makes the
delete path forget the keys when the count reaches zero.

**Probing before the row exists.** Every action button on the add form gathers
host keys itself. `withHostKeys` in `app.js` attempts the action first and only
a `host_keys_required` answer sends the user to the review — so the server stays
the authority on whether an endpoint is already trusted, and a host some other
server already verified is never re-reviewed. The accepted keys are held
client-side in `pendingAddKeys`, keyed on the endpoint they were accepted for,
and handed to Add, Test connection and Check prerequisites alike.

The two probe routes (`POST /api/probe/test`, `/api/probe/prereq-check`) take
those keys on a `ServerProbe` and pin them only for the duration of the
connection, forgetting them again in a `finally` — the same "keys survive only if
a row references them" invariant `add_server` keeps, since a probe creates no row.
An endpoint that is already trusted is left untouched: the pin is a no-op and the
stored keys are used and kept.

**One code for one condition.** When no keys are supplied and the endpoint is
untrusted, `add_server` refuses before connecting and `_connect` raises
`HostNotTrusted` from the probes, before it so much as opens the client key
(since dev.40 — it used to decrypt and parse our key first, so a missing or
locked key could hide the untrusted answer behind a generic failure). Both now answer `409` with code
`host_keys_required`, naming `hostname` and `port` as their own fields. They used
to differ — a `400 host_keys_required` from add and a `409 host_not_trusted` from
the probes — which meant every caller had to know both, and the form handled one
of them on Add while the probe buttons handled the other. A single handler is
only possible because the answer is single.

**Editing forgets the endpoint it leaves.** `update_server` runs the same
cross-user `count_servers_for_endpoint` refcount the delete path does, so
repointing the last server at an address forgets that address's keys. Without it
every corrected typo left an orphan behind — the same orphans Admin → Known
hosts grew a purge button for, manufactured faster than the button could clear
them.

---

## Not capturing yourself

Capturing an interface that carries pcap-server's own traffic records its own
web session: over plain HTTP that is the admin password verbatim, and on any
connection the session cookie and TOTP code — written into a capture that is
then stored and browsable in this UI. On a Docker host, capturing `any` also
sweeps the bridge interfaces and records every other container's traffic.

`localnet.py` answers this in two layers, because they can see different things.

**The address layer** (`describe_if_local`) runs before anything connects, in
decreasing order of certainty: loopback and any address the container holds
(unambiguous), any address `HOST_ADDRESSES` names, the default gateway (on a
Docker bridge network, that is the host), and the names Docker publishes for
the host. `HOST_ADDRESSES` is the one answer to the host's own LAN address,
which a bridged container cannot otherwise see and which is exactly what an
operator would type for their own Docker host. It is read from the environment
on each call rather than captured at import, and an entry that is not an IP
address is logged and dropped rather than quietly ignored — a typo there would
silently remove a protection the operator believes they turned on. It is also
the only layer that works with no connection, no trusted keys and an
unreachable target.

**The kernel layer** (`describe_if_same_kernel`) covers exactly that case.
Containers share the host's kernel, so `/proc/sys/kernel/random/boot_id` inside
this container is the *host's* boot id. A target that reports the same value is
running on this kernel: it is this machine, whatever address was used to reach
it. Topology does not enter into it, so a LAN address, an alias, a VPN address
and macvlan are all one comparison. The file is world-readable, so the probe
needs no privilege, and it rides a connection that is already open.

It is a positive identification test and is deliberately not treated as more
than that. A target that reports no boot id — a BSD host, a masked `/proc` — has
proved nothing, and refusing it would break legitimate targets for no security
gain. Absence of proof is not proof of non-locality, so the address checks still
apply underneath.

Where each one runs:

| Point | Checks | Why there |
|---|---|---|
| Add server | address, then kernel over the probe's own connection | Stops the server existing at all. The keys accepted on the way in are what lets the probe connect, which is the whole reason the order was inverted |
| Edit server | address only | No probe: an edit can repoint a row, so its verification is cleared and has to be earned again rather than re-proved here |
| Check prerequisites, Test connection | kernel (the probe already connected) | The two actions an operator reaches for when a server misbehaves — and what clears a **Never checked** server |
| Start a capture | stored finding, then address, then "has anything ever checked this?" | A row added before the guard existed, or a hostname DNS has moved, is otherwise never re-examined. The last of the three is weakest and runs last on purpose: it must never be reported in place of a self-target finding |
| `run_tcpdump`, on the capture's own connection | kernel | The only check with no window between it and the capture — this is the connection tcpdump is about to run on |

A finding from a connection is stored on the server row (`self_target_reason`)
and shown in the server list. The row is not deleted: refusing a capture is the
backend's business, and discarding someone's configuration over a finding is
not.

Two things clear it, which together are the recovery path if a finding is ever
wrong. **Editing the row's endpoint** clears it, on the same reasoning that
clears `os_name` — a finding describes a machine, and a new endpoint has not
been examined. **Connecting again and finding otherwise** also clears it:
*Check prerequisites* and *Test connection* re-derive the finding from the host
in front of them and write the answer either way, so they are never blocked by
the stored value. Starting a capture is the one path that trusts the stored
finding without re-proving it, because a capture is the thing worth refusing
cheaply.

---

## Filters that cannot match anything

A capture filter that matches nothing does not announce itself. tcpdump starts,
runs for its full duration, and comes back with zero packets — which reads
exactly like "there was no such traffic". The operator learns nothing except
that a capture window was spent, and on a production host that is not always
cheap to repeat.

The filters that go wrong this way are built rather than typed. The capture
filter library offers **…and this** to combine two picks, and for a host row
plus a protocol row `and` is correct. For two protocol rows it is not: a packet
carries one source port and one destination port, so two services is one
constraint more than there are slots to hold it. Three is hopeless.

Two checks run, and they answer different questions.

**`bpf.py`'s structural check** models the port constraints directly: which
ports each `and` operand permits, on which of the two slots, under which
protocol. It then searches for a single packet satisfying all of them — a
protocol and two port values, so the whole search space is small enough to
brute-force. It exists because **libpcap cannot answer the question that
matters most**. `tcp port 80 and tcp port 443` compiles perfectly well, because
it genuinely matches a packet running from port 80 to port 443; libpcap is
right to accept it and will never object. Only a model of what was meant can
say no such traffic exists.

**The compile check** hands the expression to the real tcpdump with `-d`, which
compiles and exits without opening an interface or needing any privilege. That
is the authority on emptiness and the only thing that can speak to syntax,
because it is the same compiler the target host will use.

The structural model is **sound rather than complete**: it stays silent about
anything it does not fully understand — a `not` anywhere, an operand that is
not purely about ports, a named port whose number lives in `/etc/services` on
the target. Every unparsed term is read as "constrains nothing", which can only
make it quieter. That direction is deliberate. A warning that is wrong about a
filter somebody meant teaches them to dismiss the next one, and the next one
may be right.

Neither check refuses a capture. Both warn, and the operator decides.

The same model is implemented twice, in `bpf.py` and in `app.js`, and that is a
cost paid for timing: the browser copy answers with no round trip, so the
filter menu can carry its warning at the moment of the click rather than after
a capture has been started. `bpf.py` is the authority — it also compiles. A
browser test runs a shared corpus through both and fails if they disagree,
because nothing else would notice them drifting apart.

The check endpoint is a `GET` under `/api/bpf/`, for two reasons that are easy
to get wrong. `GET` because it changes nothing, and because the
read-only-over-HTTP middleware refuses mutating calls — a checker that vanished
exactly when the app went read-only would be missing from the configuration
where a wasted capture is hardest to retry. Its own prefix because
`/api/captures/{capture_id}` would otherwise match `check-filter` as an id,
leaving correctness dependent on route declaration order.

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

## Sanitizing a capture

`GET /api/captures/{id}/sanitize` streams a sanitized copy of a finished capture
(or, with `view=`, of one saved view run through `stream_filtered_pcap` first).
Nothing is written: the capture is decrypted in flight exactly as for a
download, and the output goes straight to the response.

**Two readers, one capture.** The capture is opened twice at once:

- `framewalk.walk()` reads every record's headers — Ethernet, VLAN, Linux cooked
  v1/v2, raw IP, MPLS, PPPoE, IPv4, IPv6 and its extension headers, TCP, UDP,
  ICMP and ICMPv6 (including the header an error quotes and neighbour-discovery
  targets and options), ARP, GRE, VXLAN, Geneve and IP-in-IP — and reports
  where every address and every checksum is. This covers the addresses on every
  packet without tshark.
- tshark runs once with a display filter built from the ticked options, and
  prints `-T json -x` for only the packets that match: each field with its byte
  position. The sanitizer reads that in step with the records, by frame number.
  tshark prints nothing for a frame the filter does not select, so the walker
  waits for it; memory is one packet from each side.

The JSON is split on tshark's own indentation (`"\n  }"` ends a packet and
appears nowhere else) and read in 1 MB chunks. Reading it a line at a time was
three quarters of the run time.

**Positions are checked, not trusted.** A field from a reassembled, decompressed
or decoded buffer reports a position in *that* buffer. So a field is only written
where its reported bytes are actually found in the frame at its reported offset;
anything else is counted in the summary's `unplaced` rather than written to a
guess. Reassembly and defragmentation are off, so ordinary fields do refer to the
frame. So is TCP sequence analysis, together with `no_subdissector_on_error`:
tshark does not hand a segment it judges to be a retransmission to the protocol
above, so a retransmitted login would otherwise pass through with its password —
measured, 50,000 frames of HTTP `Authorization` reported one field without them.

There is no `-J` top-level layer filter, although it would cut tshark's output
fivefold, because the fields that matter are often not top-level layers: NTLMSSP
sits inside HTTP or SMB2, Kerberos inside SPNEGO. `-J ntlmssp` reports nothing
for an HTTP NTLM login. The header layers the walker has covered are skipped when
the JSON is walked instead.

**Field names are asked of tshark.** `tshark -G fields` is read once per process
for the types of the rule fields and every `FT_IPv4`, `FT_IPv6` and `FT_ETHER`
field. The filter only names fields this tshark has, since a display filter
naming an unknown field is refused outright. Address-typed fields are only
rewritten when their bytes decode to the value shown, which skips fields that
display an address without storing one (STUN's XOR-mapped address).

**Checksums** are updated incrementally, RFC 1624, innermost first — an outer
VXLAN UDP checksum covers the inner packet's checksums, so they have to be
final before it is. Incremental rather than recomputed because a frame cut
short by the snap length has a checksum over bytes that were never captured,
and a checksum that was wrong in the original (offload) should stay exactly as
wrong.

**Keys.** `capture_key()` asks the vault for 64 bytes derived from the capture's
own data key under the label `pcap-server sanitize v1` (`CaptureVault.derived_key`
— the data key itself never leaves the vault). A rekey rewraps the data key
without changing it, so the mapping survives rotation. A plaintext capture has no
data key; it gets the install-wide `data/sanitize.key` combined with its id. The
first 32 bytes key Crypto-PAn, the second 32 key the HMACs for MACs and names.

**The summary** — counts, field names, ports, never a value from the capture —
is known only when the stream ends, long after the response began. The browser
sends a random ticket with the download and polls
`GET /api/captures/{id}/sanitize/summary?ticket=` for it; summaries live in
memory for 15 minutes at most, 500 at most, keyed by user and capture, and are
handed out once. A failure after the response has started cuts the download off,
and the summary says so, so a truncated file never passes for a sanitized one.

A capture in a link type the walker does not know (802.11 radiotap, for one) or
in pcapng is refused before the response starts, for the same reason: a
sanitizer that cannot find the addresses must not produce a file that looks
sanitized.

---

## Storage layout

| Path | Contents | Notes |
| --- | --- | --- |
| `/app/data` | SQLite database | WAL mode, foreign keys on |
| `/app/captures` | Capture files | `<uuid>.pcap.enc` when encryption is on |
| `/app/ssh-keys` | SSH private keys | Uploaded through the Admin panel |
| `/app/data/sanitize.key` | Random key for sanitizing captures stored before encryption was on | Mode `0600`, created on first use, never replaced |
| `/app/data/tls` | Built-in HTTPS certificate, sealed key, sealed DNS credentials, settings | Mode `0700`; see [tls.md](tls.md#what-is-stored) |
| `/run/secrets/…` | Master key | Deliberately **not** on a data volume |

**Host-side modes are the operator's to set, and `data/` is the one that
matters.** On each start the entrypoint chowns `ssh-keys/`, `data/` and
`captures/` to `appuser` (UID 1000) so a bind mount from the host is writable;
it does not set a mode, so they keep whatever the host's umask gave them —
`0755` by default. The database stores each user's **TOTP secret as plain
text**, because codes have to be computed from it, so a world-readable `data/`
hands over a working second factor for every account. Password hashes are
scrypt and session tokens are stored only as digests, so those degrade to an
offline-cracking problem rather than an immediate one; the TOTP seeds do not.
The Quick start therefore creates all four directories `0700`, and
`warn_if_data_dir_exposed()` in `main.py` logs a warning at startup when the data
directory is open to group or others — the only way an install made before that
advice would find out.

Captures and stored SSH keys are sealed, so their directories leak metadata
rather than contents. `secrets/` is never chowned — the Docker daemon reads the
master key as root before the container exists.

Tables: `users`, `sessions`, `trusted_devices`, `active_servers`, `known_hosts`,
`known_usernames`, `captures`, `capture_views`, `custom_filters`,
`custom_display_filters`, `settings`.

Four of those are **scoped to one account** and hold what an operator was
looking at rather than how the app is configured: `active_servers`,
`known_usernames`, `capture_views` and `custom_filters`. Each carries a
`user_id` foreign key onto `users`, each is removed with its owner by
`ON DELETE CASCADE` rather than by anything remembering to, and every statement
that reads or writes one names the `user_id` in its own `WHERE` clause rather
than checking ownership beside the query. A saved capture filter is in that
group for the same reason a server is: `host 10.0.0.7 and tcp port 445` says
what is being investigated and where.

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
| `session_duration_hours` | 8 |
| `session_idle_timeout_minutes` | 60 |
| `device_trust_days` | 30 |
| `rate_limit_max_attempts` | 5 |
| `rate_limit_lockout_minutes` | 15 |
| `rate_limit_packets_per_min` | 30 |
| `rate_limit_captures_per_min` | 10 |

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
- Captures on interfaces with segmentation/receive offload active (GRO/GSO/TSO
  — common on virtio-net and other virtualized NICs) can contain frames far
  larger than any real Ethernet frame, and correspondingly inflated file sizes
  and packet counts. This is a property of the target's NIC driver, not of what
  pcap-server writes; see the dev.33 CHANGELOG entry.
- Self-capture detection cannot see the host's LAN address from inside a bridged
  container.
- Passwordless sudo for `tcpdump` on the target is a privilege boundary the
  operator chooses to open. Use a dedicated account for it. The `setcap` route,
  on a tcpdump limited to a `pcap` group, avoids sudo entirely and is preferred.
  A package upgrade usually undoes it.
- Interface names on an `any` capture come from the target's table at the start
  and end of the capture. An interface that came and went entirely between the
  two shows as its index.
- The single-writer SQLite database is fine for the concurrency this tool sees
  and would not be for much more.
- Sanitizing finds what Wireshark dissects into a field. A credential in a JSON
  body, a hostname in a URL or a `Referer`, or anything in a protocol Wireshark
  does not know is not replaced; the summary lists undissected payload by port.
  Fields split across TCP segments are only found where their first segment
  carries them.
- Prefix preservation is also a known weakness of Crypto-PAn: anyone who knows
  some real addresses in the capture, or managed to get chosen traffic into it,
  learns the mapping of those prefixes, and so the matching bits of every other
  address under them. Name stand-ins keep length and character classes.
- Prefix preservation means a public address can map into a private or
  reserved range, and with **Keep private ranges** could in principle collide
  with a private address that was kept. IPv6 solicited-node multicast addresses
  (and the `33:33:ff…` MACs they use) keep the last 24 bits of the address they
  solicit.

---

## Roadmap

**Windows targets.** Capture from Windows machines as well as Linux and other
Unix hosts. The SSH half carries over: Windows ships an OpenSSH server, and
asyncssh's SFTP client fetches from it like any other. The target side does
not, because it is POSIX throughout: interfaces are listed from
`/sys/class/net`, the capture is staged in `/tmp` and run as `tcpdump -v -w`
(under `sudo -n` when the server is set to), the running packet count is parsed
from tcpdump's stderr, and the prerequisite probe is a shell script. A Windows
target needs its own version of each, chosen per server rather than guessed.
The likely capture tool is Wireshark's `dumpcap.exe` over Npcap: it takes an
interface, a BPF capture filter, a packet count, a duration and a snap length,
and writes pcapng, which tshark already reads. `pktmon` is built in and needs
nothing installed, but has no BPF filter and writes ETL that has to be
converted with `pktmon etl2pcap` before tshark can open it. The argument
validation is written for tcpdump and would need a counterpart for whichever
tool is chosen.

**MCP server.** Expose pcap-server's capabilities over the Model Context
Protocol, so an agent can list servers, start a capture, and query the resulting
packets as tools rather than by driving the HTTP API. The interesting questions
are authorisation — an MCP client is not a browser session and should not
inherit one — and how much of a capture should be allowed to cross that boundary
at all.

