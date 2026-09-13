# Changelog

## 0.1.0-dev.21 — 2026-09-13

### Added

- **Capture filters can be built up from more than one pick.** Both insertion
  paths -- the filter library's Use button and the "Try:" chips -- assigned to
  the BPF field, so a second choice wiped the first and a filter like "this
  host, but only its SMB traffic" could not be assembled from the library at
  all. It had to be typed by hand.

  A pick into an empty field still just fills it. A pick into a field that
  already holds an expression offers the same four modes the display filter's
  right-click menu has: replace, `…and this`, `…or this`, or replace with the
  negation.

  It asks rather than defaulting because neither default is safe. The library
  is mostly port and protocol rows, where a second pick means `or` --
  `tcp port 80 and tcp port 443` matches nothing -- while a host row combined
  with a protocol row means `and`. A capture filter that matches nothing does
  not announce itself: the capture runs to its full duration and comes back
  empty, which looks exactly like a quiet network.

  Both sides are parenthesised. `a and b or c` parses as `(a and b) or c`, so
  appending without parentheses rebinds an expression already in the box.
  Composition uses BPF's `and`/`or`/`not` keywords rather than `&&`/`||`,
  because the capture request validator refuses `&` and `|` -- the command is
  assembled as a string for the remote shell. libpcap accepts both spellings,
  so the words cost nothing.

  The display filter's chips are unchanged. It already has composition on the
  right-click menu over a packet field, and its chips are worked examples --
  somewhere to start rather than something to build onto.

### Fixed

- The display filter's right-click menu had an item labelled "…and not
  selected" that did not do that. `combineFilter`'s `not` mode ignores the
  current expression and replaces it with the negation, which is Wireshark's
  "Not Selected". Relabelled to match its behaviour; nothing about what it
  does has changed.

## 0.1.0-dev.20 — 2026-09-13

### Changed

- **Trusting a host now shows you what you are trusting.** Pressing "Trust
  host" ran `ssh-keyscan` and stored every key it got back, in one step. The
  operator was shown nothing and asked only whether they had meant to press the
  button, so "trust this host" meant "pin whatever answers on that address right
  now" -- which is the exact substitution host key verification exists to catch.
  A verification step nobody can perform is ceremony, not security.

  It is two steps now, the way `ssh` itself has always done it: you are shown
  each key's SHA256 fingerprint and you accept or cancel.

  - `POST /api/admin/known-hosts/scan` is **no longer mutating**. It asks the
    host for its keys, returns each one with its fingerprint, and stores
    nothing. Scanning can no longer change what this server trusts.
  - `POST /api/admin/known-hosts/confirm` is new, and pins the keys handed back
    to it. It does **not** re-scan: what it stores is what was on screen when
    the operator said yes. Re-scanning on confirm would reopen the hole the
    review was meant to close, since a key swapped between the display and the
    acceptance would be pinned with nobody having seen it.

  Fingerprints are in OpenSSH's own format, so they compare directly against
  `ssh-keygen -lf` run on the target -- which is the detail that makes the
  feature usable rather than decorative. The README gives the one-line command
  that prints all of them.

  A key that cannot be parsed cannot be fingerprinted, so it cannot be
  reviewed: it is listed as unreadable, left out of what is accepted, and
  refused by the confirm route as well rather than trusted to have been
  filtered by the UI.

- Admin → Known Hosts labels the button for an already-trusted host **Review
  keys** rather than "Rescan", which described what the old one-step scan did
  to the store.

### Fixed

- `docs/architecture.md` still described the fail-open host key behaviour that
  0.1.0-dev.17 replaced -- it claimed an unverified host connects unchecked.
  It is refused, as the README has said since that release.

## 0.1.0-dev.19 — 2026-09-13

### Fixed

- **A released frontend fix actually reaches the browser.** `StaticFiles`
  sends `ETag` and `Last-Modified` and no `Cache-Control` at all, and with no
  `Cache-Control` a browser falls back to heuristic freshness -- roughly a
  tenth of the file's age since `Last-Modified` -- and serves `app.js` from
  its own cache without asking. So a deployment could run this release's
  backend against the previous release's page, which from the outside is
  indistinguishable from the fix not working. dev.18 shipped a repair for a
  dead button and the button stayed dead for exactly this reason. Frontend
  files are now served `Cache-Control: no-cache`, which means *revalidate*,
  not *do not store*: the `ETag` still stands, so a reload costs one
  conditional request answered `304` with no body.
- **The server list refreshes when you come back to it.** Host trust is
  changed on the Admin tab and displayed on the Servers tab, but the list was
  only fetched at boot and after a server was added, edited or removed.
  Trusting a host in Admin and returning showed it as still untrusted, from a
  copy of the data taken before the trust existed -- the API had been correct
  the whole time. The tab now refetches on activation, the way the Admin tab
  already did, and the open server keeps its highlight across the refetch
  (selection had lived only as a class on the element the re-render replaces).

## 0.1.0-dev.18 — 2026-09-13

### Fixed

- **The Trust host button on a server does something.** It was registered on
  `delegate("admin-known-hosts", ...)` while the button renders inside
  `#server-list`, and `delegate()` bails on `!container.contains(el)` -- so
  every click was dropped on the floor. A button that looked right, sat in the
  right place, and produced no request, no error and no feedback. Introduced
  in dev.17 alongside the button itself. There are now browser tests for the
  warning, for the button being wired at all, and for declining the prompt,
  the first of which fails against the old wiring.

## 0.1.0-dev.17 — 2026-09-13

### Changed

- **An untrusted host is refused, not connected to unverified.** This is a
  breaking change for any host whose keys have never been scanned. Previously
  a host with nothing stored was connected to with host key validation turned
  off -- not "unverified but otherwise normal", but the SSH key offered to
  whatever answered on that address, with nothing checked. That was because
  asyncssh reads `known_hosts=None` as *skip validation* rather than *use the
  default file*, and the empty case handed it exactly that. `_connect` now
  refuses before a socket is opened, naming the host and where to trust it.
  Trusting a host still works, because that runs `ssh-keyscan` and never goes
  through `_connect`.
- **A server says when its host is not trusted yet.** `/api/servers` reports
  `host_trusted` per row and the server list shows it, with a **Trust host**
  button inline for admins and a "ask an admin" line for everyone else. The
  refusal above is otherwise invisible until a capture will not start, on a
  screen that never mentions trust. The store stays admin-owned and keyed on
  the endpoint rather than moving into the per-user server profile: several
  servers can point at one host and share one decision, and re-pinning a host
  decides what every user's connections to it are checked against.
- **The host key mismatch error says what a mismatch is.** It read "Host key
  verification failed. Scan the host key first via Admin > Known Hosts" --
  which described the one situation it can never be raised for, since the
  no-keys case is now refused earlier and previously never reached it either.
  It now says the host answered with a key that does not match the trusted
  ones, and that the cause is a rebuild, a re-key, or something else answering
  on that address.

### Fixed

- **A trusted host uses its strongest key, not the one it was scanned in.**
  Forgetting a host's keys and rescanning could quietly change which key the
  handshake settled on -- in practice down to RSA. The stored keys were
  written into the temporary `known_hosts` file in the order SQLite returned
  them, which is the order `ssh-keyscan` printed them; and every write
  reshuffles that, since `add_known_host` is an `INSERT OR REPLACE` against a
  `UNIQUE` key and a replaced row is re-inserted with a new autoincrement id.
  asyncssh builds its list of acceptable server host
  key algorithms by walking that file in order and SSH takes the first one the
  server also holds, so the first line was deciding the algorithm -- on the
  strength of nothing but scan order. The file is now written strongest first,
  by the same `_HOST_KEY_RANK` that already existed to *report* a
  weaker-than-available choice after the fact but had never been allowed to
  prevent one. Every stored key is still written, because a key missing from
  the file is a key that cannot verify the host after a rotation.
- **Deleting a running capture stops it, instead of letting go of it.** Delete
  and Stop had drifted apart. Stop interrupted `tcpdump` and let the monitor
  finish; Delete signalled the process, cancelled the monitor without waiting
  for it, and dropped the row -- and two things fell out of that gap. The
  monitor's `finally` ends in a `_persist()`, and `upsert_capture` is an
  `INSERT OR REPLACE`, so the row was deleted and then written straight back a
  tick later as a `failed` capture called "cancelled", whose file had already
  been unlinked. And because only `_collect` clears the target host and a
  cancelled monitor never reaches it, the pcap stayed in the target's `/tmp`,
  complete and readable, after the operator had deleted it. A delete now waits
  for the monitor to unwind before it touches the row, interrupts `tcpdump`
  the same way Stop does, removes the remote file over the connection the
  capture is already running on, and closes the session -- in that order.
  Signalling a process that has already exited no longer fails the delete
  either: a capture deleted while transferring has no `tcpdump` left to
  interrupt, and the record should still go.
- **Deleting a capture says what it did.** The prompt was one line for a
  finished capture and the same line for a live one, and the row simply
  vanished afterwards -- including when the request failed, which left the
  capture looking deleted until the next refresh brought it back. Deleting a
  running capture now says what it is about to do to the target host and asks
  in those terms, the button reports that it is stopping rather than sitting
  there looking unclicked, a failure is shown instead of swallowed, and the
  one outcome an operator has to act on -- the capture gone from here but its
  file still on the target -- names the path to remove by hand.

## 0.1.0-dev.16 — 2026-09-12

### Added

- **Saved views.** A display filter worth keeping can be saved as a named tab
  on the capture it belongs to. The tabs are still there the next time that
  capture is opened -- they are stored server-side against the account and the
  capture, not in the browser -- and each one downloads as its own pcap
  containing only the packets its filter selects. "All packets" is always
  first and is the unfiltered capture rather than a saved row, so it cannot be
  renamed or deleted. A filtered download is refused over plain HTTP for the
  same reason the full one is: a filtered capture is not a less sensitive one,
  and "just the authentication traffic" is frequently the most sensitive slice
  there is.
- **The display filter autocompletes.** Typing offers matching protocol and
  field names -- protocols first, because a bare protocol is a complete filter
  on its own where a field name is not, and a field completion leaves the
  caret on a space ready for the comparison. Matching is on the token under
  the caret rather than the whole box, so it still works partway through an
  expression, and it is substring rather than prefix-only, so `syn` finds
  `tcp.flags.syn`. The eight "Try:" chips remain; they teach the shape of a
  filter and had nothing to offer after that.

### Fixed

- **The capture filter library can be scrolled.** `.panel` is
  `overflow: hidden` and the library -- eighty-odd expressions inside a
  `<details>` -- expanded past the bottom of the capture panel and was simply
  clipped: no scrollbar, no way to reach the end of the list. The library now
  has its own bounded scroll box, and the capture tab scrolls as a whole. The
  scroll box is a wrapper rather than the multi-column element itself, because
  a multi-column element given a fixed height fragments sideways into more
  columns instead of growing taller.
- **A capture's monitor deadline is its own.** The timeout lived on the
  manager, written by `start()` and read by whichever monitor task got there
  first. With `max_concurrent_captures` above 1 that is a race: a ten-minute
  capture started alongside a five-second one had its deadline rewritten to
  the short one's and was abandoned after 65 seconds with "capture did not
  finish in time".

### Security

- **An unknown username costs the same as a real one.** Login short-circuited
  on `bool(user)`, so a username that does not exist answered in microseconds
  where a real one took the ~100 ms scrypt is deliberately tuned to. That
  difference is a username oracle measurable from anywhere that can reach the
  login endpoint. A failed lookup now verifies against a fixed hash that no
  password can satisfy, at identical cost.
- **Packet detail is rate-limited.** Listing packets was capped in dev.15;
  fetching one packet's detail was not, despite spawning tshark twice per call
  (PDML, then the frame bytes). It now draws on the same per-user budget.
- **A chunk's declared length is bounded before it is allocated.** The 4-byte
  length prefix is read before anything authenticates it -- it has to be,
  because it says how much to read in order to authenticate it. Unbounded, a
  corrupted or tampered capture could ask for a 4 GiB allocation per chunk.
  Nothing the sealer writes ever exceeds the 64 KiB chunk size.
- **Path containment uses `Path.is_relative_to`, in one place.** Four separate
  copies of `str(path).startswith(str(base))` decided whether an SSH key name
  escaped the keys directory. That test is wrong in the same way in all four:
  with a base of `/app/ssh-keys` it accepts `/app/ssh-keys-backup/id_rsa`,
  because the string genuinely is a prefix. Nothing reachable gets past the
  model validators to exercise it, which is exactly why it should not have
  been four checks waiting for a fifth caller to forget one.
- **Expired rows and aged-out limiter keys are actually deleted.**
  `cleanup_expired_sessions` was imported and never called, and both rate
  limiters only ever pruned the one key they were asked about. Nothing was
  ever *served* from the dead state, but a long-running container accumulated
  expired session rows, expired trusted-device rows, and a limiter entry per
  client address seen since boot. An hourly sweep now clears all three.

## 0.1.0-dev.15 — 2026-09-12

### Security

- **Packet listing and capture start are rate-limited per user.** Login was
  the only endpoint with a cap on how often it could be called; listing
  packets (which spawns tshark) and starting a capture (which opens an SSH
  connection) had none. Both are now capped per user on a sliding one-minute
  window — 30 requests/minute for packet listing, 10/minute for capture start
  — configurable from the Admin tab like the existing login rate limits.
- **`ServerAuth.hostname` rejects the same characters `KnownHostEndpoint`
  already did.** It previously let `$`, backtick, backslash, and line breaks
  through to asyncssh and the known_hosts store — a narrower rule than the
  host-key routes enforced on the same kind of value, for no reason tied to
  what either route actually needs. Both hostname fields now validate through
  one shared function, so the two cannot drift apart again.

## 0.1.0-dev.14 — 2026-09-12

### Added

- **Rotate the master key without re-encrypting a single capture.**
  `backend/rekey.py` rewraps each capture's data encryption key under a new
  master key and leaves the encrypted body untouched: 84 bytes rewritten per
  file, whatever the capture weighs. It runs as a dry run unless told
  otherwise, verifies the new header before replacing the old one, and is safe
  to re-run — a file already rotated is recognised and skipped. Losing a master
  key previously meant losing every capture under it; now the key can be
  retired on a schedule.
- **The UI is tested in a browser.** Three suites under `tests/browser`, 31
  tests, driving a real chromium against a real server. The API suites cover
  the API thoroughly, which is not the same as covering the app: a form with no
  way to submit it, an inline script the CSP silently dropped, and a filter
  library that filled in a field on a different tab all shipped while those
  suites were green, because none of them produces a bad HTTP response. A
  missing browser reports as SKIPPED with the remedy in the reason, never
  silently omitted.
- **One capture at a time per interface, not per server.** Capturing on `eth0`
  no longer blocks a capture on `eth1` of the same host, which is the normal
  case for anything with more than one leg in the network. Captures now record
  which interface they were taken on, and a second capture on an interface
  already busy is refused with a 409 that names it — distinct from the 429 that
  means the overall capture limit is reached.

### Changed

- **The filter library moved into the Capture tab.** It was a tab of its own,
  which meant choosing a filter filled in a field you could not see, on a tab
  you had just left, and the app had to switch tabs to show you what your click
  had done. It now sits directly under the BPF field it fills, collapsed by
  default — eighty-odd expressions are not the answer for anyone who already
  knows what they want to type, and the field above is.
- **The deployment instructions describe a deployment that works.** The README
  quick start did not: `docker compose up -d` exits 1 on a fresh clone, and
  nothing said where the bind mounts land or what has to exist before the first
  start.

### Security

- **A floating image tag can no longer move backward.** Releasing an older
  version re-pointed `:dev` and `:latest` at the older image, so a deployment
  tracking a floating tag could be silently downgraded — past a fix it already
  had. The release workflow now refuses to move a floating tag to a version
  below the one it currently points at.
- **The CSP hash is pinned by a test.** The pre-paint theme script is allowed
  by content hash rather than `'unsafe-inline'`, so editing it without
  recomputing the hash makes the browser drop it — no error, no failed request,
  nothing to notice. A test now hashes whatever is actually in `index.html` and
  prints the value to paste in when it does not match. The comment that used to
  carry that recipe was itself wrong: it split on the first script tag in the
  file, which was the one inside the comment, so it hashed the comment.

### Fixed

- **Enter submits every form, instead of five named fields.** There is no
  `<form>` element anywhere in this UI, so Enter is never the browser's own
  behaviour — it worked only where the code named a field by id, and that list
  left out every field of the server form, the stored-username box beside it,
  and Add user under Admin. Typing a name and pressing Enter did nothing at
  all: no request, no error, no feedback, which reads as a form with no way to
  submit it rather than a missing shortcut. A container now names its own
  submit button in the markup, so a form added later is wired up where it is
  written rather than in a list somewhere else.
- **The page declares an icon.** Without one the browser asks for
  `/favicon.ico` on every page load and gets a 404 — a failed request in
  everyone's console for the lifetime of the app, of exactly the kind a real
  failure looks like.

## 0.1.0-dev.13 — 2026-09-12

### Added

- **Click a field, see its bytes. Click a byte, find its field.** The detail
  tree and the hex pane are now two views of the same frame. Selecting a field
  highlights exactly the bytes it occupies, in both the hex and ASCII columns;
  clicking a byte selects the innermost field covering it and opens every
  ancestor so the row is actually on screen. This is the interaction the viewer
  existed to provide and could not, because `-T json` reports no offsets.
- **Right-click to filter, from the tree or from a packet row.** Wireshark's
  Apply as Filter menu, with the same four combinators — selected, not
  selected, and selected, or selected — plus Prepare as Filter, which fills the
  box without running it, and Copy value. On a packet row the menu builds from
  the column under the cursor: an address, a protocol, a length, a frame
  number. Right-clicking a row also offers a Conversation filter, both
  endpoints of the exchange and nothing else.
- **Individual flag bits are filterable.** Because the tree carries real field
  names all the way down, a TCP flag bit is a row like any other:
  right-clicking `.... .... ..1. = Syn: Set` produces `tcp.flags.syn == 1`.

### Changed

- **The username field starts empty on a new server, and says the Admin panel
  is not a prerequisite.** Same defect as the key field below, and more
  confusing because of what it implied: the box arrived with the most recently
  used name already filled in and the text input hidden, so the field read as
  locked to the saved list — and the only route to a new name was the last entry
  of a dropdown there was no reason to open. Adding the username through Admin →
  SSH usernames first looked like the required route. It never was; the field
  simply never said so. Nothing is preselected now, the hint spells out both
  paths, and adding is refused until a name is actually given.
- **The SSH key field starts empty on a new server.** A `<select>` selects its
  first option by default, so the add form silently arrived with whichever key
  sorted first already chosen — and a server added without looking would
  authenticate with a key nobody picked. The field now opens on a disabled
  "— select a key —" placeholder that cannot be chosen back, and Add, Test
  connection and Check prerequisites all refuse with a plain sentence until a
  key, a hostname and a username are actually present. Editing an existing
  server still shows that server's own key, because there the value is a fact
  rather than an unanswered question.
- **The Add server form carries a standing warning about capturing from its own
  host.** Pointing pcap-server at the machine it runs on writes your session
  cookie and TOTP code — and over plain HTTP your password — into a capture this
  UI then stores and serves back. The obvious cases were already refused
  outright: hostname aliases, loopback, the container's own addresses, and the
  default gateway, which on a Docker bridge is the host. What that cannot see is
  the host's own LAN address, because a bridged container has no knowledge of
  it — and that is the address an operator would actually type. Detection stays
  and is unchanged; the warning covers the case detection is structurally unable
  to reach, and a test now pins that limitation rather than leaving it implied.
- **The dissection tree comes from PDML instead of `-T json`.** The JSON output
  gives a field's name and value and nothing else. PDML gives four more things
  the viewer cannot work without: `pos` and `size`, the byte offset and length
  that make highlighting possible at all; `showname`, Wireshark's own label, so
  a row reads "Source Port: 51234" rather than "tcp.srcport: 51234", and so the
  bit diagrams for flag fields arrive already drawn; and `hide`, which marks
  the generated duplicates — `ip.src_host` beside `ip.src`, `tcp.port` beside
  `tcp.srcport` — that Wireshark does not display and that were doubling the
  length of every tree here.
- **The hex pane is rendered from the frame's bytes rather than pasted from
  tshark.** `-x` output is a single block of text with nothing in it to
  address; a field cannot highlight a range of a text node. Each byte is now
  its own element, with the offset gutter and ASCII column laid out here. The
  bytes come from `-T json -x`, which reports the frame data source as one
  unambiguous hex string, where the text form has to be scraped and can carry a
  second block for reassembled data whose offsets do not match PDML's.
- Tool runs per packet click are unchanged at two — PDML carries no frame
  bytes, so fetching them is still a second pass.

### Security

- PDML is parsed only after the bytes are checked for a document type
  declaration, which tshark never emits. Expat resolves internal entities, so a
  declaration reaching the parser is the one route by which a captured packet's
  own contents could mount an expansion attack against this process.
- Filter values built by clicking are quoted before they are sent, and a value
  containing any character the display filter rejects (`;`, `$`, a backtick, a
  backslash) falls back to testing that the field is merely present. The
  validator was not relaxed to accommodate click-to-filter.

### Fixed

- **The limit on simultaneous captures was unreachable.** `max_concurrent_captures`
  has been enforced since captures were first written — five at once by default,
  because each running capture holds an SSH session to the target and a local
  file handle — but it was missing from the Admin panel's list of settings, so
  the only way to change it was to edit the database. It is now a field like any
  other, and a test asserts that every setting the backend defaults has a row in
  the panel, so the next one cannot go missing the same way.
- **An address in a generated filter was quoted, which tshark rejects
  outright.** Anything non-numeric was being wrapped in quotes, so the first
  conversation filter produced `ip.addr == "192.168.1.50"` — a type error, not
  a string comparison, and a 400 from the API. Addresses, MACs and IPv6
  literals now go in bare; genuine strings such as a Host header still get
  quoted. Found in a browser, not by the test suite, which is why the rule
  tshark enforces is now pinned by tests of its own.

## 0.1.0-dev.12 — 2026-09-12

### Added

- **A capture filter library, on its own Filters tab.** Around eighty BPF
  expressions grouped by what you are actually looking for rather than by port
  number: Active Directory (Kerberos, LDAP, SMB, RPC, WinRM), name resolution
  and core services, web, mail, remote access, databases, network
  infrastructure, voice, TCP flag matching, and size-based filters. Searchable
  by name, port or expression, and choosing one drops it into the Capture form.
  Ports are written out rather than relying on tcpdump's service-name lookup,
  which resolves through the target's `/etc/services` and can differ per host.
- **Timestamps in your own time zone.** A `-tz` view flag renders each packet's
  time as a full local date and time. tshark cannot do this itself — its
  `frame.time` is the capture host's local time, and the container runs on UTC
  with no idea where the reader is — so the server sends epoch seconds and the
  browser formats them. `-tttt` still shows the server's UTC.

### Fixed

- **`-e` showed two empty columns on most captures.** `tcpdump -i any` writes a
  Linux cooked capture, which has no Ethernet header at all, so `eth.src` and
  `eth.dst` are empty on every frame — and `any` is the default interface, so
  the MAC flag did nothing for the captures people actually take. The cooked
  field is requested alongside the Ethernet one now and whichever the frame has
  wins. A cooked header records no destination address, so that column is
  honestly empty. The flag stays — it earns its place on a capture from a named
  interface, where both addresses are real — and its help now says which case is
  which instead of leaving you to guess why the columns were blank.
- **The view-flag picker described a state that could not occur.** It said
  "dotted ones are on by default" when nothing is on by default.

### Changed

- **The light theme is called Flashbang.**

- **The packet viewer gives its height to packets.** On an 800px window the
  chrome above the packet list came to 309px of a 721px viewer — a toolbar, a
  filter-help row, two bordered flag-group boxes, a resolve-hostnames control
  and a legend — leaving the list 272px and twelve visible rows. Everything that
  is reference material rather than something you read packets against now sits
  behind one of two toggles on a single 30px bar, closed by default and
  remembered per browser. An open drawer is capped and scrolls rather than
  pushing the list off the bottom.
- **The detail pane appears when there is something to show.** It used to hold a
  third of the viewer to display "Click a packet above". With nothing selected
  it is a 26px hint strip, and it opens on selection and closes again when the
  list is redrawn.
- **The list/detail split is remembered**, and can no longer be dragged to a
  state with no way back: the detail pane keeps a minimum height.

Chrome above the list is 76px instead of 309, and an 800px window shows 28
packet rows instead of 12.

## 0.1.0-dev.11 — 2026-09-12

### Fixed

- **The packet viewer was blank and every capture counted zero packets**, while
  the same capture downloaded and opened correctly in Wireshark. Wiretap, the
  library beneath both `tshark` and `capinfos`, accepts a regular file or a FIFO
  on stdin and rejects anything else with *The standard input is a "special
  file" or socket or other non-regular file*. asyncio's `stdin=PIPE` is a real
  pipe and passes that check; uvloop's is a Unix socketpair and does not, and
  `uvicorn[standard]` selects uvloop in the container. So every `tshark` and
  `capinfos` call failed in a real deployment and none of them failed in the
  test suite, which runs on stock asyncio. The pipe is created explicitly with
  `os.pipe()` now, so the tool is handed a FIFO under either event loop. The
  regression test asserts the kind of descriptor rather than the loop.
- **A failed packet count was indistinguishable from an empty capture.**
  `get_packet_count` returned 0 both when a capture held no packets and when
  `capinfos` never ran, which is what let the failure above look like a
  legitimately empty result for a whole release. It raises now. A capture whose
  count fails is kept rather than discarded: the pcap is intact, and tcpdump's
  own running total already stands in for the number.
- **Monitor tasks were cancelled at shutdown but never awaited**, so the
  `finally` block that releases the SSH connection and writes the closing row
  ran whenever the garbage collector reached the coroutine — after the event
  loop had already closed.
- **A rejected request reached the user as raw pydantic JSON.** A 422 arrives as
  an array of `{loc, msg, type}`; only the `msg` fields are written for a person
  to read.

### Fixed

- **A mistyped display filter looked exactly like one that matched nothing.**
  Both produced an empty packet list reading "No packets match", so a typo in a
  field name was indistinguishable from a correct filter selecting no packets.
  tshark exits non-zero on an expression it cannot parse and zero when a valid
  filter matches nothing, so the two are told apart now: a rejected filter comes
  back with tshark's own message and the caret line pointing at the token it
  objected to, shown under the filter box, with the previous packet list left in
  place.

### Changed

- **Stored SSH usernames moved from the Admin panel to the Servers tab**, in a
  collapsible section under the server list. The list is per-user, so putting it
  behind the admin-only tab meant a non-admin could accumulate usernames but
  never prune them. It now sits beside the form that offers them, and adding or
  editing a server refreshes it without a reload.
- **`CaptureManager._monitor` split into three.** Waiting for tcpdump to exit,
  bringing the pcap back, and deciding what a failure means are separate
  concerns; the live-count throttle became a small class rather than a closure
  over two mutable locals. No behaviour change.
- **The display filter no longer refuses valid Wireshark syntax.** `&` and `|`
  were rejected as shell metacharacters, which ruled out `&&`, `||` and bitwise
  matching such as `tcp.flags & 0x02` — the operators most people type. The
  display filter reaches tshark through `create_subprocess_exec` as a single
  argument with no shell anywhere on the path, so those characters are text for
  tshark to parse, not commands; there is now a test asserting exactly that
  rather than an assurance in a comment. `;`, `$`, backtick and backslash stay
  rejected, and the capture filter keeps the stricter rule, because that one
  does travel inside a command string over SSH.

### Security

- **Two-factor authentication is now enforced by the API, not only by the UI.**
  A first login returns `needs_totp_setup` and the frontend acts on it, but no
  route ever checked `totp_confirmed` — so any client that ignored the flag held
  a session backed by a password alone, with the whole API behind it. The check
  now lives on `get_current_user`, the dependency every protected route already
  uses, so a new route cannot forget it. The two enrolment endpoints opt out
  visibly by depending on `get_session_user` instead, and `/api/auth/status`
  keeps answering so the UI can still route a half-enrolled account to the
  screen that finishes enrolment. A refused call returns a structured
  `totp_setup_required` that the frontend turns into the enrolment screen rather
  than an opaque 403.

### Added

- **Both filters now offer clickable examples**, and the display filter has real
  documentation. The BPF examples existed only inside the "Where are the tcpdump
  flags?" explainer, and the display filter had nothing at all beyond its
  placeholder text — so the two filters people most need help with were the two
  with the least of it. The viewer gains a cheatsheet whose first point is the
  one that actually trips people up: the display filter is not the same language
  as the capture filter. `tcp port 443` versus `tcp.port == 443`, applied at
  different times, for different purposes.


- **Running captures report how many packets they have taken.** `tcpdump -v`
  under `-w` prints its running total to stderr once a second, and the monitor
  reads it as it arrives, so a capture in progress shows a count instead of
  nothing until the transfer completes. Both the digit run and the retained
  stderr are bounded: that output comes from the host being captured on.
- **Captures can be renamed.** The name replaces the UUID as the title in the
  list and in the viewer heading, with the server and command kept beneath it.
- **The capture page's server picker shows the host name with its address**, the
  way the Servers tab already labels the same host.

### Changed

- **SSH usernames are stored instead of derived.** They were a `GROUP BY` over
  the server list, so deleting the last server that used a login name discarded
  the name with it, there was no way to add one ahead of time or remove one, and
  the only affordance was a `datalist` on a text box, which Chromium draws no
  arrow for — the feature existed and could not be found. Usernames are their
  own table now, back-filled once from existing servers and recorded by the
  database layer so a server can never use a name the list has not seen. The
  form field is a real dropdown, and Admin gains add, rename and remove.
  Removing a stored username removes the suggestion only; servers already
  configured with it are untouched.

### Documentation

- **The README was reordered around the reader rather than the feature list.**
  It opened with twenty-four bullets and then interleaved concepts with
  operational detail. It now runs: what it does, quick start, your first
  capture, the two filters, security, capture privilege on the target, running
  it, reference, architecture. A contents line sits at the top.
- **The README has a Security section**, which it did not before: what is
  encrypted and under which key, how startup fails closed, what degrades over
  plain HTTP, how sign-in works, exactly what runs on the target host, and a
  plain list of what none of it protects against.
- The architecture document no longer describes the TOTP gap as open — it was
  closed earlier in this same set of changes — and now records the display
  filter's character rule and the local-time flag.

- **`docs/architecture.md`** — the first full account of how the app is built
  and what each security measure defends against: the module layout and why
  there is no ORM or service layer, the life of a capture, how an encrypted
  capture reaches `tshark` without ever becoming a plaintext file, the envelope
  format, the reasoning behind every input validator, host-key handling,
  self-capture detection, the browser-side headers, and the known limits.
- **Roadmap** — an MCP server and a packet sanitizer, in the README and in the
  architecture document.
- The architecture document's authentication section records the TOTP
  enforcement gap that writing it uncovered, and the Security entry above is the
  fix.
- The README no longer says `-v` is refused. pcap-server now passes it on every
  capture, which is what the live packet count reads.

## 0.1.0-dev.10 — 2026-09-12

### Fixed

- **Every capture failed at the final step under uvloop.** A capture that ran
  and transferred correctly then died with `could not supply capture data to
  capinfos`, and the error path deleted the pcap it had just downloaded — so a
  successful capture left nothing behind. `capinfos` exits as soon as it has
  counted the packets, closing its stdin while chunks are still being written.
  Under plain asyncio that write raises `BrokenPipeError`, which was caught and
  ignored; under uvloop — which uvicorn selects in the container, so this only
  ever reproduced in a real deployment — it raises
  `RuntimeError("...the handler is closed")`, which was not. A genuine read
  failure is still reported: only a closed pipe is ignored.
- **A capture that failed to launch held a concurrency slot forever.** `start()`
  registers the capture as running before invoking tcpdump, and only the
  monitor task ends a running capture. When the launch itself raised — an
  unreachable host, a missing key, sudo refusing — no monitor was ever created,
  so the record stayed `running` for the life of the process. Each failure
  permanently consumed one of `max_concurrent_captures`, and after enough of
  them every capture was refused with "already running" until the container was
  restarted. A failed launch now closes its own record.
- **`getcap` was reported missing on hosts that had it.** The prerequisite probe
  looked for `getcap` with `command -v` alone, while `tcpdump` beside it also
  searched the sbin directories — precisely because a non-login SSH session for
  a non-root user has no `/usr/sbin` on `$PATH`. Since `getcap` installs to
  `/sbin` on Debian and Ubuntu, the capability check reported it uninstalled on
  exactly the hosts it was installed on. It now gets the same fallback search,
  and the warning carries the right package name per distribution.
- **A missing comma blanked the entire UI.** A string concatenation in the
  read-only-over-HTTP banner was missing its separator, which is a parse error
  for the whole of `app.js` — every screen rendered empty. Introduced after
  `0.1.0-dev.9` was tagged, so no released version is affected.

### Security

- Update `starlette` 0.50.0 → 1.3.1 and `fastapi` 0.125.0 → 0.141.1, found by
  `pip-audit` in this release's security gate. `fastapi` 0.125.0 capped
  `starlette` below 0.51.0, which is why 0.50.0 was held; 0.141.1 lifts the cap.
  The advisory that concretely applies here is `request.url` being rebuilt from
  an unvalidated path and `Host` header (PYSEC-2026-248, PYSEC-2026-161): this
  app reads `request.url.path` to decide which requests are refused over plain
  HTTP, so a path that re-parses differently is a way past that control. Also
  fixed: form limits silently ignored for urlencoded bodies (PYSEC-2026-249).
  Two more are not reachable here — `HTTPEndpoint` dispatch (unused) and a
  Windows-only `StaticFiles` UNC traversal (this ships as a Linux container).
  `starlette` 1.x removes `on_event`, so the shutdown handler is now a lifespan
  context manager.
- **SSH usernames are validated.** The username was the one connection field
  with no validator, and it is interpolated into the sudoers rule the
  prerequisite check prints for an operator to run as root. A username carrying
  sudoers syntax — `x ALL=(ALL) NOPASSWD: ALL #` — produced a rule granting
  unrestricted root to that account, presented as the fix to paste. Usernames
  are now restricted to the characters a real login name uses, excluding
  everything sudoers gives meaning to.
- **The printed sudoers rule installs through `visudo`.** The prerequisite
  check told operators to `echo ... | sudo tee /etc/sudoers.d/pcap-server`,
  which the README warns against in the same breath: a malformed file there
  breaks `sudo` for everyone on the host until someone with existing root
  repairs it. It now pipes through `visudo`, which validates before installing.
  The group form also creates the group it references, which it previously did
  not — a rule naming a group that doesn't exist matches nobody, and captures
  kept failing with the same error.

### Changed

- **One list of servers, not two.** "Active Servers" and "Saved Servers" were
  separate persistent tables holding the same columns, with a save/load round
  trip copying rows between them. Both survived restarts, so the split bought
  nothing and the two names meant nearly the same thing. They are now a single
  **Servers** list; existing saved profiles are carried into it on first start
  and the retired table is dropped. Servers can be edited in place, which
  previously only saved profiles could be.
- **Test connection and Check prerequisites work before a server is saved.**
  Both were only reachable from a server's detail page, so a host could only be
  probed after committing to it. The add form now offers both against the
  details typed into it, via endpoints that take connection parameters directly.
  The same self-target refusal and key checks apply as when adding.
- **Usernames are remembered.** The add and edit forms suggest SSH usernames
  already used, and default to the most recent one.
- **Known Hosts is driven by the servers you have configured.** It required
  typing a hostname that the app already knew, and listed one row per key with
  a Remove button — but a host answers with one key per algorithm, so removing a
  single row left the rest still verifying the host and the next scan restored
  the removed one alongside them, which read as deletion doing nothing. Hosts
  now appear automatically from the configured servers, with trust shown and
  granted per host, a **Forget** that drops the whole set, and the stored time
  displayed so a rescan is visible as one.
- **Connections report which host key was negotiated.** Testing a connection now
  shows the algorithm the handshake settled on, and warns — without blocking —
  when the host had a stronger one on offer.
- The Known Hosts and SSH Keys panels now explain what they hold and how they
  differ: host keys prove the machine's identity, SSH keys are the private keys
  this app logs in with.

## 0.1.0-dev.9 — 2026-09-12

### Security

- **Bound concurrent captures.** Starting a capture had no limit at all: any
  authenticated user could call the start-capture endpoint without bound, each
  call opening a new SSH connection to a target host and a new local file, with
  nothing capping how many ran at once. A new `Max concurrent captures` setting
  in Admin → Settings (default 5) is checked first, before any connection is
  opened or file created; going over it is refused with a clear error rather
  than a stalled or resource-starved container.
- **SSH private keys are sealed at rest.** The one secret in this app that
  grants remote code execution on another machine was stored in plaintext on
  the data volume. Keys are now sealed under the same master key as captures,
  content-sniffed the same way captures are (so no filename or API change was
  needed), and never exist as a plaintext file on disk: uploads are sealed
  before the first write, and reads decrypt straight into an in-memory key
  object handed to the SSH library, never a plaintext path. Keys uploaded
  before this release are sealed at startup with the same verify-then-replace
  safety captures already use — a crash partway through leaves either the
  original key or a verified sealed replacement, never a half-written one that
  could lock an admin out of a saved server. A locked or unconfigured vault
  refuses the connection with a clear reason rather than silently falling back
  to reading a plaintext key that no longer exists.
- **`script-src` drops `'unsafe-inline'`.** Every inline `onclick`/`onchange`
  handler in the UI (32 of them) was moved to `addEventListener`, most via one
  small event-delegation helper for dynamically-rendered lists. The one
  remaining inline script — applying the saved theme before first paint, which
  has to run before the external script is even loaded — is now pinned by
  SHA-256 content hash instead of being exempted from the policy.
- Update `starlette` 0.41.3 → 0.50.0 and `python-multipart` 0.0.20 → 0.0.32,
  found by running `pip-audit` as part of this release's security gate. The
  two that concretely apply to this app: a multipart file upload large enough
  to spool to disk blocked the event loop's main thread (reachable through the
  admin-only SSH key upload endpoint), and a crafted `Range` header against
  any static asset caused quadratic-time processing in `FileResponse` —
  unauthenticated, since `StaticFiles` serves the frontend before sign-in.
  `fastapi` moves to 0.125.0, the lowest version compatible with a patched
  starlette. Five further starlette advisories need starlette 1.x, which
  drops the `on_event` hook this app's shutdown handler still uses; none of
  the five apply to code this app actually runs (no `HTTPEndpoint` subclasses,
  no security decision built from a reconstructed `request.url`, no reliance
  on `application/x-www-form-urlencoded` size limits, and the Windows-only UNC
  issue doesn't apply to this Linux-only deployment) — migrating to `lifespan`
  handlers to close them anyway is tracked as follow-up, not bundled into a
  release meant to be a security fix, not a framework migration.

### Changed

- Add a pytest harness (`scripts/check.sh`, `.github/workflows/check.yml`)
  covering `crypto.py`, `vault.py`, `auth.py`, `main.py`'s transport-security
  surface (including a regression test for the `X-Forwarded-For` rate-limiter
  bypass fixed in dev.8), `localnet.py`, `ssh_manager.py`'s hostile-input
  handling, and `packet_parser.py`. Tests needing `tshark`/`capinfos` are
  skipped rather than silently omitted when those tools aren't present, and
  are reported as skipped (`pytest -r s`) so the gap stays visible. CI now
  runs the same script on every push and pull request — previously the only
  workflow fired on version tags, so ordinary commits had no automated check
  at all.

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
