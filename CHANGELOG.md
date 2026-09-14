# Changelog

## 0.1.0-dev.31 — 2026-09-13

### Added

- **Sanitized downloads.** **Sanitize** on a finished capture's card, and in the
  Viewer's toolbar, downloads `<name>-sanitized.pcap`: the same packets at the
  same sizes, with what identifies people and places replaced. With a saved view
  open in the Viewer, only that view's packets.
  - **Credentials** (ticked to start): HTTP Authorization and cookie values,
    FTP and POP passwords, IMAP and SMTP logins, SNMP communities, RADIUS
    passwords, NTLM and Kerberos responses, LDAP simple binds, MySQL,
    PostgreSQL and SQL Server passwords, VNC responses. Masked with `*`, keeping
    the auth scheme and cookie names.
  - **IP addresses** (ticked): prefix-preserving Crypto-PAn, so a subnet is still
    a subnet — in headers, tunnels (GRE, VXLAN, Geneve, IP-in-IP), ICMP errors,
    ARP, neighbour discovery, DNS answers, DHCP and routing protocols, and
    reverse lookups. Optionally keeping private ranges.
  - **MAC addresses** (ticked): locally administered stand-ins, optionally
    keeping the vendor prefix.
  - **Hostnames** and **usernames**: same-length stand-ins. One host gets one
    stand-in whether it appears in DNS, the TLS server name, HTTP `Host`, DHCP or
    NetBIOS.
  - **Strip payload**: keep headers only.
  - Checksums are updated, so the file opens cleanly — and a checksum that was
    wrong in the original stays wrong.
  - **The same capture always gets the same stand-ins**, derived from the
    capture's own encryption key, so two sanitized downloads line up, and
    rotating the master key does not change them. Nothing about the mapping is
    stored.
  - Built as it downloads; no sanitized copy is written anywhere. HTTPS only,
    like every download.
  - When it finishes, the dialog lists what was replaced, fields found in
    decoded or reassembled data that could not be replaced in place, and payload
    no dissector understood, by port. A failure cuts the download off and says
    not to share the partial file.

### Documentation

- README: **Sanitizing a capture**, including what it does not find. The
  sanitizer is off the roadmap.
- architecture.md: how a sanitize works — the frame walker, the tshark pass kept
  in step with it, why positions are checked against the frame, the tshark
  preferences it needs, keys, and its known limits. security.md: what a
  sanitized download does and does not promise.

## 0.1.0-dev.30 — 2026-09-13

### Changed

- **The Servers tab.**
  - Each server in the list carries a trust dot — green when connections are
    allowed, amber when its host keys are not trusted yet — and the heading
    counts them.
  - A chosen server reads as facts instead of greyed-out input boxes that looked
    editable and were not, with a Trusted / Not trusted pill.
  - **Capture from this server** opens the Capture tab with that server already
    chosen and the cursor in Name. It is disabled while the host is untrusted,
    since the capture would be refused.
  - Before anything is chosen the pane says what the tab is for and offers
    **+ Add a server**, instead of one sentence in an empty pane.
  - The Add server warning about pointing pcap-server at its own host is one
    line with **Why?** behind it, instead of a paragraph above the first field.
  - **SSH usernames** moved into the server list's sidebar.
- **The Capture tab.** The form is one card, top to bottom in the order a
  capture is thought about: name; server, interface and live stream; filter and
  the filter library; then the optional limits in a quieter row. **Start
  capture** is a real button in the card's footer rather than a thin full-width
  bar. "Where are the tcpdump flags?" moved below the list.
- **The capture list.**
  - A heading with a count, and how many are running.
  - A coloured left edge per status, with a pulse while running.
  - Stats as small chips: interface, packets, size in KB/MB/GB rather than
    always KB, how long it took, when it started.
  - A short ID with the full one on hover.
  - Errors on a line of their own.
  - Delete is outlined rather than solid red.
- **Plain-HTTP warnings.**
  - On the sign-in page: a headline, two sentences, and the fixes as a short
    list — built-in Let's Encrypt recommended, a reverse proxy (self-signed if
    there is no domain) otherwise — with a link to the README's HTTPS section.
    It was about a hundred words in one block.
  - Inside the app: one line, with **Set up HTTPS** for an admin, which opens
    Admin → HTTPS.
  - A refused action shows a laid-out panel with the same button.
- **The command line in HTTPS setup is filled in** from the steps: domain,
  email, provider, wait and staging. Credentials are still prompted for, never
  copied into the command, and typed values are shell-quoted.
- **Every "restart the container" for `COOKIE_SECURE` now says
  `docker compose up -d`.** Compose reads the environment when it creates a
  container, so `docker compose restart` — or stop and start — keeps the old
  value and the change silently does nothing. The same is true of
  `TRUST_PROXY_HEADERS`.
- Focus rings, hover states and a small logo mark that follows the theme.
  Animations stop under reduced motion.

### Fixed

- **A phone could not hold the toolbar.** At 400px it was 505px wide and the
  whole app scrolled sideways.
- **Built-in HTTPS no longer warns "Session cookies are not protected".** The
  status endpoint reported the `COOKIE_SECURE` variable rather than the cookie
  flag actually applied, so every built-in HTTPS install that kept the shipped
  `COOKIE_SECURE=false` — as the docs say it may — was told to change it.
- Opening Add server no longer leaves the previously chosen server highlighted.

### Documentation

- **The README leads with HTTPS.** A note under the introduction, and an HTTPS
  section before the Quick start comparing the three ways: built-in Let's
  Encrypt (recommended), a reverse proxy with a real certificate, and a reverse
  proxy with a self-signed certificate when there is no domain. The Quick start
  gains step 7, Turn on HTTPS.
- **Self-signed certificates**, new in the reverse proxy guide: one `openssl`
  command, Caddy's `tls internal`, nginx, and Nginx Proxy Manager's custom
  certificate.
- **Roadmap: Windows targets** — what carries over, what does not, and
  `dumpcap` versus `pktmon`.

## 0.1.0-dev.29 — 2026-09-13

### Fixed

- **A certificate request no longer fails polling your DNS.** lego, left to its
  defaults, polls DNS through the container's resolver until it can see the
  challenge record, and only then asks Let's Encrypt to check. On a network where
  certbot, Nginx Proxy Manager and Proxmox all obtain certificates for the same
  domain, that poll got `recursive nameservers: NS 127.0.0.11:53 returned
  NXDOMAIN` for its whole two minutes. None of those tools polls local DNS: they
  wait a fixed delay and let Let's Encrypt look. pcap-server now does the same —
  **Wait before validation**, 30 seconds by default, as Proxmox — and never
  polls a resolver for the challenge record.

- **A failed request says what went wrong.** The message was lego's raw log,
  led by its advice to back up an account directory that is deleted the moment
  it exits. It is now lego's actual error, with a hint for the common causes.

### Changed

- **Cloudflare asks for one field.** Providers with several ways to
  authenticate show the usual one first — for Cloudflare just
  `CF_DNS_API_TOKEN`, as Nginx Proxy Manager does — and the alternatives under
  **Other ways to authenticate**. Four empty boxes read as four required ones.
- **The plain-HTTP banner names both ways to HTTPS** — the built-in Let's
  Encrypt certificate first, a reverse proxy second — and the refusal message
  over HTTP says the same.
- **The command-line instructions say where to run them**: in the folder
  holding `docker-compose.yml`, or with `docker exec` from anywhere.
- **The Admin panel is organised into sections.** It was every section stacked
  in one column, each opening with a paragraph of explanation — about 2,000px
  before the last control. It is now a list down the side (Overview, HTTPS,
  Encryption, Users, SSH keys, Known hosts, Settings) with one section on screen
  at a time. **Overview** shows how each one stands, and the list marks sections
  that need attention. Each section leads with one sentence; the longer
  explanations are behind **Learn more**.
- **HTTPS setup is three steps, and out of the way until wanted.** The section
  leads with the certificate's status and what can be done about it; **Set up
  certificate** walks through domain, DNS provider, and request. A failed request
  leaves the steps open with what was typed, ready to correct.

## 0.1.0-dev.28 — 2026-09-13

### Added

- **pcap-server can get its own HTTPS certificate.** Admin → HTTPS certificate
  requests one from Let's Encrypt, a button switches the app over to it, and it
  renews itself — `docker compose up -d` and no reverse proxy is now a complete
  install. The domain is proved with a DNS record (DNS-01), so the machine needs
  no inbound port at all, and **about two hundred DNS providers** are offered:
  pick yours and the form shows that provider's settings. Everything happens in
  the panel. Full guide: [docs/tls.md](docs/tls.md).

- **The same thing from the command line**, which keeps DNS credentials off the
  network: `docker compose exec -it pcap-server python -m backend.tls issue
  --domain … --email … --provider …` prompts for them. Also `status`, `renew`
  and `providers`.

- **Saved display filters.** The Viewer has a **Save filter** button beside the
  display filter, and what you save is listed as **Your filters** at the top of
  **Filter help**, for use on any capture. Like saved capture filters they are
  private to your account. They are not saved views: a view is a tab on one
  capture.

- **A startup warning when the data directory is not private.** dev.27 told new
  installs to `chmod 0700` their directories, but nothing told existing ones.
  The app now logs `DATA DIRECTORY IS NOT PRIVATE` when other accounts on the
  host can reach the database, which holds every user's TOTP secret. It warns
  and carries on; one `chmod 0700 data` fixes it without a restart.

### Security

- **The certificate's private key is sealed under the master key** and is never
  a plaintext file. The ACME client works in a `/dev/shm` directory that is
  removed when it exits, and at startup the key is handed to the TLS library
  through a memory-only file. DNS credentials are sealed the same way.
- **The ACME client is only ever told what its documentation lists for the
  chosen provider.** lego also reads `LEGO_*` variables (which include hooks
  that run commands) and `NAME_FILE` variables (which read a file); neither can
  be set. Settings a provider takes as a file path are pasted as contents and
  written by the app. The `exec`, `manual` and `acmedns` providers are left out,
  and so are three file settings whose contents reach further than a
  credential: an AWS shared credentials file (`credential_process` runs a
  command), an Oracle Cloud config file (it names a key file path), and a
  Kerberos keytab (binary).
- **Provider URLs cannot point back into the container.** URL and server
  settings must be `http(s)://`, and may not be loopback, link-local (where cloud
  metadata lives), unspecified or multicast — checked when saved and again after
  a DNS lookup just before lego runs. LAN addresses stay allowed, for
  self-hosted DNS servers.
- **Settings that switch off TLS verification of a provider's API are not
  offered** (ISPConfig, EfficientIP, NameSurfer, Infoblox).
- **The certificate routes work over plain HTTP**, admin-only — they are how an
  install gets off plain HTTP without a proxy. On HTTP the credentials in that
  request cross the network unencrypted; the Admin panel says so and offers the
  command above instead.
- **Domain and email are validated before they reach lego's command line**,
  every value is passed as `--flag=value`, and the finished command is checked
  again — a domain beginning with `-` would otherwise be read as a flag.
- **Built-in HTTPS refuses passphrase mode.** A restarted app is locked and could
  not open its own key; if a certificate is stored and passphrase mode is turned
  on, the app refuses to start and says how to fix it.
- TLS 1.2 is the minimum, with ECDHE/AEAD ciphers only. Session cookies are
  marked `Secure` whenever built-in HTTPS is serving, whatever `COOKIE_SECURE`
  says.

### Changed

- **The image starts with `python -m backend.serve`** instead of uvicorn's CLI,
  because the app has to open its vault before the TLS context is built.
  `docker-compose.yml` is unchanged.
- **lego 5.4.1 is in the image**: one static binary, downloaded at build time by
  pinned version and SHA-256 in a build stage of its own. No extra Python
  environment.
- **The base image is pinned by digest** (`python:3.12-slim@sha256:78387bc3…`)
  rather than by tag, so a rebuild is the same image. `.github/dependabot.yml`
  proposes the new digest weekly, so the pin does not freeze out Debian and
  CPython security fixes.
- **`python -m backend.rekey` also re-wraps** the TLS key and DNS credentials in
  `data/tls`.
- **The capture filter's example chips are gone.** The filter library under the
  field has eighty-odd searchable expressions; eight more beside it were only
  something else to read. The display filter keeps its examples.
- **Save filter sits to the left of the BPF field, and only appears once there
  is something in it.** It used to sit below the field whether or not there was
  anything to save.
- **The Live stream option lines up with the rest of the form.** Its tickbox
  used to float above a label that wrapped into the filter column, because the
  form's generic field styling was stretching it into a full-width input. It is
  now a field like the others — **Live stream — still saved**, then
  **Watch as it records** — and the note about needing a target says the same
  thing in half the words.

## 0.1.0-dev.27 — 2026-09-13

### Fixed

- **The Stop capture button no longer appears on a saved capture.** The live bar
  is shown for any capture that was live streamed, finished ones included —
  that it was watched as it recorded is worth saying about a stored capture. Its
  *controls* were not gated the same way, so **Stop** and **Follow** were both
  offered against a capture that had already been saved. Stop then did nothing
  at all, silently, because there was no live capture for it to act on. Both are
  now hidden unless packets are actually still arriving, including after a
  capture fails rather than only after it completes.

### Changed

- **Admin has moved off the tab bar** and up into the toolbar, beside the
  version, the source link and Logout. The tab bar is the work — the servers you
  capture from, the capture you are setting up, and the captures you have open.
  Admin is somewhere you go occasionally to change how the app runs, and it was
  keeping a seat warm next to Capture.

- **The first-time setup in `docker-compose.yml` is one paste-able block**
  again, with the explanation underneath rather than wrapped around each line.

- **Setup now sets directory permissions, not just creates the directories.**
  `chmod 0700 ssh-keys data captures secrets` is part of the Quick start. At a
  default umask these are world-readable, and `data/` holds the database —
  which stores every user's TOTP secret as plain text, because codes have to be
  computed from it. Anyone able to read that file could produce a valid second
  factor for any account. **Existing installations were not created this way**;
  check with `ls -ld data` and fix it in place.

- **pytest 8.3.4 → 9.0.3, and pytest-asyncio 0.25.2 → 1.4.0**, closing
  PYSEC-2026-1845. Test-only: the Dockerfile installs `requirements.txt`, so
  pytest was never in the shipped image. The two move together because 0.25.2
  pins `pytest<9`. `pip-audit` is now clean.

### Documentation

- **Reverse proxy setup is its own document**, written as a procedure rather
  than a config reference: [docs/reverse-proxy.md](docs/reverse-proxy.md). The
  three settings that actually matter, then Caddy, nginx and Nginx Proxy Manager
  each worked start to finish, and a checklist for confirming it worked — which
  includes checking the app is **not** reachable except through the proxy, the
  one failure with no banner to announce it.

- **Caddy has a worked example for the first time**
  ([`docs/Caddyfile.example`](docs/Caddyfile.example)). Two of the three
  settings are already its defaults; it needs one line.

- **The proxy can be part of this stack.** Either Caddy or NPM can run as a
  service in the same compose file, so the install carries its own TLS and
  pcap-server publishes no port at all. Includes DNS challenges, for a host with
  no inbound ports from the internet — and the recommendation inverts there,
  because stock `caddy:2` ships no DNS provider modules and needs a custom
  build, while NPM does DNS challenges from its UI.

- **The Nginx Proxy Manager guide was rewritten.** It assumed you would stand
  NPM up *for* pcap-server on a shared Docker network. NPM is a proxy people
  already run, usually on another machine — so it now covers the proxy host
  fields, what actually goes in *Forward Hostname / IP*, how to reach the admin
  UI when it is bound to loopback, and how to firewall the app's port when the
  proxy is elsewhere.

## 0.1.0-dev.26 — 2026-09-13

### Added

- **A capture now says what it was capturing.** The BPF filter is stored on the
  capture record rather than handed to tcpdump and forgotten, and the capture
  list badges it — under the filter library's own name where the library knows
  one, so `tcp port 443` reads as **HTTPS**, and as the expression itself where
  it does not. The exact expression is on hover either way.

  The reason is that an empty packet list from a filtered capture and an empty
  packet list from a quiet network look identical on screen, and they lead to
  opposite conclusions. Captures taken before this release carry no badge:
  their filter was never recorded, and it is not reconstructed from the
  command string — guessing wrong would be a claim about what is inside the
  file.

- **Your own saved capture filters.** **Save this filter** puts whatever is in
  the BPF field into a named list of your own, which appears at the top of the
  filter library as **Your filters**. They are private to your account, the way
  your servers and stored usernames are: a capture filter usually names the
  hosts and ports you are investigating. The expression goes through the same
  validator the Capture form uses, because a saved filter is replayed into a
  real capture later.

- **Captures open as tabs.** Each capture opened in the Viewer gets its own tab
  on the bar, so two can be kept open and compared by clicking between them
  rather than returning to the list each time. A capture still recording shows
  a pulsing dot on its tab. Closing a tab leaves the capture alone.

- **The server, interface and capture filter are shown in the Viewer**, on the
  line above the filter box. It matters most during a live stream, where the
  capture list is a tab away and a filter narrower than you remember looks
  exactly like a quiet network.

- **A capture is summarised before it starts.** Pressing **Start capture** now
  shows what is about to run on the target host — name, server, interface,
  duration, packet cap, snap length and filter — and asks. Three of those
  fields mean "the server maximum" when left blank, so an empty Duration box
  does not look like five minutes of capture; and the server and the filter
  both persist between captures, which is how the right capture ends up run
  against the wrong host.

- **An admin can reset another account's two-factor authentication.**
  Admin → Users → **Reset MFA**. Previously a lost authenticator meant deleting
  the user and making them again, which also discarded their servers, their
  stored usernames, their saved filters and every capture they owned — a
  punishment for losing a phone.

  The reset destroys the old secret rather than merely unconfirming it, ends
  every session that account holds, and forgets its trusted devices. All three
  matter: a live session already carries both factors, and a trusted device is
  a second factor in its own right.

  **An admin cannot reset their own.** It would not help — reaching any route
  means already being past the second factor — and it would let a stolen
  session cookie replace an admin's second factor with the thief's own. The
  locked-out sole admin is answered from the host instead, by
  `docker compose run --rm --entrypoint python pcap-server -m backend.resetmfa
  <username> --apply`, which is dry-run by default and never touches a
  password.

### Changed

- **Captures are named when they are taken.** Name is the first field on the
  capture form and the form will not start without one. It is the only thing
  about a capture that nothing else can supply — the server, the interface and
  the filter are all on the record afterwards, but what you were looking for is
  not. Renaming afterwards still works. The rule is the form's, not the API's:
  a scripted capture is not refused for a cosmetic reason.

- **The dark theme is true black**, so an unlit pixel costs an OLED panel
  nothing, and the surfaces above it read as genuinely raised rather than as
  one dark grey on a slightly darker one.

- **The accent colour is a periwinkle blue instead of teal.** The old teal sat
  almost exactly on the packet list's UDP colour, so the colour meaning "this
  is interactive" and the colour meaning "this row is UDP" were the same
  colour. Blue is clear of every packet hue.

- **There is no standing Viewer tab.** It led to an empty panel for most of a
  session. The Viewer exists while a capture is open in it, and not otherwise.

- **Saved filters and saved views are capped per user** — 200 filters, and 50
  views per capture. Both are rows an authenticated caller could create in a
  loop with nothing else bounding them. The numbers are far above hand-curated
  use; they are a stop on a script, not a ration.

- **The README is a tour again, not a manual.** It was 1360 lines and every
  subject was in it at full depth. It is now ~600, and five subjects moved to
  one document each — [target hosts](docs/target-hosts.md),
  [filters](docs/filters.md), [live streaming](docs/live-streaming.md),
  [security](docs/security.md) and [operating it](docs/operating.md) — each
  linked from a table at the top. Nothing was deleted; the README keeps the
  short version of each and points at the long one.

- **The Quick start is less quick.** It now names what the host needs, says to
  have an authenticator app ready before you begin — TOTP enrolment is part of
  creating the first account, and there is no TOTP reset in the app — checks
  that the container actually came up rather than only that `up -d` returned,
  and carries an **If it does not come up** table for the three failures that
  account for almost all of them.

## 0.1.0-dev.25 — 2026-09-13

### Added

- **A capture filter that cannot match anything is now caught before the
  capture runs.** Joining two library picks with **…and this** is how it
  happens: a packet has one source port and one destination port, so two
  services is one constraint more than there are slots to hold it. The filter
  compiles, tcpdump starts, and the capture comes back empty — which reads
  exactly like "there was no such traffic".

  Two checks stand behind this, and they catch different things. The browser
  reasons about the ports directly, so the **…and this** option in the filter
  menu carries its warning at the moment of the click, with no round trip. The
  server compiles the expression with the real tcpdump before the capture
  starts, which is the same verdict the target host will reach and the only
  thing that can speak to syntax.

  Both are advisory. A filter that looks empty but is deliberate is still
  yours to run — the warning says what is wrong and what to do instead, and
  the capture starts if you say so.

  The two also answer different questions. `tcp port 80 and tcp port 443`
  compiles perfectly well, because it does match a packet running from port 80
  to port 443; libpcap is right to accept it and will never object. Only a
  model of what was meant can say that no such traffic exists, which is why
  the port reasoning is not simply a tcpdump wrapper.

### Changed

- **The Live stream tickbox now clears once a capture has started.** It is a
  per-capture decision rather than a preference, and leaving it ticked meant
  the next capture streamed too — which matters because a live stream is
  capped far lower than an ordinary capture (two at a time by default), so an
  accidental one can refuse a capture somebody meant to take. A failed start
  leaves it ticked, since the next thing to happen is a retry.

- **The README's Quick start no longer clones the repository.** The image is
  published and `docker-compose.yml` is the whole install, so the first step
  is now fetching that one file from a release tag — which is what keeps the
  file and the image version it names in step with each other. Cloning is
  still documented for anyone who wants to change the code.

  Also new: **Choosing a version**, on pinning a release against tracking the
  floating `:dev` tag, and **Upgrading**.

- **The README now explains running without a reverse proxy**, rather than
  only how to set one up. What still works over plain HTTP, what is refused,
  and — the part that catches people out — why browsing `http://localhost:8080`
  on the Docker host is *still* read-only: with a published port the
  connection reaches the container from the bridge gateway, not from loopback,
  so the loopback exemption never fires. Host networking or an SSH tunnel are
  the two ways to get a genuinely local connection.

  It also says plainly what read-only over HTTP does and does not protect.
  It protects your configuration and your SSH keys; it does not protect your
  session cookie, your password at sign-in, or the contents of a capture you
  view. And it explains why `TRUST_PROXY_HEADERS=true` is not a way to unlock
  the app without a proxy: the header it tells the app to believe is one any
  client can send.

### Fixed

- Three browser tests waited on a bare JavaScript expression, which Playwright
  can only evaluate by building it into a function inside the page — something
  this app's Content Security Policy forbids. They passed only while their
  condition was already true on the first look; the first one to need real
  polling failed with a CSP error rather than a useful message. All three now
  pass a function.

## 0.1.0-dev.24 — 2026-09-13

### Changed

- **A live stream now has to be pointed at something.** Ticking **Live stream**
  with the interface on `any` and no BPF filter is refused, by the capture form
  and by the server. Either an interface or a filter is enough; both narrow it
  further.

  The live preview is a fixed-size buffer held in the server's memory, and it
  does not refill: pointed at every packet on every link of a host doing real
  work it fills within seconds, and the preview is then frozen for the rest of
  the capture. Raising the limit buys seconds and spends memory. Narrowing the
  capture is the lever that works, so it is now required rather than suggested
  after the fact.

  The capture form explains this in place, as soon as **Live stream** is ticked
  on a form that narrows nothing, and clears itself as soon as an interface or
  a filter is chosen. The Start button does not send a request that would be
  refused.

  **Ordinary captures are untouched.** `any` with no filter is still the
  default and still the normal thing to run — there is no preview buffer to
  fill when nobody is watching, and the saved pcap is complete either way.

- **The frozen-preview message now names the remedy.** It said the capture was
  still running and would be saved in full, which is the reassurance; it now
  also says that a narrower filter or a more specific interface keeps the next
  live view going for longer, which is the only thing left to act on by the
  time it appears.

### Fixed

- **`scripts/check.sh` now picks a Python the pins actually support.** It built
  its virtualenv with bare `python3`, and distributions have started shipping
  3.14 there — Fedora 44 does. `pydantic-core` has no wheel above cp313, so pip
  fell back to building it from source, which needs PyO3 ≤ 3.13 and failed with
  a Rust error that never mentions Python versions. The project's own test
  script was unrunnable on a current machine, and the reason was unreadable.

  It now searches `python3.12`, `python3.13`, `python3.11`, `python3` and takes
  the first in range — 3.12 first, since that is what the Dockerfile and CI
  use — honours `PYTHON=` as an override and refuses rather than silently
  substituting, and rebuilds an existing `.venv` that was built by an
  unsupported interpreter instead of reusing it forever. When nothing suitable
  is installed it says so in one line, naming the range and what it found.

- **Long capture titles no longer run off the Capture page.** An unnamed
  capture is titled with the whole tcpdump command, including the remote
  `/tmp/pcap_<uuid>.pcap` path. The row is a flex layout whose text column took
  its content's intrinsic width, so instead of wrapping it grew wider than the
  panel, the page scrolled sideways, and the text was cut off at the edge. It
  wraps now, the row itself breaks onto a second line when the window is narrow
  rather than crushing the buttons, and the status badges sit level with the
  first line of the title instead of floating in the middle of the block.

## 0.1.0-dev.23 — 2026-09-13

### Added

- **Live streaming.** Tick **Live stream** on the capture form and the Viewer
  opens on the capture as it records, rows appearing as packets are taken.
  Until now a capture was invisible until it finished: `tcpdump -w` writes on
  the remote host, and nothing but a running packet count crossed the wire
  before the transfer.

  **It is the same viewer, with the same display filter.** The filter box, its
  autocomplete, the view flags, name resolution and saved views all behave
  exactly as they do on a stored capture, because the live routes call the same
  `get_packet_list` and `get_packet_detail` over a different `PcapSource`.
  There is one filtering implementation, not a cut-down second one for live
  captures — a filter can be applied, and saved as a view, while the capture is
  still running.

  **A live stream is still an ordinary capture.** The authoritative pcap still
  accumulates on the target and is still fetched and sealed when the capture
  ends, so nothing about storage changes and closing the browser loses nothing.
  Stopping it takes it through the same stopping/transferring/completed states
  as any capture, after which the Viewer reopens it from the saved file, keeping
  the display filter you were watching through. It stays marked **live stream**
  in the capture list afterwards.

  Two limits apply, because a live stream costs more than an ordinary capture
  while it runs. **Max simultaneous live streams** (2) bounds concurrent live
  captures — each holds an SFTP channel open on the target and costs a tshark
  run over the whole buffer per poll — and does not block ordinary captures.
  **Live stream preview limit** (16 MB) bounds the buffer; at the cap the
  preview freezes and says so, while the capture keeps running and is saved in
  full. Freezing was chosen over a rolling window because dropping the oldest
  packets renumbers frames, which breaks the detail pane and the saved views
  taken during the capture.

  Two things had to be got right for any of it to work, both measured against
  the real tools rather than assumed. A partially written *sealed* capture
  cannot be read at all — the truncation check refuses it outright, which is
  deliberate and was not weakened — so the live bytes are a pass-through and
  never become a file on the data volume. And tshark exits non-zero on a
  capture cut mid-packet, which is the same signal that means "your display
  filter was refused"; since a live read lands mid-record constantly, every
  poll with a filter applied would otherwise have blamed the operator's
  perfectly good filter. pcap-server walks the pcap record headers itself and
  hands tshark only whole records.

  A live capture is also given `-U`, so tcpdump writes each packet as it
  arrives instead of a buffer at a time. It changes when bytes reach the file,
  not which bytes — the saved capture is byte-identical either way.

### Changed

- **The saved-view chips are readable.** They were set at `0.75rem` — 12px,
  smaller than everything around them — for labels an operator typed themselves
  and reads at a glance while packets scroll. They are now the same size as the
  app's own content text, with the padding and the action glyphs scaled to
  match; the download, edit and delete buttons on a chip were a few pixels of
  click target sitting next to each other. A browser test now asserts the chip
  is no smaller than a capture's name, so a later tidy-up cannot quietly shrink
  it again.

## 0.1.0-dev.22 — 2026-09-13

### Fixed

- **The app offered eight capture filters its own API refused.** `validate_bpf`
  banned `&` and `|` along with the shell metacharacters, and every `tcpflags`
  or byte-offset filter needs them -- so the whole **TCP behaviour** group in
  the library, plus one of the worked-example chips on the Capture tab, failed
  with "BPF filter contains disallowed characters" the moment you pressed
  Start. Each half was correct on its own terms and nothing connected them,
  which is why no test saw it.

  `&` and `|` are allowed now; `;`, `$`, a backtick and a backslash still are
  not, and none of those mean anything in BPF. The expression was never
  exposed to the remote shell in the first place: it is one argv element,
  quoted by `_shell_quote` before the command string is assembled, and passed
  after `--` so it cannot be read as an option. The character check is the
  second line of defence under that quoting rather than the only one.

  `tests/test_filter_library.py` now reads the real library out of `app.js` and
  puts every expression through both gates -- the request validator, and
  `tcpdump -d`, which is the only authority on whether an expression is a
  filter at all. The list and the validator cannot drift apart again.

### Added

- **Fragment filters in the capture library**, under Size and shape. Two rows,
  not one: a fragment either carries the MF flag or sits at a non-zero offset,
  and matching only the offset misses the first fragment -- the one carrying
  the transport headers. The second row, fragments after the first, is what
  arrives when the first one went missing.
- **NTLMSSP.** As a display-filter protocol in the Viewer, with its four most
  useful fields (`ntlmssp.messagetype`, `.auth.username`, `.auth.domain`,
  `.ntlmserverchallenge`), all checked against `tshark -G fields` rather than
  written from memory.

  On the capture side it is a row under Windows and Active Directory that
  records the transports NTLM negotiates over. NTLMSSP has no port of its own
  -- it rides inside SMB, RPC, LDAP and HTTP at an offset that moves with the
  enclosing protocol, and BPF matches fixed offsets -- so there is no capture
  filter for it, and the row says where the real one lives.

### Changed

- **The Viewer's display filter sits below the capture name** instead of
  beside it. Sharing a row cost the filter half the width on a narrow window,
  and put the name of the capture and the thing you are doing to it on one
  line as though they were the same kind of thing.

- **The capture filter library stays open while you choose.** It collapsed
  itself on every pick, because the field it fills sits above the list and the
  collapse was the only sign the click had landed. That made choosing a second
  filter a matter of reopening the list -- which is most of the work in
  building one up from several rows.

  The feedback moves inside the library instead: a bar showing the expression
  as it is being built, so picking three filters in a row never takes your eye
  off the list you are picking them from. It has a **Clear** button, because
  starting over is a normal part of composing and by then the field itself can
  be scrolled out of sight behind the list.

  The bar reads the field rather than tracking clicks, so it follows a typed
  edit or a manual clear just as well as a library pick -- the field stays the
  single source of truth.

  Choosing a filter no longer pulls focus into the field either. Both the
  collapse and the focus jump moved the page out from under someone part-way
  through choosing.

  The browser tests for filter composition used to reopen the library between
  picks, which is how plain the friction was from the inside. They no longer
  need to, and that file now runs in a third of the time.

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
