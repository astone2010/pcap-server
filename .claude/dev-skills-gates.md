# Dev Skills gate state
Track: release sequence (dev pre-release — branch not merged to main)
Version: 0.1.0-dev.8  (NOT yet tagged — user deferred tagging; prereq work folded in rather than burning dev.9)
Updated: 2026-09-12

🔢 VERSION    ✅ 0.1.0-dev.8 in main.py, docker-compose.yml, CHANGELOG; v0.1.0-dev.7 tagged on remote at 9085701
🔨 BUILD      ✅ 249 checks green across 9 suites (adds SSH connection-leak measurement against a live server, CaptureManager lifecycle, and always-visible repo/release links). This container now HAS tcpdump 4.99.4 + tshark, so for the first time the viewer was tested against a real 40-packet capture and the probe against a real SSH server running a real /bin/sh. Caveat: no docker daemon, image not rebuilt (Dockerfile unchanged)
🔒 SECURITY   ✅ 0 Critical, 0 High. FIXED a rate-limiter bypass found while answering an nginx question: _client_ip trusted X-Forwarded-For unconditionally and read the LEFTMOST entry, so any caller could invent a fresh address per request and never trip the login limiter -- unlimited password guessing against a directly-exposed instance, and equally against one behind nginx using the usual $proxy_add_x_forwarded_for. Now the header is only consulted when TRUST_PROXY_HEADERS is set, and the rightmost (proxy-appended) entry is used. FIXED a leaked SSH connection per capture (authenticated connection to a production host outliving its work, measured server-side); added login timeout, keepalives, monitor ceiling, bounded download; stopped disclosing the exact version to unauthenticated callers. Probe output treated as untrusted: hostile-host suite proves command-injection, traversal, substitution and non-tcpdump paths are all rejected, and the discovered path is re-validated before storage. Probe asserted read-only by test (no package manager, no writes, only `sudo -n true`)
📄 DOCS       ✅ CHANGELOG dev.8 gains Features + Changed sections; README gains "Checking a server before you capture" incl. the PATH and setcap findings and why there are no distro templates
📦 RELEASE    ➖ N/A — dev pre-release, no PR to main
🚀 SHIP       ⬜ — user has deferred tagging until more work lands

Env: remote container (Claude executes git after approval; tag pushes handed to user)
Branch: claude/admiring-wright-k20ptf

CORRECTION ON RECORD: dev.7's changelog claimed -n/-nn were fixed in the viewer.
Testing against real tshark showed that was over-stated. tshark's Info column
prints ports numerically regardless of resolution settings (verified on port 80:
-N mt and -n give byte-identical output), so tcpdump's ports-named-vs-numeric
distinction is not expressible in this view at all. Host names additionally need
nameres.network_name AND nameres.use_external_name_resolver. Replaced both chips
with one explicit "Resolve hostnames" toggle, default off, since resolution means
reverse-DNS on every address in a capture. dev.8's changelog records this.

SELF-CAPTURE HAZARD (demonstrated 2026-09-12; GUARDED as of this work):
  Capturing an interface that carries pcap-server's own web traffic records the
  app's HTTP session. Over plain HTTP this was verified to recover the admin
  password verbatim from the resulting pcap
  ({"username":"alice","password":"..."}), and would equally capture session
  cookies and TOTP codes. On the Docker host, `-i any` also sweeps the bridge
  interfaces and so captures container traffic. Candidate mitigations: warn when
  the capture target resolves to a local address, suggest a BPF exclusion for
  the app's own port (e.g. `not port 8080`), or offer it as a default filter.
  Read-only-over-HTTP reduces but does not remove this: sign-in is still
  permitted over HTTP, which is exactly the request that carries the password.

  GUARD IMPLEMENTED: a server whose hostname resolves to loopback, to an address
  this container answers on, to the default gateway (the Docker host on a bridge
  network), or to a published host alias (host.docker.internal and friends) is
  refused on add, on save, on edit, and on load of a profile stored before the
  check existed. The refusal names the matched address and explains the exposure.

  WHAT THE GUARD CANNOT SEE: the host's LAN address, when the container is
  bridged and has never been told what the host is called. `extra_hosts` or
  --add-host makes it resolvable and the check then catches it. So this is a
  guard against the likely mistakes, not proof of non-locality, and it is worded
  that way rather than implying more than it knows.

CONCURRENT CAPTURES ARE UNBOUNDED (user-reported 2026-09-12, not yet fixed):
  Nothing limits how many captures run at once. start_capture takes no lock and
  checks no quota, so a user can launch capture after capture and each one:
    - opens its own SSH connection to the target (bounded only by sshd's
      MaxSessions/MaxStartups, which will start refusing connections)
    - starts another tcpdump on the remote host, each writing its own file into
      the remote /tmp -- several long captures can fill it
    - stages another pcap on the captures volume, with no disk quota
    - holds another asyncio task and monitor timer for its full duration
  Two captures on the same interface also record the same packets twice, so the
  cost is paid for duplicate data.
  Candidate fixes, in rough order of value: a per-user concurrent-capture limit
  (an admin setting, like the existing max_capture_seconds); refusing a second
  running capture against the same server+interface; a free-space check on the
  remote /tmp during the prereq probe and before each start; and a total-size
  cap on the captures volume with oldest-first eviction or a plain refusal.
  Note the interaction with encryption: sealed captures are slightly larger than
  the plaintext (~0.18%), so a disk cap should be measured on stored bytes.

REQUESTED, NOT YET BUILT (user asked these be noted, 2026-09-12):
- Saved usernames: remember usernames already used and offer them as a dropdown
  when adding a server, instead of retyping. Belongs with the saved-servers
  table; consider per-user scope, same as active/saved servers.
- Capture sanitiser: an option to scrub a pcap before download so it can be
  analysed safely elsewhere. Worth scoping carefully -- candidates are payload
  stripping (headers only, like a post-hoc snaplen), credential redaction in
  cleartext protocols (HTTP Basic, FTP, SMTP AUTH, SNMP community strings),
  and MAC/IP anonymisation. tshark and tcprewrite can do parts of this; the
  design question is whether the sanitised copy replaces the download or is
  offered alongside the raw one.

Deferred by user decision:
- Encryption at rest: envelope encryption, PLUGGABLE key source — Docker
  secret/env as shipped default, admin passphrase (RAM-only) optional. Stop
  writing plaintext SSH keys to disk: asyncssh.import_private_key takes bytes.
  Scope should include captured pcaps (a capture of cleartext traffic is a
  credential dump) and TOTP secrets.
- TLS/ACME: LIKELY MOOT FOR THIS USER. They run Nginx Proxy Manager, which
  already issues and auto-renews Let's Encrypt certificates, including DNS-01 for
  hosts with no inbound port 80. The Caddy-sidecar work was scoped to solve a
  problem they have already solved; do not build it without asking. The
  reachability question (HTTP-01 vs DNS-01) is likewise NPM's to answer.
  Original note follows.
- TLS/ACME (superseded by the above): NOW LOAD-BEARING, not just nice to have. Capture download is
  refused over plain HTTP as of this work, so without a proxy in front there is
  no way to retrieve a capture except from loopback. Recommendation unchanged:
  Caddy sidecar over certbot. Reachability (HTTP-01 vs DNS-01) still unanswered.
  Original note: Recommendation on record: Caddy sidecar over certbot.
  Reachability (HTTP-01 vs DNS-01) unanswered and must be settled first.
- Tagging: user wants more work landed before any tag is cut.
