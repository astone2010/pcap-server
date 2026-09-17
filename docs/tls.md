# Built-in HTTPS

*Part of the [pcap-server](../README.md) documentation.*

**pcap-server can get its own certificate from Let's Encrypt and serve HTTPS
itself**, with no reverse proxy in front of it. Over plain HTTP the app is
read-only, and this is the shortest way out of that: request a certificate,
switch over, done. Renewal is automatic. Everything is in the Admin panel —
nothing to install, no files to edit, no commands to run.

**This is the recommended way to turn on HTTPS.** A reverse proxy is still the
right answer if you already run one — see
[Setting up a reverse proxy](reverse-proxy.md). And if you have no domain, or do
not want a DNS provider account, a proxy with
[a self-signed certificate](reverse-proxy.md#no-domain-a-self-signed-certificate)
gets you HTTPS without either.

## What you need

| | |
| --- | --- |
| **A domain whose DNS you can edit through an API** | About two hundred DNS providers are supported — Cloudflare, Route 53, DigitalOcean, Hetzner, OVH, Porkbun, deSEC, Google Cloud DNS, Azure, your own server over RFC 2136, and many more. The name you use (say `pcap.example.com`) should resolve to this machine; a private LAN address is fine |
| **API credentials for that provider** | Scoped as narrowly as the provider allows — ideally DNS edits on the one zone |
| **Outbound HTTPS** | To Let's Encrypt and to your DNS provider's API. Nothing inbound: the machine never has to be reachable from the internet |
| **A master key the app can read unattended** | `MASTER_KEY_FILE`, as in the Quick start (or `PCAP_MASTER_KEY`). **Not available in passphrase mode** — [why](#passphrase-mode) |

**How it proves the domain is yours.** Let's Encrypt asks for a TXT record under
`_acme-challenge.pcap.example.com`; pcap-server creates it through your
provider's API, Let's Encrypt looks it up, and the record is removed again. This
is the DNS-01 challenge. It is the reason no inbound port is needed — and why a
capture box on a private network can have a real, browser-trusted certificate.

The work is done by [lego](https://go-acme.github.io/lego/), an ACME client
built into the image as a single binary. Its provider list is the one offered.

## Getting the certificate

There are two ways, and they do the same thing. **The Admin panel is the
everyday one; the command line keeps credentials off the network.**

### From the Admin panel

**Admin → HTTPS → Set up certificate.** Setup is three steps:

1. **Domain** — the name, and a **contact email** Let's Encrypt writes to about
   expiry problems.
2. **DNS provider** — pick yours. The fields below change to that provider's
   settings, with lego's description of each and a link to its guide. For
   providers with several ways to authenticate, the usual one is shown and the
   rest are under **Other ways to authenticate** — for Cloudflare that is just
   `CF_DNS_API_TOKEN`, an API token with **Zone → DNS → Edit** on the zone, the
   same token Nginx Proxy Manager asks for.
   Settings a provider normally takes as a **file** — a Google service account
   key, a TransIP private key — are boxes you paste the file's contents into.
   pcap-server writes them where lego needs them; you never give it a path.
   **More settings** holds the optional ones: propagation timeouts, TTLs, API
   endpoints.
3. **Request** — **Wait before validation** — 30 seconds unless your provider is slow to
   publish. After creating the record pcap-server waits this long, then asks Let's
   Encrypt to look — the same as Proxmox's validation delay and certbot's
   propagation seconds. It does not query your DNS itself.
   Then **Request certificate**, which takes about a minute. When it is issued,
   **Switch to HTTPS**. Once a certificate exists, **Change settings** reopens
   the same steps.

Stored credentials are never shown again. The panel lists which settings are
stored; leave a stored field blank to keep it, or fill it in to replace it.
Choosing a different provider starts from nothing.

This works **over plain HTTP**, even though almost nothing else does — it is
the one way off plain HTTP that does not need a proxy, so refusing it there
would defeat the point. It is still admin-only. Understand what that costs: **on
plain HTTP the credentials you type cross the network unencrypted**, where
anyone on the path can read them. The panel says so when the page is on HTTP.
On a network you trust, that may be fine; if you are not sure, use the command
line.

The switch refuses while a capture is running, since restarting would end it.

### From the Docker host

```bash
docker compose exec -it pcap-server python -m backend.tls issue \
    --domain pcap.example.com --email you@example.com --provider cloudflare
docker compose restart pcap-server
```

Run it from the directory holding `compose.yaml` — elsewhere, `docker
compose` answers `no configuration file provided`. From anywhere,
`docker exec -it <container> python -m backend.tls ...` does the same, with the
container's name from `docker ps` (for example `pcap-server-1`).

**Admin → HTTPS → Set up certificate** shows this command under **Prefer the
command line?**, already filled in with the domain, email, provider, wait and
staging choice entered in the steps — everything except the credentials.

It prompts for each of the provider's credentials, without echoing the secret
ones. They are typed into the container, not sent to it, so they never cross a
network — and they are never command-line arguments, which every process on the
host could read from `ps`.

- `python -m backend.tls providers` lists the provider codes;
  `python -m backend.tls providers route53` lists one provider's settings.
- To script it, swap `-it` for `-T` and pipe `NAME=value` lines in:
  `... issue --domain ... --email ... --provider hetzner < dns.env`. For a
  setting that is a file, give `NAME=@/path/inside/the/container`.

## After the switch

- **The address becomes `https://` on the same port you already use** — the
  host side of the `ports:` line in `compose.yaml`. With the shipped
  `"8080:8080"` that is `https://pcap.example.com:8080`; with `"9443:8080"` it
  is `:9443`. Plain HTTP stops answering there: the port now speaks only TLS.
  The right-hand `8080` is the app's port inside the container and stays as it
  is. To drop the port number from the address, publish `"443:8080"`.
- **Everyone is signed out**, as on any restart, and signs back in at the
  `https://` address.
- **Cookies are marked `Secure` automatically.** `COOKIE_SECURE=false` in the
  compose file can stay as it is; built-in HTTPS overrides it.
- **Do not set `TRUST_PROXY_HEADERS`.** That is for a proxy in front, and with
  nothing in front it would let any client claim a secure connection.
- **HSTS is sent.** Browsers that have visited will insist on `https://` for
  that hostname for a year. If you later [go back to plain
  HTTP](#removing-it), reach it by IP address rather than by that name.

## Renewal

Automatic. Let's Encrypt certificates last 90 days; pcap-server checks hourly
and renews once fewer than 30 are left. **A renewed certificate is picked up
without a restart** — the running server swaps it in for every connection
after.

A failed renewal is logged, shown in the Admin panel, and retried six hours
later rather than every hour, so a revoked credential does not burn through
Let's Encrypt's limit of five failed validations an hour. The working
certificate stays in place until a renewal succeeds.

To renew by hand: **Renew now** in the panel, or
`docker compose exec pcap-server python -m backend.tls renew`. A renewal done
from the command line is picked up by the running server within the hour.
`... python -m backend.tls status` shows what is configured and when the
certificate expires.

## Testing with staging

Tick **Staging**, or add `--staging`, to use Let's Encrypt's staging service.
Its certificates are **not trusted by browsers**, but its rate limits are
generous — use it to check your credentials and DNS work before asking for a
real one. Request again without it to replace the staging certificate.

## What is stored

Everything is in `data/tls/`, mode `0700`:

| File | Contents |
| --- | --- |
| `fullchain.pem` | The certificate chain. Public by nature, so not encrypted |
| `privkey.pem.enc` | The certificate's private key, **sealed under the master key** — the same envelope as captures and SSH keys |
| `dns-credentials.enc` | The DNS provider's settings, sealed the same way |
| `acme.json` | Domain, email, provider and the staging flag. Nothing secret |

**The private key is never a plaintext file**, not even briefly:

- lego runs in a fresh directory under `/dev/shm`, which is memory, not disk.
  Its ACME account key, the issued key, and any credential file a provider
  needed all live there, and the directory is removed when lego finishes,
  whether it succeeded or not. Nothing lego writes survives.
- At startup the sealed key is opened into a memory-only file (a `memfd`, with
  no name on any filesystem), handed to the TLS library, and closed. After that
  it exists only inside the running server.

**Rotating the master key covers it.** `python -m backend.rekey` re-wraps the
files in `data/tls/` along with captures and SSH keys — see
[Rotating the master key](operating.md#rotating-the-master-key).

## What lego is allowed to be told

lego takes its provider settings from environment variables, and it reads
others too: `LEGO_*` variables include hooks that run commands, and for any
setting `NAME`, a variable `NAME_FILE` makes lego read the value from a file.
So pcap-server passes lego **only** the variables lego's own documentation
lists for the provider you chose — never one it does not list, never a
`LEGO_*` or `_FILE` variable, and never the app's own environment. Settings lego
reads as a path are filled with a path pcap-server wrote itself.

Three providers are left out because they cannot be made safe or cannot work
here: `exec` (runs a program you name), `manual` (waits for someone at a
terminal), and `acmedns` (keeps state in a file that has to outlive each run).
Three single settings are left out for the same kind of reason: an AWS shared
credentials file (it can carry `credential_process`, which runs a command —
use the access key variables), an Oracle Cloud config file (it names a key file
path lego would read — paste the private key instead), and a Kerberos keytab
(binary, so it cannot be pasted).

**Endpoints have limits.** Many providers take an API URL or a server address —
a self-hosted PowerDNS, an ISPConfig panel, an RFC 2136 nameserver. lego sends
your credentials there from inside the container, so those settings are checked:

- only `http://` and `https://` URLs;
- never loopback (`127.0.0.1`, `::1`, `localhost` — the container itself),
  link-local (`169.254.0.0/16`, `fe80::/10`, where cloud metadata services
  live), unspecified (`0.0.0.0`) or multicast addresses;
- checked as typed when you save, and again after a DNS lookup just before lego
  runs, so a hostname that resolves to one of those is refused too.

Addresses on your own network (`10.x`, `192.168.x`, `fd00::/8` and the like)
are allowed — a DNS server on the LAN is what these settings exist for.

**Certificate checks stay on.** Settings that switch off verification of the
provider's own certificate (ISPConfig, EfficientIP, NameSurfer, Infoblox) are
not offered: with them, anyone on the path to the panel could read the
credentials sent to it. A self-hosted panel needs a certificate lego can
verify.

## Removing it

**Remove** in the panel deletes all four files. A server that is currently on
HTTPS carries on until the next restart, then comes back on plain HTTP. Mind
[HSTS](#after-the-switch) when you reconnect.

## Passphrase mode

Built-in HTTPS **does not work with `ENCRYPTION_MODE=passphrase`**, and refuses
the combination rather than half-working.

The key that serves HTTPS is sealed under the master key. In passphrase mode
the app starts locked — the master key does not exist until an admin types the
passphrase — so after a restart it cannot open its own certificate key and has
no HTTPS to offer. The passphrase would have to be typed over plain HTTP, which
refuses the unlock. Nothing could break the loop.

So: the Admin panel and the command line both refuse to request a certificate
in passphrase mode, and if a certificate is already stored when passphrase mode
is switched on, **the app refuses to start** and says how to fix it — switch
back to `MASTER_KEY_FILE`, or delete the certificate and key from `data/tls/`.
For passphrase mode, use a [reverse proxy](reverse-proxy.md).

## When something goes wrong

| You see | It means |
| --- | --- |
| `lego exited 1` naming your provider and an authentication error | The credentials are wrong, expired, or not allowed to edit that zone |
| `invalid email address` / `invalidContact` | Let's Encrypt refuses some addresses outright, `example.com` ones among them |
| `too many certificates already issued` | A Let's Encrypt rate limit. Use [staging](#testing-with-staging) while experimenting |
| `recursive nameservers: NS 127.0.0.11:53 returned NXDOMAIN` | 0.1.0-dev.28 only, which polled your DNS before validating. From dev.29 pcap-server waits instead — see below |
| `NXDOMAIN looking up TXT for _acme-challenge...` from Let's Encrypt | The record was not published by the time Let's Encrypt looked. Raise **Wait before validation** |
| `no configuration file provided: not found` from `docker compose exec` | You are not in the directory holding `compose.yaml`. `cd` there, or use `docker exec -it <container> ...` |
| `HTTPS NOT ENABLED: ... Serving plain HTTP` in the log at startup | A certificate is stored but its key would not open — most often the master key was replaced without [rotating](operating.md#rotating-the-master-key). The app starts on plain HTTP rather than not at all, so you can get in and fix it |
| `REFUSING TO START` mentioning passphrase | See [Passphrase mode](#passphrase-mode) |
| The browser shows garbage or "connection reset" at `http://` | The port speaks TLS now. Use `https://` |

### Why it waits instead of checking

lego, left to its defaults, polls DNS until it can see the challenge record
before involving Let's Encrypt — through the container's resolver, which
forwards to your network's DNS. certbot (and so Nginx Proxy Manager) and Proxmox
never do that: they wait a fixed delay and let Let's Encrypt look from the
public internet. On a network where those work, lego's poll was seen to get
`NXDOMAIN` for its whole two-minute window, so pcap-server waits the way they
do. It never polls a resolver for the challenge record; the provider still looks up which DNS zone the domain is in, as before.

If Let's Encrypt reports `NXDOMAIN looking up TXT`, the record was not published
in time: raise **Wait before validation**.
