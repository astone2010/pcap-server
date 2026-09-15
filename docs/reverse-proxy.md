# Setting up a reverse proxy

*Part of the [pcap-server](../README.md) documentation.*

**Over plain HTTP pcap-server is read-only.** It will not hand a capture over,
upload an SSH key, or change any setting — and read-only is enough to block your
first capture. Putting it behind TLS is what restores full access.

**You may not need a proxy at all.** pcap-server can obtain and renew its own
Let's Encrypt certificate and serve HTTPS itself — see
[Built-in HTTPS](tls.md), which is the recommended route. A proxy is the better
fit when you already run one, in passphrase mode, or when there is no domain to
get a certificate for — in which case see
[No domain: a self-signed certificate](#no-domain-a-self-signed-certificate).

This page is the setup, start to finish, for the three proxies people actually
use. Pick one and follow it; you do not need the other two.

| | When it fits | Certificates |
| --- | --- | --- |
| **[Caddy](#caddy)** | Nothing else is proxying yet. Least work by a distance — about five lines, and two of the three settings below are already its defaults | Obtains and renews them itself |
| **[nginx](#nginx)** | It is already on the box, or you want the config in version control | certbot alongside it |
| **[Nginx Proxy Manager](#nginx-proxy-manager)** | You already run NPM in front of other things. pcap-server is one more proxy host on it | Handled in its UI |

**Neither Caddy nor NPM has to be something you already run.** Both can live in
this stack's own compose file, so the install is self-contained and nothing
external has to know about it — see
[Running the proxy in the same stack](#running-the-proxy-in-the-same-stack).
That is also the section to read if the host has **no inbound ports from the
internet**, which is the usual case for something like this: certificates then
come from a DNS challenge, and the two proxies differ sharply in how much work
that is.

---

## The three settings that matter

Whichever you pick, these are what make it work and keep it safe. The
per-proxy sections below say how each one expresses them.

### 1. Tell the app that TLS terminated at the proxy

The proxy must send `X-Forwarded-Proto`, and the app must be told to believe it:

```yaml
environment:
  - TRUST_PROXY_HEADERS=true
  - COOKIE_SECURE=true      # back to the default now that you have TLS
```

Without **both**, pcap-server sees a plain-HTTP request and stays read-only. The
header is only trusted when that variable is set, because anyone can send one.

**Apply it with `docker compose up -d`, not `docker compose restart`.** A
restart — or a stop and start — keeps the environment the container was created
with, so the app carries on read-only as if nothing had changed. `up -d`
recreates the container with the new values.

### 2. Once you trust that header, control who can reach the app directly

This is the part that is easy to get wrong. Trusting `X-Forwarded-Proto` means
**anything that can reach the app directly can claim to be the proxy** — send
the header itself and get full write access, bypassing the read-only protection
entirely.

So the app's port must not be open to everything. In order of preference:

1. **Publish nothing.** Proxy and app on the same Docker network; the proxy
   reaches it by container name. Nothing else can reach it at all.
2. **Bind to loopback** — `"127.0.0.1:8080:8080"` instead of `"8080:8080"` —
   when the proxy runs directly on the same host.
3. **Firewall it to the proxy's address** when the proxy is on another machine.
   Worked rules are in the [NPM guide](nginx-proxy-manager.md#the-trade-off-when-npm-is-elsewhere),
   which is where this case usually comes up.

If you cannot do any of the three, leave `TRUST_PROXY_HEADERS` unset. The app
stays read-only, which is a smaller loss than an unauthenticated write path.

### 3. Do not buffer responses to disk

A capture download is decrypted in flight — no plaintext pcap is ever written to
the app's own disk. A proxy that spools large responses to a temp file undoes
that, leaving an unencrypted copy of the capture on the proxy.

- **nginx and NPM buffer by default.** You must turn it off.
- **Caddy streams by default.** You must not turn buffering on.

---

## Caddy

Caddy gets certificates by itself, so there is no certbot and no renewal cron.
It needs the domain to resolve to this host and ports 80 and 443 to reach it.

**1. A Caddyfile.** The complete version with the reasoning is
[`Caddyfile.example`](Caddyfile.example); the working core is:

```caddy
pcap.example.com {
	reverse_proxy pcap-server:8080 {
		header_up X-Forwarded-For {remote_host}
	}
}
```

That is the whole config. Two of the three settings above are already right:
Caddy sets `X-Forwarded-Proto`, and it streams responses rather than spooling
them. The one line you add replaces Caddy's default `X-Forwarded-For`, which
appends the peer to whatever the client sent and so leaves client-supplied text
in front of the real address.

**2. Put both on one Docker network and publish nothing:**

```yaml
services:
  pcap-server:
    image: ghcr.io/darthrater78/pcap-server:0.1.0-dev.36
    # No `ports:` at all. Caddy reaches it by name over the shared network,
    # and nothing else can reach it directly.
    environment:
      - TRUST_PROXY_HEADERS=true
      - COOKIE_SECURE=true
      # ... the rest of the environment block unchanged
    networks: [web]

  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data          # certificates live here — keep this volume
      - caddy_config:/config
    networks: [web]

networks:
  web:

volumes:
  caddy_data:
  caddy_config:
```

**3. Start it and watch the certificate arrive:**

```bash
docker compose up -d
docker compose logs -f caddy | grep -i certificate
```

Keep `caddy_data`. It holds the certificates and the ACME account key; losing it
means re-issuing, and Let's Encrypt rate-limits that.

---

## nginx

**1. Take the worked config.** [`nginx.conf.example`](nginx.conf.example) is
complete and commented, including which two lines are not optional. Copy it to
`/etc/nginx/conf.d/pcap-server.conf` and change `pcap.example.com` and the
certificate paths.

The settings from above, in nginx's terms:

```nginx
proxy_set_header X-Forwarded-Proto $scheme;   # 1 — unlocks write access
proxy_set_header X-Forwarded-For   $remote_addr;  # not $proxy_add_x_forwarded_for
proxy_buffering off;                          # 3 — or downloads land on disk
proxy_request_buffering off;
```

`$remote_addr` rather than the usual `$proxy_add_x_forwarded_for`: the latter
appends the real peer to whatever the client sent, leaving attacker-supplied
text in the header. pcap-server reads the rightmost entry for exactly that
reason, but sending only the address nginx saw removes the ambiguity.

**2. Get a certificate:**

```bash
sudo certbot --nginx -d pcap.example.com
```

**3. Bind the app to loopback**, since nginx is on the same host:

```yaml
    ports:
      - "127.0.0.1:8080:8080"   # not "8080:8080"
    environment:
      - TRUST_PROXY_HEADERS=true
      - COOKIE_SECURE=true
```

**4. Reload:**

```bash
sudo nginx -t && sudo systemctl reload nginx
docker compose up -d
```

Do not add `add_header` lines for CSP, HSTS or X-Frame-Options. pcap-server
sends its own, and nginx's `add_header` appends a second header rather than
replacing the first.

---

## Nginx Proxy Manager

NPM generates its own config, so almost none of the nginx file applies — but it
buffers by default, so setting 3 has to be pasted into the **Advanced** tab of
the proxy host:

```nginx
proxy_buffering off;
proxy_request_buffering off;
proxy_read_timeout 600s;
proxy_send_timeout 600s;
client_max_body_size 0;
```

`proxy_buffering off` is the important line. Without it, every capture you
download leaves a plaintext copy in NPM's container filesystem.

If NPM itself is new to you, this project's author has written a walkthrough of
setting it up, independently of pcap-server:
**[It's a Secret to Everybody](https://ramblingnonsense.nscriven.net/p/its-a-secret-to-everybody)**.

**[nginx-proxy-manager.md](nginx-proxy-manager.md)** is the full guide: the
proxy host fields, what to put in *Forward Hostname / IP* depending on where NPM
runs, what NPM already sets for you, and how to firewall the app's port when NPM
is on another machine.

---

## No domain: a self-signed certificate

Every certificate authority that browsers trust wants proof that you control a
domain. Without one — or without wanting to set up an account at a DNS provider
— you can still have HTTPS: the proxy serves a certificate you made, and
everything behind it works as it does with a real one. pcap-server never sees
the certificate; it only sees the proxy's `X-Forwarded-Proto: https`.

**What it costs.** Browsers warn that they do not recognise the certificate.
You can click through, but the better fix is to import the certificate — or, for
Caddy, its local root — into the trust store of each machine you browse from,
once. **Do not get into the habit of clicking through**: a warning you always
dismiss is one you will also dismiss when something really is intercepting the
connection.

**What does not change.** [The three settings above](#the-three-settings-that-matter)
apply exactly as written: `TRUST_PROXY_HEADERS=true` and `COOKIE_SECURE=true`,
nothing but the proxy able to reach the app's port, and no response buffering.

### Making the certificate

Caddy makes its own (below). For nginx and NPM, one command on any machine with
OpenSSL. Put in **every name and address you will type into the browser** —
a browser checks the `subjectAltName`, not the common name:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
    -keyout pcap.key -out pcap.crt -subj "/CN=pcap.lan" \
    -addext "subjectAltName=DNS:pcap.lan,IP:192.168.1.50" \
    -addext "extendedKeyUsage=serverAuth"
chmod 0600 pcap.key
```

The 825 days and the `serverAuth` line are not arbitrary: macOS and iOS refuse a TLS certificate
valid for more than 825 days, or without `serverAuth`, even one you have told
them to trust. `pcap.key` is the private key: it stays on the proxy.
`pcap.crt` is the part you import into browsers.

### Caddy: `tls internal`

Caddy runs its own small certificate authority, issues from it and renews by
itself, so there is no certificate to make. The Caddyfile from
[the Caddy section](#caddy) with one line added, and the site named by the
address or name you browse to:

```caddy
https://192.168.1.50, https://pcap.lan {
	tls internal
	reverse_proxy pcap-server:8080 {
		header_up X-Forwarded-For {remote_host}
	}
}
```

The compose file is the one in the Caddy section. Only port 443 has to be
reachable, and only from your own network. The root to import into browsers is
in the `caddy_data` volume:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

### nginx

Use [`nginx.conf.example`](nginx.conf.example) as it is, with these changes:

```nginx
server_name pcap.lan 192.168.1.50;     # in both server blocks
ssl_certificate     /etc/nginx/certs/pcap.crt;
ssl_certificate_key /etc/nginx/certs/pcap.key;
# and delete the two ssl_stapling lines: there is no issuer to staple from
```

No certbot. Steps 3 and 4 of [the nginx section](#nginx) — loopback binding and
reload — are unchanged.

### Nginx Proxy Manager

1. **SSL Certificates → Add SSL Certificate → Custom.** Upload `pcap.key` as the
   certificate key and `pcap.crt` as the certificate. Leave the intermediate
   empty.
2. On the pcap-server proxy host, **SSL** tab: choose that certificate and turn
   on **Force SSL**.
3. Paste the **Advanced** block from [the NPM section](#nginx-proxy-manager) —
   buffering off matters as much here as anywhere.

Then [check it worked](#checking-it-worked) as for any proxy. The checks are the
same; the only difference is the warning you accepted to get there.

---

## Running the proxy in the same stack

Both Caddy and NPM can be services in **this** compose file rather than
something external. The install then carries its own TLS: one `docker compose
up -d`, nothing else on the network has to be configured, and pcap-server
publishes no port at all — the proxy reaches it by container name over a private
Docker network, which is the strongest answer to
[setting 2](#2-once-you-trust-that-header-control-who-can-reach-the-app-directly)
there is.

### First, which challenge you need

This is what decides which of the two is less work, and it is worth settling
before you pick.

| | Needs | Use when |
| --- | --- | --- |
| **HTTP-01** | ports 80 and 443 reachable **inbound from the internet** | the box is genuinely published |
| **DNS-01** | **outbound** access only — to Let's Encrypt and to your DNS provider's API | the box is internal, behind CGNAT, or you simply do not want it exposed |

A capture server is usually the second one. Nothing about DNS-01 requires the
host to be reachable: you prove you control the domain by writing a `TXT`
record, so the certificate is issued for a name that resolves to a private
address. Both proxies still need to **reach out**, to the ACME directory and to
the DNS API.

And then they diverge, in the one way that matters:

| | DNS-01 |
| --- | --- |
| **NPM** | In the UI. Pick the provider in the SSL tab, paste an API token, done. No image to build |
| **Caddy** | Needs a **custom image**. The stock `caddy:2` ships no DNS provider modules at all — [Caddy's own docs](https://caddyserver.com/docs/automatic-https) put it as "DNS provider support is a community effort" — so the provider plugin has to be compiled in with `xcaddy` |

So the recommendation inverts depending on the challenge. **HTTP-01: Caddy**, by
a mile — five lines and no certificate management. **DNS-01: NPM**, unless you
are comfortable maintaining a custom Caddy build.

### NPM as a sidecar

Current NPM uses SQLite by default, so there is no second database service to
run.

```yaml
services:
  pcap-server:
    image: ghcr.io/darthrater78/pcap-server:0.1.0-dev.36
    # No `ports:`. NPM reaches it by name; nothing else can reach it at all,
    # which is what makes trusting X-Forwarded-Proto safe here.
    environment:
      - TRUST_PROXY_HEADERS=true
      - COOKIE_SECURE=true
      # ... the rest of the environment block unchanged
    networks: [web]

  npm:
    image: jc21/nginx-proxy-manager:latest
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      # The ADMIN UI. Loopback only -- reach it with an SSH tunnel:
      #   ssh -L 8181:127.0.0.1:81 you@thishost
      # It is a second front door onto the box, and it is not pcap-server's.
      - "127.0.0.1:81:81"
    volumes:
      - ./npm/data:/data
      - ./npm/letsencrypt:/etc/letsencrypt
    networks: [web]

networks:
  web:
```

```bash
mkdir -p npm/data npm/letsencrypt
chmod 0700 npm/data npm/letsencrypt
docker compose up -d
```

Then, in the NPM UI:

1. **Change the default admin account first.** NPM creates one on first run with
   credentials that are the same for every install, and it prompts you to
   replace them. Do that before anything else — you have just added a second
   administrative web UI to a host that handles packet captures.
2. **Proxy Hosts → Add:** scheme `http`, Forward Hostname `pcap-server` (the
   container name), Forward Port `8080`, Websockets off.
3. **SSL → Request a new certificate**, tick **Use a DNS Challenge**, choose
   your provider and paste a token scoped to that one zone. Check your provider
   is on NPM's list before committing to this route.
4. **Advanced tab** — paste the buffering block from
   [the NPM section above](#nginx-proxy-manager). NPM buffers by default, and
   without this every capture you download leaves a plaintext copy inside the
   NPM container.

**What this costs, stated plainly:** a second admin UI with its own
authentication, its own update cadence and its own datastore, in front of a tool
whose whole job is handling sensitive captures. Keeping port 81 off the network
is not optional decoration — it is what keeps that second door shut.

#### Reaching the NPM admin UI when it is on loopback

`127.0.0.1:81:81` binds port 81 to the **host's** loopback, so it is reachable
from a shell on that host and from nowhere else. On a headless box that needs an
answer, and there are three reasonable ones.

**An SSH tunnel — the default, and the one to use for first-run setup.** From
your own machine:

```bash
ssh -N -L 8181:127.0.0.1:81 you@pcap-host
```

Leave it running and open `http://localhost:8181`. The tunnel terminates on the
host, so `127.0.0.1:81` in that command is resolved *there*, which is exactly
what you want. Nothing is exposed for longer than the SSH session, and you are
already trusting SSH to that host — pcap-server does nothing else.

Do the first-run steps through this: change the default admin account, add the
proxy host, request the certificate. Then close it.

**Bind it to a management interface** if you have one and a tunnel each time is
too much friction:

```yaml
      - "10.0.0.20:81:81"     # this host's management address, not 0.0.0.0
```

Reachable from that network and no other. Worth pairing with a firewall rule
restricting it further, because Docker publishes ports around ufw's INPUT chain
by default — test from a third machine rather than assuming.

**Put NPM behind itself**, once it is working: add a proxy host for the admin UI
pointing at `127.0.0.1:81`, give it a certificate, and attach an **Access List**
so it demands credentials before nginx will even proxy it. This is the most
convenient option and the easiest to get wrong — without the access list you
have published an unauthenticated-until-login admin panel to whatever the proxy
listens on. It also cannot be how you start, since you need the UI to create the
proxy host in the first place.

What not to do: publish `81:81`. That puts a management interface with
well-known default credentials on every interface of a machine that holds packet
captures, and the window between `docker compose up -d` and you changing the
password is the whole exposure.

### Caddy as a sidecar with a DNS challenge

The compose from [the Caddy section](#caddy) already works for HTTP-01. For
DNS-01 you additionally need a Caddy binary with your provider compiled in.
Cloudflare as the example:

`caddy/Dockerfile`:

```dockerfile
FROM caddy:2-builder AS builder
# One --with per provider. The full list is github.com/caddy-dns
RUN xcaddy build --with github.com/caddy-dns/cloudflare

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

`Caddyfile`:

```caddy
pcap.example.com {
	tls {
		dns cloudflare {env.CF_API_TOKEN}
	}
	reverse_proxy pcap-server:8080 {
		header_up X-Forwarded-For {remote_host}
	}
}
```

In the compose file, build it rather than pulling it, and pass the token in from
a `.env` file kept beside the compose file — never inline:

```yaml
  caddy:
    build: ./caddy
    restart: unless-stopped
    environment:
      - CF_API_TOKEN=${CF_API_TOKEN:?set CF_API_TOKEN in .env}
    ports:
      # 443 only. With a DNS challenge nothing needs to reach port 80 from
      # outside, so do not publish it unless you want the plain-HTTP redirect.
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    networks: [web]
```

```bash
chmod 0600 .env          # it holds a DNS API token
docker compose up -d --build
docker compose logs -f caddy | grep -i -e certificate -e error
```

Scope the API token to **editing DNS for that one zone** and nothing else. It
can create records in your domain; that is a credential worth treating like the
master key.

The cost here is the inverse of NPM's: no second admin UI and no extra
datastore, but you now maintain a custom image, and you have to rebuild it to
take a Caddy security update rather than just pulling a tag.

## Checking it worked

Sign in through the proxy and look for three things:

| | |
| --- | --- |
| The amber **Read-only** bar across the top of the app | gone |
| A completed capture's button | **Download**, not **Download (HTTPS only)** |
| Admin → Settings | saves, rather than refusing with an HTTPS message |

If the bar is still there, the app is not seeing `X-Forwarded-Proto: https`.
Check both halves, and that the container was recreated with `docker compose
up -d` rather than restarted: the proxy sending the header, and `TRUST_PROXY_HEADERS=true`
in the container's environment. One without the other does nothing.

Then check the part nothing on screen shows — that the app is **not** reachable
except through the proxy. From a third machine:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://<pcap-server-host>:8080/
```

A connection refused or timeout is what you want. A `200` means anyone on that
network can send `X-Forwarded-Proto: https` and write to the app — go back to
[setting 2](#2-once-you-trust-that-header-control-who-can-reach-the-app-directly).
Docker's published ports bypass ufw's INPUT chain by default, so test this
rather than assuming the rule took.

---

## Related

- [Running it without a reverse proxy](operating.md#running-it-without-a-reverse-proxy)
  — what you can still do, and what you give up.
- [Traffic in transit](security.md#traffic-in-transit) — why the app refuses
  what it refuses over plain HTTP.
