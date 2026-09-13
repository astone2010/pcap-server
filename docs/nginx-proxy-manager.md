# pcap-server behind Nginx Proxy Manager

NPM generates its own nginx config, so most of
[`nginx.conf.example`](nginx.conf.example) does not apply. Three things do.

This assumes NPM is **already running** as your shared proxy and pcap-server is
one more host on it. If you have not chosen a proxy yet, see
[Setting up a reverse proxy](reverse-proxy.md) — Caddy is less work for a single
service.

> New to NPM itself? This project's author has written a longer walkthrough of
> setting it up, separately from pcap-server:
> **[It's a Secret to Everybody](https://ramblingnonsense.nscriven.net/p/its-a-secret-to-everybody)**.
> What follows here is only the pcap-server-specific part.

## 1. Point it at pcap-server

NPM is almost always **a proxy you already run**, sitting in front of several
things. pcap-server is one more proxy host on it, not a reason to stand another
one up. So the question is only how NPM reaches it.

**Proxy Hosts → Add Proxy Host → Details:**

| Field | Value |
| --- | --- |
| Domain Names | `pcap.example.com` |
| Scheme | `http` — TLS terminates at NPM |
| Forward Hostname / IP | the host pcap-server runs on |
| Forward Port | `8080` |
| Cache Assets | off |
| Block Common Exploits | on is fine |
| Websockets Support | off — pcap-server does not use them |

Then **SSL → Request a new SSL Certificate**, Force SSL on. NPM handles
Let's Encrypt itself, including DNS challenges for hosts with no inbound
port 80.

### What to put in "Forward Hostname / IP"

| Where NPM runs | What to forward to |
| --- | --- |
| A different machine | that machine's LAN address or DNS name, e.g. `10.0.0.20` |
| The same Docker host, on a shared network | the container name, `pcap-server`, and publish no ports at all |
| The same Docker host, separate networks | the host's Docker bridge address, and publish `8080` |

`127.0.0.1` is not one of the answers unless NPM is in the same container.
Loopback inside the pcap-server container is that container, not your host.

### The trade-off when NPM is elsewhere

Forwarding from another machine means pcap-server's port has to be reachable on
the network, not bound to loopback. That matters because of what
`TRUST_PROXY_HEADERS=true` does: **anything that can reach the app directly can
send `X-Forwarded-Proto: https` itself** and get full write access, bypassing
the read-only-over-HTTP protection entirely.

So restrict who can reach it. On the pcap-server host, with NPM at `10.0.0.5`:

```bash
# firewalld
sudo firewall-cmd --permanent --add-rich-rule \
    'rule family=ipv4 source address=10.0.0.5/32 port port=8080 protocol=tcp accept'
sudo firewall-cmd --permanent --add-rich-rule \
    'rule family=ipv4 port port=8080 protocol=tcp drop'
sudo firewall-cmd --reload
```

```bash
# ufw
sudo ufw allow from 10.0.0.5 to any port 8080 proto tcp
sudo ufw deny 8080/tcp
```

Note that Docker's published ports bypass ufw's INPUT rules by default — check
with `curl http://<host>:8080/` from a third machine rather than assuming. If
you cannot restrict it, leave `TRUST_PROXY_HEADERS` unset: the app stays
read-only, which is a smaller loss than an unauthenticated write path.

## 2. What NPM already does

NPM's generated location block sets these for you — nothing to add:

```nginx
proxy_set_header X-Forwarded-Proto $scheme;     # what unlocks write access
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header Host              $host;
```

Because `X-Forwarded-Proto` is set, the app only needs:

```yaml
environment:
  - TRUST_PROXY_HEADERS=true
  - COOKIE_SECURE=true
```

Note that NPM uses `$proxy_add_x_forwarded_for`, which appends the real peer to
whatever the client sent — so the leftmost entry is attacker-controlled.
pcap-server reads the **rightmost** entry for its login rate limiter precisely
because proxies do this, so NPM's default is safe as-is.

NPM also handles Let's Encrypt itself, including DNS challenges for hosts with
no inbound port 80. There is nothing to configure in pcap-server for
certificates.

## 3. What you must add — Advanced tab

Open the proxy host → **Advanced** → **Custom Nginx Configuration**, and paste:

```nginx
# Required. A capture download is decrypted on the fly. With buffering on,
# nginx spools large responses to proxy_temp_path, writing an unencrypted copy
# of the pcap onto the proxy's disk -- which undoes encrypting captures at rest.
proxy_buffering off;
proxy_request_buffering off;

# A large capture takes longer than the 60s default to stream.
proxy_read_timeout 600s;
proxy_send_timeout 600s;

# No ceiling on a capture download.
client_max_body_size 0;
```

`proxy_buffering off` is the important line. Without it every capture you
download leaves a plaintext copy in NPM's container filesystem.

Do not add `add_header` lines for CSP, HSTS or X-Frame-Options: pcap-server
sends its own, and nginx's `add_header` appends a second header rather than
replacing the first.

## Checking it worked

Sign in over the proxy. If the red **"Read-only: this connection is not
encrypted"** banner is gone and the capture list shows **Download** rather than
**Download (HTTPS only)**, the proxy headers are getting through.
