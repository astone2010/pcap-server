# pcap-server behind Nginx Proxy Manager

NPM generates its own nginx config, so most of
[`nginx.conf.example`](nginx.conf.example) does not apply. Three things do.

## 1. Networking — the one that stops it working at all

NPM runs in its own container, so `127.0.0.1` inside the pcap-server container
is **not** reachable from it. Do not bind pcap-server to loopback here; put both
containers on the same Docker network and publish nothing.

```yaml
# pcap-server's compose file
services:
  pcap-server:
    # No ports: at all. NPM reaches it over the shared network, and nothing
    # else can reach it directly -- which is what makes trusting NPM's
    # X-Forwarded-Proto header safe.
    networks:
      - proxy

networks:
  proxy:
    external: true
    name: npm_default        # whatever NPM's network is actually called
```

Find NPM's network with `docker network ls`, then attach NPM to it too if it is
not already. In the NPM proxy host:

| Field | Value |
| --- | --- |
| Scheme | `http` |
| Forward Hostname / IP | `pcap-server` (the container name, not an IP) |
| Forward Port | `8080` |
| Websockets Support | off — pcap-server does not use them |
| Block Common Exploits | on is fine |

**If you keep `ports:` published, do not set `TRUST_PROXY_HEADERS=true`.**
Anything that can reach the app directly could then send
`X-Forwarded-Proto: https` itself and get full write access, bypassing the
read-only-over-HTTP protection entirely.

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
