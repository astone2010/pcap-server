# pcap-server

Remote packet capture and analysis tool with a Wireshark-style web interface.
Connect to remote servers via SSH, run tcpdump captures, and analyze packets
in your browser.

## Features

- **Remote capture** — run tcpdump on remote servers over SSH
- **Packet analysis** — Wireshark-style packet list and protocol detail views
- **Multi-user** — scrypt password hashing, TOTP two-factor auth, trusted devices
- **Admin panel** — manage users, configure settings, scan SSH host keys
- **SSH host key verification** — Trust On First Use (TOFU) with known hosts database
- **Saved servers** — store connection profiles per user
- **Configurable** — capture limits, session duration, rate limiting all adjustable from the GUI
- **Process safety** — remote tcpdump processes are always cleaned up on shutdown

## Quick Start

```bash
git clone https://github.com/darthrater78/pcap-server.git
cd pcap-server
docker compose up -d
```

Open `http://localhost:8080`. The first user to register becomes the admin.

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SSH_KEYS_DIR` | `/app/ssh-keys` | Directory for SSH private keys |
| `CAPTURES_DIR` | `/app/captures` | Directory for downloaded pcap files |
| `DATA_DIR` | `/app/data` | Directory for the SQLite database |

### Admin Settings (GUI)

These are configurable from the Admin tab by the admin user:

| Setting | Default | Description |
|---|---|---|
| Max capture seconds | 300 | Maximum duration for a single capture |
| Max capture packets | 100000 | Maximum packets per capture |
| Session duration (hours) | 8 | Login session lifetime |
| Device trust (days) | 30 | How long a trusted device skips MFA |
| Rate limit attempts | 5 | Failed login attempts before lockout |
| Rate limit lockout (minutes) | 15 | Lockout duration after too many failures |

## SSH Keys

Place private key files in the `ssh-keys/` directory (mounted at `/app/ssh-keys`).
The server reads key filenames from this directory and presents them as options
when connecting to a remote server.

## Architecture

- **Backend** — Python/FastAPI with asyncssh for SSH connections
- **Frontend** — vanilla HTML/CSS/JS, no build step
- **Database** — SQLite with WAL mode
- **Container** — Docker with python:3.12-slim base, runs as non-root user

## Development

```bash
docker compose up --build
```

The Docker Compose file mounts `./data` and `./captures` as bind mounts for
persistent storage across container restarts.

## License

See repository for license details.
