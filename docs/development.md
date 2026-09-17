# Development

*Part of the [pcap-server](../README.md) documentation.*

```bash
git clone https://github.com/darthrater78/pcap-server.git
cd pcap-server
./scripts/check.sh
```

`scripts/check.sh` is the whole test story. It builds a virtualenv, installs
`backend/requirements-dev.txt` into it, reports which of tshark, tcpdump,
capinfos and a chromium binary it found, and runs pytest with `-r s` so a
skipped test is printed with its reason rather than quietly dropped.
`.github/workflows/check.yml` runs that same script rather than reimplementing
the checks, so CI and a developer's machine cannot pass and fail independently
of each other.

## Python version

**It needs Python 3.11–3.13, and it picks the interpreter itself.** The ceiling
is the newest Python the suite has actually been run on. It was first forced:
until dev.39 the pinned `pydantic-core` shipped no wheel above cp313, pip's
source fallback needed PyO3 ≤ 3.13, and on a newer Python the install died in a
Rust build that never mentions Python versions. The current pin does ship 3.14
wheels, but the ceiling moves only once the whole suite has passed on 3.14.
Distributions have started shipping 3.14 as `python3` (Fedora 44 does), so on
such a machine the script needs a 3.13 or older interpreter installed alongside.

So it searches `python3.12`, `python3.13`, `python3.11`, then `python3`, and
uses the first one in range; 3.12 comes first because that is what the
Dockerfile and CI use. Set `PYTHON=/path/to/python3.12` to override the search,
and it will refuse rather than quietly pick something else. An existing `.venv`
is checked too, not trusted — one built by an out-of-range interpreter is
rebuilt, because otherwise a single bad run poisons every later one with the
same unreadable failure. If nothing suitable is installed it says so in one
line, with the range and what it found:

```
No supported Python found. This project needs 3.11-3.13, the range its test
suite has been run on.
Found: python3 = 3.14.7
Install one (e.g. 'sudo dnf install python3.12'), or set PYTHON=/path/to/python3.12
```

## Missing tools skip, they do not fail

The suites that need tshark, capinfos or a browser report as SKIPPED with the
remedy in the reason. That is deliberate — but a green run with twenty skips is
not the same as a green run, so read the skip list.

| Tool | Needed by | Get it |
| --- | --- | --- |
| `tshark`, `capinfos` | packet list, detail and count suites | your distribution's `tshark`/`wireshark-cli` package |
| chromium | `tests/browser` | `python -m playwright install chromium`, or point `PCAP_TEST_CHROMIUM` at one you already have |
| `tcpdump` | reported for completeness; captures run on the remote host | your distribution's `tcpdump` package |

## Layout

| Path | What is in it |
| --- | --- |
| `backend/main.py` | every route, the middleware, and the app's wiring |
| `backend/models.py` | pydantic models and every input validator |
| `backend/capture.py` | a capture's life from start to a terminal status |
| `backend/ssh_manager.py` | connections, the prerequisite probe, key handling |
| `backend/crypto.py`, `vault.py`, `pcapsource.py`, `rekey.py` | encryption at rest, and reading it back without a plaintext file |
| `backend/resetmfa.py` | host-side second-factor reset, for when nobody can sign in to press the button |
| `backend/packet_parser.py` | everything that shells out to tshark or capinfos, including Protocol Hierarchy, Conversations and Follow Stream |
| `backend/sanitizer.py` | the sanitized-download pipeline: the tshark pass, field rules, pcap record walking |
| `backend/anonymize.py`, `framewalk.py` | keyed stand-ins for addresses and names, and the checksum updates that keep a sanitized frame valid |
| `backend/database.py` | the SQLite schema and every query |
| `backend/serve.py` | the container's entry point: opens the vault, then starts uvicorn, over TLS when a certificate is stored |
| `backend/tls/` | built-in HTTPS, self-contained: DNS provider allowlist, sealed storage, the one place lego runs, renewal, Admin routes and `python -m backend.tls` |
| `frontend/` | `index.html`, `css/style.css`, `js/app.js`, `js/tls.js`. No build step |
| `scripts/` | `check.sh`, the test entry point; `gen_lego_providers.py`, which regenerates the provider allowlist when lego's version moves |
| `docs/` | one document per subject; the README links them all |
| `tests/` | API and unit suites |
| `tests/browser/` | playwright suites driving the real UI |

## Running it against your own changes

`docker-compose.yml` as published has no `build:` section — only `image:`,
pointing at the release tag — so `docker compose up --build` against it as-is
builds nothing; it just starts the same published image everyone else runs.
Give it one locally with a `docker-compose.override.yml` next to it — Compose
picks this up automatically, no `-f` needed:

```yaml
# docker-compose.override.yml
services:
  pcap-server:
    build: .
```

Then create the directories and master key as in step 1 of the setup steps at
the top of `docker-compose.yml`, and run:

```bash
docker compose up --build
```

The data directories are bind-mounted, so state survives a rebuild. Edit
source and re-run the same command to rebuild and restart on top of it.

## A note on style

Comments in this codebase explain *why*, and frequently name the bug that made
the code what it is. That is on purpose: a check with no stated reason is a
check the next person deletes. Keep it up in anything you add.
