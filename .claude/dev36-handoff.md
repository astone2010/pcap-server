# Handoff — four items for 0.1.0-dev.36

Written 2026-09-15, at the close of the 0.1.0-dev.35 session (shipped:
tag `v0.1.0-dev.35` -> `2916f09`, ghcr digest `sha256:fd6f2021…`).

Read `.claude/dev-skills-gates.md` first for the gate state and what dev.35
actually changed. Nothing here is started; all four are scoped, not built.

**Items 3 and 4 are the same knot and should be looked at together** — both are
about host-key trust: when it can first be established (3) and how long it
outlives the server that needed it (4). Items 1 and 2 are independent and can
be done in any order, or split into their own release.

Resume with: **"run the dev36 handoff"**.

## Where to start

1. **Run the orphan query in item 4** — it takes a minute and it tells you
   whether the inherited-trust path is real in this install. It is also the
   evidence behind item 3's report.
2. **Put the three open questions to the user before writing code.** All three
   are decisions, not details, and none can be inferred from the codebase:
   - what happens to freshly-scanned host keys when an add does not complete
     (abandoned / host down / refused as a self-target) — item 3
   - whether the accept-the-fingerprints step makes adding a server admin-only,
     defers to an admin, or becomes a non-admin capability — item 3
   - whether deleting the last server for a host forgets its keys, or only
     flags them as orphaned — item 4
3. **Then build items 3 and 4 together.** They are one knot; see the note under
   item 3's decided flow for why the new add flow manufactures item 4's
   orphans by design.

Items 1 and 2 are independent and can go in any order, or in their own release.

---

## 1. `entrypoint.sh` fails silently when the data dirs are unset

**Status:** pre-existing, found during dev.34's smoke run, still present at
`2916f09`. Not caused by dev.35.

`entrypoint.sh` chowns the three data directories to `appuser` so a bind mount
from the host is writable:

```sh
for dir in "$SSH_KEYS_DIR" "$CAPTURES_DIR" "$DATA_DIR"; do
    if [ -n "$dir" ] && [ -d "$dir" ]; then
        chown -R appuser:appuser "$dir" 2>/dev/null || true
    fi
done
```

Two failure modes, both silent:

- **Unset variables.** The loop is keyed off `$DATA_DIR` / `$CAPTURES_DIR` /
  `$SSH_KEYS_DIR`, which `docker-compose.yml` always sets — so the app has only
  ever been run where they exist. A hand-rolled `docker run` that omits them
  does nothing at all here, and the app then dies with `unable to open database
  file` with nothing pointing at ownership. This cost a wasted smoke run in
  dev.34 and was designed around in dev.35's smoke script rather than fixed.
- **`|| true` swallows a real failure.** A chown that genuinely fails (read-only
  mount, unusual ownership) is indistinguishable from success.

**Suggested shape** — decide with the user, do not assume:

- Default the three paths to the Dockerfile's own values rather than treating
  unset as "nothing to do", so a bare `docker run` behaves like compose.
- Keep `|| true` (a chown failing is not always fatal — a named volume is
  already correct) but **log** what was attempted and what failed, so the
  eventual "unable to open database file" has a breadcrumb in front of it.
- Consider a startup check that reads/writes a probe file in `$DATA_DIR` as
  `appuser` and fails loudly with the actual cause.

**Testing:** there is no test covering `entrypoint.sh` at all today. Anything
here should come with one — the container smoke path in dev.35's
`scratchpad/smoke35.sh` is a reasonable starting point for the shape.

---

## 2. `release.yml` publishes to ghcr regardless of whether Check passed

**Status:** raised with the user in dev.34, explicitly not asked to be fixed
then, still true at `2916f09`. Raised again at the close of dev.35.

`release.yml` triggers on `on: push: tags: ['v*']`, builds the image, pushes it
to ghcr as both `:<version>` and `:dev`, and creates the GitHub release. It
runs **no tests** and is **not gated on `check.yml`**. Nothing stops a tag on a
commit whose Check went red from publishing to `:dev`.

In practice every release so far has been tagged on a commit that Check passed
on the branch push — but that is a habit of whoever runs the tag block, not a
property of the pipeline.

**Options to put to the user:**

| Approach | Trade-off |
|---|---|
| Run the suite inside `release.yml` before the build step | Simplest to reason about; adds ~8 minutes to every release (Check took 8m13s on dev.35) |
| Gate on the existing Check run for that commit (query the API, fail if not success) | Fast, no duplicate work; needs a token with `actions: read` and has to handle "Check never ran for this SHA" |
| `workflow_run` trigger chained off Check | The idiomatic GitHub answer, but it does not fire on tag pushes the way this repo releases, so it likely does not fit without reworking the release trigger |

Note the interaction with dev.35's own CI fix: `check.yml` deliberately does
**not** run on tag pushes (`branches: ['**']`, added in dev.34 by `6121629`),
so the second option is querying a run from the *branch* push, keyed on the
commit SHA the tag points at. That is the right key — the tag and the branch
head are the same commit in this repo's flow — but it must be checked rather
than assumed, and it needs a clear failure when someone tags a commit that was
never pushed to a branch.

---

## 3. THE DISCUSSION: stopping a same-host server at add time

**This is the one with a real design decision in it.** Everything below was
observed by the user against the shipped dev.35 image, not theorised.

### What the user saw

> "I was able to add the server, but the test pre-reqs would not work until I
> saved the server and manually trusted them. I think this was part of the same
> server detection behavior, as I was able to add a new server without having to
> trust after adding. The actual capture prevention worked as designed, though
> we should really stop them at the server add"

### Why it happened — confirmed in the code, not guessed

1. **`POST /api/servers` runs address checks only.** `_reject_self_target` calls
   `describe_if_local`, which covers loopback, the container's own addresses,
   the default gateway and Docker's host aliases. The host's own **LAN address**
   is invisible to all of those — that is the documented limit of the address
   layer (`tests/test_localnet.py::test_the_case_address_checks_cannot_catch`).
   So the row is created.
2. **The kernel check needs a connection**, and `_connect`
   (`backend/ssh_manager.py:317`) **fails closed** when the host has no trusted
   keys: `"<host>:<port> has no trusted host keys, so its identity cannot be
   verified"`. The pre-add probe routes (`/api/probe/test`,
   `/api/probe/prereq-check`) go through `_connect`, so for any host not already
   trusted they return 502 — and dev.35's boot-id check, which sits *after* the
   connection succeeds, never runs.
3. **Trust is only offered after the row exists.** The `trust-server-host`
   button lives on the server list item (`app.js`, `renderServerList`), and
   `scan_host_keys` deliberately does not go through `_connect` — so trusting is
   reachable, but only once there is a server to trust it for.

So the strong check is unreachable at add time **by construction**: it needs a
connection, a connection needs trusted host keys, and trust comes after the
add. The user's other server did not need trusting because its keys were
already stored from earlier work.

This also means the add form offers **Test connection** and **Check
prerequisites** buttons that cannot succeed for any host not already trusted —
a UX wart independent of self-capture, and probably the thing to fix first,
since it is the same ordering problem.

### What dev.35 does and does not claim

It does not claim to stop this at add. `docs/architecture.md`'s table says the
add/edit path runs "address, then kernel **once the probe connects**" — and for
an untrusted host the probe does not connect. The capture prevention the user
confirmed working is the layer below: the stored finding, the address re-check,
and `run_tcpdump`'s check on the capture's own connection.

### DECIDED by the user (2026-09-15) — the flow to build

> "at server add, the user should be presented the proposed key BEFORE having to
> add the server. that way pre-req can be done correctly"

So the add flow becomes:

```
enter details -> scan the host's keys -> SHOW THE FINGERPRINTS, user accepts
              -> probe (this is where the kernel check finally runs)
              -> create the server, only if the probe did not refuse it
```

This resolves the ordering knot: `scan_host_keys` uses `ssh-keyscan` and
deliberately does **not** go through `_connect`, so it works with no prior
trust. Once the user accepts the fingerprints, the probe can connect, the
boot-id check runs, and a self-target is refused **before any row is created** —
which is what the user asked for. It also removes the wart that caused the
report: the add form's **Test connection** and **Check prerequisites** buttons
stop being things that cannot possibly work yet.

**The trap, and why item 4 is now a prerequisite rather than a companion.**
Accepting keys before the server exists means trust is stored for a server that
may never be created — the user abandons the form, the probe fails, or the
probe refuses it as a self-target. Every one of those paths leaves a
`known_hosts` entry with nothing referencing it. **This flow manufactures item
4's orphans by design.** Refusing a self-capture target and leaving its host
keys trusted forever would be a poor trade. So build the two together, and
decide explicitly what happens to freshly-scanned keys when the add does not
complete:

- abandoned form → keys were accepted by a human, but nothing uses them
- probe refuses (self-target) → arguably should be rolled back outright
- probe fails (host down) → the user may well retry in a minute; keeping them is
  reasonable

**Non-admins.** Trusting a host is currently admin-gated (the server list tells
a non-admin to "ask an admin to trust it under Admin → Known Hosts"). The new
flow puts a trust decision inside the add form, which every user can reach.
Decide with the user: does adding a server become admin-only, does the accept
step defer to an admin, or does accepting-for-your-own-server become a
non-admin capability? This is a real authorisation change and must not be made
by accident.

**Unreachable hosts.** Make sure a host that is simply down can still be
added — otherwise a server cannot be pre-staged, which is a capability the
current flow has. Likely shape: allow the add with a clear "not yet verified"
state, and let item 3's option B below cover it.

### Still worth doing alongside

**B. Fail closed on unverified rows.** A row that has never had a successful
kernel check is "unverified", and captures from it are refused with a message
saying to run Check prerequisites first. This is what covers the
added-while-unreachable case above, so the pre-staging capability does not
reopen the hole. On its own it is mostly a better *message* —
`run_tcpdump`'s check already stops the capture — but paired with the new flow
it is the honest state for a server nothing has ever connected to.

**C. Let the operator tell the container what the host is.** An optional
`HOST_ADDRESSES` env var (comma-separated) folded into `_own_addresses()`, and a
documented `extra_hosts: ["host.docker.internal:host-gateway"]` in
`docker-compose.yml`. Turns the LAN-address case into an address-layer hit,
available with no connection and no trust at all — so it catches a self-target
even in the unreachable-host path, before any key is scanned. A few lines, and
the only check that works that early. Note `HOST_ALIASES` already covers
`host.docker.internal`, so the compose half may be most of the value.

---

## 4. Deleting a server leaves its trusted host keys behind

**Raised by the user at the close of dev.35**, while discussing item 3: "if a
server is deleted the keys need to go with it."

**Confirmed in the code, not guessed:**

- `known_hosts` (`backend/database.py:103`) is keyed `UNIQUE(hostname, port,
  key_type)`. It is **global, not per-user**, and carries no reference to any
  server row. `added_by` is provenance only, and it is `ON DELETE SET NULL`.
- `DELETE /api/servers/{server_id}` calls `db.delete_active_server` and nothing
  else. The trust entries survive.

**Consequences:**

- Delete a server, re-add the same host, and it connects with **no trust step**
  — silently inheriting a pinning that nobody re-verified. This is very likely
  what the user hit in item 3 ("I was able to add a new server without having to
  trust after adding"), and it is worth confirming against their actual
  `known_hosts` table before building anything.
- In a multi-user install, a second user adding that hostname gets the same free
  pass. Trust is an admin-owned decision presented as "you were shown the
  fingerprints and accepted them"; inheriting it silently undermines that.
- Orphaned rows accumulate in Admin → Known hosts with nothing saying they are
  orphans.

**What this is *not*:** a MITM hole. If the host is rebuilt and re-keys, the
stored key no longer matches and the connection fails closed. The issue is trust
outliving its subject, and being granted to someone who never vetted it.

**First thing to run — confirm it is live in this install, not theoretical.**
Any host listed here is trusted with nothing referencing it:

```zsh
sudo docker exec <container> python -c "
import sqlite3, os
c = sqlite3.connect(os.path.join(os.environ['DATA_DIR'], 'pcap-server.db'))
hosts = {(r[0], r[1]) for r in c.execute('SELECT hostname, port FROM known_hosts')}
servers = {(r[0], r[1]) for r in c.execute('SELECT hostname, port FROM active_servers')}
print('trusted with no server:', sorted(hosts - servers))"
```

If the user's re-added server shows up there, that confirms the inherited-trust
path in item 3's report and is the evidence to start from. Note the database
file is `pcap-server.db`, not `pcap.db` — getting that wrong in dev.35's smoke
script produced an empty file and a check that silently proved nothing.

**The nuance that stops this being a one-liner:** because the table is global,
deleting keys along with a server would revoke trust for *another user's* server
— or another of your own — pointing at the same `(hostname, port)`. Any fix has
to be reference-counted across **all** users, which the current per-user
`list_active_servers` query does not do.

**Options for the user:**

| Approach | Trade-off |
|---|---|
| **A.** On delete, forget the host keys only if no remaining server row (any user) references that `(hostname, port)` | Matches the user's instinct; needs a new cross-user query, and it silently revokes an admin's decision when the last server happens to be a non-admin's |
| **B.** Leave keys alone, but mark orphans in Admin → Known hosts ("no server uses this") with a purge action | Never revokes anything behind an admin's back; relies on someone visiting the admin screen |
| **C.** Prompt at delete time when it is the last reference: "also forget this host's keys?" | Explicit and auditable, keeps the decision with the person doing the deleting; one more dialog |

**Suggested: A for the single-user case it actually bites, with the refcount
across all users — plus B so pre-existing orphans are visible.** Put the choice
to the user rather than assuming; the multi-user revocation question is
genuinely theirs.

The primitives already exist: `forget_known_host(hostname, port)`
(`database.py:777`) and `delete_known_host(id)` (`:764`).

**Test coverage to add:** deleting a server with a sibling pointing at the same
endpoint must keep the keys; deleting the last one must not leave an orphan
(whichever behaviour is chosen); another user's server must count as a
reference.

---

### Do not re-litigate

- The boot-id mechanism itself is verified and works — a container on this host
  reports the host's boot id byte-for-byte, checked in the real image
  (`scratchpad/smoke35.log`, `VERDICT: MATCH`). The gap is *when* it can run,
  not *whether* it works.
- Failing open on an unreadable boot id is deliberate, documented in
  `backend/localnet.py` and pinned by tests. A BSD target proves nothing; do not
  "fix" this into a refusal.
- No PRs before 1.0 (memory `release-process`). Tag pushes are always the
  user's to run.
