# Preparing a target host

*Part of the [pcap-server](../README.md) documentation.*

Everything in this section happens on the machine you want to capture
*from*, not on the machine running pcap-server. It is a one-time job per host,
and **Servers → Check prerequisites** prints the exact command for the host in
front of you rather than a generic one.

## Adding a server

The SSH key field starts empty and has to be chosen. Add, Test connection and
Check prerequisites all refuse until a hostname, a username and a key are
present, so a server is never created with a key nobody picked.

**Add asks for the host's fingerprints, then connects, then creates the
server** — in that order, and the order is the point. Nothing can connect to a
host whose identity is not pinned, and the strongest check that this is not the
machine pcap-server runs on needs a connection to make, so the keys have to be
accepted first for that check to have anything to run over. If the check
refuses the host, or you close the dialog, the keys are forgotten again: an add
that does not complete leaves nothing pinned behind it.

You do not need to be an admin for this. If the host already has trusted keys —
because another server points at it — you are not asked, and the keys it has
are kept.

**Check the fingerprints before you accept them.** Each key's SHA256
fingerprint is shown and nothing is pinned until you accept. On the target,
over a console or a session you already trust, run:

```bash
for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $f; done
```

Rather than reading 43 base64 characters off two screens, paste what the host
printed into **Compare a fingerprint** and the matching key lights up — the
`SHA256:` prefix and any stray spacing are ignored. Accepting without comparing
pins whatever answered on that address, which is the one thing host key
verification exists to prevent. An existing server can be trusted later with
the **Trust host** button on it; admins can also work from **Admin → Known
hosts**.

**Adding a server whose host is not up yet still works.** A host that is down
answers no scan, so you are asked whether to add it anyway. Such a server is
created untrusted and unchecked, exactly as every server used to be, and it is
marked **Never checked** in the list. Captures from it are refused until
something has actually connected: trust its keys with **Trust host**, then run
**Check prerequisites**.

**Never add the machine pcap-server itself runs on.** Capturing from its own
host records pcap-server's own traffic — your session cookie and TOTP code, and
over plain HTTP your password — into a capture this UI then stores and serves
back, and on a Docker host the `any` interface sweeps every other container too.
This is refused automatically, and there is no override. Hostname aliases,
loopback, the container's own addresses and the default gateway (on a Docker
bridge, the host machine) are caught before anything connects. The host's own
LAN address gives none of that away from inside a bridged container — so it is
caught a second way instead, as soon as anything connects: a container shares
its host's kernel, and a target reporting the same kernel boot id as
pcap-server is this machine, whatever address was used to reach it. A server
found that way keeps its place in the list, marked, with captures from it
refused; it is not deleted for you. Capture this host from a different machine.

The kernel check needs a connection, so it cannot help while a host is
unreachable or untrusted. If you run pcap-server in a container on a machine
you might plausibly point it at, name that machine's addresses in
`HOST_ADDRESSES` (see [Environment variables](operating.md#environment-variables)):
the refusal then happens before anything connects.

## Checking a server before you capture

**Servers → Check prerequisites** probes a host for what a capture needs and
reports what it found. Every command it runs is a read; the one privileged call
is `sudo -n true`, which answers "would sudo work" without doing anything. **It
never installs or changes anything** — where something is missing it prints the
command for you to run yourself.

It checks the OS, whether tcpdump is installed and where, whether tcpdump is on
the SSH session's PATH, whether capture privilege exists, whether `/tmp` is
writable, and the SELinux mode. The OS it finds is kept on the server and shown
in the server list and its details; run the check again after upgrading a host
to refresh it. Changing a server's hostname or port clears it.

Two findings are worth knowing about in advance:

- **tcpdump is usually in `/usr/sbin`, which a non-login SSH session often drops
  from PATH for non-root users.** A bare `tcpdump` then fails with "command not
  found" on a host where it is plainly installed. The check records the absolute
  path and captures use it, so this resolves itself once you have run the check.
- **`setcap` beats sudo.** A file capability on tcpdump lets an unprivileged
  user capture with no sudo at all, and it works the same on every
  distribution. The check recommends it first, and offers it as an option on a
  server where sudo already works. When tcpdump already has the capability but
  the server is still set to use sudo, it says to untick sudo — and it checks
  sudo first in that case, because a capture then runs `sudo -n tcpdump` and a
  sudo that wants a password fails before the capability can matter.

There are no per-distribution templates, and deliberately so: tcpdump is libpcap
everywhere, so its flags and filter syntax are identical across distributions.
What differs is PATH, whether sudo exists and which group grants it (`wheel` on
RHEL-family, `sudo` on Debian-family), and SELinux — all of which the probe reads
off the host rather than guessing from a distribution label. The detected distro
is used for exactly one thing: printing the right install command.

## Capture privilege: what tcpdump needs

tcpdump needs a privilege to open a capture interface that a plain SSH user
doesn't have by default. There are two ways to grant it — try the first one
before reaching for sudo, since it grants far less.

### Preferred: a file capability, no sudo at all

`cap_net_raw` on the tcpdump binary itself lets it capture
without being root or touching sudo at all. On its own, though, that lets
**every** account on the host capture, since anyone can run tcpdump. Limit the
binary to a group first:

```bash
sudo groupadd -f pcap
sudo usermod -aG pcap pcapuser                 # the SSH user this server logs in as
sudo chgrp pcap /usr/sbin/tcpdump              # use your host's real path
sudo chmod 750 /usr/sbin/tcpdump
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

**The order matters:** changing a file's group clears its capabilities, so
`setcap` goes last. The group takes effect at the account's next login, which
for pcap-server is the next SSH connection. Then untick **Run tcpdump with
sudo** on the server if it was ticked.

Run **Servers → Check prerequisites** in the UI first — it discovers the
actual tcpdump path on that host (it's `/usr/sbin/tcpdump` on some distros,
`/usr/bin/tcpdump` on others) and prints these commands with that path and the
server's username, along with whether the capability is already set. When
tcpdump carries the capability but anyone can run it, the check says so. When
the SSH user is not in the group, the check reports that tcpdump is there but
this user cannot run it, rather than that it is missing.

**`cap_net_admin` is optional, and can stop tcpdump starting.** Many guides set
`cap_net_raw,cap_net_admin=eip`. A capture — on `any` or a named interface, in
promiscuous mode — needs only `cap_net_raw`; `cap_net_admin` is for things
pcap-server never asks tcpdump to do, such as wireless monitor mode. It is
also not always allowed: the kernel refuses to run a binary whose file
capabilities include one outside the host's capability bounding set, which is
the default inside many containers and LXC guests. tcpdump then fails with
"Operation not permitted" before it prints anything. If you want it anyway:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```

and run **Check prerequisites** — it reports a tcpdump the host will not run
with its capabilities, and the command to narrow them.

**Re-check after upgrading tcpdump.** A package upgrade usually replaces the
binary, and the new one has neither the capability nor the group and mode.
`getcap /usr/sbin/tcpdump` prints nothing when the capability is gone.

### If setcap isn't available: passwordless sudo, scoped to tcpdump only

Some hosts don't have `libcap2-bin`/`getcap` installed, or you'd rather use
sudo.

**Why it has to be passwordless.** pcap-server authenticates to your hosts with
SSH keys and nothing else — it never asks you for, stores, or transmits a login
password for a target host, and there is no prompt in a capture for one to be
typed into. Captures run over a non-interactive SSH session, so when `sudo`
asks for a password there is nobody there to answer and no password on hand to
send. That is why the grant has to be `NOPASSWD` — and exactly why it should be
scoped to one binary instead of the whole account. pcap-server invokes
`sudo -n` ("never prompt") to keep this honest: a host that still wants a
password fails immediately with a clear error rather than hanging until the
capture times out.

If you would rather not open a `NOPASSWD` grant at all, use the `setcap` route
above — it needs no sudo and no password, and it grants less.

> **Not set up for key-based SSH yet?** This project's author has written a
> guide to moving off passwords entirely:
> **[Stop Using Passwords for SSH](https://ramblingnonsense.nscriven.net/p/stop-using-passwords-for-ssh)**.
> pcap-server needs that to be true of every host you capture from — there is
> no password path for it to fall back on.

**Scope the grant to tcpdump. Do not make the account blanket-passwordless.**
Searching for "passwordless sudo" turns up this rule almost everywhere, and it
is the wrong one here:

```
# DON'T: every command, as root, no password. Far more than capturing needs.
pcapuser ALL=(ALL) NOPASSWD: ALL
```

That grants unrestricted root for every purpose, permanently, to an account
whose private key is sitting in pcap-server's key store. What captures actually
need is one binary:

```
# DO: this one binary, nothing else.
pcapuser ALL=(root) NOPASSWD: /usr/sbin/tcpdump
```

Both let `sudo -n tcpdump` run unprompted, so pcap-server works either way —
the difference is entirely in what *else* becomes possible if that account is
ever compromised. Take the second one. The full steps:

```bash
# 1. Find the exact tcpdump path first -- use it below, not a bare "tcpdump".
#    A bare command name in a sudoers NOPASSWD rule can be satisfied by
#    anything earlier on $PATH, not just the real binary.
which tcpdump
#   e.g. /usr/sbin/tcpdump

# 2. Write the rule with visudo -f, which validates syntax before saving --
#    a malformed file dropped straight into /etc/sudoers.d/ with cat/tee can
#    break sudo entirely for everyone on the host until it's fixed manually.
sudo visudo -f /etc/sudoers.d/pcap-server
```

In the editor that opens, add one line (replace `pcapuser` with the actual
SSH username this server config uses, and the path with what step 1 printed):

```
pcapuser ALL=(root) NOPASSWD: /usr/sbin/tcpdump
```

Save and exit; `visudo` will refuse to write the file at all if the syntax is
wrong, rather than leaving a broken sudoers.d entry behind. Then lock down the
permissions, since sudoers.d files are ignored if they're group- or
world-writable:

```bash
sudo chmod 0440 /etc/sudoers.d/pcap-server
sudo chown root:root /etc/sudoers.d/pcap-server
```

To do it in one line without an editor — piping through `visudo` rather than
`tee`, so the file is still validated before it replaces anything:

```bash
echo 'pcapuser ALL=(root) NOPASSWD: /usr/sbin/tcpdump' \
  | sudo EDITOR='tee' visudo -f /etc/sudoers.d/pcap-server
```

Then tick **Run tcpdump with sudo** on the server in the UI to actually use it.

**Check prerequisites** prints this exact command for you, with the username and
the discovered tcpdump path already filled in. To grant it to a group instead
of a named account, create the group first — a rule naming a group that doesn't
exist matches nobody and captures keep failing with the same error:

```bash
sudo groupadd -f pcap && sudo usermod -aG pcap pcapuser
echo '%pcap ALL=(root) NOPASSWD: /usr/sbin/tcpdump' \
  | sudo EDITOR='tee' visudo -f /etc/sudoers.d/pcap-server
```

**Understand what this grants, even scoped this way.** `tcpdump` can run
arbitrary commands as root via its `-z` flag and read any file via `-r`, so
anyone who can open a shell as that user on that host effectively has root
there. pcap-server never sends those flags — `-z`, `-Z`, `-W`, `-G`, `-C`,
`-r`, `-F` and `-V` are rejected by a server-side allowlist that refuses to
start if one is ever added to it, and every argument is shell-quoted — but the
sudoers grant itself is still a privilege boundary you are choosing to open.
Use a dedicated, unprivileged account for this and nothing else — don't reuse
a login you use for other purposes on that host.
