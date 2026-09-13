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

**Never add the machine pcap-server itself runs on.** Capturing from its own
host records pcap-server's own traffic — your session cookie and TOTP code, and
over plain HTTP your password — into a capture this UI then stores and serves
back, and on a Docker host the `any` interface sweeps every other container too.
The obvious cases are refused automatically: hostname aliases, loopback, the
container's own addresses, and the default gateway, which on a Docker bridge is
the host machine. The case that cannot be detected is the host's own LAN
address, because a bridged container has no knowledge of it — which is why the
form warns as well as checks. Capture this host from a different machine.

## Checking a server before you capture

**Servers → Check prerequisites** probes a host for what a capture needs and
reports what it found. Every command it runs is a read; the one privileged call
is `sudo -n true`, which answers "would sudo work" without doing anything. **It
never installs or changes anything** — where something is missing it prints the
command for you to run yourself.

It checks the OS, whether tcpdump is installed and where, whether tcpdump is on
the SSH session's PATH, whether capture privilege exists, whether `/tmp` is
writable, and the SELinux mode.

Two findings are worth knowing about in advance:

- **tcpdump is usually in `/usr/sbin`, which a non-login SSH session often drops
  from PATH for non-root users.** A bare `tcpdump` then fails with "command not
  found" on a host where it is plainly installed. The check records the absolute
  path and captures use it, so this resolves itself once you have run the check.
- **`setcap` beats sudo.** `sudo setcap cap_net_raw,cap_net_admin+eip
  /usr/sbin/tcpdump` lets an unprivileged user capture with no sudo at all, and
  it works the same on every distribution. The check recommends this first.

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

`cap_net_raw`/`cap_net_admin` on the tcpdump binary itself lets that one user
capture without being root or touching sudo at all:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/tcpdump   # use your host's real path
```

Run **Servers → Check prerequisites** in the UI first — it discovers the
actual tcpdump path on that host (it's `/usr/sbin/tcpdump` on some distros,
`/usr/bin/tcpdump` on others) and gives you the exact command to run, along
with whether the capability is already set. This is a one-time step per host
and survives a tcpdump package upgrade being reapplied by the package
manager's postinst on most distros; verify with `getcap $(which tcpdump)`
after a package update if you want to be sure.

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
