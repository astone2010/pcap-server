# Sanitizing a capture

*Part of the [pcap-server](../README.md) documentation.*

**Sanitize** — on a finished capture's card, and in the Viewer's toolbar —
downloads `<name>-sanitized.pcap`: the same packets, the same sizes, with what
identifies people and places replaced. In the Viewer with a saved view open, it
sanitizes just that view's packets. It is built as it downloads, so no
sanitized copy is stored. Like every other download, it needs HTTPS.

## The options

| Option | Ticked to start | What happens |
| --- | --- | --- |
| **Credentials** | yes | Masked with `*`: HTTP `Authorization` (the scheme word is kept), cookie values (names kept), FTP/POP passwords, IMAP and SMTP logins, SNMP communities, RADIUS passwords, NTLM and Kerberos responses, LDAP simple binds, MySQL, PostgreSQL and SQL Server passwords, VNC responses |
| **IP addresses** | yes | Replaced prefix-preserving ([Crypto-PAn](https://en.wikipedia.org/wiki/Crypto-PAn)): hosts that shared a subnet still share one. Headers, tunnels, ICMP errors, ARP, neighbour discovery, and addresses inside DNS, DHCP and routing protocols. Reverse lookups (`…in-addr.arpa`) go with them |
| ↳ Keep private ranges | no | 10/8, 172.16/12, 192.168/16, 100.64/10, link-local and fc00::/7 are left as they are |
| **MAC addresses** | yes | Replaced with locally administered addresses |
| ↳ Keep vendor prefix | no | Only the last three bytes are replaced |
| **Hostnames** | no | DNS names, TLS server name, HTTP `Host`, DHCP and NetBIOS names — label by label, with the last label (`.com`, `.local`) kept, so one host gets one stand-in wherever it appears |
| **Usernames** | no | Same-length stand-ins, in FTP, POP, IMAP, SMTP, NTLM, Kerberos, LDAP, RADIUS, SMB and database logins |
| **Strip payload** | no | Everything after the TCP or UDP header is cut off, as if captured with a short snap length |

Loopback, multicast, broadcast and group MAC addresses are never replaced: they
are the same on every network. Checksums are updated to match, so a sanitized
capture opens without a wall of checksum errors — and one that was already wrong
in the original, as outgoing packets captured before checksum offload are,
stays exactly as wrong.

## The same capture always gets the same stand-ins

Sanitize it today and again next month and the two files line up, address for
address. The mapping is derived from that capture's own encryption key, so it
changes for nothing — not even for a master-key rotation — and nothing about it
is stored. A different capture maps differently. (A capture stored before
encryption was switched on uses a random key created once in
`data/sanitize.key` instead.)

## Read the summary before sharing

When the download finishes, the dialog lists what was replaced, and two things
it could not vouch for:

- **Found but not replaced in place** — fields read from decoded, decompressed
  or reassembled data, which has no fixed position in a packet. NTLM inside an
  HTTP header is base64, for example; there the whole header is masked anyway,
  but not every carrier is.
- **Payload no dissector understood**, by port — traffic Wireshark could not
  read, and so could not search. A password on a custom port is invisible to
  every rule above.

## What it cannot promise

Sanitizing is best effort by nature: it replaces what Wireshark can find, in the
places listed above, and a credential in a JSON body or a hostname in a URL is
not one of them. Replaced addresses keep their structure on purpose, and that
cuts both ways: someone who already knows the real address of a host or two in
the capture learns how their prefixes map, and with it part of every address
that shares them. Stand-in names keep their length. For anything leaving your
hands, **Strip payload** is the option that does not depend on recognising what
is in a packet.

## Related

- [architecture.md](architecture.md#sanitizing-a-capture) — the pipeline: the
  tshark pass, field rules, and the checksum updates.
