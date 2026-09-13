# Filters

*Part of the [pcap-server](../README.md) documentation.*

There are two filter languages in this app and they are not interchangeable.
This page is both of them in full: which is which, how to build one without
typing it, and the ways a capture filter can silently record nothing.

## The two filters

The one thing worth getting straight before you use either.

| | Where | When it runs | Syntax | Example |
| --- | --- | --- | --- | --- |
| **Capture filter** | Capture tab | tcpdump, on the remote host, as packets go past | BPF | `tcp port 443` |
| **Display filter** | Viewer | tshark, when the list is drawn | Wireshark display syntax | `tcp.port == 443` |

The capture filter decides **what is recorded**, and anything it excludes is
gone for good. The display filter decides **what you see** out of what was
already recorded, so it costs nothing to change your mind.

Display filters name a protocol field with a dot and compare it with an
operator — `ip.addr == 10.0.0.1`, `frame.len > 1000`,
`http.request.method == "GET"` — or use a bare protocol name on its own, like
`dns`. Combine with `and`, `or`, `not`, or with `&&`, `||`, `!`.

The display filter offers clickable examples, and **Save filter** beside it keeps
one of your own, listed at the top of **Filter help** for any capture. **Browse the capture filter library** sits
under the BPF field on the Capture tab — a searchable list grouped by protocol,
which fills the field above it when you choose one. The Viewer has a full
display-filter cheatsheet behind **Filter help**.

The library stays open while you choose, and shows the expression as it is
being built, so several filters can be picked in a row without reopening the
list or looking away from it. **Clear** on that bar starts over.

Choosing a second capture filter while the field already holds one asks how to
combine them — **…and this**, **…or this**, or replace — rather than guessing.
Neither guess is safe: two protocol rows almost always mean `or`, since
`tcp port 80 and tcp port 443` matches nothing, while a host row plus a
protocol row means `and`. Both sides are parenthesised, because `a and b or c`
parses as `(a and b) or c` and would quietly rebind a filter you already had.
A capture filter that matches nothing does not announce itself — the capture
simply runs and comes back empty — so it is never composed for you silently.

A display filter tshark cannot parse is reported back with tshark's own message
and the position it objected to. An empty packet list therefore always means the
filter was valid and nothing matched it.

## Building a display filter by clicking

Most display filters do not need to be typed. **Right-click** anything in the
viewer and the Wireshark menu appears:

- **In the detail tree** — any field, at any depth, including a single TCP flag
  bit. Right-clicking `.... .... ..1. = Syn: Set` gives `tcp.flags.syn == 1`.
- **In the packet list** — the menu builds from the column under the cursor: an
  address, a protocol, a length, a frame number. It also offers a
  **Conversation filter**, which is both endpoints of that exchange and nothing
  else.

Each menu offers the same four combinators as Wireshark — apply the expression
on its own, negate it, or join it to whatever is already in the box with `&&`
or `||` — plus **Prepare as filter**, which fills the box without running it.

Addresses go into the filter bare and text values are quoted, because Wireshark
treats `192.168.1.50` as an address literal and rejects it in quotes. A value
containing a character the display filter does not accept falls back to testing
that the field is simply present.

## Filters that capture nothing

Combining two library picks with **…and this** is the easy way to build a
filter that matches nothing. A packet carries one source port and one
destination port, so requiring two services is one condition more than there
are slots for it, and requiring three is hopeless. The filter compiles,
tcpdump runs for the full duration, and the capture comes back empty — which
looks exactly like there having been no such traffic.

pcap-server checks for this in two places. In the filter library the
**…and this** option carries a warning the moment you open the menu, saying
what is wrong and that `or` is probably what you want. And a capture whose
filter cannot match anything asks for confirmation before it starts.

Both are warnings, not refusals. An odd-looking filter you mean is still yours
to run — press on and the capture starts.

One case is worth knowing about because nothing else will ever flag it:
`tcp port 80 and tcp port 443` is a perfectly valid filter. It matches a packet
travelling from port 80 to port 443, so tcpdump accepts it without complaint.
Traffic like that essentially does not exist, which is why pcap-server says so
even though the compiler will not.

Shell metacharacters are rejected in the filter, which is passed to tcpdump as a
single quoted argument after `--`. `-z`, `-W`, `-G`, `-C`, `-r`, `-F`, `-V` and
`-Z` are permanently refused: tcpdump may be running under `sudo`, and those turn
a capture into code execution or file reads as root.

## Where are the tcpdump flags?

A capture always runs as `tcpdump -w <file>`, so that a pcap comes back for
analysis. `-w` turns tcpdump from a printer into a writer: it stops formatting
text and writes raw packet records. tcpdump's display flags — `-vv`, `-vvv`,
`-q`, `-A`, `-X`, `-XX`, `-e`, `-n`, `-nn`, `-t`/`-tt`/`-ttt`/`-tttt` — format
text that is never emitted under `-w`, so they cannot affect the capture and are
not accepted. The ones that describe how to *read* a capture live in the Viewer
instead, where they change the packet list.

`-v` is the exception, and pcap-server adds it to every capture itself, which is
why it appears in the command shown against each one. It still changes nothing
in the file. Under `-w` it makes tcpdump report its running packet total on
stderr once a second, which is what the live count on a running capture reads —
the pcap is on the remote host until the capture ends, so there is nothing else
to count.

## Related

- [Streaming a capture live](live-streaming.md) — a live stream needs an
  interface or a filter, and this is why.
- [architecture.md](architecture.md#input-validation) — every validator the
  filter passes through, and the reason each one exists.
