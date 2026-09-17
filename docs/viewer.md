# Reading a capture

*Part of the [pcap-server](../README.md) documentation.*

**View** on a finished capture opens it in the packet viewer: a Wireshark-style
list on top, the decoded protocol tree and hex dump below, and a display-filter
box across the top. Display filters themselves — both languages, and building
one by right-clicking — are in [filters.md](filters.md).

## Captures open as tabs

Each capture you open gets its own tab on the bar at the top, next to Servers,
Capture and Admin. Open two and you can click between them — comparing a
capture taken before a change with one taken after is what the packet list is
usually for, and it should not mean going back to the list each time. Close a
tab with the **×** on it; the capture itself is untouched, and it opens again
from the Capture tab.

There is no standing **Viewer** tab. It led to an empty panel for most of a
session, and a tab that is usually empty is one people learn not to press. The
Viewer exists while something is open in it and not otherwise.

Each tab says which capture it holds. Inside the panel, the line above the
filter box names the **server, the interface and the capture filter** the
packets are coming from — which is the question a packet table cannot answer,
and matters most when a filter narrower than you remember looks exactly like a
quiet network.

## Choosing the columns

The packet list starts on the columns Wireshark opens with — number, time,
source, destination, protocol, length and the Info summary — and none of them
are fixed. **Drag a heading** to move it, or **right-click one** to hide it,
nudge it left or right, or open the **Columns** dialog (also on the toolbar).

Adding a column is the useful half. Any field tshark knows can be one, which is
most of what Wireshark dissects: `tcp.window_size` beside every packet while
chasing a stall, `dns.qry.name` while reading a resolver's traffic,
`http.host`, `ip.ttl`, `vlan.id`. Two ways in:

- **Right-click a field in the packet detail** below the list and choose
  **Apply as Column** — the same gesture as in Wireshark, and the quickest,
  because the field is already in front of you.
- **The Columns dialog**, which lists common fields by name and takes any other
  as typed. A name this server's tshark does not recognise is refused there and
  then, rather than becoming a column that is silently empty on every packet.

Columns can be renamed, and the arrangement is **saved to your account** — not
to the browser — so it is the same list on every capture and on whatever you
sign in from next. **Reset to default columns** in the dialog puts it back.

An added column is fetched on the same pass that draws the list, so it costs no
extra round trip, and right-clicking one filters on the field it came from
rather than on a guess made from the value.

Timestamps can be relative, epoch, delta, the server's UTC, or your own time
zone.

## Which interface a packet crossed

A capture on `any` has an **Interface** column: the interface each packet went
through and which way — `eth0 out`, `docker0 in`, `bcast` for broadcast. The
file itself only numbers interfaces, so pcap-server reads the host's names when
the capture starts and again when it ends. Right-click a cell for **Apply as
filter** on `sll.ifindex`, the same menu every other column offers. An
interface that existed only in the middle of a capture shows as `#3`, and an
older tcpdump that writes the first cooked format records no interface at all,
so the column shows just the direction. Captures on a named interface have no
such column.

**The name does not survive a download.** The mapping lives only in
pcap-server's own database; the `.pcap` file itself — classic pcap, the same
format tcpdump always wrote — has nowhere to carry it. Opened elsewhere, a
downloaded capture still shows the raw interface **index** (`sll.ifindex`,
under *Linux cooked capture v2* in any real Wireshark's own packet detail —
no plugin needed), just not the name that went with it here. If you need a
specific interface's traffic to stay identifiable after download, filter to
it first — right-click the column, **Apply as filter**, then download that —
rather than downloading the whole `any` capture and losing the mapping.

## Field and byte selection

The detail tree and the hex pane are two views of the same frame. Click a field
and its bytes light up in both the hex and ASCII columns; click a byte and the
innermost field covering it is selected, with every parent opened so the row is
on screen. This works because the dissection comes from tshark's PDML output,
which reports each field's byte offset and length — the JSON output does not.

**Export bytes**, in the detail toolbar once a packet is selected, saves that
packet's raw bytes as a `.bin` file — built client-side from the same hex the
detail pane already holds, so it costs no extra request.

## Follow a stream

Right-click a TCP or UDP packet — its row in the list, or anywhere in its
detail pane — for **Follow TCP Stream** / **Follow UDP Stream**: the whole
conversation, reassembled in the order it was sent, one colour per direction.
**Set as display filter** narrows the packet list to the same stream
(`tcp.stream eq N` / `udp.stream eq N`).

## Protocol Hierarchy and Conversations

Two toolbar buttons give the shape of a capture without reading it packet by
packet. **Protocol Hierarchy** breaks it down by layer — `eth` → `ip` → `tcp`
→ `http`, each with a frame count, a byte count and a share of the whole —
nested the way the protocols themselves nest. **Conversations** lists every
address pair's traffic, split by direction, and every address's own total;
either table's rows offer a one-click filter onto them. Both read the current
display filter's slice of the capture when one is set, and the whole thing
otherwise.

## Saved views

A display filter you will want again is worth keeping. **Save view** turns
whatever is in the filter box into a named tab on that capture — "auth
traffic", "the retransmissions", "everything to the DC" — and the tabs are
still there the next time you open it, on any machine you sign in from.

| | |
| --- | --- |
| Switching | click a tab; its filter goes into the box and the list redraws |
| **All packets** | always first, always present. It is the unfiltered capture, not a saved row, so it cannot be renamed or deleted |
| Editing | the selected tab offers rename, and will take the filter currently in the box if you have refined it |
| Downloading | **↓** on the selected tab downloads *that view* as its own pcap, containing only the packets its filter selects |
| Leaving a view | typing over the filter deselects the tab, rather than leaving it claiming to show something it no longer does |

Views are stored server-side against your account and that capture, not in the
browser, and they go when the capture does. Two things follow from that: they
survive a different browser, and another user's views are not yours to see.

**A filtered download is still packet data**, and frequently the most sensitive
slice of a capture rather than a less sensitive one — so it is refused over
plain HTTP for the same reason the full download is.

## Related

- [sanitizing.md](sanitizing.md) — downloading a capture, or one saved view,
  with credentials and identifiers replaced.
- [architecture.md](architecture.md#statistics-protocol-hierarchy-conversations-follow-stream)
  — how the statistics views are computed.
