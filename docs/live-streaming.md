# Streaming a capture live

*Part of the [pcap-server](../README.md) documentation.*

Normally a capture is written on the remote host and comes back only when it
ends: `tcpdump -w` writes there, and nothing but a running packet count crosses
the wire until the transfer. Tick **Live stream** on the capture form and you
can watch it instead — the Viewer opens on the capture as it records, and rows
appear as packets are taken.

It is the same viewer. The display filter, its autocomplete, the view flags,
name resolution and saved views all work exactly as they do on a stored
capture, because the live view runs the same tshark over the same code path;
there is no second, cut-down filter language for live captures. A filter
narrows what you are watching as it arrives, and can be saved as a view while
the capture is still running.

**A live stream is still an ordinary capture.** Nothing about storage changes.
The authoritative pcap still accumulates on the remote host and is still
fetched and sealed into the vault when the capture ends, so a live-streamed
capture and an ordinary one are the same file by the time either is saved.
Closing the browser does not lose it. This is also why a dropped SSH connection
mid-capture costs nothing: the packets are on the target, not in the browser.

## A live stream has to be pointed at something

**Live streaming needs an interface or a BPF filter — either one will do.**
Ticking **Live stream** with the interface left on `any` and no filter is
refused, and the capture form says so before the Start button does.

The reason is the preview buffer below: it is a fixed number of megabytes held
in the server's memory, and it does not refill. `any` with no filter points it
at every packet on every link the target host has, which on a host doing real
work fills it within seconds — the preview then freezes for the rest of the
capture and there is nothing to do but start again. Narrowing the capture is
the fix, so the narrowing is required up front rather than suggested afterwards.

Which one to reach for depends on the question. `-i eth0` when it is about one
link; a filter such as `host 10.0.0.5` or `tcp port 443` when it is about one
conversation. Both together narrow it further still, and the
[capture filter library](filters.md#building-a-display-filter-by-clicking) on the same screen is
there to build the expression from.

**Capturing without live streaming has no such requirement.** `any` with no
filter remains the default and is the normal thing to run — there is no preview
buffer to fill when nobody is watching, and the pcap comes back complete either
way. Untick **Live stream** and the restriction is gone.

## Stopping and keeping it

**Stop capture**, from the live bar or the capture list, ends it. The capture
then goes through exactly the states it always does — stopping, transferring,
completed — and the Viewer waits and reopens it from the saved file, keeping
whatever display filter you were watching through. From that point it is a
stored capture like any other: downloadable, filterable, saved views and all.
It stays marked **live stream** in the capture list afterwards, because how a
capture was taken is worth knowing later.

## What it costs, and the two limits

A live stream is more expensive than an ordinary capture while it runs, so two
limits apply.

**At most two live streams at once** (Max simultaneous live streams). Each one
holds an SFTP channel open on the target and costs a tshark run over the whole
accumulated buffer on every poll. Starting a third is refused with a message
saying so; an ordinary capture can still start, since that limit is separate.

**The preview stops at 16 MB** (Live stream preview limit). At the cap the live
view freezes and says so plainly — *"the capture is still running and will be
saved in full"* — because the capture does keep going, and its final pcap is
complete. The running packet count continues to climb next to the frozen
preview so it is obvious which of the two stopped. The message also names the
remedy, because by then the only one left is for next time: a narrower filter
or a more specific interface keeps a live view going for longer. Raising the
limit is the wrong lever — it buys seconds and spends the server's memory.

Freezing was chosen over the alternative, dropping the oldest packets to keep a
rolling window. A rolling window renumbers frames underneath the detail pane,
so a packet you just watched scroll past can no longer be opened — and a frame
number that means something different on each poll would quietly break the
saved views taken during the capture.

## Why it is read the way it is

Two things rule out the obvious designs, and both were measured rather than
assumed:

- **The partially written stored file cannot be read.** Captures are sealed as
  they land, and the truncation check refuses an incomplete sealed file
  outright rather than yielding the chunks it holds. That is an anti-tamper
  property worth more than a live view, so nothing here weakens it — the live
  bytes are a pass-through, and no plaintext partial capture is ever written to
  the data volume.
- **tshark objects to a capture cut mid-packet.** Fed a torn record it emits
  every complete packet, warns, and exits non-zero — which is the same signal
  that means "tshark refused your display filter". So pcap-server walks the
  pcap record headers itself and only ever hands tshark whole records; a filter
  is never blamed for the capture being mid-write.

A live capture is also given `-U`, so tcpdump writes each packet as it arrives
rather than a buffer at a time. It changes when bytes reach the file, not which
bytes, so the saved capture is identical either way.
