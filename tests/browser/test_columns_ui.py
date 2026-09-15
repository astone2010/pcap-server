"""Arranging the packet list's columns, in the browser.

The server side -- what a layout may contain, which field names are real -- is
proven in tests/test_column_layout.py and tests/test_packet_parser.py. What
these tests are about is the half that only exists here: the headings are drawn
from the layout, they can be moved and hidden, a field can be turned into a
column from the packet detail's own right-click menu, and a column that was
added is fetched and filtered against the field it came from.

window.api is overridden for the layout route (as it is in the stats-dialog
suite) so nothing here depends on a stored layout or a real capture.
"""

from __future__ import annotations

from tests.browser.conftest import needs_browser

pytestmark = needs_browser

CAPTURE = {
    "id": "cap-any", "name": "", "server_id": "s1", "server_label": "edge",
    "interface": "any", "user_id": "u1", "status": "completed",
    "command": "", "packet_count": 1, "file_size": 1, "error": "",
}

PACKET = {
    "number": 1, "timestamp": "0.0", "source": "10.0.0.1", "destination": "10.0.0.2",
    "protocol": "UDP", "length": 42, "info": "Standard query", "src_mac": "", "dst_mac": "",
    "interface": "eth0", "ifindex": 2, "direction": "out",
    "tcp_stream": None, "udp_stream": None,
    "values": {"udp.dstport": "53"},
}


async def _capture_saves(page):
    """Answer the layout route from memory and record what was PUT, so a test
    can assert on the layout that was saved as well as the one drawn."""
    await page.evaluate(
        """() => {
            const real = window.api;
            window.saved = [];
            window.storedLayout = null;
            window.api = async (path, opts) => {
                if (path.startsWith("/api/column-layout")) {
                    if (!opts || !opts.method || opts.method === "GET") {
                        return {columns: window.storedLayout, default: !window.storedLayout};
                    }
                    if (opts.method === "DELETE") {
                        window.storedLayout = null;
                        window.saved.push(null);
                        return {columns: null, default: true};
                    }
                    const body = JSON.parse(opts.body);
                    window.storedLayout = body.columns;
                    window.saved.push(body.columns.map((c) => c.id));
                    return {columns: body.columns, default: false};
                }
                return real(path, opts);
            };
        }"""
    )


async def _draw(page, packet=None, capture=None):
    """The table as loadPackets would leave it, without the fetch: the row
    renderer and the heading renderer are the two halves under test."""
    return await page.evaluate(
        """([capture, packet]) => {
            captures = [capture];
            viewingCaptureId = capture.id;
            currentPackets = [packet];
            const cols = packetColumns();
            document.getElementById("packet-tbody").innerHTML = packetRowHtml(packet, cols);
            activatePanel("viewer");
            hide("viewer-empty");
            show("packet-viewer");
            return {
                headings: [...document.querySelectorAll("#packet-head-row th")]
                    .filter((th) => !th.hidden).map((th) => th.textContent),
                cells: [...document.querySelectorAll("#packet-tbody td")]
                    .filter((td) => !td.hidden).map((td) => td.textContent.trim()),
                span: cols.span,
                fields: cols.fields,
            };
        }""",
        [capture or CAPTURE, packet or PACKET],
    )


async def test_the_default_layout_is_the_table_this_viewer_always_had(app_page):
    await _capture_saves(app_page)
    got = await _draw(app_page)
    assert got["headings"] == [
        "No.", "Time", "Source", "Destination", "Interface", "Protocol", "Length", "Info",
    ]
    assert got["span"] == len(got["headings"])
    # Nothing added, so the packet list asks for no extra fields.
    assert got["fields"] == []


async def test_a_heading_and_its_cells_stay_in_step_when_a_column_moves(app_page):
    await _capture_saves(app_page)
    await _draw(app_page)
    await app_page.evaluate("() => moveColumn('protocol', -1)")
    await app_page.wait_for_function(
        "() => document.querySelectorAll('#packet-head-row th')[4].textContent === 'Protocol'"
    )
    headings = await app_page.eval_on_selector_all(
        "#packet-head-row th", "els => els.map(e => e.textContent)"
    )
    cells = await app_page.eval_on_selector_all(
        "#packet-tbody td", "els => els.map(e => e.dataset.col)"
    )
    assert headings.index("Protocol") == cells.index("protocol")
    assert await app_page.evaluate("() => window.saved.at(-1).indexOf('protocol')") == 4


async def test_hiding_a_column_from_the_heading_menu_removes_it(app_page):
    await _capture_saves(app_page)
    await _draw(app_page)
    await app_page.click("#packet-head-row th[data-col=length]", button="right")
    await app_page.wait_for_selector("#filter-menu")
    labels = await app_page.eval_on_selector_all(
        "#filter-menu .filter-menu-item", "els => els.map(e => e.textContent)"
    )
    assert any(label.startswith("Hide Length") for label in labels)
    await app_page.click("#filter-menu .filter-menu-item:has-text('Hide Length')")
    await app_page.wait_for_function(
        "() => !document.querySelector('#packet-head-row th[data-col=length]')"
    )
    saved = await app_page.evaluate("() => window.saved.at(-1)")
    assert "length" not in saved


async def test_apply_as_column_turns_a_detail_field_into_a_column(app_page):
    """Wireshark's own route to a new column, and the reason the menu item
    exists at all: the field is right there in front of you."""
    await _capture_saves(app_page)
    await _draw(app_page)
    await app_page.evaluate(
        """() => {
            const tree = document.getElementById("packet-detail-tree");
            tree.innerHTML = "";
            const leaf = document.createElement("div");
            leaf.className = "tree-leaf";
            leaf.textContent = "Destination Port: 53";
            leaf.dataset.field = "udp.dstport";
            leaf.dataset.value = "53";
            tree.appendChild(leaf);
        }"""
    )
    await app_page.click("#packet-detail-tree .tree-leaf", button="right")
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('Apply as Column')")
    await app_page.wait_for_function(
        "() => !!document.querySelector('#packet-head-row th[data-col=\\'field:udp.dstport\\']')"
    )
    # Titled from the field's own name, not from the value it happened to have.
    title = await app_page.inner_text("#packet-head-row th[data-col='field:udp.dstport']")
    assert title == "Destination Port"
    saved = await app_page.evaluate("() => window.saved.at(-1)")
    assert "field:udp.dstport" in saved
    # Placed before Info rather than past it: Info is the widest column in the
    # table, and anything appended after it starts life off the right edge.
    assert saved.index("field:udp.dstport") == saved.index("info") - 1


async def test_an_added_column_is_fetched_and_rendered_from_its_field(app_page):
    await _capture_saves(app_page)
    await app_page.evaluate(
        """() => {
            columnLayout = [
                {id: "number", title: "No.", field: ""},
                {id: "field:udp.dstport", title: "Dst port", field: "udp.dstport"},
                {id: "info", title: "Info", field: ""},
            ];
            columnLayoutIsDefault = false;
        }"""
    )
    got = await _draw(app_page)
    assert got["headings"] == ["No.", "Dst port", "Info"]
    assert got["cells"] == ["1", "53", "Standard query"]
    # What the packet list must ask the server for, beyond the built-in fields.
    assert got["fields"] == ["udp.dstport"]


async def test_right_clicking_an_added_column_filters_on_that_field(app_page):
    """Not on a field guessed from the value's shape: the cell knows which
    field it was drawn from, so `53` filters as a UDP port and not as
    something that merely looks like a number."""
    await _capture_saves(app_page)
    await app_page.evaluate(
        """() => {
            columnLayout = [
                {id: "number", title: "No.", field: ""},
                {id: "field:udp.dstport", title: "Dst port", field: "udp.dstport"},
            ];
            columnLayoutIsDefault = false;
        }"""
    )
    await _draw(app_page)
    await app_page.click("#packet-tbody td[data-col='field:udp.dstport']", button="right")
    await app_page.wait_for_selector("#filter-menu")
    labels = await app_page.eval_on_selector_all(
        "#filter-menu .filter-menu-item", "els => els.map(e => e.textContent)"
    )
    assert any("udp.dstport == 53" in label for label in labels)


async def test_the_dialog_adds_a_preset_column_and_reset_puts_it_back(app_page):
    await _capture_saves(app_page)
    await _draw(app_page)
    await app_page.click("#btn-columns")
    await app_page.wait_for_selector("#column-dialog[open]")
    rows = await app_page.eval_on_selector_all(
        "#column-rows tr", "els => els.map(e => e.dataset.col)"
    )
    assert rows[0] == "number" and "info" in rows

    await app_page.fill("#column-add-field", "ip.ttl")
    await app_page.click("#btn-column-add")
    await app_page.wait_for_function(
        "() => !!document.querySelector('#packet-head-row th[data-col=\\'field:ip.ttl\\']')"
    )
    assert "field:ip.ttl" in await app_page.evaluate("() => window.saved.at(-1)")

    await app_page.click("#btn-column-reset")
    await app_page.wait_for_function(
        "() => !document.querySelector('#packet-head-row th[data-col=\\'field:ip.ttl\\']')"
    )
    # A reset deletes the layout rather than storing a copy of the default.
    assert await app_page.evaluate("() => window.saved.at(-1)") is None


async def test_a_layout_the_server_refuses_is_rolled_back(app_page):
    """The table is redrawn before the save lands, so that moving a column
    feels like moving it. That is only honest if a refusal puts it back."""
    await _capture_saves(app_page)
    await _draw(app_page)
    await app_page.evaluate(
        """() => {
            const real = window.api;
            window.api = async (path, opts) => {
                if (path.startsWith("/api/column-layout") && opts && opts.method === "PUT") {
                    throw new Error("tshark does not know nope.nope");
                }
                return real(path, opts);
            };
        }"""
    )
    await app_page.evaluate("() => removeColumn('length')")
    await app_page.wait_for_function(
        "() => !!document.querySelector('#packet-head-row th[data-col=length]')"
    )
    headings = await app_page.eval_on_selector_all(
        "#packet-head-row th", "els => els.map(e => e.textContent)"
    )
    assert "Length" in headings


async def test_the_interface_column_stays_hidden_off_an_any_capture(app_page):
    """Unchanged by layouts: the field it reads only exists in a Linux cooked
    header, so on a capture of one named interface the column has nothing to
    show and is drawn hidden rather than left blank on every row."""
    await _capture_saves(app_page)
    named = {**CAPTURE, "id": "cap-eth0", "interface": "eth0"}
    got = await _draw(app_page, capture=named)
    assert "Interface" not in got["headings"]
    assert got["span"] == 7
    hidden = await app_page.eval_on_selector_all(
        "#packet-head-row th[data-col=interface]", "els => els.map(e => e.hidden)"
    )
    assert hidden == [True], "the column should still be present, just hidden"
