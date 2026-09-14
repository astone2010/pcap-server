"""Protocol Hierarchy, Conversations and Follow Stream: the three statistics
dialogs, each fed from its own API route.

The route logic itself -- real tshark, real aggregation -- is proven in
tests/test_packet_parser.py against a real capture; nothing here needs tshark
at all. What these tests are about is the browser side: does the dialog draw
what the route hands back, and does clicking its buttons do the right thing.
window.api is overridden for the paths under test, as window.open is
elsewhere in this suite, and left alone (delegated to the real one) for
everything else the page calls along the way.
"""

from __future__ import annotations

from tests.browser.conftest import needs_browser

pytestmark = needs_browser


async def _stub_api(page, path_fragment: str, response):
    await page.evaluate(
        """([fragment, response]) => {
            const real = window.api;
            window.api = async (path, opts) => {
                if (path.includes(fragment)) return response;
                return real(path, opts);
            };
        }""",
        [path_fragment, response],
    )


async def _open_viewer(page, capture_id: str = "cap-1"):
    await page.evaluate(
        """(id) => {
            viewingCaptureId = id;
            activatePanel("viewer");
            hide("viewer-empty");
            show("packet-viewer");
        }""",
        capture_id,
    )


async def test_protocol_hierarchy_renders_the_nested_tree(app_page):
    tree = [{
        "name": "eth", "frames": 10, "bytes": 1000,
        "children": [{
            "name": "ip", "frames": 10, "bytes": 900,
            "children": [{"name": "tcp", "frames": 8, "bytes": 800, "children": []}],
        }],
    }]
    await _stub_api(app_page, "/protocol-hierarchy", tree)
    await _open_viewer(app_page)

    await app_page.click("#btn-protocol-hierarchy")
    await app_page.wait_for_selector("#protocol-hierarchy-dialog[open]")

    text = await app_page.inner_text("#protocol-hierarchy-tree")
    assert "eth" in text and "ip" in text and "tcp" in text
    assert "frames:10" in text
    # tcp is 8 of eth's 10 frames -- 80.0%, computed against the root, not
    # against its immediate parent.
    assert "80.0%" in text

    await app_page.click("#protocol-hierarchy-dialog [data-close-dialog]")
    assert await app_page.locator("#protocol-hierarchy-dialog[open]").count() == 0


async def test_conversations_renders_pairs_and_endpoints(app_page):
    payload = {
        "conversations": [{
            "a": "10.0.0.1", "b": "10.0.0.2",
            "packets_a_to_b": 4, "bytes_a_to_b": 253,
            "packets_b_to_a": 3, "bytes_b_to_a": 205,
        }],
        "endpoints": [
            {"address": "10.0.0.1", "packets": 4, "bytes": 253},
            {"address": "10.0.0.2", "packets": 3, "bytes": 205},
        ],
    }
    await _stub_api(app_page, "/conversations", payload)
    await _open_viewer(app_page)

    await app_page.click("#btn-conversations")
    await app_page.wait_for_selector("#conversations-dialog[open]")

    pairs_text = await app_page.inner_text("#conversations-pairs")
    assert "10.0.0.1" in pairs_text and "10.0.0.2" in pairs_text
    endpoints_text = await app_page.inner_text("#conversations-endpoints")
    assert "10.0.0.1" in endpoints_text and "253" in endpoints_text


async def test_conversations_filter_button_applies_the_pair_and_closes(app_page):
    payload = {
        "conversations": [{
            "a": "10.0.0.1", "b": "10.0.0.2",
            "packets_a_to_b": 4, "bytes_a_to_b": 253,
            "packets_b_to_a": 3, "bytes_b_to_a": 205,
        }],
        "endpoints": [],
    }
    await _stub_api(app_page, "/conversations", payload)
    # applyDisplayFilter -> loadPackets makes a real request; harmless against
    # a capture id that does not exist, and irrelevant to what is under test
    # here, which is what ends up in the display filter box.
    await _open_viewer(app_page)

    await app_page.click("#btn-conversations")
    await app_page.wait_for_selector("#conversations-dialog[open]")
    await app_page.click("#conversations-pairs [data-conv-filter]")

    assert await app_page.input_value("#display-filter") == "ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2"
    assert await app_page.locator("#conversations-dialog[open]").count() == 0


async def test_follow_stream_colors_each_direction_and_shows_endpoints(app_page):
    result = {
        "protocol": "tcp", "stream": 0,
        "a": "10.0.0.1:12345", "b": "10.0.0.2:80",
        "segments": [
            {"from_a": True, "hex": "4745542f"},           # "GET/"
            {"from_a": False, "hex": "4f4b"},               # "OK"
        ],
    }
    await _stub_api(app_page, "/stream/tcp/0", result)
    await _open_viewer(app_page)

    await app_page.evaluate("() => openFollowStream('tcp', 0)")
    await app_page.wait_for_selector("#follow-stream-dialog[open]")

    endpoints = await app_page.inner_text("#follow-stream-endpoints")
    assert "10.0.0.1:12345" in endpoints and "10.0.0.2:80" in endpoints and "2 segments" in endpoints

    a_text = await app_page.inner_text("#follow-stream-body .stream-a")
    b_text = await app_page.inner_text("#follow-stream-body .stream-b")
    assert a_text == "GET/"
    assert b_text == "OK"


async def test_follow_stream_set_as_filter_uses_the_right_field_and_index(app_page):
    result = {"protocol": "udp", "stream": 3, "a": "10.0.0.1:5353", "b": "10.0.0.3:53", "segments": []}
    await _stub_api(app_page, "/stream/udp/3", result)
    await _open_viewer(app_page)

    await app_page.evaluate("() => openFollowStream('udp', 3)")
    await app_page.wait_for_selector("#follow-stream-dialog[open]")
    await app_page.click("#btn-follow-stream-filter")

    assert await app_page.input_value("#display-filter") == "udp.stream eq 3"
    assert await app_page.locator("#follow-stream-dialog[open]").count() == 0


async def test_a_tcp_packets_row_offers_follow_stream_from_its_own_menu(app_page):
    """Wireshark's own workflow: right-click the row, no need to have opened
    the packet first. packetRowHtml carries tcp_stream for exactly this."""
    packet = {
        "number": 1, "timestamp": "0.0", "source": "10.0.0.1", "destination": "10.0.0.2",
        "protocol": "TCP", "length": 66, "info": "x", "src_mac": "", "dst_mac": "",
        "interface": "", "ifindex": 0, "direction": "", "tcp_stream": 0, "udp_stream": None,
    }
    await _stub_api(app_page, "/stream/tcp/0", {
        "protocol": "tcp", "stream": 0, "a": "10.0.0.1:1", "b": "10.0.0.2:2", "segments": [],
    })
    await _open_viewer(app_page)
    await app_page.evaluate(
        """(p) => {
            const cols = packetColumns();
            document.getElementById("packet-tbody").innerHTML = packetRowHtml(p, cols);
        }""",
        packet,
    )

    await app_page.click('#packet-tbody tr[data-frame="1"] .col-proto', button="right")
    await app_page.wait_for_selector("#filter-menu")
    labels = await app_page.eval_on_selector_all(
        "#filter-menu .filter-menu-item", "els => els.map(e => e.textContent.trim())"
    )
    assert "Follow TCP Stream" in labels
    assert not any("Follow UDP" in label for label in labels)

    await app_page.click("#filter-menu .filter-menu-item:has-text('Follow TCP Stream')")
    await app_page.wait_for_selector("#follow-stream-dialog[open]")


async def test_follow_stream_reports_the_servers_own_error(app_page):
    await app_page.evaluate(
        """() => {
            window.api = async () => { throw new Error("no such tcp stream: 99"); };
        }"""
    )
    await _open_viewer(app_page)

    await app_page.evaluate("() => openFollowStream('tcp', 99)")
    await app_page.wait_for_selector("#follow-stream-dialog[open]")
    assert "no such tcp stream: 99" in await app_page.inner_text("#follow-stream-body")
