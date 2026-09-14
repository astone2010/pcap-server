"""Three things a host can tell the page, drawn by the real renderers.

The server list, the prerequisite results and the packet table are driven with
data put straight into the page, as in test_sanitize_ui: what arrives from the
API is covered in tests/test_servers.py and tests/test_packet_parser.py, and
what is under test here is how it is shown.
"""

from __future__ import annotations

from tests.browser.conftest import needs_browser

pytestmark = needs_browser

SERVER = {
    "id": "srv-1", "name": "edge", "hostname": "203.0.113.17", "port": 22,
    "username": "alice", "ssh_key_name": "k", "use_sudo": True,
    "tcpdump_path": "", "os_name": "Rocky Linux 9.4 (Blue Onyx)", "host_trusted": True,
}


async def _servers(page, *servers):
    await page.click(".tab[data-tab='servers']")
    # Opening the tab fetches the real (empty) list; waiting for that first keeps
    # it from landing after these rows and wiping them.
    await page.evaluate(
        """async (servers) => { await loadServers(); activeServers = servers; renderServerList(); selectServer(servers[0].id); }""",
        list(servers),
    )


async def test_the_os_shows_under_the_server_and_in_its_facts(app_page):
    await _servers(app_page, SERVER)
    assert await app_page.inner_text(".server-item .server-os") == SERVER["os_name"]
    assert await app_page.inner_text("#server-os") == SERVER["os_name"]


async def test_an_unchecked_server_says_where_the_os_comes_from(app_page):
    await _servers(app_page, {**SERVER, "os_name": ""})
    assert await app_page.query_selector(".server-item .server-os") is None
    assert "Check prerequisites" in await app_page.inner_text("#server-os")


async def test_an_os_name_cannot_inject_markup(app_page):
    await _servers(app_page, {**SERVER, "os_name": "<img src=x id=pwn>"})
    assert await app_page.query_selector("#pwn") is None
    assert await app_page.inner_text("#server-os") == "<img src=x id=pwn>"


async def test_an_info_row_reads_as_an_option_not_a_fault(app_page):
    await _servers(app_page, SERVER)
    await app_page.evaluate(
        """() => renderPrereqs(document.getElementById("prereq-result"), {checks: [
            {name: "Capture privilege", status: "ok", detail: "Passwordless sudo works.", fix: ""},
            {name: "Capture without sudo", status: "info", detail: "Optional.", fix: "  sudo setcap x"},
        ]})"""
    )
    row = app_page.locator(".prereq-row.info")
    assert await row.locator(".prereq-icon").inner_text() == "i"
    assert "if you want it" in (await row.locator(".prereq-fix-label").text_content()).lower()


CAPTURE = {
    "id": "cap-any", "name": "", "server_id": "s1", "server_label": "edge",
    "interface": "any", "user_id": "u1", "live_stream": False, "status": "completed",
    "command": "", "packet_count": 1, "file_size": 1, "error": "",
}


async def _row(page, capture, packet):
    return await page.evaluate(
        """([capture, packet]) => {
            captures = [capture];
            viewingCaptureId = capture.id;
            const cols = packetColumns();
            document.getElementById("packet-tbody").innerHTML = packetRowHtml(packet, cols);
            const th = document.querySelector("th.col-iface");
            const td = document.querySelector("#packet-tbody td.col-iface");
            return {thHidden: th.hidden, tdHidden: td.hidden, text: td.innerText,
                    title: td.firstElementChild.title, span: cols.span};
        }""",
        [capture, packet],
    )


PACKET = {
    "number": 1, "timestamp": "0.0", "source": "10.0.0.1", "destination": "10.0.0.2",
    "protocol": "UDP", "length": 42, "info": "x", "src_mac": "", "dst_mac": "",
    "interface": "eth0", "ifindex": 2, "direction": "out",
}


async def test_an_any_capture_shows_which_interface_each_packet_crossed(app_page):
    got = await _row(app_page, CAPTURE, PACKET)
    assert not got["thHidden"] and not got["tdHidden"]
    assert got["text"].split() == ["eth0", "out"]
    assert "sll.ifindex == 2" in got["title"]
    assert "sent by this host" in got["title"]
    assert got["span"] == 8


async def test_a_named_interface_capture_has_no_interface_column(app_page):
    got = await _row(app_page, {**CAPTURE, "interface": "eth0"}, {**PACKET, "interface": "", "ifindex": 0, "direction": ""})
    assert got["thHidden"] and got["tdHidden"]
    assert got["span"] == 7


async def test_an_unrecorded_name_says_so_on_hover(app_page):
    got = await _row(app_page, CAPTURE, {**PACKET, "interface": "#7", "ifindex": 7, "direction": "in"})
    assert got["text"].split() == ["#7", "in"]
    assert "not recorded" in got["title"]
