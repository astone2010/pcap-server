"""The server list's self-target flag, drawn by the real renderer.

A server the backend has proved to be the machine pcap-server runs on is
refused for captures but stays in the list -- deleting someone's configuration
over a finding is not the backend's to do. What is under test here is that the
row says so, because an entry that simply fails every time with nothing stated
is the dead end the flag exists to prevent. Where the finding comes from is
covered in tests/test_servers.py and tests/test_localnet.py.
"""

from __future__ import annotations

from tests.browser.conftest import needs_browser

pytestmark = needs_browser

FINDING = ("the target reports the same kernel boot id as pcap-server itself, "
           "so it is the machine this container is running on")

SERVER = {
    "id": "srv-1", "name": "edge", "hostname": "203.0.113.17", "port": 22,
    "username": "alice", "ssh_key_name": "k", "use_sudo": True,
    "tcpdump_path": "", "os_name": "", "self_target_reason": "",
    "host_trusted": True,
}


async def _servers(page, *servers):
    await page.click(".tab[data-tab='servers']")
    # Opening the tab fetches the real (empty) list; waiting for that first keeps
    # it from landing after these rows and wiping them.
    await page.evaluate(
        """async (servers) => { await loadServers(); activeServers = servers; renderServerList(); selectServer(servers[0].id); }""",
        list(servers),
    )


async def test_a_self_target_server_says_why_it_is_refused(app_page):
    await _servers(app_page, {**SERVER, "self_target_reason": FINDING})
    text = await app_page.inner_text(".server-item .server-warn-self")
    assert "machine pcap-server runs on" in text
    assert "same kernel boot id" in text


async def test_the_row_is_marked_so_it_reads_differently_from_the_rest(app_page):
    await _servers(app_page, {**SERVER, "self_target_reason": FINDING})
    assert await app_page.query_selector(".server-item.self-target") is not None
    assert await app_page.query_selector(".server-item .server-dot-warn") is not None


async def test_an_ordinary_server_carries_no_flag(app_page):
    await _servers(app_page, SERVER)
    assert await app_page.query_selector(".server-item .server-warn-self") is None
    assert await app_page.query_selector(".server-item.self-target") is None


async def test_a_finding_cannot_inject_markup(app_page):
    """The string is written by the backend, but it is rendered the same way as
    every other value that reaches innerHTML -- escaped, not trusted."""
    await _servers(app_page, {**SERVER, "self_target_reason": "<img src=x id=pwn>"})
    assert await app_page.query_selector("#pwn") is None
    assert "<img src=x id=pwn>" in await app_page.inner_text(".server-item .server-warn-self")
