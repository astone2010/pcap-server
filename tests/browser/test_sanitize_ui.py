"""The Sanitize dialog: what it offers, what it sends, and what it reports.

The capture list is filled in directly, as in test_live_stream_ui, so the
real renderer and the real dialog run without a capture pipeline behind them.
window.open is stubbed: the request it would make is what is under test here,
and the download itself is covered against the real route in
tests/test_sanitizer.py.
"""

from __future__ import annotations

from tests.browser.conftest import needs_browser

pytestmark = needs_browser

CAPTURE_ID = "22222222-2222-2222-2222-222222222222"


def _row(**overrides):
    row = {
        "id": CAPTURE_ID,
        "name": "Lobby wifi",
        "server_id": "s1",
        "server_label": "target (alice@target.example)",
        "interface": "eth0",
        "user_id": "u1",
        "live_stream": False,
        "status": "completed",
        "command": "tcpdump -w /tmp/x.pcap -i eth0",
        "packet_count": 12,
        "file_size": 4096,
        "error": "",
    }
    row.update(overrides)
    return row


async def _show(page, *rows, secure=True):
    await page.click(".tab[data-tab='capture']")
    await page.wait_for_selector("#panel-capture.active")
    await page.evaluate(
        """([rows, secure]) => {
            secureTransport = secure;
            captures = rows;
            renderCaptures();
            window.__opened = [];
            window.open = (url) => { window.__opened.push(url); return null; };
        }""",
        [list(rows), secure],
    )


async def _open_dialog(page):
    await _show(page, _row())
    await page.click(f"[data-action='sanitize-capture'][data-id='{CAPTURE_ID}']")
    await page.wait_for_selector("#sanitize-dialog[open]")


async def test_a_finished_capture_offers_sanitize_beside_download(app_page):
    await _show(app_page, _row())
    buttons = await app_page.eval_on_selector_all(
        f"[data-id='{CAPTURE_ID}']", "els => els.map(e => e.dataset.action)"
    )
    assert buttons.index("sanitize-capture") == buttons.index("download-capture") + 1


async def test_no_sanitize_button_over_plain_http(app_page):
    await _show(app_page, _row(), secure=False)
    assert await app_page.locator("[data-action='sanitize-capture']").count() == 0


async def test_the_dialog_opens_with_the_usual_fields_ticked(app_page):
    await _open_dialog(app_page)
    checked = await app_page.eval_on_selector_all(
        "#sanitize-form input[type=checkbox]",
        "els => Object.fromEntries(els.map(e => [e.name, e.checked]))",
    )
    assert checked == {
        "credentials": True, "ips": True, "keep_private": False, "macs": True,
        "keep_oui": False, "hostnames": False, "usernames": False, "strip_payload": False,
    }
    assert await app_page.text_content("#sanitize-target") == "Lobby wifi"


async def test_a_sub_option_follows_its_parent(app_page):
    await _open_dialog(app_page)
    await app_page.check("#sanitize-form input[name=keep_private]")
    await app_page.uncheck("#sanitize-form input[name=ips]")
    assert await app_page.is_disabled("#sanitize-form input[name=keep_private]")
    assert not await app_page.is_checked("#sanitize-form input[name=keep_private]")
    await app_page.check("#sanitize-form input[name=ips]")
    assert await app_page.is_enabled("#sanitize-form input[name=keep_private]")


async def test_nothing_ticked_says_so_and_sends_nothing(app_page):
    await _open_dialog(app_page)
    for name in ("credentials", "ips", "macs"):
        await app_page.uncheck(f"#sanitize-form input[name={name}]")
    await app_page.click("#sanitize-form button[type=submit]")
    assert await app_page.is_visible("#sanitize-error")
    assert await app_page.evaluate("window.__opened") == []


async def test_download_sends_the_choices_and_a_ticket(app_page):
    await _open_dialog(app_page)
    await app_page.check("#sanitize-form input[name=hostnames]")
    await app_page.check("#sanitize-form input[name=keep_oui]")
    await app_page.click("#sanitize-form button[type=submit]")
    opened = await app_page.evaluate("window.__opened")
    assert len(opened) == 1
    url = opened[0]
    assert url.startswith(f"/api/captures/{CAPTURE_ID}/sanitize?")
    for part in ("credentials=true", "ips=true", "keep_private=false", "macs=true",
                 "keep_oui=true", "hostnames=true", "usernames=false", "strip_payload=false"):
        assert part in url
    ticket = url.split("ticket=")[1]
    assert len(ticket) == 24 and all(c.isalnum() or c in "-_" for c in ticket)
    assert await app_page.is_visible("#sanitize-report")
    assert await app_page.is_hidden("#sanitize-form")


async def test_an_unfinished_capture_is_not_offered_the_dialog(app_page):
    await _show(app_page, _row(status="running"))
    await app_page.evaluate(f"() => openSanitizeDialog('{CAPTURE_ID}')")
    assert await app_page.locator("#sanitize-dialog[open]").count() == 0
    assert await app_page.is_visible("#https-refusal")


async def test_the_summary_leads_with_what_was_not_replaced_as_plain_text(app_page):
    """Field names come from tshark, which read them out of packets. They are
    shown as text, never as markup."""
    await _open_dialog(app_page)
    await app_page.evaluate(
        """() => {
            document.getElementById('sanitize-form').hidden = true;
            document.getElementById('sanitize-report').hidden = false;
            renderSanitizeSummary({done: true, summary: {
                frames: 1200,
                masked: {credentials: 4, usernames: 0, hostnames: 0, reverse_dns_names: 0},
                addresses: {ipv4: 7, ipv6: 0, mac: 3},
                stripped_frames: 0,
                unplaced: {'<img src=x onerror=window.__xss=1>': 2},
                undissected: [{transport: 'udp', port: 31337, frames: 5, bytes: 2048}],
            }});
        }"""
    )
    text = await app_page.text_content("#sanitize-summary")
    assert "IPv4 addresses" in text and "Credentials" in text
    assert "IPv6 addresses" not in text  # zero counts are left out
    assert "Found but not replaced in place" in text
    assert "<img src=x onerror=window.__xss=1>" in text
    assert await app_page.locator("#sanitize-summary img").count() == 0
    assert "UDP port 31337" in text
    assert await app_page.evaluate("window.__xss === undefined")


async def test_a_failed_sanitize_says_not_to_share_the_partial_file(app_page):
    await _open_dialog(app_page)
    await app_page.evaluate(
        "() => renderSanitizeSummary({done: true, error: 'tshark failed while sanitizing'})"
    )
    status = await app_page.text_content("#sanitize-status")
    assert "Do not share" in status and "tshark failed" in status


async def test_the_dialog_fits_a_phone(app_page):
    await app_page.set_viewport_size({"width": 400, "height": 800})
    await _open_dialog(app_page)
    fits = await app_page.evaluate(
        """() => {
            const box = document.getElementById('sanitize-dialog').getBoundingClientRect();
            return box.left >= 0 && box.right <= window.innerWidth;
        }"""
    )
    assert fits
