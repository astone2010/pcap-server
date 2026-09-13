"""Live streaming and the saved-view chips, from the browser.

Neither is visible from an HTTP test. Whether the Viewer appends packets to a
table on a timer, whether a capture reports itself as live streamed in the
list, and whether a chip's label is large enough to read are all questions
about the page.

The captures here are registered over the API and driven through page state
rather than by running tcpdump against a real interface: what is under test is
the viewer's behaviour, and a test that needed a live host to prove the chips
are readable would be a test nobody runs.
"""

from __future__ import annotations

import pytest

from tests.browser.conftest import needs_browser

pytestmark = needs_browser


async def _capture_tab(page):
    await page.click(".tab[data-tab='capture']")
    await page.wait_for_selector("#panel-capture.active")
    return page


async def _seed_captures(page, captures):
    """Put rows into the page's capture list without a capture pipeline.

    renderCaptures reads the module-level `captures` array, so this exercises
    the real renderer against the real markup -- only the fetch is bypassed.
    The Capture tab has to be the active one first: the list lives inside its
    panel, and a row in an inactive panel is in the DOM but not on screen.
    """
    await _capture_tab(page)
    await page.evaluate(
        "rows => { captures = rows; renderCaptures(); }",
        captures,
    )


def _row(**overrides):
    row = {
        "id": "11111111-1111-1111-1111-111111111111",
        "name": "",
        "server_id": "s1",
        "server_label": "target (alice@target.example)",
        "interface": "eth0",
        "user_id": "u1",
        "live_stream": False,
        "status": "completed",
        "command": "tcpdump -w /tmp/x.pcap -v -i eth0",
        "packet_count": 12,
        "file_size": 4096,
        "error": "",
    }
    row.update(overrides)
    return row


# --- the option on the capture screen ----------------------------------------


async def test_the_capture_screen_offers_live_streaming(app_page):
    """It has to be here. A live view you can only reach after the fact is not
    a live view."""
    await _capture_tab(app_page)
    assert await app_page.is_visible("#cap-live")
    assert not await app_page.is_checked("#cap-live"), "off unless asked for"


async def test_the_live_option_says_the_capture_is_still_saved(app_page):
    """The assumption people make is that a live capture lives in the browser
    and is lost when the tab closes. It does not, and the label says so."""
    await _capture_tab(app_page)
    label = await app_page.inner_text(".live-stream-option")
    assert "saved" in label.lower()


async def test_starting_a_capture_sends_the_live_flag(app_page):
    """The checkbox has to reach the request body. A tickbox that changes
    nothing is worse than no tickbox."""
    await _capture_tab(app_page)
    await app_page.evaluate(
        """() => {
            window.__sentBody = null;
            window.__origFetch = window.fetch;
            window.fetch = (url, opts) => {
                if (String(url).endsWith('/api/captures') && opts && opts.method === 'POST') {
                    window.__sentBody = JSON.parse(opts.body);
                    return Promise.resolve(new Response(
                        JSON.stringify({ id: 'x', status: 'running' }),
                        { status: 200, headers: { 'Content-Type': 'application/json' } },
                    ));
                }
                return window.__origFetch(url, opts);
            };
            const sel = document.getElementById('cap-server');
            sel.innerHTML = '<option value="s1">s1</option>';
            sel.value = 's1';
        }"""
    )
    await app_page.check("#cap-live")
    await app_page.click("#btn-start-capture")
    await app_page.wait_for_function("window.__sentBody !== null")

    body = await app_page.evaluate("window.__sentBody")
    assert body["live_stream"] is True


# --- how a live capture reads in the list ------------------------------------


async def test_a_live_streamed_capture_is_marked_as_one(app_page):
    """And stays marked after it finishes: the operator asked for a live
    stream, and the saved capture should still say how it was taken."""
    await _seed_captures(app_page, [_row(live_stream=True, status="completed")])
    await app_page.wait_for_selector(".badge-live")
    assert (await app_page.inner_text(".badge-live")).strip().lower() == "live stream"


async def test_an_ordinary_capture_carries_no_live_mark(app_page):
    await _seed_captures(app_page, [_row(live_stream=False, status="completed")])
    await app_page.wait_for_selector(".capture-item")
    assert await app_page.locator(".badge-live").count() == 0


async def test_a_running_live_capture_can_be_watched_from_the_list(app_page):
    await _seed_captures(app_page, [_row(live_stream=True, status="running")])
    await app_page.wait_for_selector("[data-action='view-capture']")
    assert "Watch live" in await app_page.inner_text("[data-action='view-capture']")
    # Stop stays available alongside it.
    assert await app_page.locator("[data-action='stop-capture']").count() == 1


async def test_a_running_ordinary_capture_offers_no_viewer(app_page):
    """There is nothing to show: the pcap is on the remote host until the
    transfer, so a View button would open an empty table."""
    await _seed_captures(app_page, [_row(live_stream=False, status="running")])
    await app_page.wait_for_selector(".capture-item")
    assert await app_page.locator("[data-action='view-capture']").count() == 0


# --- the live bar in the viewer ----------------------------------------------


async def test_opening_a_live_capture_shows_the_live_bar(app_page):
    """The viewer opens on a running capture the same way it opens on a stored
    one -- with one extra strip saying it is still going."""
    row = _row(live_stream=True, status="running", packet_count=3)
    await _seed_captures(app_page, [row])
    # The poll would 404 against a capture the server does not know; the bar and
    # the mode switch are what this test is about, so the fetch is stubbed.
    await app_page.evaluate(
        """() => {
            window.fetch = (url, opts) => {
                if (String(url).includes('/live/packets')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        packets: [], status: 'running', finished: false, live: true,
                        buffered_packets: 0, buffered_bytes: 0, buffer_capacity: 16777216,
                        frozen: false, problem: '', read_error: '', captured_packets: 3,
                    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
                }
                return Promise.resolve(new Response('[]', {
                    status: 200, headers: { 'Content-Type': 'application/json' },
                }));
            };
        }"""
    )
    await app_page.click("[data-action='view-capture']")
    await app_page.wait_for_selector("#live-bar:not([hidden])")
    await app_page.wait_for_function(
        "document.getElementById('live-status').textContent.includes('captured')"
    )
    status = await app_page.inner_text("#live-status")
    assert "Live" in status
    assert "3 captured" in status
    assert await app_page.is_visible("#btn-live-stop")


async def test_a_frozen_preview_says_the_capture_is_still_running(app_page):
    """The one thing here that could actively mislead.

    A preview that stops updating, with no sign the capture is still going,
    reads as the capture having died -- when in fact the saved pcap will be
    complete.
    """
    await _seed_captures(app_page, [_row(live_stream=True, status="running")])
    await app_page.evaluate(
        """() => {
            window.fetch = (url) => {
                if (String(url).includes('/live/packets')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        packets: [], status: 'running', finished: false, live: true,
                        buffered_packets: 400, buffered_bytes: 16777216,
                        buffer_capacity: 16777216, frozen: true, problem: '',
                        read_error: '', captured_packets: 98000,
                    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
                }
                return Promise.resolve(new Response('[]', {
                    status: 200, headers: { 'Content-Type': 'application/json' },
                }));
            };
        }"""
    )
    await app_page.click("[data-action='view-capture']")
    await app_page.wait_for_selector("#live-bar.live-frozen")

    status = await app_page.inner_text("#live-status")
    assert "still running" in status
    assert "saved in full" in status
    assert "98000" in status, "tcpdump's own total keeps climbing past a frozen preview"

    # The pulse stops with the stream. A blinking "live" dot over a view that
    # has stopped updating is the misleading part, not decoration.
    animation = await app_page.eval_on_selector(
        ".live-dot", "el => getComputedStyle(el).animationName"
    )
    assert animation == "none"


async def test_leaving_the_viewer_stops_the_polling(app_page):
    """A live view polls on a timer. Left running it reads a capture and spends
    the rate limit on a table nobody is looking at."""
    await _seed_captures(app_page, [_row(live_stream=True, status="running")])
    await app_page.evaluate(
        """() => {
            window.__polls = 0;
            window.fetch = (url) => {
                if (String(url).includes('/live/packets')) {
                    window.__polls += 1;
                    return Promise.resolve(new Response(JSON.stringify({
                        packets: [], status: 'running', finished: false, live: true,
                        buffered_packets: 0, buffered_bytes: 0, buffer_capacity: 1,
                        frozen: false, problem: '', read_error: '', captured_packets: 0,
                    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
                }
                return Promise.resolve(new Response('[]', {
                    status: 200, headers: { 'Content-Type': 'application/json' },
                }));
            };
        }"""
    )
    await app_page.click("[data-action='view-capture']")
    await app_page.wait_for_function("window.__polls > 0")

    await app_page.click(".tab[data-tab='capture']")
    await app_page.wait_for_function("typeof liveTimer !== 'undefined' && liveTimer === null")
    assert await app_page.evaluate("inLiveView()") is False


# --- the saved-view chips ----------------------------------------------------


async def test_a_saved_view_chip_is_large_enough_to_read(app_page):
    """These carry operator-typed names, read at a glance while packets scroll.

    They were set at 0.75rem -- 12px -- which is smaller than everything around
    them and, as reported, close to unreadable. The floor is the app's own body
    size, so a future tidy-up cannot quietly shrink them again.
    """
    await app_page.click(".tab[data-tab='viewer']")
    await app_page.wait_for_selector("#panel-viewer.active")
    await app_page.evaluate(
        """() => {
            document.getElementById('packet-viewer').hidden = false;
            savedViews = [{ id: 'v1', name: 'kerberos', display_filter: 'kerberos' }];
            renderViewTabs();
        }"""
    )
    await app_page.wait_for_selector(".view-tab")

    size = await app_page.eval_on_selector(
        ".view-tab", "el => parseFloat(getComputedStyle(el).fontSize)"
    )
    # Compared against the app's own primary content size -- what a capture's
    # name is set in -- rather than the root 16px, which nothing in this UI
    # actually uses. A hard-coded number alone would drift the moment the
    # scale changed; this says what the chip should be as large as, and why.
    content_size = await app_page.evaluate(
        """() => {
            const probe = document.createElement('div');
            probe.className = 'title';
            const item = document.createElement('div');
            item.className = 'capture-item';
            const info = document.createElement('div');
            info.className = 'info';
            info.appendChild(probe);
            item.appendChild(info);
            document.body.appendChild(item);
            const size = parseFloat(getComputedStyle(probe).fontSize);
            item.remove();
            return size;
        }"""
    )
    assert size >= 14, f"saved-view chips are {size}px -- too small to read"
    assert size >= content_size, (
        "a chip label is content, not chrome: an operator-typed view name should "
        f"not be set smaller than a capture's name ({content_size}px)"
    )


async def test_the_chip_action_buttons_are_a_real_click_target(app_page):
    """Three glyphs a few pixels apart is a row of buttons you cannot hit."""
    await app_page.click(".tab[data-tab='viewer']")
    await app_page.wait_for_selector("#panel-viewer.active")
    await app_page.evaluate(
        """() => {
            document.getElementById('packet-viewer').hidden = false;
            savedViews = [{ id: 'v1', name: 'kerberos', display_filter: 'kerberos' }];
            activeViewId = 'v1';
            renderViewTabs();
        }"""
    )
    await app_page.wait_for_selector(".view-tab-action")
    box = await app_page.locator(".view-tab-action").first.bounding_box()
    assert box["width"] >= 12 and box["height"] >= 12, f"action button is {box}"
