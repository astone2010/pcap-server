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


async def test_the_live_option_lines_up_with_the_fields_beside_it(app_page):
    """It used to stack: the generic form rules made its label a block and gave
    the tickbox a full-width input box. Its control should now sit at the same
    height as the field next to it -- the Interface dropdown since dev.30, which
    grouped Server, Interface and Live stream onto one row and moved the limits
    (Snap length among them) to a row of their own."""
    await _capture_tab(app_page)
    toggle = await app_page.locator(".live-stream-toggle").bounding_box()
    beside = await app_page.locator("#cap-interface").bounding_box()
    tick = await app_page.locator("#cap-live").bounding_box()
    assert abs(toggle["y"] - beside["y"]) <= 2
    assert abs(toggle["height"] - beside["height"]) <= 2
    assert tick["width"] < 30, "the tickbox is back to being a full-width input"


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
    # A live stream has to be pointed at something or the form refuses to send
    # it at all, so this one carries a filter. What is under test is the flag
    # reaching the body, not the rule.
    await app_page.fill("#cap-bpf", "tcp port 443")
    # The form requires a name, and summarises the capture in a confirm before
    # anything is sent. Neither is what this test is about, so both are simply
    # satisfied -- but if either stops happening, the ones below say so.
    await app_page.fill("#cap-name", "live flag check")
    app_page.on("dialog", lambda dialog: dialog.accept())
    await app_page.click("#btn-start-capture")
    # An arrow function, not a bare expression. Playwright can only evaluate
    # a bare expression string by building it into a function INSIDE the page,
    # which this app's CSP forbids (`script-src 'self'` with no 'unsafe-eval').
    # That only bites when the predicate is false on the first look and real
    # polling starts -- which is exactly what happened when the capture start
    # grew a filter-check round trip ahead of the POST. The bare form had been
    # passing purely because the body was already there by the time it ran.
    await app_page.wait_for_function("() => window.__sentBody !== null")

    body = await app_page.evaluate("window.__sentBody")
    assert body["live_stream"] is True


# --- a live stream has to be pointed at something ----------------------------
#
# The server refuses an untargeted live stream outright (LiveStreamNotTargeted
# -> 400). These are about the form saying so first: the answer is entirely in
# the fields on screen, and finding it out from a bounced request is finding it
# out one step too late.


async def test_the_target_notice_is_hidden_until_live_streaming_is_asked_for(app_page):
    """It is not an error. Nothing is wrong with an ordinary capture on "any",
    which is the normal thing to run."""
    await _capture_tab(app_page)
    assert await app_page.is_hidden("#live-target-notice")


async def test_ticking_live_stream_on_an_untargeted_form_explains_why_not(app_page):
    await _capture_tab(app_page)
    await app_page.check("#cap-live")
    await app_page.wait_for_selector("#live-target-notice", state="visible")
    text = await app_page.inner_text("#live-target-notice")
    # Both ways out, because either one is enough and an operator told only
    # about filters will not think of the dropdown.
    assert "interface" in text.lower()
    assert "bpf filter" in text.lower()


async def test_typing_a_filter_clears_the_notice(app_page):
    """The field that resolves it is the field the notice points at, so the
    notice has to follow it as it is typed rather than on submit."""
    await _capture_tab(app_page)
    await app_page.check("#cap-live")
    await app_page.wait_for_selector("#live-target-notice", state="visible")
    await app_page.fill("#cap-bpf", "host 10.0.0.5")
    await app_page.wait_for_selector("#live-target-notice", state="hidden")


async def test_clearing_the_filter_brings_the_notice_back(app_page):
    """Emptying the box puts the form back where it started, and a notice that
    only ever appeared once would leave it looking valid."""
    await _capture_tab(app_page)
    await app_page.check("#cap-live")
    await app_page.fill("#cap-bpf", "host 10.0.0.5")
    await app_page.wait_for_selector("#live-target-notice", state="hidden")
    await app_page.fill("#cap-bpf", "   ")
    await app_page.wait_for_selector("#live-target-notice", state="visible")


async def test_unticking_live_stream_clears_the_notice(app_page):
    """Capturing everything without watching it has no such limit, so the
    notice must not linger over a form it no longer applies to."""
    await _capture_tab(app_page)
    await app_page.check("#cap-live")
    await app_page.wait_for_selector("#live-target-notice", state="visible")
    await app_page.uncheck("#cap-live")
    await app_page.wait_for_selector("#live-target-notice", state="hidden")


async def test_an_untargeted_live_capture_is_never_sent(app_page):
    """The request would be refused, so it is not made. Letting it go and
    surfacing the 400 would be the same answer, one round trip later, in an
    alert rather than next to the field that fixes it."""
    await _capture_tab(app_page)
    await app_page.evaluate(
        """() => {
            window.__posted = false;
            window.__origFetch = window.fetch;
            window.fetch = (url, opts) => {
                if (String(url).endsWith('/api/captures') && opts && opts.method === 'POST') {
                    window.__posted = true;
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
    await app_page.wait_for_selector("#live-target-notice", state="visible")
    assert await app_page.evaluate("window.__posted") is False


# --- the capture list has to fit the panel -----------------------------------


LONG_COMMAND = (
    "tcpdump -w /tmp/pcap_11111111-1111-1111-1111-111111111111.pcap -v -U "
    "-i eth0 -s 128 -- tcp port 443 and host 198.51.100.77 and not port 22"
)


async def test_a_long_capture_title_wraps_instead_of_running_off_the_panel(app_page):
    """An unnamed capture is titled with the whole tcpdump command, which is
    longer than the panel on any window.

    .capture-item is a flex row, and a flex item's min-width defaults to its
    content's intrinsic width -- so the text column grew wider than the panel
    rather than wrapping inside it, the panel scrolled sideways, and the line
    ran off the edge where it could not be read. Asserted as "the list is no
    wider than the space it has" rather than against a pixel count, because
    that is the property that was broken.
    """
    await _seed_captures(app_page, [_row(name="", command=LONG_COMMAND)])
    await app_page.wait_for_selector(".capture-item")
    overflow = await app_page.evaluate(
        """() => {
            const list = document.getElementById('capture-list');
            const item = document.querySelector('.capture-item');
            return {
                list: list.scrollWidth - list.clientWidth,
                item: item.scrollWidth - item.clientWidth,
            };
        }"""
    )
    assert overflow["list"] <= 1, f"capture list scrolls sideways by {overflow['list']}px"
    assert overflow["item"] <= 1, f"capture row scrolls sideways by {overflow['item']}px"


async def test_a_long_capture_title_is_actually_shown_on_more_than_one_line(app_page):
    """Fitting the panel is not enough on its own -- clipping it would do that
    too. The text has to still be there, wrapped."""
    await _seed_captures(app_page, [_row(name="", command=LONG_COMMAND)])
    await app_page.wait_for_selector(".capture-item .title")
    lines = await app_page.evaluate(
        """() => {
            const t = document.querySelector('.capture-item .title');
            const line = parseFloat(getComputedStyle(t).lineHeight) || 16;
            return Math.round(t.getBoundingClientRect().height / line);
        }"""
    )
    assert lines >= 2, "the command was put on one line and cut off, not wrapped"


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
        "() => document.getElementById('live-status').textContent.includes('captured')"
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
    await app_page.wait_for_function("() => window.__polls > 0")

    await app_page.click(".tab[data-tab='capture']")
    await app_page.wait_for_function("() => typeof liveTimer !== 'undefined' && liveTimer === null")
    assert await app_page.evaluate("inLiveView()") is False


# --- the saved-view chips ----------------------------------------------------


async def test_a_saved_view_chip_is_large_enough_to_read(app_page):
    """These carry operator-typed names, read at a glance while packets scroll.

    They were set at 0.75rem -- 12px -- which is smaller than everything around
    them and, as reported, close to unreadable. The floor is the app's own body
    size, so a future tidy-up cannot quietly shrink them again.
    """
    # There is no standing Viewer tab any more -- one exists per capture open
    # in the viewer, and this test has no capture. The panel is shown directly:
    # what is under test is the chip strip, not how the panel is reached.
    await app_page.evaluate("() => activatePanel('viewer')")
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
    # There is no standing Viewer tab any more -- one exists per capture open
    # in the viewer, and this test has no capture. The panel is shown directly:
    # what is under test is the chip strip, not how the panel is reached.
    await app_page.evaluate("() => activatePanel('viewer')")
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


# --- what the viewer says about the capture it is showing ---------------------
#
# While a live stream runs, the capture list is a tab away and the packet table
# cannot answer "which host am I watching, and what did I ask it for". A filter
# narrower than you remember looks exactly like a quiet network.


async def _label_for(page, capture):
    await page.evaluate(
        """(c) => {
            captures = [c];
            setViewerLabel(c.id);
        }""",
        capture,
    )
    return await page.inner_text("#viewer-capture-label")


def _viewed(**over):
    base = {
        "id": "cap-1", "name": "slow logons", "server_id": "s1",
        "server_label": "web-01 (root@10.0.0.5)", "interface": "eth0",
        "status": "running", "live_stream": True, "bpf_filter": "tcp port 445",
    }
    return {**base, **over}


async def test_the_viewer_names_the_server_it_is_reading(app_page):
    text = await _label_for(app_page, _viewed())
    assert "web-01 (root@10.0.0.5)" in text


async def test_the_viewer_shows_the_capture_filter(app_page):
    text = await _label_for(app_page, _viewed())
    assert "tcp port 445" in text


async def test_the_viewer_shows_the_interface(app_page):
    assert "eth0" in await _label_for(app_page, _viewed())


async def test_an_unfiltered_capture_claims_nothing_about_its_filter(app_page):
    """Empty is "no filter" OR "taken before the column existed". Saying "no
    capture filter" would assert the first and be wrong about the second."""
    text = await _label_for(app_page, _viewed(bpf_filter=""))
    assert "filter" not in text.lower()
    assert "web-01 (root@10.0.0.5)" in text, "the rest of the line still renders"


async def test_the_capture_name_is_still_the_heading(app_page):
    text = await _label_for(app_page, _viewed())
    assert text.startswith("Capture: slow logons (cap-1)")


# --- the live bar's controls belong to a live capture -------------------------
#
# The bar itself is shown for any capture that was live streamed, finished ones
# included: "this was watched as it recorded" is worth saying about a stored
# capture. Its BUTTONS are not. Stop on a saved capture is offered against
# nothing -- stopLiveCapture() returns early with no live capture id, so it
# silently did nothing, which is worse than a control that is not there.


async def _stored_live_streamed(page, status="completed"):
    """Open a capture that WAS live streamed and has since been saved."""
    await page.evaluate(
        """(status) => {
            captures = [{
                id: 'stored', name: 'finished', server_id: 's1',
                server_label: 'web-01', interface: 'eth0',
                status: status, live_stream: true, bpf_filter: 'tcp port 445',
            }];
            openCaptures = ['stored'];
            viewingCaptureId = 'stored';
            renderCaptureTabs();
            activatePanel('viewer');
            document.getElementById('packet-viewer').hidden = false;
            document.getElementById('live-bar').hidden = false;
            setLiveControls(false);
        }""",
        status,
    )
    await page.wait_for_selector("#live-bar:not([hidden])")


async def _live_bar(page):
    """The bar as it looks while packets are still arriving. The panel has to be
    activated too -- a control inside a display:none panel is hidden whatever
    its own attribute says, which is not what these tests are asking about."""
    await page.evaluate(
        """() => {
            activatePanel('viewer');
            document.getElementById('packet-viewer').hidden = false;
            document.getElementById('live-bar').hidden = false;
            setLiveControls(true);
        }"""
    )
    await page.wait_for_selector("#btn-live-stop", state="visible")


async def test_a_saved_capture_does_not_offer_stop(app_page):
    await _stored_live_streamed(app_page)
    assert await app_page.is_hidden("#btn-live-stop")


async def test_a_saved_capture_does_not_offer_follow(app_page):
    """Nothing left to follow once the list is complete. A checkbox that
    changes nothing is the same bug in miniature."""
    await _stored_live_streamed(app_page)
    assert await app_page.is_hidden("#live-follow")


async def test_the_bar_itself_still_shows_on_a_saved_live_stream(app_page):
    """The controls go, the bar stays: that the capture was watched as it
    recorded is a fact about the capture, not about its state."""
    await _stored_live_streamed(app_page)
    assert await app_page.is_visible("#live-bar")


async def test_a_running_capture_does_offer_stop(app_page):
    """The other half of the rule. A test that only asserted the hiding would
    pass with the controls hidden always."""
    await _live_bar(app_page)
    await app_page.wait_for_selector("#btn-live-stop", state="visible")
    assert await app_page.is_visible("#live-follow")


async def test_opening_a_saved_capture_clears_controls_left_over_from_a_live_one(app_page):
    """The order that actually bites: watch one capture live, then open a saved
    one. Without the clear on the stored path the buttons carried over."""
    await _live_bar(app_page)
    await app_page.wait_for_selector("#btn-live-stop", state="visible")
    await _stored_live_streamed(app_page)
    assert await app_page.is_hidden("#btn-live-stop")
