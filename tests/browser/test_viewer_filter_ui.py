"""The two viewer filter surfaces that only exist in the browser.

Neither can be seen from an HTTP test. The autocomplete is a constant list in
app.js driven by keystrokes, and whether a panel can be scrolled to its end is
a question about CSS -- the API is green either way.

The viewer normally opens only for a completed capture, which needs a real
pcap and a real tshark. These tests unhide the viewer instead and drive the
filter box directly: the handlers are bound at page load regardless of whether
a capture is open, so what is under test here is the same code a real session
runs, without dragging a capture pipeline into a CSS and keyboard test.
"""

from __future__ import annotations

import pytest

from tests.browser.conftest import needs_browser

pytestmark = needs_browser


async def _viewer(page):
    await page.click(".tab[data-tab='viewer']")
    await page.wait_for_selector("#panel-viewer.active")
    # The viewer is empty until a capture is chosen; the filter box and its
    # handlers exist regardless.
    await page.evaluate("document.getElementById('packet-viewer').hidden = false")
    await page.wait_for_selector("#display-filter", state="visible")
    return page


# --- autocomplete ------------------------------------------------------------


async def test_typing_a_protocol_prefix_offers_completions(app_page):
    await _viewer(app_page)
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "tc")

    await app_page.wait_for_selector("#display-filter-ac .filter-ac-item")
    tokens = await app_page.eval_on_selector_all(
        "#display-filter-ac .filter-ac-token", "els => els.map(e => e.textContent)"
    )
    assert "tcp" in tokens


async def test_a_bare_protocol_is_offered_before_its_fields(app_page):
    """`tcp` is a complete filter on its own; `tcp.port` is not. The one that
    can be used as typed comes first."""
    await _viewer(app_page)
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "tc")

    await app_page.wait_for_selector("#display-filter-ac .filter-ac-item")
    tokens = await app_page.eval_on_selector_all(
        "#display-filter-ac .filter-ac-token", "els => els.map(e => e.textContent)"
    )
    assert tokens[0] == "tcp"


async def test_matching_is_not_limited_to_the_start_of_a_field_name(app_page):
    """Nobody remembers that the SYN flag is spelled tcp.flags.syn."""
    await _viewer(app_page)
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "syn")

    await app_page.wait_for_selector("#display-filter-ac .filter-ac-item")
    tokens = await app_page.eval_on_selector_all(
        "#display-filter-ac .filter-ac-token", "els => els.map(e => e.textContent)"
    )
    assert "tcp.flags.syn" in tokens


async def test_enter_takes_the_highlighted_completion(app_page):
    await _viewer(app_page)
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "kerb")
    await app_page.wait_for_selector("#display-filter-ac .filter-ac-item")
    await app_page.keyboard.press("Enter")

    assert await app_page.input_value("#display-filter") == "kerberos"
    assert await app_page.is_hidden("#display-filter-ac")


async def test_a_field_completion_leaves_room_for_the_comparison(app_page):
    """A field name is not a filter by itself, so the caret lands on a space
    ready for the operator rather than jammed against the name."""
    await _viewer(app_page)
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "ip.add")
    await app_page.wait_for_selector("#display-filter-ac .filter-ac-item")
    await app_page.keyboard.press("Tab")

    assert await app_page.input_value("#display-filter") == "ip.addr "


async def test_arrow_keys_move_the_highlight(app_page):
    await _viewer(app_page)
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "tcp.f")
    await app_page.wait_for_selector("#display-filter-ac .filter-ac-item")

    first = await app_page.eval_on_selector(
        "#display-filter-ac .filter-ac-item[aria-selected='true'] .filter-ac-token",
        "e => e.textContent",
    )
    await app_page.keyboard.press("ArrowDown")
    second = await app_page.eval_on_selector(
        "#display-filter-ac .filter-ac-item[aria-selected='true'] .filter-ac-token",
        "e => e.textContent",
    )
    assert first != second


async def test_escape_closes_the_list_without_changing_the_box(app_page):
    await _viewer(app_page)
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "dn")
    await app_page.wait_for_selector("#display-filter-ac .filter-ac-item")
    await app_page.keyboard.press("Escape")

    assert await app_page.is_hidden("#display-filter-ac")
    assert await app_page.input_value("#display-filter") == "dn"


async def test_completing_a_token_mid_expression_leaves_the_rest_alone(app_page):
    """The match is on the token under the caret, not the whole box."""
    await _viewer(app_page)
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "ip.addr == 10.0.0.1 && kerb")
    await app_page.wait_for_selector("#display-filter-ac .filter-ac-item")
    await app_page.keyboard.press("Enter")

    assert await app_page.input_value("#display-filter") == "ip.addr == 10.0.0.1 && kerberos"


async def test_a_fully_typed_token_is_not_offered_back(app_page):
    """Accepting it would change nothing, and it costs a row that a real
    completion could use."""
    await _viewer(app_page)
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "kerberos")
    tokens = await app_page.eval_on_selector_all(
        "#display-filter-ac .filter-ac-token", "els => els.map(e => e.textContent)"
    )
    assert "kerberos" not in tokens
    assert "kerberos.CNameString" in tokens


async def test_the_list_closes_when_nothing_is_left_to_offer(app_page):
    await _viewer(app_page)
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "zzznotafield")
    assert await app_page.is_hidden("#display-filter-ac")


# --- the capture filter library can be scrolled ------------------------------


async def test_the_filter_library_sits_in_a_scroll_container(app_page):
    """.panel is overflow:hidden. Before this the library expanded past the
    bottom of the capture panel and was clipped with no scrollbar anywhere --
    the end of an eighty-entry list was simply unreachable."""
    await app_page.click(".tab[data-tab='capture']")
    await app_page.wait_for_selector("#panel-capture.active")
    await app_page.click("#filter-library-details > summary")
    await app_page.wait_for_selector("#filter-library .filter-group")

    box = await app_page.evaluate("""() => {
        const el = document.querySelector(".filter-library-scroll");
        if (!el) return null;
        const style = getComputedStyle(el);
        return {
            overflowY: style.overflowY,
            scrollable: el.scrollHeight > el.clientHeight,
        };
    }""")
    assert box is not None, "the library has no scroll container"
    assert box["overflowY"] == "auto"
    assert box["scrollable"], "the library fits its box, so nothing is being clipped either"


async def test_the_capture_panel_itself_scrolls(app_page):
    """The library is not the only thing below the fold once it is open: the
    explainers and the capture list are under it."""
    await app_page.click(".tab[data-tab='capture']")
    await app_page.wait_for_selector("#panel-capture.active")
    overflow = await app_page.eval_on_selector(
        "#panel-capture", "el => getComputedStyle(el).overflowY"
    )
    assert overflow == "auto"


async def test_the_library_actually_scrolls_when_asked(app_page):
    await app_page.click(".tab[data-tab='capture']")
    await app_page.wait_for_selector("#panel-capture.active")
    await app_page.click("#filter-library-details > summary")
    await app_page.wait_for_selector("#filter-library .filter-group")

    moved = await app_page.evaluate("""() => {
        const el = document.querySelector(".filter-library-scroll");
        el.scrollTop = 200;
        return el.scrollTop;
    }""")
    assert moved > 0


# --- saved view tabs ---------------------------------------------------------
#
# The API side is covered in tests/test_capture_views.py. What that cannot show
# is the strip itself: whether it stays out of the way until there is something
# to show, which tab reads as selected, and whether the per-tab actions are
# reachable. Driving renderViewTabs directly rather than opening a real capture
# keeps a rendering test out of the capture pipeline -- app.js is a classic
# script, so its top-level bindings are reachable from evaluate().


async def _render_tabs(page, views, active=""):
    await page.click(".tab[data-tab='viewer']")
    await page.wait_for_selector("#panel-viewer.active")
    await page.evaluate(
        """([views, active]) => {
            document.getElementById("packet-viewer").hidden = false;
            savedViews = views;
            activeViewId = active;
            renderViewTabs();
        }""",
        [views, active],
    )


async def test_the_tab_strip_is_hidden_until_a_view_is_saved(app_page):
    """An operator who never saves one should not pay a line of chrome."""
    await _render_tabs(app_page, [])
    assert await app_page.is_hidden("#view-tabs")


async def test_saved_views_appear_as_tabs_after_all_packets(app_page):
    await _render_tabs(app_page, [
        {"id": "v1", "name": "auth traffic", "display_filter": "kerberos"},
        {"id": "v2", "name": "retransmissions", "display_filter": "tcp.analysis.retransmission"},
    ])
    names = await app_page.eval_on_selector_all(
        "#view-tabs .view-tab-name", "els => els.map(e => e.textContent)"
    )
    assert names == ["All packets", "auth traffic", "retransmissions"]


async def test_all_packets_is_selected_by_default_and_cannot_be_removed(app_page):
    """It is not a saved row -- it is what the viewer shows with an empty
    filter, so there is nothing to rename or delete."""
    await _render_tabs(app_page, [{"id": "v1", "name": "dns", "display_filter": "dns"}])
    selected = await app_page.eval_on_selector(
        "#view-tabs .view-tab[aria-selected='true'] .view-tab-name", "e => e.textContent"
    )
    assert selected == "All packets"

    actions = await app_page.eval_on_selector(
        "#view-tabs .view-tab", "el => el.querySelectorAll('[data-action]').length"
    )
    assert actions == 0  # only the tab's own select-view, no per-view buttons


async def test_the_selected_view_offers_download_edit_and_delete(app_page):
    await _render_tabs(
        app_page,
        [{"id": "v1", "name": "dns", "display_filter": "dns"}],
        active="v1",
    )
    actions = await app_page.eval_on_selector_all(
        "#view-tabs .view-tab[aria-selected='true'] .view-tab-action",
        "els => els.map(e => e.dataset.action)",
    )
    assert actions == ["download-view", "edit-view", "delete-view"]


async def test_clicking_a_tab_puts_its_filter_in_the_box(app_page):
    await _render_tabs(app_page, [{"id": "v1", "name": "dns", "display_filter": "dns"}])
    await app_page.click("#view-tabs .view-tab[data-id='v1']")
    assert await app_page.input_value("#display-filter") == "dns"


async def test_typing_over_a_views_filter_deselects_that_view(app_page):
    """The tab claimed you were looking at "dns" while the box said something
    else. Editing by hand means you have left the view."""
    await _render_tabs(
        app_page,
        [{"id": "v1", "name": "dns", "display_filter": "dns"}],
        active="v1",
    )
    await app_page.click("#display-filter")
    await app_page.type("#display-filter", "udp")

    selected = await app_page.eval_on_selector(
        "#view-tabs .view-tab[aria-selected='true'] .view-tab-name", "e => e.textContent"
    )
    assert selected == "All packets"


async def test_a_view_name_cannot_inject_markup_into_the_strip(app_page):
    await _render_tabs(app_page, [
        {"id": "v1", "name": "<img src=x onerror=alert(1)>", "display_filter": "tcp"},
    ])
    name = await app_page.eval_on_selector(
        "#view-tabs .view-tab[data-id='v1'] .view-tab-name", "e => e.textContent"
    )
    assert name == "<img src=x onerror=alert(1)>"
    assert await app_page.eval_on_selector_all("#view-tabs img", "els => els.length") == 0
