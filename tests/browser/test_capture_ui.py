"""The Capture tab, and the filter library that now lives inside it.

The library used to be a tab of its own. Choosing a filter there filled in a
field on a different tab, so the app had to switch tabs to show you what your
click had done -- and the only way to use a capture filter was to leave the
form you were filling in, find the filter, and be sent back. It sits under the
BPF field now, and that arrangement is what these tests hold in place: the
field it fills has to be the field above it.

None of this is visible from the API. There is no endpoint for the filter
library; it is a constant in app.js rendered into the page.
"""

from __future__ import annotations

import pytest

from tests.browser.conftest import needs_browser

pytestmark = needs_browser

HOST = "203.0.113.41"
KEY_NAME = "browser-test-key"


@pytest.fixture(autouse=True)
def clean_slate(api_client):
    for server in api_client.get("/api/servers").json():
        api_client.delete(f"/api/servers/{server['id']}")
    yield


async def _capture_tab(page):
    await page.click(".tab[data-tab='capture']")
    await page.wait_for_selector("#panel-capture.active")
    return page


async def _open_library(page):
    await page.click("#filter-library-details > summary")
    await page.wait_for_selector("#filter-library .filter-group")


async def test_the_tab_bar_no_longer_has_a_filters_tab(app_page):
    """One fewer place to go. The library is not a destination any more."""
    labels = await app_page.eval_on_selector_all(
        ".tab:not([hidden])", "els => els.map(e => e.textContent.trim())"
    )
    assert labels == ["Servers", "Capture", "Viewer", "Admin"]


async def test_switching_tabs_shows_exactly_one_panel(app_page):
    await _capture_tab(app_page)
    assert await app_page.is_visible("#panel-capture")
    assert await app_page.is_hidden("#panel-servers")
    assert await app_page.is_hidden("#panel-viewer")


async def test_the_filter_library_sits_below_the_bpf_field_it_fills(app_page):
    """Position is the feature, so it is what the test asserts.

    DOCUMENT_POSITION_FOLLOWING (4) means the library comes after the field in
    document order -- on screen, below it -- and both are inside the Capture
    panel, so choosing a filter leaves the answer visible above the list.
    """
    await _capture_tab(app_page)
    relation = await app_page.evaluate(
        """() => {
            const field = document.getElementById("cap-bpf");
            const library = document.getElementById("filter-library-details");
            return {
                inCapturePanel: document.getElementById("panel-capture").contains(library),
                follows: Boolean(field.compareDocumentPosition(library) & 4),
            };
        }"""
    )
    assert relation == {"inCapturePanel": True, "follows": True}


async def test_the_filter_library_starts_collapsed(app_page):
    """It is eighty-odd expressions; the field above is the answer for anyone
    who already knows what they want to type."""
    await _capture_tab(app_page)
    assert await app_page.eval_on_selector("#filter-library-details", "el => el.open") is False
    assert await app_page.is_hidden("#filter-library-search")


async def test_choosing_a_filter_fills_the_field_and_collapses_the_library(app_page):
    """The click's only feedback is the field above, so the list has to close.

    If the library stayed open it would cover the field it had just filled in,
    and nothing on screen would confirm the click did anything at all.
    """
    await _capture_tab(app_page)
    await _open_library(app_page)

    row = app_page.locator("#filter-library tr").first
    expression = (await row.locator(".filter-expr code").text_content()).strip()
    await row.locator("button[data-action='use-library-filter']").click()

    assert await app_page.input_value("#cap-bpf") == expression
    assert await app_page.eval_on_selector("#filter-library-details", "el => el.open") is False


async def test_searching_the_library_narrows_it_to_what_matches(app_page):
    await _capture_tab(app_page)
    await _open_library(app_page)
    before = await app_page.locator("#filter-library tr").count()

    await app_page.fill("#filter-library-search", "dns")
    await app_page.wait_for_function(
        "count => document.querySelectorAll('#filter-library tr').length < count",
        arg=before,
    )

    rows = await app_page.eval_on_selector_all(
        "#filter-library tr", "els => els.map(e => e.textContent.toLowerCase())"
    )
    assert rows, "a search for dns should match something"
    # A row can match on its group heading rather than its own text, which is
    # why this checks the section it sits in as well.
    sections = await app_page.eval_on_selector_all(
        "#filter-library section", "els => els.map(e => e.textContent.toLowerCase())"
    )
    assert all("dns" in section for section in sections)


async def test_a_search_that_matches_nothing_says_so(app_page):
    """An empty panel would read as a broken library."""
    await _capture_tab(app_page)
    await _open_library(app_page)
    await app_page.fill("#filter-library-search", "zzzznotafilter")

    empty = await app_page.wait_for_selector("#filter-library .empty-state")
    assert "zzzznotafilter" in await empty.text_content()


async def test_an_unreachable_server_still_leaves_any_in_the_interface_list(app_page, api_client):
    """The interface list comes off the host by SSH, so it can simply fail.

    When it does the dropdown must keep "any" rather than emptying out: an
    empty dropdown is a form that cannot be submitted, on a host that might
    only be briefly unreachable. The request really does fail here -- 203.0.113
    is unroutable by definition -- so this is the failure path, not a mock.
    """
    api_client.post(
        "/api/servers",
        json={
            "name": "unreachable",
            "hostname": HOST,
            "port": 22,
            "username": "capture-user",
            "ssh_key_name": KEY_NAME,
            "use_sudo": False,
        },
    ).raise_for_status()

    # Waiting for the failed response, not just for the page to settle: "any"
    # is also what the dropdown holds before anything is asked for, so a test
    # that asserted too early would pass without the failure path ever running.
    async with app_page.expect_response(lambda r: r.url.endswith("/interfaces")) as failure:
        await app_page.reload()
        await app_page.wait_for_selector("#app-screen:not([hidden])")
        await _capture_tab(app_page)
    assert (await failure.value).status == 502

    await app_page.wait_for_function(
        "() => document.getElementById('cap-interface').options.length > 0"
    )
    interfaces = await app_page.eval_on_selector_all(
        "#cap-interface option", "els => els.map(e => e.value)"
    )
    assert interfaces == ["any"]


async def test_the_capture_tab_reports_no_console_errors(app_page):
    await _capture_tab(app_page)
    await _open_library(app_page)
    assert app_page.console_errors == []


# --- composing a second filter ------------------------------------------------
#
# Both insertion paths used to assign to the box, so a second pick wiped the
# first and a filter like "this host, and only its SMB traffic" could not be
# built from the library at all -- only typed by hand.
#
# Which combinator is wanted cannot be read off the click, and neither default
# is safe. The library is mostly port and protocol rows, where a second pick
# means `or` (`tcp port 80 and tcp port 443` matches nothing); a host row
# combined with a protocol row means `and`. So the pick offers the same four
# modes the display filter's right-click menu already does, and a BPF filter
# that matches nothing is never composed silently.


async def _menu_labels(page):
    return await page.eval_on_selector_all(
        "#filter-menu .filter-menu-item", "els => els.map(e => e.textContent)"
    )


async def _pick_library_row(page, index: int = 0) -> str:
    row = page.locator("#filter-library tr").nth(index)
    expression = (await row.locator(".filter-expr code").text_content()).strip()
    await row.locator("button[data-action='use-library-filter']").click()
    return expression


async def test_a_pick_into_an_empty_box_does_not_ask_which_combinator(app_page):
    """There is nothing to combine with, so the menu would be four ways of
    spelling one outcome."""
    await _capture_tab(app_page)
    await _open_library(app_page)

    expression = await _pick_library_row(app_page)

    assert await app_page.input_value("#cap-bpf") == expression
    assert await app_page.locator("#filter-menu").count() == 0


async def test_a_second_pick_asks_rather_than_overwriting(app_page):
    await _capture_tab(app_page)
    await _open_library(app_page)
    first = await _pick_library_row(app_page)

    await _open_library(app_page)
    await _pick_library_row(app_page, 1)

    await app_page.wait_for_selector("#filter-menu")
    assert await app_page.input_value("#cap-bpf") == first, \
        "the box must not change until a combinator is chosen"
    labels = await _menu_labels(app_page)
    assert any("and this" in label for label in labels)
    assert any("or this" in label for label in labels)


async def test_or_composes_both_sides_in_parentheses(app_page):
    """`a and b or c` parses as `(a and b) or c`, so an unparenthesised append
    rebinds an expression the operator already had in the box."""
    await _capture_tab(app_page)
    await _open_library(app_page)
    first = await _pick_library_row(app_page)

    await _open_library(app_page)
    second = await _pick_library_row(app_page, 1)
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('or this')")

    assert await app_page.input_value("#cap-bpf") == f"({first}) or ({second})"


async def test_and_composes_both_sides_in_parentheses(app_page):
    await _capture_tab(app_page)
    await _open_library(app_page)
    first = await _pick_library_row(app_page)

    await _open_library(app_page)
    second = await _pick_library_row(app_page, 1)
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('and this')")

    assert await app_page.input_value("#cap-bpf") == f"({first}) and ({second})"


async def test_replace_is_still_available_from_the_menu(app_page):
    await _capture_tab(app_page)
    await _open_library(app_page)
    await _pick_library_row(app_page)

    await _open_library(app_page)
    second = await _pick_library_row(app_page, 1)
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('Replace with:')")

    assert await app_page.input_value("#cap-bpf") == second


async def test_the_composed_filter_never_uses_the_c_operators(app_page):
    """`&` and `|` are refused by the capture request validator, because the
    command is assembled as a string and those are shell metacharacters.
    libpcap spells the same thing `and` and `or`."""
    await _capture_tab(app_page)
    await _open_library(app_page)
    await _pick_library_row(app_page)

    await _open_library(app_page)
    await _pick_library_row(app_page, 1)
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('and this')")

    composed = await app_page.input_value("#cap-bpf")
    assert "&&" not in composed and "||" not in composed


async def test_a_suggestion_chip_composes_like_a_library_row(app_page):
    """A chip and a library row are the same gesture; picking a second chip
    should not wipe the first either."""
    await _capture_tab(app_page)
    await _open_library(app_page)
    first = await _pick_library_row(app_page)

    await app_page.click("#bpf-suggestions .filter-chip")
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('or this')")

    composed = await app_page.input_value("#cap-bpf")
    assert composed.startswith(f"({first}) or (")


async def test_the_display_filter_chips_are_left_alone(app_page):
    """The display filter already has composition, on the right-click menu over
    a packet field. Its chips are worked examples -- a starting point rather
    than something to build onto -- and they still replace."""
    await _capture_tab(app_page)
    labels = await app_page.eval_on_selector_all(
        "#display-filter-suggestions .filter-chip", "els => els.map(e => e.textContent)"
    )
    assert labels, "the display filter should still offer its chips"
