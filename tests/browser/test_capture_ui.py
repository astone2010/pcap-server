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
    # Saved filters are per-user and this suite shares one account, so a filter
    # left behind by one test is a row in another test's library.
    for f in api_client.get("/api/filters").json():
        api_client.delete(f"/api/filters/{f['id']}")
    yield


async def _capture_tab(page):
    await page.click(".tab[data-tab='capture']")
    await page.wait_for_selector("#panel-capture.active")
    return page


async def _open_library(page):
    await page.click("#filter-library-details > summary")
    await page.wait_for_selector("#filter-library .filter-group")


async def test_the_tab_bar_is_only_the_work(app_page):
    """What is left on the bar is what you are doing: the servers you capture
    from, the capture you are setting up, and the captures you have open.

    Three things came off it. The filter library was a tab and is now a
    collapsible under the field it fills. The Viewer had a standing tab that
    led to an empty panel most of a session; captures open as tabs of their own
    instead. And Admin moved to the toolbar -- it is somewhere you go
    occasionally to change how the app runs, not something you work in.
    """
    labels = await app_page.eval_on_selector_all(
        ".tab-bar .tab:not([hidden])", "els => els.map(e => e.textContent.trim())"
    )
    assert labels == ["Servers", "Capture"]


async def test_admin_is_in_the_toolbar_not_the_tab_bar(app_page):
    assert await app_page.locator(".toolbar #admin-tab").count() == 1
    assert await app_page.locator(".tab-bar #admin-tab").count() == 0


async def test_the_admin_button_still_opens_the_admin_panel(app_page):
    """It is outside the tab bar, so the delegated handler there cannot reach
    it and it carries its own listener. That is exactly the kind of wiring that
    breaks silently."""
    await app_page.click("#admin-tab")
    await app_page.wait_for_selector("#panel-admin.active")
    assert await app_page.is_hidden("#panel-servers")


async def test_the_admin_button_shows_that_it_is_selected(app_page):
    """A toolbar button cannot show selection the way a tab does, and the panel
    it opens takes over the window -- so nothing else on screen would say which
    one you are looking at."""
    await app_page.click("#admin-tab")
    await app_page.wait_for_selector("#admin-tab.active")
    await app_page.click(".tab[data-tab='capture']")
    await app_page.wait_for_selector("#panel-capture.active")
    assert await app_page.locator("#admin-tab.active").count() == 0


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


async def test_choosing_a_filter_fills_the_field_and_leaves_the_library_open(app_page):
    """The library used to collapse itself on every choice.

    That was the only feedback the click had landed -- the field it fills sits
    above the list -- but it made choosing a second filter a matter of
    reopening the list, which is most of the work in building one up. The
    preview bar is the feedback now, so the list can stay where it is.
    """
    await _capture_tab(app_page)
    await _open_library(app_page)

    row = app_page.locator("#filter-library tr").first
    expression = (await row.locator(".filter-expr code").text_content()).strip()
    await row.locator("button[data-action='use-library-filter']").click()

    assert await app_page.input_value("#cap-bpf") == expression
    assert await app_page.eval_on_selector("#filter-library-details", "el => el.open") is True
    assert await app_page.text_content("#filter-preview-expr") == expression


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

    second = await _pick_library_row(app_page, 1)
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('or this')")

    assert await app_page.input_value("#cap-bpf") == f"({first}) or ({second})"


async def test_and_composes_both_sides_in_parentheses(app_page):
    await _capture_tab(app_page)
    await _open_library(app_page)
    first = await _pick_library_row(app_page)

    second = await _pick_library_row(app_page, 1)
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('and this')")

    assert await app_page.input_value("#cap-bpf") == f"({first}) and ({second})"


async def test_replace_is_still_available_from_the_menu(app_page):
    await _capture_tab(app_page)
    await _open_library(app_page)
    await _pick_library_row(app_page)

    second = await _pick_library_row(app_page, 1)
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('Replace with:')")

    assert await app_page.input_value("#cap-bpf") == second


async def test_the_composed_filter_never_uses_the_c_operators(app_page):
    """The composed filter reads like the rows it was composed from.

    This used to be enforcement: the validator refused `&` and `|` outright.
    That ban also refused every tcpflags filter in the library, so it was
    narrowed, and both spellings are accepted now. The composition still uses
    the words, because every row in the library and every example in the man
    page does -- a filter that switched notation halfway would read as
    something the operator had not chosen.
    """
    await _capture_tab(app_page)
    await _open_library(app_page)
    await _pick_library_row(app_page)

    await _pick_library_row(app_page, 1)
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('and this')")

    composed = await app_page.input_value("#cap-bpf")
    assert "&&" not in composed and "||" not in composed


async def test_the_capture_filter_has_no_example_chips(app_page):
    """The library replaced them; a second, smaller list of examples beside it
    was only something more to read."""
    await _capture_tab(app_page)
    assert await app_page.locator("#bpf-suggestions").count() == 0
    assert await app_page.locator(".bpf-filter .filter-chip").count() == 0


async def test_the_display_filter_chips_are_left_alone(app_page):
    """The display filter already has composition, on the right-click menu over
    a packet field. Its chips are worked examples -- a starting point rather
    than something to build onto -- and they still replace."""
    await _capture_tab(app_page)
    labels = await app_page.eval_on_selector_all(
        "#display-filter-suggestions .filter-chip", "els => els.map(e => e.textContent)"
    )
    assert labels, "the display filter should still offer its chips"


async def test_several_filters_can_be_chosen_without_reopening_the_library(app_page):
    """The point of the whole change.

    Three picks, one opening of the list. Before this the library collapsed on
    every choice, so the second and third each cost a reopen -- and the tests
    for composition in this file had to reopen it between picks, which is how
    obvious the friction was from the inside.
    """
    await _capture_tab(app_page)
    await _open_library(app_page)

    first = await _pick_library_row(app_page, 0)
    second = await _pick_library_row(app_page, 1)
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('or this')")
    third = await _pick_library_row(app_page, 2)
    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('and this')")

    assert await app_page.input_value("#cap-bpf") == f"(({first}) or ({second})) and ({third})"
    assert await app_page.eval_on_selector("#filter-library-details", "el => el.open") is True


async def test_the_preview_follows_the_field_when_it_is_typed_into(app_page):
    """The field stays the source of truth. A bar that only tracked clicks
    would disagree with the field the moment anyone edited it by hand."""
    await _capture_tab(app_page)
    await _open_library(app_page)
    await _pick_library_row(app_page)

    await app_page.fill("#cap-bpf", "tcp port 9999")
    await app_page.wait_for_function(
        "() => document.getElementById('filter-preview-expr').textContent === 'tcp port 9999'"
    )


async def test_the_preview_is_hidden_until_there_is_something_to_preview(app_page):
    await _capture_tab(app_page)
    await _open_library(app_page)
    assert await app_page.is_hidden("#filter-preview")

    await _pick_library_row(app_page)
    assert await app_page.is_visible("#filter-preview")


async def test_clear_empties_the_field_without_leaving_the_library(app_page):
    """Starting over is a normal part of composing, and by then the field can
    be scrolled out of sight behind the list."""
    await _capture_tab(app_page)
    await _open_library(app_page)
    await _pick_library_row(app_page)

    await app_page.click("#filter-preview-clear")

    assert await app_page.input_value("#cap-bpf") == ""
    assert await app_page.is_hidden("#filter-preview")
    assert await app_page.eval_on_selector("#filter-library-details", "el => el.open") is True


# --- library contents ---------------------------------------------------------


async def test_the_library_offers_a_fragment_filter(app_page):
    """A fragment is either flagged as having more behind it or sits at a
    non-zero offset, so the filter has to test both. Matching only the offset
    misses the first fragment -- the one carrying the headers."""
    await _capture_tab(app_page)
    await _open_library(app_page)
    await app_page.fill("#filter-library-search", "fragment")
    await app_page.wait_for_selector("#filter-library tr")

    rows = await app_page.eval_on_selector_all(
        "#filter-library tr", "els => els.map(e => e.textContent)"
    )
    joined = " ".join(rows)
    assert "ip[6] & 0x20 != 0 or ip[6:2] & 0x1fff != 0" in joined
    assert "ip[6:2] & 0x1fff != 0" in joined


async def test_the_library_covers_ntlm_by_its_transports(app_page):
    """NTLMSSP has no port of its own -- it rides inside SMB, RPC, LDAP and
    HTTP at an offset that moves with the enclosing protocol, and BPF matches
    fixed offsets. So the capture-side entry records the transports, and the
    row says where the real filter lives."""
    await _capture_tab(app_page)
    await _open_library(app_page)
    await app_page.fill("#filter-library-search", "ntlm")
    await app_page.wait_for_selector("#filter-library tr")

    rows = await app_page.eval_on_selector_all(
        "#filter-library tr", "els => els.map(e => e.textContent)"
    )
    assert rows, "the library should offer something for ntlm"
    joined = " ".join(rows)
    assert "tcp port 445" in joined
    assert "ntlmssp display filter" in joined, \
        "the row must point at the display filter, or it reads as an NTLM capture filter"


async def test_ntlmssp_is_offered_as_a_display_filter_protocol(app_page):
    """Where an NTLM filter actually works: the Viewer, where the dissector
    can find it inside whatever carried it."""
    protocols = await app_page.evaluate(
        "() => DISPLAY_FILTER_PROTOCOLS.map(p => p[0])"
    )
    assert "ntlmssp" in protocols


async def test_the_ntlmssp_display_fields_are_offered_too(app_page):
    """Names checked against `tshark -G fields`, not written from memory."""
    fields = await app_page.evaluate("() => DISPLAY_FILTER_FIELDS.map(f => f[0])")
    for name in (
        "ntlmssp.messagetype",
        "ntlmssp.auth.username",
        "ntlmssp.auth.domain",
        "ntlmssp.ntlmserverchallenge",
    ):
        assert name in fields, name


# --- warning about a combination that will not match anything ---------------
#
# The menu already existed to avoid guessing the combinator. It was not enough:
# it offered `and` as an equal-weight choice even where `and` is provably
# wrong, and a filter that matches nothing does not announce itself -- the
# capture runs for its full duration and comes back empty, which reads exactly
# like "there was no such traffic".


async def _menu_warning(page):
    return await page.eval_on_selector_all(
        "#filter-menu .filter-menu-warn", "els => els.map(e => e.textContent)"
    )


async def test_and_is_flagged_when_it_would_match_nothing(app_page):
    """Two services on one packet needs two port slots and a coincidence."""
    await _capture_tab(app_page)
    await app_page.fill("#cap-bpf", "port 88")
    await _open_library(app_page)
    await app_page.fill("#filter-library-search", "kerberos password change")

    await _pick_library_row(app_page)

    await app_page.wait_for_selector("#filter-menu")
    warnings = await _menu_warning(app_page)
    assert warnings, "combining two different services with `and` should be flagged"
    assert "or" in warnings[0].lower(), "the warning has to say what to do instead"


async def test_the_flagged_option_is_still_clickable(app_page):
    """A warning the operator can overrule is one they will read.

    Taking the option away would make the check something to resent the first
    time it is wrong about a filter they meant.
    """
    await _capture_tab(app_page)
    await app_page.fill("#cap-bpf", "port 88")
    await _open_library(app_page)
    await app_page.fill("#filter-library-search", "kerberos password change")
    second = await _pick_library_row(app_page)

    await app_page.wait_for_selector("#filter-menu")
    await app_page.click("#filter-menu .filter-menu-item:has-text('and this')")

    assert await app_page.input_value("#cap-bpf") == f"(port 88) and ({second})"


async def test_or_is_never_flagged(app_page):
    """`or` is the answer the warning points at, so it cannot carry one itself."""
    await _capture_tab(app_page)
    await app_page.fill("#cap-bpf", "port 88")
    await _open_library(app_page)
    await app_page.fill("#filter-library-search", "kerberos password change")
    await _pick_library_row(app_page)

    await app_page.wait_for_selector("#filter-menu")
    labels = await _menu_labels(app_page)
    warn_count = len(await _menu_warning(app_page))
    assert any("or this" in label for label in labels)
    assert warn_count == 1, "only the `and` option should be carrying a warning"


async def test_a_harmless_combination_carries_no_warning(app_page):
    """A host row and a protocol row is exactly what `and` is for."""
    await _capture_tab(app_page)
    await app_page.fill("#cap-bpf", "host 10.0.0.1")
    await _open_library(app_page)
    await app_page.fill("#filter-library-search", "kerberos")

    await _pick_library_row(app_page)

    await app_page.wait_for_selector("#filter-menu")
    assert await _menu_warning(app_page) == []


async def test_the_browser_check_agrees_with_the_python_one(app_page):
    """The two copies of the port model must not drift.

    backend/bpf.py is the authority -- it also compiles the expression with the
    real tcpdump, which the browser cannot do. The browser copy exists only for
    timing: it answers with no round trip, so the menu can carry the warning at
    the moment of the click. That is worth having only while the two agree, and
    nothing else in the suite would notice them diverging.
    """
    from backend import bpf

    corpus = [
        "port 88 and port 464",
        "tcp port 80 and tcp port 443",
        "port 88 and port 464 and port 53",
        "tcp port 80 and udp port 53",
        "src port 80 and src port 443",
        "((port 88) and (port 464)) and (tcp port 445 or tcp port 135) and (port 53)",
        "(tcp port 445 or tcp port 135 or tcp port 389) and (port 464)",
        "port 88 or port 389",
        "host 10.0.0.1 and tcp port 445",
        "host 10.0.0.1 and (tcp port 445 or port 88)",
        "not (tcp port 22 and host 10.0.0.1)",
        "",
        "tcp",
        "net 192.168.1.0/24",
        "(port 80 or host 10.0.0.1) and port 443",
        "port 88 and port 88",
        "tcp port 445 or port 137 or port 138 or tcp port 139",
        "portrange 1-100 and port 500 and port 600",
        "port domain and port http and port https",
    ]

    in_browser = await app_page.evaluate(
        "exprs => exprs.map(e => { const w = bpfCheckExpression(e); return w ? w.code : null; })",
        corpus,
    )
    in_python = [(w.code if (w := bpf.structural_check(e)) else None) for e in corpus]

    mismatches = [(e, js, py) for e, js, py in zip(corpus, in_browser, in_python) if js != py]
    assert not mismatches, f"browser and server models disagree: {mismatches}"


# --- the capture filter on the capture list ----------------------------------
#
# A capture used to say where it ran and what it was called, and nothing about
# what it was selecting for -- so an empty packet list gave no way to tell "the
# network was quiet" from "the filter excluded it". Those are opposite
# conclusions from the same screen.
#
# The list is driven directly here rather than by taking real captures: what is
# under test is the badge, and a real capture needs a target host, a real
# tcpdump and a pcap coming back.


async def _list(page, *captures):
    await _capture_tab(page)
    await page.evaluate(
        """(rows) => {
            captures = rows;
            activeServers = [];
            renderCaptures();
        }""",
        list(captures),
    )
    await page.wait_for_selector(".capture-item")


def _capture(**over):
    base = {
        "id": "11111111-2222-3333-4444-555555555555",
        "name": "a capture",
        "server_id": "s1",
        "server_label": "web-01 (root@10.0.0.5)",
        "status": "completed",
        "interface": "eth0",
        "live_stream": False,
        "bpf_filter": "",
        "packet_count": 12,
        "file_size": 2048,
        "error": "",
        "command": "tcpdump -w /tmp/x.pcap -i eth0",
    }
    return {**base, **over}


async def test_a_filter_the_library_knows_is_shown_by_its_name(app_page):
    """`tcp port 443` is HTTPS in the library, and the library is where the
    name comes from -- one list, so a filter cannot be offered under one name
    and listed under another."""
    await _list(app_page, _capture(bpf_filter="tcp port 443"))
    assert (await app_page.inner_text(".badge-filter")).strip() == "HTTPS"


async def test_the_badge_carries_the_expression_itself_in_its_title(app_page):
    """The name describes the filter; the title is the filter. A capture was
    run with an expression, not with a description of one."""
    await _list(app_page, _capture(bpf_filter="tcp port 443"))
    title = await app_page.get_attribute(".badge-filter", "title")
    assert "tcp port 443" in title


async def test_an_expression_the_library_does_not_know_is_shown_verbatim(app_page):
    """No partial matching. Naming `tcp port 443 and host 10.0.0.1` "HTTPS"
    would name the capture after the broader half of its own filter."""
    composed = "tcp port 443 and host 10.0.0.1"
    await _list(app_page, _capture(bpf_filter=composed))
    assert (await app_page.inner_text(".badge-filter")).strip() == composed
    # And it is marked as a raw expression rather than a name, which is what
    # sets it in a monospace face.
    assert await app_page.locator(".badge-filter-raw").count() == 1


async def test_an_unfiltered_capture_carries_no_badge_at_all(app_page):
    """Empty means "no filter" OR "taken before the column existed", and the
    two are indistinguishable. A badge either way would be a claim; silence is
    not."""
    await _list(app_page, _capture(bpf_filter=""))
    assert await app_page.locator(".badge-filter").count() == 0


async def test_the_badge_is_not_uppercased_like_the_status_badges(app_page):
    """`HOST 10.0.0.1` does not read as a BPF expression. The status badges
    beside it are labels for states; this is content read off the capture."""
    await _list(app_page, _capture(bpf_filter="host 10.0.0.1"))
    transform = await app_page.eval_on_selector(
        ".badge-filter", "el => getComputedStyle(el).textTransform"
    )
    assert transform == "none"


# --- requiring a name --------------------------------------------------------


async def test_the_capture_form_refuses_to_start_without_a_name(app_page):
    """Required by the form and not by the API -- see CaptureRequest. What is
    asserted is that nothing is sent, not that a 4xx comes back."""
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
            document.getElementById('cap-name').value = '';
        }"""
    )
    await app_page.click("#btn-start-capture")
    await app_page.wait_for_selector("#cap-name-msg.save-filter-bad")
    assert await app_page.evaluate("window.__posted") is False


async def test_the_name_field_is_the_one_focused_when_it_is_missing(app_page):
    """Saying no is half of it; the other half is putting the cursor where the
    answer goes."""
    await _capture_tab(app_page)
    await app_page.evaluate(
        """() => {
            const sel = document.getElementById('cap-server');
            sel.innerHTML = '<option value="s1">s1</option>';
            sel.value = 's1';
            document.getElementById('cap-name').value = '';
        }"""
    )
    await app_page.click("#btn-start-capture")
    assert await app_page.evaluate("() => document.activeElement.id") == "cap-name"


# --- the pre-capture summary -------------------------------------------------


async def test_starting_a_capture_asks_first_and_says_what_it_will_do(app_page):
    """Three of the six fields mean "the server maximum" when left blank, so
    what is about to happen is not legible from the form itself."""
    await _capture_tab(app_page)
    await app_page.evaluate(
        """() => {
            window.__posted = false;
            window.__origFetch = window.fetch;
            window.fetch = (url, opts) => {
                if (String(url).endsWith('/api/captures') && opts && opts.method === 'POST') {
                    window.__posted = true;
                    return Promise.resolve(new Response('{"id":"x"}', {
                        status: 200, headers: { 'Content-Type': 'application/json' },
                    }));
                }
                return window.__origFetch(url, opts);
            };
            const sel = document.getElementById('cap-server');
            sel.innerHTML = '<option value="s1">web-01</option>';
            sel.value = 's1';
        }"""
    )
    await app_page.fill("#cap-name", "slow logons")
    await app_page.fill("#cap-bpf", "tcp port 445")

    # expect_event rather than a handler plus a poll: the click blocks in the
    # page until the dialog is answered, so there is nothing to wait for
    # afterwards that would not already have happened.
    async with app_page.expect_event("dialog") as info:
        await app_page.click("#btn-start-capture")
    dialog = await info.value
    summary = dialog.message
    await dialog.dismiss()

    assert "slow logons" in summary
    assert "web-01" in summary
    assert "tcp port 445" in summary
    # Dismissed, so nothing was sent.
    assert await app_page.evaluate("window.__posted") is False


async def test_a_blank_duration_is_described_rather_than_shown_as_blank(app_page):
    """An empty Duration box does not look like five minutes of capture."""
    await _capture_tab(app_page)
    summary = await app_page.evaluate(
        """() => describeCapture({
            name: 'x', interface: 'any', bpf_filter: '', live_stream: false,
        }, 'web-01')"""
    )
    assert "the server maximum" in summary
    assert "none" in summary


# --- captures open as tabs of their own --------------------------------------


async def test_there_is_no_viewer_tab_until_a_capture_is_open(app_page):
    assert await app_page.locator(".tab-capture").count() == 0
    assert await app_page.locator("#capture-tab-strip").inner_html() == ""


async def test_an_open_capture_gets_a_tab_labelled_with_its_name(app_page):
    await app_page.evaluate(
        """() => {
            captures = [{ id: 'cap-1', name: 'slow logons', status: 'completed',
                          server_id: 's1', live_stream: false, bpf_filter: '' }];
            openCaptures = ['cap-1'];
            viewingCaptureId = 'cap-1';
            renderCaptureTabs();
        }"""
    )
    await app_page.wait_for_selector(".tab-capture")
    assert (await app_page.inner_text(".tab-capture-name")).strip() == "slow logons"
    assert await app_page.locator(".tab-capture.active").count() == 1


async def test_two_captures_open_at_once_are_two_tabs(app_page):
    """The point of the change: comparing two captures is clicking between
    them, not going back to the list each time."""
    await app_page.evaluate(
        """() => {
            captures = [
                { id: 'a', name: 'before', status: 'completed', server_id: 's', live_stream: false, bpf_filter: '' },
                { id: 'b', name: 'after', status: 'completed', server_id: 's', live_stream: false, bpf_filter: '' },
            ];
            openCaptures = ['a', 'b'];
            viewingCaptureId = 'b';
            renderCaptureTabs();
        }"""
    )
    await app_page.wait_for_selector(".tab-capture")
    names = await app_page.eval_on_selector_all(
        ".tab-capture-name", "els => els.map(e => e.textContent.trim())"
    )
    assert names == ["before", "after"]
    active = await app_page.eval_on_selector(
        ".tab-capture.active", "el => el.dataset.captureId"
    )
    assert active == "b"


async def test_a_capture_with_no_name_falls_back_to_a_short_id(app_page):
    await app_page.evaluate(
        """() => {
            captures = [{ id: 'abcdef0123456789', name: '', status: 'completed',
                          server_id: 's', live_stream: false, bpf_filter: '' }];
            openCaptures = ['abcdef0123456789'];
            viewingCaptureId = 'abcdef0123456789';
            renderCaptureTabs();
        }"""
    )
    await app_page.wait_for_selector(".tab-capture")
    assert (await app_page.inner_text(".tab-capture-name")).strip() == "abcdef01"
    # The whole id is still reachable, on the tab's title.
    assert await app_page.get_attribute(".tab-capture", "title") == "abcdef0123456789"


async def test_closing_the_last_tab_leaves_the_viewer_altogether(app_page):
    """Not an empty Viewer panel with no tab pointing at it."""
    await app_page.evaluate(
        """() => {
            captures = [{ id: 'only', name: 'only', status: 'completed',
                          server_id: 's', live_stream: false, bpf_filter: '' }];
            openCaptures = ['only'];
            viewingCaptureId = 'only';
            renderCaptureTabs();
            activatePanel('viewer');
        }"""
    )
    await app_page.wait_for_selector("#panel-viewer.active")
    await app_page.click(".tab-close")
    await app_page.wait_for_selector("#panel-capture.active")
    assert await app_page.locator(".tab-capture").count() == 0
    assert await app_page.evaluate("viewingCaptureId") is None


async def test_closing_a_background_tab_leaves_the_open_one_alone(app_page):
    await app_page.evaluate(
        """() => {
            captures = [
                { id: 'a', name: 'before', status: 'completed', server_id: 's', live_stream: false, bpf_filter: '' },
                { id: 'b', name: 'after', status: 'completed', server_id: 's', live_stream: false, bpf_filter: '' },
            ];
            openCaptures = ['a', 'b'];
            viewingCaptureId = 'b';
            renderCaptureTabs();
            activatePanel('viewer');
        }"""
    )
    await app_page.wait_for_selector(".tab-capture")
    await app_page.click('.tab-capture[data-capture-id="a"] .tab-close')
    await app_page.wait_for_function("() => openCaptures.length === 1")
    assert await app_page.evaluate("viewingCaptureId") == "b"
    assert await app_page.is_visible("#panel-viewer")


async def test_a_capture_deleted_elsewhere_loses_its_tab(app_page):
    """syncCaptureTabs runs on every capture-list refresh. A tab pointing at a
    capture that no longer exists is a tab that opens an error."""
    await app_page.evaluate(
        """() => {
            captures = [{ id: 'gone', name: 'gone', status: 'completed',
                          server_id: 's', live_stream: false, bpf_filter: '' }];
            openCaptures = ['gone'];
            viewingCaptureId = 'gone';
            renderCaptureTabs();
            activatePanel('viewer');
            captures = [];
            syncCaptureTabs();
        }"""
    )
    await app_page.wait_for_selector("#panel-capture.active")
    assert await app_page.locator(".tab-capture").count() == 0


# --- the operator's own saved filters ----------------------------------------
#
# These go through the real API rather than driving the render directly: the
# feature is a round trip -- type an expression, name it, come back and find it
# -- and a test that only rendered a list would not exercise the half that
# persists.


async def _reload_library(page):
    await page.evaluate("() => loadCustomFilters()")
    await page.wait_for_function("() => customFilters !== undefined")


async def test_a_saved_filter_appears_in_its_own_group_at_the_top(app_page, api_client):
    api_client.post(
        "/api/filters", json={"label": "my kerberos", "expression": "port 88 or port 464"}
    ).raise_for_status()
    await _capture_tab(app_page)
    await _reload_library(app_page)
    await _open_library(app_page)

    await app_page.wait_for_selector(".filter-group-own")
    groups = await app_page.eval_on_selector_all(
        "#filter-library .filter-group h4", "els => els.map(e => e.textContent.trim())"
    )
    assert groups[0] == "Your filters", "saved filters should not be below eighty built-ins"
    assert "my kerberos" in await app_page.inner_text(".filter-group-own")


async def test_using_a_saved_filter_fills_in_the_field_above(app_page, api_client):
    """The same thing a built-in row does. A saved filter that could not be
    used would be a list of strings."""
    api_client.post(
        "/api/filters", json={"label": "mine", "expression": "udp port 5353"}
    ).raise_for_status()
    await _capture_tab(app_page)
    await _reload_library(app_page)
    await _open_library(app_page)
    await app_page.click('.filter-group-own [data-action="use-library-filter"]')
    assert await app_page.input_value("#cap-bpf") == "udp port 5353"


async def test_save_filter_appears_only_once_there_is_something_to_save(app_page):
    """A Save button beside an empty box offers to save nothing."""
    await _capture_tab(app_page)
    await app_page.fill("#cap-bpf", "")
    assert await app_page.is_hidden("#btn-save-filter")
    await app_page.fill("#cap-bpf", "tcp port 22")
    await app_page.wait_for_selector("#btn-save-filter", state="visible")
    await app_page.fill("#cap-bpf", "   ")
    await app_page.wait_for_selector("#btn-save-filter", state="hidden")


async def test_save_filter_sits_to_the_left_of_the_field(app_page):
    await _capture_tab(app_page)
    await app_page.fill("#cap-bpf", "tcp port 22")
    button = await app_page.locator("#btn-save-filter").bounding_box()
    field = await app_page.locator("#cap-bpf").bounding_box()
    assert button["x"] + button["width"] <= field["x"]
    assert abs((button["y"] + button["height"] / 2) - (field["y"] + field["height"] / 2)) <= 3


async def test_a_filter_chosen_from_the_library_brings_the_button_too(app_page):
    """The field changes by code there, not by typing."""
    await _capture_tab(app_page)
    await app_page.fill("#cap-bpf", "")
    await _open_library(app_page)
    await _pick_library_row(app_page)
    await app_page.wait_for_selector("#btn-save-filter", state="visible")


async def test_saving_a_filter_puts_it_in_the_library_and_opens_it(app_page, api_client):
    await _capture_tab(app_page)
    await app_page.fill("#cap-bpf", "tcp port 8443")

    async def name_it(dialog):
        await dialog.accept("odd https")

    app_page.on("dialog", name_it)
    await app_page.click("#btn-save-filter")
    await app_page.wait_for_selector(".filter-group-own")

    # It really persisted, not just rendered.
    saved = api_client.get("/api/filters").json()
    assert [(f["label"], f["expression"]) for f in saved] == [("odd https", "tcp port 8443")]
    # And the list it landed in was opened, so the click visibly did something.
    assert await app_page.evaluate(
        "() => document.getElementById('filter-library-details').open"
    ) is True


async def test_a_duplicate_name_is_reported_rather_than_silently_dropped(app_page, api_client):
    api_client.post(
        "/api/filters", json={"label": "taken", "expression": "tcp port 80"}
    ).raise_for_status()
    await _capture_tab(app_page)
    await _reload_library(app_page)
    await app_page.fill("#cap-bpf", "tcp port 81")

    async def name_it(dialog):
        await dialog.accept("taken")

    app_page.on("dialog", name_it)
    await app_page.click("#btn-save-filter")
    await app_page.wait_for_selector("#save-filter-msg.save-filter-bad")
    assert len(api_client.get("/api/filters").json()) == 1


async def test_deleting_a_saved_filter_removes_it(app_page, api_client):
    api_client.post(
        "/api/filters", json={"label": "temporary", "expression": "arp"}
    ).raise_for_status()
    await _capture_tab(app_page)
    await _reload_library(app_page)
    await _open_library(app_page)
    await app_page.wait_for_selector(".filter-group-own")

    app_page.on("dialog", lambda d: d.accept())
    await app_page.click('[data-action="delete-custom-filter"]')
    await app_page.wait_for_function("() => customFilters.length === 0")
    assert api_client.get("/api/filters").json() == []


async def test_the_built_in_library_has_no_delete_button(app_page):
    """They are not the operator's to remove, and a delete that did nothing
    would be worse than none."""
    await _capture_tab(app_page)
    await _open_library(app_page)
    owned = await app_page.locator(
        '.filter-group:not(.filter-group-own) [data-action="delete-custom-filter"]'
    ).count()
    assert owned == 0
