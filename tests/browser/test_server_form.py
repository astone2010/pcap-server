"""The Servers tab: adding, editing and removing a server, by keyboard.

The keyboard half is the point. There is no <form> element anywhere in this
app, so the browser never submits anything on its own -- Enter works only where
app.js makes it work. It once made it work in five places, named by element id,
and the server form was in none of them: typing a hostname and pressing Enter
did nothing at all. No request, no error, no feedback. The API was working
perfectly the entire time, which is why every test then in the repo passed.
"""

from __future__ import annotations

import json

import pytest

from tests.browser.conftest import needs_browser

pytestmark = needs_browser

# TEST-NET-3 (RFC 5737): documentation addresses, guaranteed not to be routed
# anywhere. add_server refuses a target that resolves to this machine, so the
# hostname has to be something real-looking that is definitely not local.
HOST = "203.0.113.17"
OTHER_HOST = "203.0.113.23"
KEY_NAME = "browser-test-key"


@pytest.fixture(autouse=True)
def clean_slate(api_client):
    """One session's server serves every test, so each starts from empty.

    Stored usernames matter as much as servers here: the username field renders
    as a plain text box while none are stored and as a dropdown once one is, so
    a leftover name from an earlier test changes the form this one is driving.

    Host trust matters for the same reason and was NOT being reset, which is a
    gap this suite got away with only while no test pinned anything. The tests
    for the review dialog do pin keys, and an endpoint another test left
    trusted is one this one never gets asked about: the form goes straight
    through to a real connection instead of showing the review. That failure
    looks exactly like a broken button and is nothing of the sort, so the trust
    store is emptied here alongside everything else.
    """
    for server in api_client.get("/api/servers").json():
        api_client.delete(f"/api/servers/{server['id']}")
    for username in api_client.get("/api/usernames").json():
        api_client.delete(f"/api/usernames/{username['id']}")
    for host in api_client.get("/api/admin/host-trust").json():
        if host["key_types"]:
            api_client.post(
                "/api/admin/known-hosts/forget",
                json={"hostname": host["hostname"], "port": host["port"]},
            )
    yield


async def _open_usernames(page) -> None:
    """The stored-username list is collapsed until asked for.

    Eighty-odd expressions' worth of explanation sits beside it, and most
    visits to this tab are about a server rather than a name.
    """
    await page.click("details.usernames-panel > summary")
    await page.wait_for_selector("#new-ssh-username")


async def _fill_add_form(page, hostname: str, username: str = "capture-user") -> None:
    await page.click("#btn-add-server")
    await page.wait_for_selector("#new-srv-host")
    await page.fill("#new-srv-host", hostname)
    await page.fill("#new-srv-user", username)
    await page.select_option("#new-srv-key", KEY_NAME)


class accepting_dialogs:
    """Answer yes to whatever the add flow asks, for the length of a block.

    Adding a server scans the host for its keys first and shows the
    fingerprints before creating anything -- so that the probe, and therefore
    the check that this is not the machine pcap-server runs on, can happen
    before the row exists. Against TEST-NET-3 the scan cannot succeed, so the
    form offers to add the server unverified instead. That is the pre-staging
    path, and it is what these tests want: a server row, untrusted and
    unchecked, which is exactly the state every added server used to be in.

    Registered around the submit rather than for the whole test, because the
    Trust host tests install a dialog handler of their own afterwards and
    playwright lets only the first one answer.
    """

    def __init__(self, page):
        self.page = page
        self.messages: list[str] = []

    async def _accept(self, dialog):
        self.messages.append(dialog.message)
        await dialog.accept()

    async def __aenter__(self):
        self.page.on("dialog", self._accept)
        return self

    async def __aexit__(self, *exc):
        self.page.remove_listener("dialog", self._accept)
        return False


async def _add_via_form(page, hostname: str, username: str = "capture-user", *, submit=None):
    """Fill the add form, submit it, and wait for the row to appear."""
    await _fill_add_form(page, hostname, username)
    async with accepting_dialogs(page):
        if submit is None:
            await page.click("button[data-action='add-server']")
        else:
            await submit()
        await page.wait_for_selector(f"#server-list >> text={hostname}")


async def test_enter_in_the_server_form_adds_the_server(app_page):
    """The regression this suite exists for.

    Enter is pressed in the hostname field -- not the last field, not a field
    anyone wired up by name -- and the form's own primary button is what runs.
    """
    await _add_via_form(
        app_page, HOST, submit=lambda: app_page.press("#new-srv-host", "Enter")
    )

    assert f"capture-user@{HOST}:22" in await app_page.text_content("#server-list")


async def test_enter_in_the_last_field_of_the_server_form_adds_it_too(app_page):
    """Every field, not one lucky one: the old bug was a list of ids."""
    await _add_via_form(
        app_page, HOST, submit=lambda: app_page.press("#new-srv-user", "Enter")
    )


async def test_enter_reports_what_the_form_is_still_missing(app_page):
    """Submitting an incomplete form has to say so, not fail silently.

    Silence is exactly what the bug looked like from the outside, so a test
    that only checked "no server was added" would have passed against it.
    """
    await app_page.click("#btn-add-server")
    await app_page.wait_for_selector("#new-srv-host")
    await app_page.fill("#new-srv-user", "capture-user")
    await app_page.press("#new-srv-user", "Enter")

    error = await app_page.wait_for_selector("#add-server-error:not(:empty)")
    assert "hostname" in (await error.text_content()).lower()


async def test_the_add_button_and_enter_agree(app_page):
    """Enter goes through the button, so the two cannot drift apart."""
    await _add_via_form(app_page, HOST)


async def test_enter_in_the_edit_form_saves_the_change(app_page, api_client):
    """The edit form is a second form in the same area, with its own button."""
    await _add_via_form(app_page, HOST)
    await app_page.wait_for_selector("button[data-action='edit-server']")

    await app_page.click("button[data-action='edit-server']")
    await app_page.wait_for_selector("#edit-srv-host")
    await app_page.fill("#edit-srv-host", OTHER_HOST)
    await app_page.press("#edit-srv-host", "Enter")

    await app_page.wait_for_selector(f"#server-list >> text={OTHER_HOST}")
    assert [s["hostname"] for s in api_client.get("/api/servers").json()] == [OTHER_HOST]


async def test_adding_a_server_opens_it_rather_than_leaving_an_empty_form(app_page):
    """Testing the connection is the usual next step and lives on that page."""
    await _add_via_form(app_page, HOST)

    await app_page.wait_for_selector("button[data-action='test-server']")
    assert await app_page.is_visible("button[data-action='prereq-check']")
    assert await app_page.is_visible("button[data-action='remove-server']")


async def test_removing_a_server_takes_it_off_the_list(app_page):
    await _add_via_form(app_page, HOST)
    await app_page.wait_for_selector("button[data-action='remove-server']")

    app_page.on("dialog", lambda dialog: dialog.accept())
    await app_page.click("button[data-action='remove-server']")

    await app_page.wait_for_selector("#server-list >> text=No servers added")


async def test_a_username_added_on_this_tab_is_offered_by_the_server_form(app_page):
    """The stored-username list lives beside the form it feeds.

    It used to be on the Admin panel, which made adding a username there look
    like a required first step before a server could be added. It never was.
    """
    await _open_usernames(app_page)
    await app_page.fill("#new-ssh-username", "stored-user")
    await app_page.click("#btn-add-username")
    await app_page.wait_for_selector("#username-list >> text=stored-user")

    await app_page.click("#btn-add-server")
    await app_page.wait_for_selector("#new-srv-user-select")
    options = await app_page.eval_on_selector_all(
        "#new-srv-user-select option", "els => els.map(e => e.value)"
    )
    assert "stored-user" in options


async def test_a_username_introduced_by_a_new_server_shows_up_without_a_reload(app_page):
    """Adding a server is the other way a username gets stored."""
    await _add_via_form(app_page, HOST, username="from-the-form")
    await app_page.wait_for_selector("button[data-action='test-server']")

    await _open_usernames(app_page)
    await app_page.wait_for_selector("#username-list >> text=from-the-form")


async def test_the_servers_tab_reports_no_console_errors(app_page):
    """No server is added here on purpose.

    A server pointing at an unreachable host makes the app ask for its
    interfaces and get a 502 -- a real request that really fails, which the UI
    handles by leaving "any" in the dropdown. That failure belongs to the
    Capture suite, where it is asserted rather than filtered out; this test
    would only be able to ignore it.
    """
    await _open_usernames(app_page)
    await app_page.click("#btn-add-server")
    await app_page.wait_for_selector("#new-srv-host")
    assert app_page.console_errors == []


async def test_enter_in_the_stored_username_box_saves_it(app_page):
    """The other form on this tab, and the other half of the same bug.

    One text box and one button beside it: the arrangement where pressing
    Enter is the obvious thing to do, and where doing nothing looks most like
    the app being broken.
    """
    await _open_usernames(app_page)
    await app_page.fill("#new-ssh-username", "typed-and-entered")
    await app_page.press("#new-ssh-username", "Enter")

    await app_page.wait_for_selector("#username-list >> text=typed-and-entered")
    assert await app_page.input_value("#new-ssh-username") == ""


# --- the Trust host button on a server ----------------------------------------


async def test_a_new_server_says_its_host_is_not_trusted(app_page):
    """A connection to an untrusted host is refused, so the list has to say so
    -- otherwise the first sign is a capture that will not start."""
    await _add_via_form(
        app_page, HOST, submit=lambda: app_page.press("#new-srv-host", "Enter")
    )

    await app_page.wait_for_selector("#server-list >> text=Host not trusted")


async def test_the_trust_host_button_is_wired_to_something(app_page):
    """The regression this test exists for.

    The handler was registered on delegate("admin-known-hosts", ...) while the
    button renders inside #server-list. delegate() bails on
    !container.contains(el), so every click was dropped on the floor: a button
    that looked right, sat in the right place, and did nothing. No request, no
    error, no feedback -- invisible to every API test in the repo, and to a
    browser test that only checked the button was present.

    Asserting on the dialog is deliberate: it is the first thing a click can
    produce that a test can see, so it pins the wiring itself.

    Since the fingerprint review landed, the click scans first and the dialog
    comes afterwards -- against this address, which is TEST-NET-3 and answers
    nothing, that dialog is ssh-keyscan's failure reported back. Which dialog
    it is does not matter here. That one arrives at all is the regression this
    test exists for, and it costs the ssh-keyscan timeout to find out.
    """
    await _add_via_form(
        app_page, HOST, submit=lambda: app_page.press("#new-srv-host", "Enter")
    )
    await app_page.wait_for_selector('#server-list [data-action="trust-server-host"]')

    asked: list[str] = []

    async def on_dialog(dialog):
        asked.append(dialog.message)
        await dialog.dismiss()

    app_page.on("dialog", on_dialog)
    await app_page.click('#server-list [data-action="trust-server-host"]')

    # Generous: the scan has to time out against an address that never answers
    # (ssh-keyscan -T 5) before the dialog can appear.
    for _ in range(200):
        if asked:
            break
        await app_page.wait_for_timeout(100)

    assert asked, "clicking Trust host did nothing -- the handler is not wired to #server-list"
    assert HOST in asked[0], "the prompt must name the host whose keys are about to be pinned"


async def test_declining_the_trust_prompt_leaves_the_host_untrusted(app_page):
    """Dismissing is a real answer: nothing is pinned and the warning stays.

    Whichever dialog this address produces -- the fingerprint review on a host
    that answers, the scan failure on one that does not -- dismissing it must
    leave the host exactly as untrusted as it was. The accepting half needs a
    host with real keys to review, so it is covered against the API in
    test_servers.py rather than here.
    """
    await _add_via_form(
        app_page, HOST, submit=lambda: app_page.press("#new-srv-host", "Enter")
    )
    await app_page.wait_for_selector('#server-list [data-action="trust-server-host"]')

    seen: list[str] = []

    async def decline(dialog):
        seen.append(dialog.message)
        await dialog.dismiss()

    app_page.on("dialog", decline)
    await app_page.click('#server-list [data-action="trust-server-host"]')

    for _ in range(200):
        if seen:
            break
        await app_page.wait_for_timeout(100)

    assert seen, "the click produced no dialog to decline"
    assert "Host not trusted" in await app_page.text_content("#server-list")


async def test_returning_to_the_servers_tab_refetches_the_list(app_page):
    """Host trust is changed on the Admin tab, and the server list displays it.

    The list was only ever fetched at boot and after a server was added,
    edited or removed -- so trusting a host in Admin and coming back here
    rendered a copy of the data taken before the trust existed, and the host
    still read as untrusted. The API was correct the whole time.
    """
    await _add_via_form(
        app_page, HOST, submit=lambda: app_page.press("#new-srv-host", "Enter")
    )

    refetches: list[str] = []

    def note(request):
        if request.method == "GET" and request.url.rstrip("/").endswith("/api/servers"):
            refetches.append(request.url)

    app_page.on("request", note)

    await app_page.click("#admin-tab")
    await app_page.click('.tab[data-tab="servers"]')

    for _ in range(30):
        if refetches:
            break
        await app_page.wait_for_timeout(100)

    assert refetches, "returning to the Servers tab did not refetch /api/servers"


async def test_a_refetch_keeps_the_open_server_highlighted(app_page):
    """Selection lived only as a class on an element the refetch replaces."""
    await _add_via_form(
        app_page, HOST, submit=lambda: app_page.press("#new-srv-host", "Enter")
    )
    await app_page.click(f"#server-list .server-item")
    await app_page.wait_for_selector("#server-list .server-item.active")

    await app_page.click("#admin-tab")
    await app_page.click('.tab[data-tab="servers"]')
    await app_page.wait_for_timeout(400)

    assert await app_page.query_selector("#server-list .server-item.active"), \
        "the open server lost its highlight when the list was refetched"


# --- the host key review dialog ---------------------------------------------
#
# The fingerprints used to be shown in a window.confirm(): the one decision in
# this app that needs a human to compare 43 base64 characters, rendered in a
# proportional font, uncopyable, blocking the page you would check them
# against. It is an in-page <dialog> now, with the comparison done by the
# machine when you paste what the host printed.
#
# Every test above drives the scan-FAILURE path, because TEST-NET-3 answers
# nothing -- so none of them reaches the review at all. The scan is stubbed
# here instead, which is the only way to see the dialog without a real host
# that answers on 22.

REVIEW_FP = "SHA256:4S1x+Tn5CQ2mV9wAqk3ZbYd7uEHrJ0LpNcXvFgWtQiM"
REVIEW_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIFn+HAuUUzmPJJ/9Fm6nWFEfyOfj/psANlzU7NQKcBtN"


async def _stub_scan(page, keys=None):
    """Answer /api/host-keys/scan without an SSH host, so the review appears."""
    if keys is None:
        keys = [{"key_type": "ssh-ed25519", "host_key": REVIEW_BLOB, "fingerprint": REVIEW_FP}]

    async def handler(route):
        await route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"ok": True, "keys": keys}),
        )

    await page.route("**/api/host-keys/scan", handler)


async def _open_review(page, hostname=HOST):
    """Fill the form, press Add, and wait for the review dialog to open."""
    await _fill_add_form(page, hostname)
    await page.click("button[data-action='add-server']")
    await page.wait_for_selector("#host-key-dialog[open]")


async def test_the_review_dialog_shows_the_fingerprints_it_scanned(app_page):
    """The fingerprint has to be on screen to be checked at all."""
    await _stub_scan(app_page)
    await _open_review(app_page)

    assert HOST in await app_page.text_content("#host-key-endpoint")
    rows = await app_page.text_content("#host-key-rows")
    assert REVIEW_FP in rows
    assert "ssh-ed25519" in rows


async def test_pasting_the_matching_fingerprint_confirms_it(app_page):
    """The whole reason this stopped being a confirm(): the comparison is the
    machine's job, not the reader's."""
    await _stub_scan(app_page)
    await _open_review(app_page)

    await app_page.fill("#host-key-expected", REVIEW_FP)
    await app_page.wait_for_selector("#host-key-compare-result.is-match")
    assert "matches" in await app_page.text_content("#host-key-compare-result")
    # The answer lands on the key itself, not only in a message beside it.
    assert await app_page.query_selector("#host-key-rows tr.host-key-match")


async def test_pasting_a_different_fingerprint_says_so(app_page):
    """The case that matters: a mismatch is what a MITM looks like from here."""
    await _stub_scan(app_page)
    await _open_review(app_page)

    await app_page.fill("#host-key-expected", "SHA256:WRONGWRONGWRONGWRONGWRONGWRONGWRONGWRONGwxy")
    await app_page.wait_for_selector("#host-key-compare-result.is-miss")
    assert "no match" in await app_page.text_content("#host-key-compare-result")
    assert not await app_page.query_selector("#host-key-rows tr.host-key-match")


async def test_the_comparison_ignores_the_sha256_prefix_and_spacing(app_page):
    """ssh-keygen prints 'SHA256:abc...'; some tools print the bare base64, and
    a copy out of a terminal often brings whitespace with it. Comparing on what
    it means rather than how it was copied is the difference between a check
    people run and one they give up on."""
    await _stub_scan(app_page)
    await _open_review(app_page)

    await app_page.fill("#host-key-expected", f"  {REVIEW_FP.removeprefix('SHA256:')}  ")
    await app_page.wait_for_selector("#host-key-compare-result.is-match")


async def test_cancelling_the_review_pins_nothing_and_adds_nothing(app_page, api_client):
    """Declining is a real answer. It was one in the confirm() too, and the
    no-orphan invariant depends on it staying one."""
    await _stub_scan(app_page)
    await _open_review(app_page)

    await app_page.click("#btn-host-key-reject")
    await app_page.wait_for_selector("#host-key-dialog[open]", state="detached", timeout=5000)

    await app_page.wait_for_selector("#add-server-error >> text=not accepted")
    assert api_client.get("/api/servers").json() == []
    assert [h for h in api_client.get("/api/admin/host-trust").json()
            if h["hostname"] == HOST and h["key_types"]] == []


async def test_dismissing_the_review_with_escape_counts_as_declining(app_page, api_client):
    """A dialog closed by Escape or the backdrop must settle the promise as a
    decline, not leave the flow waiting on an answer that never comes."""
    await _stub_scan(app_page)
    await _open_review(app_page)

    await app_page.keyboard.press("Escape")
    await app_page.wait_for_selector("#add-server-error >> text=not accepted", timeout=5000)
    assert api_client.get("/api/servers").json() == []


async def test_accepting_the_review_pins_the_keys_and_adds_the_server(app_page, api_client):
    """The other half, and the one the old suite could not reach: it needed a
    host with real keys to review. Stubbing the scan buys that."""
    await _stub_scan(app_page)
    await _open_review(app_page)

    # Adding succeeds but nothing can connect to TEST-NET-3 afterwards, so the
    # unreachable alert follows. It is a native confirm/alert, unlike the review.
    async with accepting_dialogs(app_page):
        await app_page.click("#btn-host-key-accept")
        await app_page.wait_for_selector(f"#server-list >> text={HOST}")

    trusted = [h for h in api_client.get("/api/admin/host-trust").json()
               if h["hostname"] == HOST]
    assert trusted and trusted[0]["key_types"] == ["ssh-ed25519"], \
        "accepting the review has to pin exactly the key that was reviewed"


async def test_test_connection_asks_for_host_keys_too(app_page):
    """The user-facing point of this release: every action button collects
    fingerprints, rather than one button collecting them and the other three
    failing with instructions to go and press it."""
    await _stub_scan(app_page)
    await _fill_add_form(app_page, HOST)

    await app_page.click("button[data-action='probe-test']")
    await app_page.wait_for_selector("#host-key-dialog[open]", timeout=15000)
    assert REVIEW_FP in await app_page.text_content("#host-key-rows")


async def test_check_prerequisites_asks_for_host_keys_too(app_page):
    """Same for the third button."""
    await _stub_scan(app_page)
    await _fill_add_form(app_page, HOST)

    await app_page.click("button[data-action='probe-prereq']")
    await app_page.wait_for_selector("#host-key-dialog[open]", timeout=15000)
    assert REVIEW_FP in await app_page.text_content("#host-key-rows")


async def test_the_separate_scan_button_is_gone(app_page):
    """It collected fingerprints and the other three buttons did not, which is
    what made the form read as a four-step ritual in no stated order. With all
    three collecting, it has nothing left to do."""
    await _fill_add_form(app_page, HOST)
    assert not await app_page.query_selector("[data-action='scan-accept-keys']")


async def test_changing_the_host_after_accepting_discards_the_keys(app_page):
    """acceptedKeysFor is keyed on the endpoint, so the keys were already
    dropped -- but the green '✓ accepted' line stayed on screen saying
    otherwise, and the next action re-scanned and re-asked, which reads as the
    accept having failed."""
    await _stub_scan(app_page)
    await _open_review(app_page)
    await app_page.click("#btn-host-key-accept")
    await app_page.wait_for_selector("#host-key-status >> text=accepted", timeout=15000)

    await app_page.fill("#new-srv-host", OTHER_HOST)
    await app_page.wait_for_selector("#host-key-status >> text=discarded")
