"""The Servers tab: adding, editing and removing a server, by keyboard.

The keyboard half is the point. There is no <form> element anywhere in this
app, so the browser never submits anything on its own -- Enter works only where
app.js makes it work. It once made it work in five places, named by element id,
and the server form was in none of them: typing a hostname and pressing Enter
did nothing at all. No request, no error, no feedback. The API was working
perfectly the entire time, which is why every test then in the repo passed.
"""

from __future__ import annotations

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
    """
    for server in api_client.get("/api/servers").json():
        api_client.delete(f"/api/servers/{server['id']}")
    for username in api_client.get("/api/usernames").json():
        api_client.delete(f"/api/usernames/{username['id']}")
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


async def test_enter_in_the_server_form_adds_the_server(app_page):
    """The regression this suite exists for.

    Enter is pressed in the hostname field -- not the last field, not a field
    anyone wired up by name -- and the form's own primary button is what runs.
    """
    await _fill_add_form(app_page, HOST)
    await app_page.press("#new-srv-host", "Enter")

    await app_page.wait_for_selector(f"#server-list >> text={HOST}")
    assert f"capture-user@{HOST}:22" in await app_page.text_content("#server-list")


async def test_enter_in_the_last_field_of_the_server_form_adds_it_too(app_page):
    """Every field, not one lucky one: the old bug was a list of ids."""
    await _fill_add_form(app_page, HOST)
    await app_page.press("#new-srv-user", "Enter")

    await app_page.wait_for_selector(f"#server-list >> text={HOST}")


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
    await _fill_add_form(app_page, HOST)
    await app_page.click("button[data-action='add-server']")

    await app_page.wait_for_selector(f"#server-list >> text={HOST}")


async def test_enter_in_the_edit_form_saves_the_change(app_page, api_client):
    """The edit form is a second form in the same area, with its own button."""
    await _fill_add_form(app_page, HOST)
    await app_page.click("button[data-action='add-server']")
    await app_page.wait_for_selector("button[data-action='edit-server']")

    await app_page.click("button[data-action='edit-server']")
    await app_page.wait_for_selector("#edit-srv-host")
    await app_page.fill("#edit-srv-host", OTHER_HOST)
    await app_page.press("#edit-srv-host", "Enter")

    await app_page.wait_for_selector(f"#server-list >> text={OTHER_HOST}")
    assert [s["hostname"] for s in api_client.get("/api/servers").json()] == [OTHER_HOST]


async def test_adding_a_server_opens_it_rather_than_leaving_an_empty_form(app_page):
    """Testing the connection is the usual next step and lives on that page."""
    await _fill_add_form(app_page, HOST)
    await app_page.click("button[data-action='add-server']")

    await app_page.wait_for_selector("button[data-action='test-server']")
    assert await app_page.is_visible("button[data-action='prereq-check']")
    assert await app_page.is_visible("button[data-action='remove-server']")


async def test_removing_a_server_takes_it_off_the_list(app_page):
    await _fill_add_form(app_page, HOST)
    await app_page.click("button[data-action='add-server']")
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
    await _fill_add_form(app_page, HOST, username="from-the-form")
    await app_page.click("button[data-action='add-server']")
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
