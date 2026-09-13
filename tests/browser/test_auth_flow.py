"""The screens between opening the app and being inside it.

First run, TOTP enrolment, sign-in, sign-out -- and the two things about the
delivered page that only a browser can answer: whether the CSP lets the app's
own inline script run, and what the signed-out page tells an unauthenticated
visitor about the build it is running.
"""

from __future__ import annotations

from tests.browser.conftest import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    needs_browser,
    totp_now,
)

pytestmark = needs_browser


async def test_first_run_offers_registration_instead_of_a_login_box(fresh_page):
    """With no accounts there is nothing to sign in to, so the page says so."""
    await fresh_page.goto("/")
    await fresh_page.wait_for_selector("#register-form:not([hidden])")
    assert await fresh_page.is_hidden("#login-form")
    assert "first admin account" in await fresh_page.text_content("#auth-subtitle")


async def test_registering_enrols_totp_and_lands_in_the_app(fresh_page):
    """The whole first run, as a person does it.

    The TOTP secret is read off the enrolment screen rather than out of the
    database: if the screen ever stops showing a usable secret, an operator
    without a QR scanner cannot enrol at all, and this is the test that notices.
    """
    import pyotp

    await fresh_page.goto("/")
    await fresh_page.wait_for_selector("#register-form:not([hidden])")
    await fresh_page.fill("#reg-username", "first-admin")
    await fresh_page.fill("#reg-password", "a-sufficiently-long-passphrase")
    await fresh_page.click("#btn-register")

    await fresh_page.wait_for_selector("#totp-setup-screen:not([hidden])")
    secret = (await fresh_page.text_content("#totp-secret-text")).strip()
    assert secret, "the enrolment screen must show the secret, not only the QR code"
    assert (await fresh_page.get_attribute("#totp-qr", "src")).startswith("data:")

    await fresh_page.fill("#totp-confirm-code", pyotp.TOTP(secret).now())
    await fresh_page.click("#btn-confirm-totp")

    await fresh_page.wait_for_selector("#app-screen:not([hidden])")
    assert (await fresh_page.text_content("#user-display")).strip() == "first-admin"


async def test_enter_signs_in_from_the_password_and_totp_fields(page, live_server):
    """Enter submits the login screen, at both of its steps.

    Sign-in is two rounds -- password, then the code -- and Enter has to work in
    each. There is no <form> element anywhere on this page, so none of this is
    the browser's default behaviour; it exists only because app.js binds it.
    """
    await page.goto("/")
    await page.fill("#login-username", ADMIN_USERNAME)
    await page.fill("#login-password", ADMIN_PASSWORD)
    await page.press("#login-password", "Enter")

    await page.wait_for_selector("#totp-group:not([hidden])")
    await page.fill("#login-totp", totp_now(live_server.totp_secret))
    await page.press("#login-totp", "Enter")

    await page.wait_for_selector("#app-screen:not([hidden])")
    assert (await page.text_content("#user-display")).strip() == ADMIN_USERNAME


async def test_a_wrong_password_is_reported_on_the_login_screen(page):
    """The failure is shown where the user is looking, and nothing lets them in."""
    await page.goto("/")
    await page.fill("#login-username", ADMIN_USERNAME)
    await page.fill("#login-password", "not-the-password")
    await page.click("#btn-login")

    error = await page.wait_for_selector("#login-error:not(:empty)")
    assert "invalid credentials" in (await error.text_content()).lower()
    assert await page.is_hidden("#app-screen")


async def test_signing_out_returns_to_the_login_screen(app_page):
    await app_page.click("#btn-logout")
    await app_page.wait_for_selector("#login-form:not([hidden])")
    assert await app_page.is_hidden("#app-screen")


async def test_the_inline_theme_script_is_allowed_by_the_csp(page):
    """The one inline script on the page has to actually run.

    It is pinned in the CSP by content hash, so editing it without recomputing
    the hash makes Chromium drop it -- no failed request, no thrown error, the
    page renders fine and flashes the wrong theme on every load. Nothing on the
    HTTP side of this app can see that; only a browser enforcing the CSP can.
    """
    await page.goto("/")
    await page.evaluate("localStorage.setItem('theme', 'light')")
    await page.reload()
    await page.wait_for_selector("#auth-screen:not([hidden])")

    assert await page.evaluate("document.documentElement.dataset.theme") == "light", (
        "the inline theme script did not run -- most likely the CSP hash in "
        "backend/main.py no longer matches frontend/index.html. Run: "
        "pytest tests/test_main.py -k csp"
    )
    refusals = [e for e in page.console_errors if "Content Security Policy" in e]
    assert refusals == []


async def test_the_signed_out_page_does_not_publish_the_running_version(page):
    """Deliberate: the version is withheld until a visitor is signed in.

    Anyone who can reach the login page would otherwise be told which build to
    match advisories against. The backend withholds it, and this checks the
    page does not fill the gap back in from somewhere else.
    """
    await page.goto("/")
    await page.wait_for_selector("#auth-screen:not([hidden])")
    assert (await page.text_content("#auth-version")).strip() == ""
    assert await page.is_visible("#auth-release-link")
    assert (await page.get_attribute("#auth-release-link", "href")).endswith("/releases")


async def test_the_signed_in_version_link_matches_the_running_build(app_page):
    """What the UI claims to be running is what is actually running."""
    status = await (await app_page.request.get("/api/auth/status")).json()
    assert status["version"], "a signed-in status must carry the version"
    assert (await app_page.text_content("#version-link")).strip() == f"v{status['version']}"
    assert (await app_page.get_attribute("#version-link", "href")).endswith(f"/v{status['version']}")


async def test_the_app_shell_loads_without_console_errors(app_page):
    """A page that throws still renders, so nothing else would notice."""
    assert app_page.console_errors == []


async def test_the_page_declares_an_icon(page):
    """Otherwise every page load ends in a 404 nobody can fix from the console.

    A browser asks for /favicon.ico on its own unless the page names an icon,
    and this app serves nothing at that path. The request is the browser's, so
    it never appears as a failed fetch in the app's own code -- only as a
    console error on every load, of exactly the kind a real failure looks like.
    """
    await page.goto("/")
    icon = await page.get_attribute("link[rel='icon']", "href")
    assert icon, "the page must name an icon"

    response = await page.request.get(icon)
    assert response.status == 200
    assert "svg" in response.headers["content-type"]
    assert page.console_errors == []


async def test_enter_in_the_add_user_box_creates_the_user(app_page, api_client):
    """The Admin panel's Add user box is a form like any other."""
    await app_page.click("#admin-tab")
    await app_page.wait_for_selector("#panel-admin.active")
    await app_page.fill("#admin-new-username", "second-operator")
    await app_page.fill("#admin-new-password", "another-long-passphrase")
    await app_page.press("#admin-new-password", "Enter")

    try:
        await app_page.wait_for_selector("#admin-user-list >> text=second-operator")
    finally:
        for user in api_client.get("/api/admin/users").json():
            if user["username"] == "second-operator":
                api_client.delete(f"/api/admin/users/{user['id']}")
