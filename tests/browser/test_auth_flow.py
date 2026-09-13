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


async def _admin(page, section):
    """Open Admin on one section. The last section is remembered per browser,
    so every test says which one it wants."""
    await page.click("#admin-tab")
    await page.wait_for_selector("#panel-admin.active")
    await page.click(f".admin-nav [data-admin-page='{section}']")
    await page.wait_for_selector(f"#admin-page-{section}:not([hidden])")


async def _start_tls_setup(page):
    await _admin(page, "https")
    await page.wait_for_selector("#btn-tls-setup")
    await page.click("#btn-tls-setup")
    await page.wait_for_selector("#tls-domain", state="visible")


async def test_enter_in_the_add_user_box_creates_the_user(app_page, api_client):
    """The Admin panel's Add user box is a form like any other."""
    await _admin(app_page, "users")
    await app_page.fill("#admin-new-username", "second-operator")
    await app_page.fill("#admin-new-password", "another-long-passphrase")
    await app_page.press("#admin-new-password", "Enter")

    try:
        await app_page.wait_for_selector("#admin-user-list >> text=second-operator")
    finally:
        for user in api_client.get("/api/admin/users").json():
            if user["username"] == "second-operator":
                api_client.delete(f"/api/admin/users/{user['id']}")


async def test_admin_shows_one_section_at_a_time(app_page):
    await _admin(app_page, "ssh-keys")
    visible = await app_page.eval_on_selector_all(
        ".admin-page", "els => els.filter(e => !e.hidden).map(e => e.id)")
    assert visible == ["admin-page-ssh-keys"]
    assert await app_page.get_attribute(".admin-nav [data-admin-page='ssh-keys']", "aria-current") == "page"


async def test_the_overview_cards_open_their_section(app_page):
    await _admin(app_page, "overview")
    await app_page.wait_for_selector("#admin-overview .admin-card[data-admin-page='https']")
    assert "No certificate" in await app_page.text_content("#admin-overview .admin-card[data-admin-page='https']")
    await app_page.click("#admin-overview .admin-card[data-admin-page='https']")
    await app_page.wait_for_selector("#admin-page-https:not([hidden])")
    # Something to act on there, so the side list marks it.
    assert await app_page.is_visible("#admin-nav-dot-https")


async def test_long_explanations_are_behind_learn_more(app_page):
    await _admin(app_page, "known-hosts")
    assert not await app_page.is_visible("#admin-page-known-hosts .learn-more p")
    await app_page.click("#admin-page-known-hosts .learn-more summary")
    assert await app_page.is_visible("#admin-page-known-hosts .learn-more p")


async def test_https_leads_with_status_and_keeps_setup_out_of_the_way(app_page):
    """Served on loopback, so the page counts as secure transport and the
    plain-HTTP credentials warning stays away; the CLI route is offered regardless."""
    await _admin(app_page, "https")
    await app_page.wait_for_selector("#admin-tls .enc-state")
    assert (await app_page.text_content("#admin-tls .enc-state")).strip() == "No certificate"
    assert await app_page.locator("#tls-domain").count() == 0, "the form should wait for Set up"
    await _start_tls_setup(app_page)
    assert await app_page.is_hidden("#tls-provider"), "step 2 is not shown yet"
    await app_page.fill("#tls-domain", "pcap.example.com")
    await app_page.fill("#tls-email", "you@example.com")
    await app_page.click("#btn-tls-next")
    await app_page.wait_for_selector("#tls-provider", state="visible")
    assert await app_page.input_value("#tls-provider") == "cloudflare"
    # One API token is the usual answer for Cloudflare; the alternatives are tucked away.
    assert await app_page.get_attribute("#tls-var-CF_DNS_API_TOKEN", "type") == "password"
    assert await app_page.is_visible("#tls-var-CF_DNS_API_TOKEN")
    assert not await app_page.is_visible("#tls-var-CF_API_KEY")
    await app_page.click("#btn-tls-next")
    await app_page.wait_for_selector("#tls-validation-delay", state="visible")
    assert await app_page.get_attribute("#tls-validation-delay", "placeholder") == "30"
    assert "python -m backend.tls issue" in await app_page.text_content("#tls-cli")
    assert await app_page.locator("#admin-tls .enc-notice-bad").count() == 0


async def test_going_back_a_step_keeps_what_was_typed(app_page):
    await _start_tls_setup(app_page)
    await app_page.fill("#tls-domain", "pcap.example.com")
    await app_page.fill("#tls-email", "you@example.com")
    await app_page.click("#btn-tls-next")
    await app_page.fill("#tls-var-CF_DNS_API_TOKEN", "typed-token-value")
    await app_page.click("#btn-tls-back")
    await app_page.wait_for_selector("#tls-domain", state="visible")
    assert await app_page.input_value("#tls-domain") == "pcap.example.com"
    await app_page.click("#btn-tls-next")
    assert await app_page.input_value("#tls-var-CF_DNS_API_TOKEN") == "typed-token-value"


async def test_step_one_needs_a_domain_and_email(app_page):
    await _start_tls_setup(app_page)
    await app_page.click("#btn-tls-next")
    await app_page.wait_for_function(
        "() => (document.querySelector('#tls-msg')?.textContent || '').includes('domain')")
    assert await app_page.is_visible("#tls-domain")


async def test_choosing_a_provider_shows_that_providers_settings(app_page):
    await _start_tls_setup(app_page)
    await app_page.fill("#tls-domain", "pcap.example.com")
    await app_page.fill("#tls-email", "you@example.com")
    await app_page.click("#btn-tls-next")
    await app_page.select_option("#tls-provider", "route53")
    await app_page.wait_for_selector("#tls-var-AWS_SECRET_ACCESS_KEY")
    assert await app_page.locator("#tls-var-CF_DNS_API_TOKEN").count() == 0
    assert "--provider route53" in await app_page.text_content("#tls-cli")
    # A setting lego reads as a path is a box for the file's contents instead.
    await app_page.select_option("#tls-provider", "transip")
    await app_page.wait_for_selector("textarea#tls-var-TRANSIP_PRIVATE_KEY_PATH")


async def test_a_refused_certificate_request_is_shown_where_it_was_made(app_page):
    await _start_tls_setup(app_page)
    await app_page.fill("#tls-domain", "--config-dir=/app/data")
    await app_page.fill("#tls-email", "you@example.com")
    await app_page.click("#btn-tls-next")
    await app_page.fill("#tls-var-CF_DNS_API_TOKEN", "cf_TestToken_0123456789abcdefghijklmnop")
    await app_page.click("#btn-tls-next")
    await app_page.click("#btn-tls-request")
    await app_page.wait_for_function(
        "() => (document.querySelector('#tls-msg')?.textContent || '').includes('fully qualified')"
    )
    assert "cf_TestToken" not in await app_page.text_content("#admin-tls")
    # Still in the wizard with the value intact, ready to fix.
    assert await app_page.input_value("#tls-var-CF_DNS_API_TOKEN") == "cf_TestToken_0123456789abcdefghijklmnop"
