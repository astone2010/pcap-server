"""Resetting an account's second factor, and the one account that cannot.

Before this, a lost authenticator meant deleting the user and making them
again -- which also discards their servers, their stored usernames, their saved
filters and every capture they own. A punishment for losing a phone.

There are two paths, and the split is the security design rather than an
accident of where the code went:

  * **An admin resets somebody else**, over the API. Ordinary case.
  * **An admin resets themselves** -- refused. Reaching any route means already
    being past the second factor, so it cannot help the admin who is actually
    locked out, and it *can* help someone holding a stolen session cookie:
    strip the MFA, enrol your own authenticator, and a session that expires in
    hours becomes a login that does not. The locked-out admin's way back in is
    `backend.resetmfa`, run against the container from the host -- the same bar
    as reading the database directly.

A reset that left a session or a trusted device alive would not be a reset, so
both are asserted here rather than assumed from the UPDATE.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from backend import main, resetmfa
from backend.auth import create_session_token


@pytest.fixture()
def secure_client():
    with TestClient(main.app, base_url="https://testserver") as c:
        yield c


def _user(*, is_admin: bool = False, confirmed: bool = True) -> str:
    user_id = str(uuid.uuid4())
    main.db.create_user(user_id, f"mfa-{user_id[:8]}", "scrypt$1$1$1$00$00", is_admin=is_admin)
    main.db.set_totp_secret(user_id, "A" * 32)
    if confirmed:
        main.db.confirm_totp(user_id)
    return user_id


@pytest.fixture()
def admin(secure_client):
    admin_id = _user(is_admin=True)
    token, _ = create_session_token(main.db, admin_id)
    secure_client.cookies.set("session", token)
    try:
        yield admin_id
    finally:
        main.db.delete_user(admin_id)


@pytest.fixture()
def victim():
    user_id = _user()
    try:
        yield user_id
    finally:
        main.db.delete_user(user_id)


# --- the ordinary case -------------------------------------------------------


def test_an_admin_can_reset_another_account(secure_client, admin, victim):
    resp = secure_client.post(f"/api/admin/users/{victim}/totp/reset")
    assert resp.status_code == 200, resp.text
    row = main.db.get_user(victim)
    assert row["totp_confirmed"] == 0


def test_the_old_secret_is_destroyed_not_merely_unconfirmed(secure_client, admin, victim):
    """Whoever still holds that authenticator could otherwise confirm the
    account straight back to where it was -- which is the opposite of a reset,
    since "the authenticator is gone or is no longer trusted" is the whole
    reason for doing one."""
    secure_client.post(f"/api/admin/users/{victim}/totp/reset")
    assert not main.db.get_user(victim)["totp_secret"]


def test_the_next_enrolment_issues_a_different_secret(secure_client, admin, victim):
    """The consequence of NULLing it: /api/auth/totp/setup reuses a stored
    secret if there is one and generates a fresh one if there is not."""
    secure_client.post(f"/api/admin/users/{victim}/totp/reset")

    token, _ = create_session_token(main.db, victim)
    with TestClient(main.app, base_url="https://testserver") as theirs:
        theirs.cookies.set("session", token)
        issued = theirs.get("/api/auth/totp/setup").json()["secret"]
    assert issued != "A" * 32


def test_the_reset_signs_them_out_everywhere(secure_client, admin, victim):
    """A live session already carries both factors. Leaving one alive would let
    the old authenticator's holder keep working for up to session_hours."""
    create_session_token(main.db, victim)
    create_session_token(main.db, victim)
    assert main.db.count_sessions_for_user(victim) == 2

    secure_client.post(f"/api/admin/users/{victim}/totp/reset")
    assert main.db.count_sessions_for_user(victim) == 0


def test_the_reset_forgets_their_trusted_devices(secure_client, admin, victim):
    """A trusted device is a second factor in its own right -- skipping TOTP is
    the entire point of one. Leaving them would exempt exactly the devices with
    the most access."""
    main.db.add_trusted_device(str(uuid.uuid4()), victim, "hash", "laptop", "2099-01-01T00:00:00")
    secure_client.post(f"/api/admin/users/{victim}/totp/reset")
    assert main.db.get_trusted_device_by_hash(victim, "hash") is None


def test_the_admins_own_session_is_untouched(secure_client, admin, victim):
    """Resetting someone else must not sign the admin out of the panel they are
    standing in."""
    secure_client.post(f"/api/admin/users/{victim}/totp/reset")
    assert secure_client.get("/api/admin/users").status_code == 200


def test_resetting_a_user_that_is_not_there_is_a_404(secure_client, admin):
    assert secure_client.post(
        f"/api/admin/users/{uuid.uuid4()}/totp/reset"
    ).status_code == 404


# --- who may call it ---------------------------------------------------------


def test_an_admin_cannot_reset_their_own(secure_client, admin):
    resp = secure_client.post(f"/api/admin/users/{admin}/totp/reset")
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "cannot_reset_own_totp"
    # And nothing happened: the refusal is not a partial reset.
    row = main.db.get_user(admin)
    assert row["totp_confirmed"] == 1
    assert row["totp_secret"] == "A" * 32


def test_a_self_reset_does_not_sign_the_admin_out(secure_client, admin):
    """The refusal must not be a denial of service on the caller either."""
    secure_client.post(f"/api/admin/users/{admin}/totp/reset")
    assert main.db.count_sessions_for_user(admin) == 1


def test_a_non_admin_cannot_reset_anybody(secure_client, victim):
    """Not even themselves, which is the same persistence path one rung down."""
    other = _user()
    plain = _user()
    token, _ = create_session_token(main.db, plain)
    try:
        with TestClient(main.app, base_url="https://testserver") as theirs:
            theirs.cookies.set("session", token)
            assert theirs.post(f"/api/admin/users/{other}/totp/reset").status_code == 403
            assert theirs.post(f"/api/admin/users/{plain}/totp/reset").status_code == 403
        assert main.db.get_user(other)["totp_confirmed"] == 1
    finally:
        main.db.delete_user(other)
        main.db.delete_user(plain)


def test_an_anonymous_caller_cannot_reset_anybody(victim):
    with TestClient(main.app, base_url="https://testserver") as anon:
        assert anon.post(f"/api/admin/users/{victim}/totp/reset").status_code == 401
    assert main.db.get_user(victim)["totp_confirmed"] == 1


def test_it_is_refused_over_plain_http(secure_client, admin, victim):
    """It changes state, so the read-only-over-HTTP middleware covers it. A
    reset crossing the wire in the clear is replayable."""
    token, _ = create_session_token(main.db, admin)
    with TestClient(main.app, base_url="http://testserver") as insecure:
        insecure.cookies.set("session", token)
        resp = insecure.post(f"/api/admin/users/{victim}/totp/reset")
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "https_required"
    assert main.db.get_user(victim)["totp_confirmed"] == 1


# --- the host-side escape hatch ----------------------------------------------
#
# The one case the API cannot cover: the only admin has lost their
# authenticator, so nobody can sign in to press the button.


def test_the_cli_dry_run_changes_nothing(capsys, victim):
    user = main.db.get_user(victim)
    assert resetmfa.main([user["username"]]) == 0
    assert main.db.get_user(victim)["totp_confirmed"] == 1
    assert "Dry run" in capsys.readouterr().out


def test_the_cli_resets_with_apply(victim):
    user = main.db.get_user(victim)
    create_session_token(main.db, victim)
    main.db.add_trusted_device(str(uuid.uuid4()), victim, "h", "laptop", "2099-01-01T00:00:00")

    assert resetmfa.main([user["username"], "--apply"]) == 0

    row = main.db.get_user(victim)
    assert row["totp_confirmed"] == 0
    assert not row["totp_secret"]
    assert main.db.count_sessions_for_user(victim) == 0
    assert main.db.get_trusted_device_by_hash(victim, "h") is None


def test_the_cli_will_reset_the_last_admin(victim):
    """Which is the entire reason it exists. The API refuses a self-reset and
    there is nobody else to ask."""
    only_admin = _user(is_admin=True)
    try:
        user = main.db.get_user(only_admin)
        assert resetmfa.main([user["username"], "--apply"]) == 0
        assert main.db.get_user(only_admin)["totp_confirmed"] == 0
    finally:
        main.db.delete_user(only_admin)


def test_an_unknown_username_is_an_error_not_a_silent_success(capsys):
    assert resetmfa.main(["definitely-not-a-user"]) == 2
    assert "no account called" in capsys.readouterr().err


def test_the_cli_lists_accounts_and_their_mfa_state(capsys, victim):
    user = main.db.get_user(victim)
    assert resetmfa.main(["--list"]) == 0
    out = capsys.readouterr().out
    assert user["username"] in out
    assert "MFA confirmed" in out


def test_the_cli_never_touches_a_password(victim):
    """It resets a second factor and nothing else. A forgotten password is a
    different problem, and not one to solve with a tool anyone who can reach
    the host may run."""
    before = main.db.get_user(victim)["password_hash"]
    user = main.db.get_user(victim)
    resetmfa.main([user["username"], "--apply"])
    assert main.db.get_user(victim)["password_hash"] == before
