"""The operator's own saved capture filters.

The built-in library is a constant in app.js and is the same for everyone.
These are the ones somebody saved, and three properties decide whether the
feature is trustworthy rather than merely present:

  * **They are private.** A capture filter routinely names the hosts and ports
    somebody is investigating -- `host 10.0.0.7 and tcp port 445` says what is
    being looked at and where. So they are scoped to their owner the way
    servers, usernames and capture views are, and every query says so in the
    statement rather than in a check beside it.
  * **The expression is validated on the way in.** A saved filter is replayed
    into a real capture later. An expression refused when typed into the
    Capture form must not become runnable by being typed into this box instead
    -- the same rule test_capture_views.py applies to display filters.
  * **A duplicate name is a 409, not a 500.** Two of your own filters called
    the same thing is a mistake worth naming.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend import main
from backend.auth import create_session_token
from backend.database import MAX_CUSTOM_FILTERS_PER_USER
from backend.models import FILTER_LABEL_MAX, CustomFilterRequest


@pytest.fixture()
def secure_client():
    with TestClient(main.app, base_url="https://testserver") as c:
        yield c


def _enrol(client: TestClient) -> str:
    user_id = str(uuid.uuid4())
    main.db.create_user(user_id, f"filters-{user_id[:8]}", "scrypt$1$1$1$00$00")
    main.db.set_totp_secret(user_id, "A" * 32)
    main.db.confirm_totp(user_id)
    token, _ = create_session_token(main.db, user_id)
    client.cookies.set("session", token)
    return user_id


@pytest.fixture()
def enrolled(secure_client):
    user_id = _enrol(secure_client)
    try:
        yield user_id
    finally:
        main.db.delete_user(user_id)


# --- the round trip ----------------------------------------------------------


def test_a_saved_filter_comes_back_in_the_list(secure_client, enrolled):
    created = secure_client.post(
        "/api/filters", json={"label": "AD auth", "expression": "port 88 or port 389"}
    )
    assert created.status_code == 200, created.text
    assert created.json()["label"] == "AD auth"

    listed = secure_client.get("/api/filters").json()
    assert [(f["label"], f["expression"]) for f in listed] == [
        ("AD auth", "port 88 or port 389")
    ]


def test_the_list_is_ordered_by_label_not_by_insertion(secure_client, enrolled):
    """A list of saved filters is read by eye. Insertion order means the one you
    want is wherever you happened to add it."""
    for label in ("zulu", "alpha", "Mike"):
        secure_client.post(
            "/api/filters", json={"label": label, "expression": "tcp port 80"}
        )
    labels = [f["label"] for f in secure_client.get("/api/filters").json()]
    assert labels == ["alpha", "Mike", "zulu"], "expected case-insensitive A-Z"


def test_deleting_one_removes_it(secure_client, enrolled):
    made = secure_client.post(
        "/api/filters", json={"label": "SMB", "expression": "tcp port 445"}
    ).json()
    assert secure_client.delete(f"/api/filters/{made['id']}").status_code == 200
    assert secure_client.get("/api/filters").json() == []


def test_deleting_one_that_is_not_there_is_a_404(secure_client, enrolled):
    assert secure_client.delete(f"/api/filters/{uuid.uuid4()}").status_code == 404


# --- privacy -----------------------------------------------------------------


def test_one_users_filters_are_invisible_to_another(secure_client, enrolled):
    secure_client.post(
        "/api/filters", json={"label": "mine", "expression": "host 10.0.0.1"}
    )
    other_id = _enrol(secure_client)
    try:
        assert secure_client.get("/api/filters").json() == []
    finally:
        main.db.delete_user(other_id)


def test_another_user_cannot_delete_yours_and_is_told_404(secure_client, enrolled):
    """404 rather than 403, for the same reason _require_own_capture gives it: a
    403 confirms the id exists, which is the one thing a caller guessing ids
    should not learn."""
    mine = secure_client.post(
        "/api/filters", json={"label": "mine", "expression": "host 10.0.0.1"}
    ).json()

    other_id = _enrol(secure_client)
    try:
        assert secure_client.delete(f"/api/filters/{mine['id']}").status_code == 404
    finally:
        main.db.delete_user(other_id)

    # And it is still there for its owner.
    _enrol(secure_client)  # a third session cannot see it either
    assert main.db.list_custom_filters(enrolled)[0]["label"] == "mine"


def test_they_need_a_session_at_all(enrolled):
    with TestClient(main.app, base_url="https://testserver") as anon:
        assert anon.get("/api/filters").status_code == 401
        assert anon.post(
            "/api/filters", json={"label": "x", "expression": "tcp"}
        ).status_code == 401


# --- names -------------------------------------------------------------------


def test_the_same_name_twice_is_a_409_not_a_500(secure_client, enrolled):
    body = {"label": "Kerberos", "expression": "port 88"}
    assert secure_client.post("/api/filters", json=body).status_code == 200
    clash = secure_client.post("/api/filters", json=body)
    assert clash.status_code == 409
    assert "already have" in clash.text


def test_two_users_may_use_the_same_name(secure_client, enrolled):
    """The UNIQUE is on (user_id, label). Someone else naming their filter
    "Kerberos" is not a reason you cannot."""
    secure_client.post("/api/filters", json={"label": "Kerberos", "expression": "port 88"})
    other_id = _enrol(secure_client)
    try:
        assert secure_client.post(
            "/api/filters", json={"label": "Kerberos", "expression": "port 88"}
        ).status_code == 200
    finally:
        main.db.delete_user(other_id)


@pytest.mark.parametrize("label", ["", "   ", "\t\n"])
def test_a_filter_needs_a_name(label):
    with pytest.raises(ValidationError):
        CustomFilterRequest(label=label, expression="tcp port 80")


def test_a_name_is_length_limited():
    with pytest.raises(ValidationError):
        CustomFilterRequest(label="x" * (FILTER_LABEL_MAX + 1), expression="tcp port 80")


def test_control_characters_are_stripped_from_a_name_rather_than_refused():
    """Same treatment CaptureViewRequest gives them: they cannot render
    anywhere useful, and a name pasted out of a terminal picks them up easily."""
    req = CustomFilterRequest(label="  Kerb\x00eros\x07  ", expression="port 88")
    assert req.label == "Kerberos"


# --- the expression ----------------------------------------------------------


@pytest.mark.parametrize("expr", ["", "   "])
def test_a_filter_needs_an_expression(expr):
    with pytest.raises(ValidationError):
        CustomFilterRequest(label="empty", expression=expr)


@pytest.mark.parametrize("expr", [
    "port 80; rm -rf /",
    "port 80 $(id)",
    "port 80 `id`",
    "port 80 \\",
])
def test_the_shell_metacharacters_are_refused_here_too(expr):
    """The point of the test: this is a SECOND door into the same argv. A
    filter saved here is replayed into a capture later, so it goes through the
    same character rule CaptureRequest applies."""
    with pytest.raises(ValidationError):
        CustomFilterRequest(label="sneaky", expression=expr)


def test_bpf_bitwise_operators_are_still_allowed():
    """`&` and `|` are BPF's own operators -- every tcpflags filter needs them.
    Banning them here would refuse the filters most worth saving."""
    req = CustomFilterRequest(
        label="SYN only", expression="tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"
    )
    assert "tcp-syn" in req.expression


def test_a_refused_expression_never_reaches_the_database(secure_client, enrolled):
    resp = secure_client.post(
        "/api/filters", json={"label": "sneaky", "expression": "port 80; id"}
    )
    assert resp.status_code == 422
    assert main.db.list_custom_filters(enrolled) == []


# --- the ceiling -------------------------------------------------------------


def test_there_is_a_cap_on_how_many_one_user_may_save(secure_client, enrolled):
    """A saved filter is a row an authenticated caller can create in a loop,
    and nothing else bounds it. The number is far above hand-curated use -- the
    built-in library is the big list, at eighty-odd -- so this is a stop on a
    script, not a ration."""
    for i in range(MAX_CUSTOM_FILTERS_PER_USER):
        main.db.add_custom_filter(enrolled, f"f{i}", "tcp port 80")

    over = secure_client.post(
        "/api/filters", json={"label": "one too many", "expression": "tcp port 80"}
    )
    assert over.status_code == 409
    assert "limit" in over.text
    assert len(main.db.list_custom_filters(enrolled)) == MAX_CUSTOM_FILTERS_PER_USER


def test_the_cap_is_per_user_not_global(secure_client, enrolled):
    """Somebody else filling their own list must not stop you saving one."""
    for i in range(MAX_CUSTOM_FILTERS_PER_USER):
        main.db.add_custom_filter(enrolled, f"f{i}", "tcp port 80")

    other_id = _enrol(secure_client)
    try:
        assert secure_client.post(
            "/api/filters", json={"label": "mine", "expression": "arp"}
        ).status_code == 200
    finally:
        main.db.delete_user(other_id)


def test_deleting_one_makes_room_again(secure_client, enrolled):
    """The cap is a ceiling on what is held, not a lifetime quota."""
    for i in range(MAX_CUSTOM_FILTERS_PER_USER):
        main.db.add_custom_filter(enrolled, f"f{i}", "tcp port 80")
    first = main.db.list_custom_filters(enrolled)[0]

    assert secure_client.delete(f"/api/filters/{first['id']}").status_code == 200
    assert secure_client.post(
        "/api/filters", json={"label": "room now", "expression": "arp"}
    ).status_code == 200
