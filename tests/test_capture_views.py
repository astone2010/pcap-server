"""Saved filtered views: a named display filter kept against one capture.

Three things decide whether this feature is trustworthy rather than merely
present, and each has tests here:

  * **Ownership.** A view is scoped to the user who saved it AND to the
    capture it was saved on. Neither half is redundant -- checking only the
    owner would let one capture's URL serve another capture's filter.
  * **The filter is validated on the way in.** A view is stored once and
    replayed on every later visit, so a filter that would be refused as a
    query parameter must not become storable by arriving through a different
    box.
  * **They actually persist.** The whole point is coming back to the capture
    and finding the tabs still there.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.auth import create_session_token
from backend.database import MAX_VIEWS_PER_CAPTURE
from backend.models import CaptureInfo, CaptureStatus


@pytest.fixture()
def secure_client():
    with TestClient(main.app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def enrolled(secure_client):
    user_id = str(uuid.uuid4())
    main.db.create_user(user_id, f"views-{user_id[:8]}", "scrypt$1$1$1$00$00", is_admin=True)
    main.db.set_totp_secret(user_id, "A" * 32)
    main.db.confirm_totp(user_id)
    token, _ = create_session_token(main.db, user_id)
    secure_client.cookies.set("session", token)
    try:
        yield user_id
    finally:
        main.db.delete_user(user_id)


def _a_capture(user_id: str, tmp_path=None) -> str:
    """A COMPLETED capture owned by user_id, registered with the manager.

    Registered in both places on purpose: the routes read the manager's
    in-memory dict for ownership and the database for the views themselves,
    and a capture that exists in only one of them tests nothing real.
    """
    capture_id = str(uuid.uuid4())
    info = CaptureInfo(
        id=capture_id,
        server_id="some-server",
        user_id=user_id,
        status=CaptureStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        local_path="",
    )
    main.capture_manager._captures[capture_id] = info
    main.db.upsert_capture({
        **info.model_dump(),
        "status": info.status.value,
        "started_at": info.started_at.isoformat(),
        "stopped_at": None,
    })
    return capture_id


@pytest.fixture()
def capture(enrolled):
    capture_id = _a_capture(enrolled)
    try:
        yield capture_id
    finally:
        main.capture_manager._captures.pop(capture_id, None)
        main.db.delete_capture(capture_id)


# --- the round trip ----------------------------------------------------------


def test_a_capture_starts_with_no_saved_views(secure_client, capture):
    resp = secure_client.get(f"/api/captures/{capture}/views")
    assert resp.status_code == 200
    assert resp.json() == []


def test_a_saved_view_comes_back_on_the_next_visit(secure_client, capture):
    created = secure_client.post(
        f"/api/captures/{capture}/views",
        json={"name": "auth traffic", "display_filter": "kerberos || ldap"},
    )
    assert created.status_code == 200

    # The point of the feature: a fresh read of the same capture still has it.
    listed = secure_client.get(f"/api/captures/{capture}/views").json()
    assert [v["name"] for v in listed] == ["auth traffic"]
    assert listed[0]["display_filter"] == "kerberos || ldap"


def test_views_keep_the_order_they_were_saved_in(secure_client, capture):
    for name in ("first", "second", "third"):
        secure_client.post(
            f"/api/captures/{capture}/views",
            json={"name": name, "display_filter": f"tcp.port == {len(name)}"},
        )
    listed = secure_client.get(f"/api/captures/{capture}/views").json()
    assert [v["name"] for v in listed] == ["first", "second", "third"]
    assert [v["position"] for v in listed] == [0, 1, 2]


def test_a_view_can_be_renamed_and_its_filter_changed(secure_client, capture):
    view = secure_client.post(
        f"/api/captures/{capture}/views",
        json={"name": "old name", "display_filter": "tcp"},
    ).json()

    updated = secure_client.put(
        f"/api/captures/{capture}/views/{view['id']}",
        json={"name": "new name", "display_filter": "udp"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "new name"
    assert updated.json()["display_filter"] == "udp"
    assert updated.json()["id"] == view["id"]


def test_deleting_a_view_leaves_the_capture_alone(secure_client, capture):
    view = secure_client.post(
        f"/api/captures/{capture}/views",
        json={"name": "temporary", "display_filter": "arp"},
    ).json()

    assert secure_client.delete(f"/api/captures/{capture}/views/{view['id']}").status_code == 200
    assert secure_client.get(f"/api/captures/{capture}/views").json() == []
    assert secure_client.get(f"/api/captures/{capture}").status_code == 200


def test_two_views_on_one_capture_cannot_share_a_name(secure_client, capture):
    body = {"name": "duplicate", "display_filter": "tcp"}
    assert secure_client.post(f"/api/captures/{capture}/views", json=body).status_code == 200
    clash = secure_client.post(f"/api/captures/{capture}/views", json=body)
    assert clash.status_code == 409
    assert "already exists" in clash.json()["detail"]


def test_the_same_name_is_fine_on_a_different_capture(secure_client, enrolled, capture):
    other = _a_capture(enrolled)
    try:
        body = {"name": "shared name", "display_filter": "tcp"}
        assert secure_client.post(f"/api/captures/{capture}/views", json=body).status_code == 200
        assert secure_client.post(f"/api/captures/{other}/views", json=body).status_code == 200
    finally:
        main.capture_manager._captures.pop(other, None)
        main.db.delete_capture(other)


# --- ownership ---------------------------------------------------------------


def test_views_on_someone_elses_capture_are_a_404(secure_client, enrolled):
    stranger = str(uuid.uuid4())
    main.db.create_user(stranger, f"other-{stranger[:8]}", "scrypt$1$1$1$00$00")
    other_capture = _a_capture(stranger)
    try:
        resp = secure_client.get(f"/api/captures/{other_capture}/views")
        assert resp.status_code == 404
    finally:
        main.capture_manager._captures.pop(other_capture, None)
        main.db.delete_capture(other_capture)
        main.db.delete_user(stranger)


def test_a_view_id_from_another_capture_is_a_404(secure_client, enrolled, capture):
    """Both halves of the check matter. The view belongs to this user, so an
    owner-only check would serve it -- but it was saved on a different capture,
    and the URL says otherwise."""
    other = _a_capture(enrolled)
    try:
        view = secure_client.post(
            f"/api/captures/{other}/views",
            json={"name": "elsewhere", "display_filter": "dns"},
        ).json()
        resp = secure_client.put(
            f"/api/captures/{capture}/views/{view['id']}",
            json={"name": "hijacked", "display_filter": "tcp"},
        )
        assert resp.status_code == 404
    finally:
        main.capture_manager._captures.pop(other, None)
        main.db.delete_capture(other)


def test_deleting_a_capture_takes_its_views_with_it(secure_client, enrolled):
    """By foreign key, not by anything remembering to -- so a route added later
    cannot leave orphans behind."""
    capture_id = _a_capture(enrolled)
    secure_client.post(
        f"/api/captures/{capture_id}/views",
        json={"name": "doomed", "display_filter": "icmp"},
    )
    assert main.db.list_capture_views(capture_id, enrolled)

    main.capture_manager._captures.pop(capture_id, None)
    main.db.delete_capture(capture_id)
    assert main.db.list_capture_views(capture_id, enrolled) == []


# --- the filter is validated on the way in -----------------------------------


@pytest.mark.parametrize("hostile", [
    "tcp.port == 80; rm -rf /",
    "tcp.port == $(whoami)",
    "tcp.port == `id`",
    "tcp.port == 80\\x00",
])
def test_a_filter_refused_as_a_query_parameter_cannot_be_saved(secure_client, capture, hostile):
    resp = secure_client.post(
        f"/api/captures/{capture}/views",
        json={"name": "hostile", "display_filter": hostile},
    )
    assert resp.status_code == 422


def test_an_overlong_filter_cannot_be_saved(secure_client, capture):
    resp = secure_client.post(
        f"/api/captures/{capture}/views",
        json={"name": "long", "display_filter": "a" * 2000},
    )
    assert resp.status_code == 422


def test_a_view_needs_a_name(secure_client, capture):
    resp = secure_client.post(
        f"/api/captures/{capture}/views",
        json={"name": "   ", "display_filter": "tcp"},
    )
    assert resp.status_code == 422


def test_a_view_name_is_stripped_of_control_characters(secure_client, capture):
    view = secure_client.post(
        f"/api/captures/{capture}/views",
        json={"name": "kerb\x00er\x07os", "display_filter": "kerberos"},
    ).json()
    assert view["name"] == "kerberos"


# --- filtered download -------------------------------------------------------


def test_downloading_a_view_with_no_filter_is_refused(secure_client, enrolled, tmp_path):
    """An empty filter is the whole capture, which already has its own
    download. Two routes producing the same bytes is a way for them to
    disagree later."""
    capture_id = _a_capture(enrolled)
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    main.capture_manager._captures[capture_id].local_path = str(pcap)
    try:
        view = secure_client.post(
            f"/api/captures/{capture_id}/views",
            json={"name": "everything", "display_filter": ""},
        ).json()
        resp = secure_client.get(f"/api/captures/{capture_id}/views/{view['id']}/download")
        assert resp.status_code == 400
        assert "no filter" in resp.json()["detail"]
    finally:
        main.capture_manager._captures.pop(capture_id, None)
        main.db.delete_capture(capture_id)


def test_a_filtered_download_is_refused_over_plain_http(capture, enrolled):
    """Same reason the full download is: a filtered capture is not a less
    sensitive one."""
    with TestClient(main.app) as http_client:
        token, _ = create_session_token(main.db, enrolled)
        http_client.cookies.set("session", token)
        resp = http_client.get(f"/api/captures/{capture}/views/any-id/download")
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "https_required"


def test_view_download_filename_is_built_from_the_name(secure_client):
    assert main._view_download_name("abc", "auth traffic") == "abc-auth-traffic.pcap"


def test_view_download_filename_cannot_break_the_header(secure_client):
    """A view name is free text and a Content-Disposition filename is not. A
    quote would end the filename early and a newline would split the header."""
    name = main._view_download_name("abc", 'evil"\r\nX-Injected: yes')
    assert '"' not in name
    assert "\r" not in name and "\n" not in name


def test_view_download_filename_survives_a_name_with_nothing_usable_in_it(secure_client):
    assert main._view_download_name("abc", "///") == "abc-view.pcap"


# --- the ceiling -------------------------------------------------------------


def test_there_is_a_cap_on_views_per_capture(secure_client, enrolled, capture):
    """Moved with the saved-filter cap, and for the same reason: it is a row an
    authenticated caller can create in a loop, and capping one unbounded
    per-user table while leaving the one beside it is the real inconsistency."""
    for i in range(MAX_VIEWS_PER_CAPTURE):
        main.db.add_capture_view(capture, enrolled, f"v{i}", "")

    over = secure_client.post(
        f"/api/captures/{capture}/views", json={"name": "one too many", "display_filter": ""}
    )
    assert over.status_code == 409
    assert "limit" in over.text
    assert len(main.db.list_capture_views(capture, enrolled)) == MAX_VIEWS_PER_CAPTURE


def test_deleting_a_view_makes_room_again(secure_client, enrolled, capture):
    for i in range(MAX_VIEWS_PER_CAPTURE):
        main.db.add_capture_view(capture, enrolled, f"v{i}", "")
    first = main.db.list_capture_views(capture, enrolled)[0]

    assert secure_client.delete(
        f"/api/captures/{capture}/views/{first['id']}"
    ).status_code == 200
    assert secure_client.post(
        f"/api/captures/{capture}/views", json={"name": "room now", "display_filter": ""}
    ).status_code == 200
