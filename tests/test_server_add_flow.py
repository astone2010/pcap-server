"""Tests for adding a server key-first, and for trust not outliving its subject.

Two changes that are really one knot.

Before this, the strong self-target check was unreachable at add time *by
construction*: it needs a connection, a connection needs trusted host keys, and
trusting was only offered once a server row existed to trust it for. So a
server pointing at the machine pcap-server itself runs on was always created,
and only refused later, when a capture was started from it. The add form even
offered Test connection and Check prerequisites buttons that could not succeed
for any host not already trusted.

Reversing the order -- scan, show fingerprints, accept, probe, then create --
puts the boot-id check before the row exists. That in turn would manufacture
orphaned trust, since keys get pinned for servers that are then never created,
which is the same defect from the other end: deleting a server already left its
host keys behind, so re-adding that host silently inherited a pinning nobody
had re-verified.

So both halves are asserted here together: keys are kept if and only if a row
references them, on the way in and on the way out.

conftest.py sets DATA_DIR/CAPTURES_DIR/SSH_KEYS_DIR and a master key before
anything importing backend.main is collected.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.auth import create_session_token

# A real ed25519 public key blob, so host_key_fingerprint parses it for real
# rather than being stubbed out -- the pin path refuses anything it cannot
# fingerprint, and that refusal is part of what is under test.
ED25519_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIFn+HAuUUzmPJJ/9Fm6nWFEfyOfj/psANlzU7NQKcBtN"
OTHER_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIMOa2cKYkYlIxaBTr5Y0R5nBMWUCXJGsKkPGmYsWr8FS"

HOST = "203.0.113.77"
OTHER_HOST = "203.0.113.78"


@pytest.fixture()
def api_client():
    with TestClient(main.app, base_url="https://testserver") as c:
        yield c


def _make_user(is_admin: bool = False) -> str:
    user_id = str(uuid.uuid4())
    main.db.create_user(user_id, f"add-{user_id[:8]}", "scrypt$1$1$1$00$00", is_admin=is_admin)
    main.db.set_totp_secret(user_id, "A" * 32)
    main.db.confirm_totp(user_id)
    return user_id


@pytest.fixture()
def signed_in(api_client):
    user_id = _make_user()
    token, _ = create_session_token(main.db, user_id)
    api_client.cookies.set("session", token)
    try:
        yield user_id
    finally:
        main.db.delete_user(user_id)


@pytest.fixture(autouse=True)
def clean_hosts():
    """These tests assert on what is stored, so nothing may leak between them."""
    for host in (HOST, OTHER_HOST):
        main.db.forget_known_host(host, 22)
    yield
    for host in (HOST, OTHER_HOST):
        main.db.forget_known_host(host, 22)


@pytest.fixture()
def a_key(monkeypatch, tmp_path):
    """_require_key checks the keys directory, which is not what is under test."""
    monkeypatch.setattr(main, "_require_key", lambda name: None)


@pytest.fixture()
def untrusted_refusal(monkeypatch):
    """What _connect really raises for a host with no stored keys.

    Reproduced verbatim rather than letting the real one run, because the real
    one would trip over the missing key file first and report that instead --
    which is not the path these tests are about. This is the refusal the
    pre-staging case actually lands in: no trust, so nothing can connect, so
    nothing can be verified.
    """
    async def test_connection(auth):
        raise ConnectionError(
            f"{auth.hostname}:{auth.port} has no trusted host keys, so its "
            "identity cannot be checked."
        )

    monkeypatch.setattr(main.ssh_manager, "test_connection", test_connection)


@pytest.fixture()
def reachable(monkeypatch):
    """A host that answers, with a boot id that is not this machine's."""
    async def test_connection(auth):
        return {"boot_id": "11111111-2222-3333-4444-555555555555"}

    monkeypatch.setattr(main.ssh_manager, "test_connection", test_connection)


def _add_body(hostname: str = HOST, **extra):
    body = {
        "hostname": hostname, "port": 22, "username": "alice",
        "ssh_key_name": "alice-key", "name": "target",
    }
    body.update(extra)
    return body


def _accepted_keys(blob: str = ED25519_BLOB):
    return [{"key_type": "ssh-ed25519", "host_key": blob}]


# --- the ordering fix: fingerprints before the row ---------------------------


def test_adding_an_untrusted_host_without_keys_is_refused_and_creates_nothing(
    api_client, signed_in, a_key
):
    """The add form has to ask for the fingerprints, so the API has to say so.

    Refused with a code rather than prose, because the form branches on it to
    decide whether to scan -- the server is the authority on whether this
    endpoint is already trusted.
    """
    resp = api_client.post("/api/servers", json=_add_body())

    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "host_keys_required"
    assert main.db.get_known_hosts(HOST, 22) == []
    assert [s for s in main.db.list_active_servers(signed_in) if s["hostname"] == HOST] == []


def test_accepted_keys_are_pinned_and_the_probe_runs_before_the_row_exists(
    api_client, signed_in, a_key, monkeypatch
):
    """The whole point: the kernel check gets a connection at add time.

    Asserted by proving the probe saw the row does not exist yet -- it runs
    against the details from the form, and at the moment it runs there is
    nothing in active_servers for this host.
    """
    probed = {}

    async def test_connection(auth):
        probed["hostname"] = auth.hostname
        probed["rows_at_probe_time"] = [
            s for s in main.db.list_active_servers(signed_in) if s["hostname"] == HOST
        ]
        # Keys must already be pinned by now, or the connection could not have
        # been made: that is the ordering this whole flow exists to fix.
        probed["keys_at_probe_time"] = main.db.get_known_hosts(HOST, 22)
        return {"boot_id": "not-this-machine"}

    monkeypatch.setattr(main.ssh_manager, "test_connection", test_connection)

    resp = api_client.post(
        "/api/servers", json=_add_body(host_keys=_accepted_keys())
    )

    assert resp.status_code == 200
    assert probed["hostname"] == HOST
    assert probed["rows_at_probe_time"] == []
    assert [k["key_type"] for k in probed["keys_at_probe_time"]] == ["ssh-ed25519"]
    assert resp.json()["kernel_verified_at"]


def test_a_self_target_is_refused_before_any_row_is_created(
    api_client, signed_in, a_key, monkeypatch
):
    """The user's actual report: "we should really stop them at the server add".

    The address checks cannot see a Docker host's own LAN address -- that is
    the documented limit of that layer. The boot-id check can, and now it runs
    early enough to matter.
    """
    async def test_connection(auth):
        return {"boot_id": "same-as-ours"}

    monkeypatch.setattr(main.ssh_manager, "test_connection", test_connection)
    monkeypatch.setattr(
        main, "describe_if_same_kernel",
        lambda boot_id: "it reports this machine's own kernel boot id",
    )

    resp = api_client.post("/api/servers", json=_add_body(host_keys=_accepted_keys()))

    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "self_capture"
    assert [s for s in main.db.list_active_servers(signed_in) if s["hostname"] == HOST] == []


def test_refusing_a_self_target_rolls_back_the_keys_it_just_pinned(
    api_client, signed_in, a_key, monkeypatch
):
    """The trap the new ordering sets for itself.

    Accepting keys before the row exists means trust gets stored for a server
    that may never be created. Refusing a self-capture target and leaving its
    host keys trusted forever would be a poor trade -- so the invariant is that
    keys survive only if a row references them.
    """
    async def test_connection(auth):
        return {"boot_id": "same-as-ours"}

    monkeypatch.setattr(main.ssh_manager, "test_connection", test_connection)
    monkeypatch.setattr(main, "describe_if_same_kernel", lambda boot_id: "this machine")

    api_client.post("/api/servers", json=_add_body(host_keys=_accepted_keys()))

    assert main.db.get_known_hosts(HOST, 22) == [], "trust outlived a refused add"


def test_an_unreachable_host_is_still_added_but_unverified_and_keeps_its_keys(
    api_client, signed_in, a_key, monkeypatch
):
    """Pre-staging a server for a machine that is not up yet is a capability the
    old flow had, and closing this hole must not take it away.

    The keys stay because the row does: the invariant is "keys iff a row",
    not "keys iff a successful probe".
    """
    async def test_connection(auth):
        raise ConnectionError("Connection refused")

    monkeypatch.setattr(main.ssh_manager, "test_connection", test_connection)

    resp = api_client.post("/api/servers", json=_add_body(host_keys=_accepted_keys()))

    assert resp.status_code == 200
    body = resp.json()
    assert body["kernel_verified_at"] == ""
    assert "Connection refused" in body["unreachable"]
    assert [k["key_type"] for k in main.db.get_known_hosts(HOST, 22)] == ["ssh-ed25519"]


def test_an_already_trusted_endpoint_needs_no_keys_and_keeps_the_ones_it_has(
    api_client, signed_in, a_key, reachable
):
    """A second server pointing at a host an admin already vetted must not be
    able to replace that decision on its way in."""
    main.db.add_known_host(HOST, 22, "ssh-ed25519", ED25519_BLOB, None)

    resp = api_client.post(
        "/api/servers", json=_add_body(host_keys=_accepted_keys(OTHER_BLOB))
    )

    assert resp.status_code == 200
    stored = main.db.get_known_hosts(HOST, 22)
    assert [s["host_key"] for s in stored] == [ED25519_BLOB], "the admin's key was replaced"


@pytest.mark.parametrize(
    "blob, status",
    [
        # Refused at the model boundary: not base64, and whitespace in a blob
        # could add a field to the known_hosts line it is written into.
        ("not-a-key", 422),
        # Well-formed base64 that is not a key. Gets past the model and is
        # caught by the fingerprint check, which is the backstop that matters:
        # a blob that cannot be fingerprinted cannot have been reviewed,
        # whatever the UI displayed.
        ("QUFBQQ==", 400),
    ],
)
def test_a_key_that_cannot_be_fingerprinted_is_refused_rather_than_stored(
    api_client, signed_in, a_key, reachable, blob, status
):
    resp = api_client.post(
        "/api/servers",
        json=_add_body(host_keys=[{"key_type": "ssh-ed25519", "host_key": blob}]),
    )

    assert resp.status_code == status
    assert main.db.get_known_hosts(HOST, 22) == []
    assert [s for s in main.db.list_active_servers(signed_in) if s["hostname"] == HOST] == []


# --- pre-staging: a host that is not up yet ----------------------------------
#
# The hole a key-first add opens in itself. Keys come from ssh-keyscan, and a
# host that is down answers with none -- so requiring them would mean a server
# could no longer be configured before the machine it points at exists.


def test_a_host_that_cannot_be_scanned_can_still_be_added_on_purpose(
    api_client, signed_in, a_key, untrusted_refusal
):
    """Configuring a server before its host is running must survive this change."""
    resp = api_client.post("/api/servers", json=_add_body(add_unverified=True))

    assert resp.status_code == 200
    body = resp.json()
    assert body["kernel_verified_at"] == "", "nothing connected, so nothing is verified"
    assert body["unreachable"], "the row must say why it is unverified"
    assert main.db.get_known_hosts(HOST, 22) == [], "nothing was trusted"
    rows = [s for s in main.db.list_active_servers(signed_in) if s["hostname"] == HOST]
    assert len(rows) == 1


def test_a_pre_staged_server_is_reported_untrusted_and_unverified(
    api_client, signed_in, a_key, untrusted_refusal
):
    """Both flags, separately: identity is unpinned AND nothing has ever checked
    it. The list has to say so, or the first sign is a capture that will not
    start, reported from a screen that never mentioned either."""
    api_client.post("/api/servers", json=_add_body(add_unverified=True))

    row = next(r for r in api_client.get("/api/servers").json() if r["hostname"] == HOST)
    assert row["host_trusted"] is False
    assert row["verified"] is False


def test_a_pre_staged_server_cannot_capture_until_something_connects(
    api_client, signed_in, a_key, untrusted_refusal, monkeypatch
):
    """Pre-staging must not become a way around the check it skipped."""
    async def should_not_run(req, server, user_id):
        raise AssertionError("a capture started from an unverified server")

    monkeypatch.setattr(main.capture_manager, "start", should_not_run)
    server_id = api_client.post("/api/servers", json=_add_body(add_unverified=True)).json()["id"]

    resp = api_client.post(
        "/api/captures", json={"server_id": server_id, "interface": "eth0"}
    )

    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "server_unverified"


def test_adding_unverified_is_never_the_default(api_client, signed_in, a_key):
    """It has to be asked for. A caller that simply omits the keys is refused,
    so the form cannot drift into skipping the review by accident."""
    resp = api_client.post("/api/servers", json=_add_body())

    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "host_keys_required"


# --- the scan half, now reachable by any signed-in user ----------------------


def test_scanning_for_the_add_form_is_not_admin_only(api_client, signed_in, monkeypatch):
    """The deliberate authorisation change. Safe for the scan specifically,
    because scanning stores nothing -- calling it cannot change what this
    server trusts."""
    async def scan(hostname, port):
        return [{"key_type": "ssh-ed25519", "host_key": ED25519_BLOB, "fingerprint": "SHA256:x"}]

    monkeypatch.setattr(main.ssh_manager, "scan_host_keys", scan)
    assert main.db.get_user(signed_in)["is_admin"] == 0

    resp = api_client.post("/api/host-keys/scan", json={"hostname": HOST, "port": 22})

    assert resp.status_code == 200
    assert main.db.get_known_hosts(HOST, 22) == [], "a scan must store nothing"


def test_the_scan_route_is_rate_limited(api_client, signed_in, monkeypatch):
    """It spawns ssh-keyscan against an address the caller chose, and it is no
    longer admin-gated."""
    async def scan(hostname, port):
        return [{"key_type": "ssh-ed25519", "host_key": ED25519_BLOB, "fingerprint": "SHA256:x"}]

    monkeypatch.setattr(main.ssh_manager, "scan_host_keys", scan)
    monkeypatch.setattr(main.host_scan_rate_limiter, "allow", lambda key: False)

    resp = api_client.post("/api/host-keys/scan", json={"hostname": HOST, "port": 22})

    assert resp.status_code == 429


# --- trusting an existing server's host, as a non-admin ----------------------


def _server_row(user_id: str, hostname: str = HOST, port: int = 22, verified: bool = True) -> str:
    server_id = str(uuid.uuid4())
    main.db.add_active_server(
        server_id, user_id, "target", hostname, port, "alice", "k", False,
        kernel_verified_at=datetime.now(timezone.utc).isoformat() if verified else "",
    )
    return server_id


def test_a_non_admin_can_trust_the_host_of_a_server_they_own(api_client, signed_in):
    server_id = _server_row(signed_in)

    resp = api_client.post(
        f"/api/servers/{server_id}/trust-host",
        json={"hostname": HOST, "port": 22, "keys": _accepted_keys()},
    )

    assert resp.status_code == 200
    assert [k["host_key"] for k in main.db.get_known_hosts(HOST, 22)] == [ED25519_BLOB]


def test_trusting_refuses_keys_for_a_different_host_than_the_server(api_client, signed_in):
    """Otherwise the route is 'pin anything you like', with a server id as
    decoration."""
    server_id = _server_row(signed_in)

    resp = api_client.post(
        f"/api/servers/{server_id}/trust-host",
        json={"hostname": OTHER_HOST, "port": 22, "keys": _accepted_keys()},
    )

    assert resp.status_code == 400
    assert main.db.get_known_hosts(OTHER_HOST, 22) == []


def test_trusting_refuses_to_replace_keys_that_already_exist(api_client, signed_in):
    """The reason this widening is bounded.

    Without it, a non-admin could add a server pointing at an endpoint an admin
    trusts, re-pin keys of their own choosing, and stand in the middle of the
    admin's connections to it.
    """
    main.db.add_known_host(HOST, 22, "ssh-ed25519", ED25519_BLOB, None)
    server_id = _server_row(signed_in)

    resp = api_client.post(
        f"/api/servers/{server_id}/trust-host",
        json={"hostname": HOST, "port": 22, "keys": _accepted_keys(OTHER_BLOB)},
    )

    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "host_already_trusted"
    assert [k["host_key"] for k in main.db.get_known_hosts(HOST, 22)] == [ED25519_BLOB]


# --- deleting a server takes its trust with it -------------------------------


def test_deleting_the_last_server_for_a_host_forgets_its_keys(api_client, signed_in):
    """Trust outliving its subject, which is what let a re-added host inherit a
    pinning nobody re-verified."""
    server_id = _server_row(signed_in)
    main.db.add_known_host(HOST, 22, "ssh-ed25519", ED25519_BLOB, signed_in)

    resp = api_client.delete(f"/api/servers/{server_id}")

    assert resp.status_code == 200
    assert resp.json()["host_keys_forgotten"] == 1
    assert main.db.get_known_hosts(HOST, 22) == []


def test_a_sibling_pointing_at_the_same_endpoint_keeps_the_keys(api_client, signed_in):
    first = _server_row(signed_in)
    _server_row(signed_in)          # same endpoint, still needs the trust
    main.db.add_known_host(HOST, 22, "ssh-ed25519", ED25519_BLOB, signed_in)

    resp = api_client.delete(f"/api/servers/{first}")

    assert resp.json()["host_keys_forgotten"] == 0
    assert [k["host_key"] for k in main.db.get_known_hosts(HOST, 22)] == [ED25519_BLOB]


def test_another_users_server_counts_as_a_reference(api_client, signed_in):
    """The nuance that stops this being a one-liner.

    known_hosts is global -- UNIQUE(hostname, port, key_type), with no
    reference to any server row -- so a refcount scoped to the caller's own
    servers would revoke trust another user's server is still verifying
    against, and break their connections to prove a point about this one.
    """
    other_user = _make_user()
    try:
        mine = _server_row(signed_in)
        _server_row(other_user)
        main.db.add_known_host(HOST, 22, "ssh-ed25519", ED25519_BLOB, signed_in)

        resp = api_client.delete(f"/api/servers/{mine}")

        assert resp.json()["host_keys_forgotten"] == 0
        assert main.db.get_known_hosts(HOST, 22) != []
    finally:
        main.db.delete_user(other_user)


def test_a_different_port_on_the_same_hostname_is_a_different_endpoint(api_client, signed_in):
    """Trust is keyed on (hostname, port), so the refcount has to be too."""
    on_22 = _server_row(signed_in, port=22)
    _server_row(signed_in, port=2222)
    main.db.add_known_host(HOST, 22, "ssh-ed25519", ED25519_BLOB, signed_in)
    main.db.add_known_host(HOST, 2222, "ssh-ed25519", OTHER_BLOB, signed_in)
    try:
        api_client.delete(f"/api/servers/{on_22}")

        assert main.db.get_known_hosts(HOST, 22) == []
        assert [k["host_key"] for k in main.db.get_known_hosts(HOST, 2222)] == [OTHER_BLOB]
    finally:
        main.db.forget_known_host(HOST, 2222)


# --- failing closed on a server nothing has ever reached ---------------------


def test_a_capture_from_an_unverified_server_is_refused_with_the_remedy(
    api_client, signed_in, monkeypatch
):
    started = False

    async def should_not_run(req, server, user_id):
        nonlocal started
        started = True
        return {}

    monkeypatch.setattr(main.capture_manager, "start", should_not_run)
    server_id = _server_row(signed_in, verified=False)

    resp = api_client.post(
        "/api/captures", json={"server_id": server_id, "interface": "eth0"}
    )

    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "server_unverified"
    assert "Check prerequisites" in resp.json()["detail"]["explanation"]
    assert not started


def test_a_verified_server_still_captures(api_client, signed_in, monkeypatch):
    """The guard must not become a wall."""
    async def start(req, server, user_id):
        return {"id": "cap-1", "status": "running"}

    monkeypatch.setattr(main.capture_manager, "start", start)
    server_id = _server_row(signed_in, verified=True)

    resp = api_client.post(
        "/api/captures", json={"server_id": server_id, "interface": "eth0"}
    )

    assert resp.status_code == 200


def test_servers_older_than_the_column_are_grandfathered_rather_than_broken(
    api_client, signed_in, monkeypatch
):
    """Refusing every existing server on upgrade would be a regression dressed
    as a security improvement.

    Those rows read as unverified because nothing ever recorded a check for
    them, not because one failed -- and the capture's own connection already
    runs the boot-id check, so what they would gain is a better message and
    what they would cost is every server breaking at once.
    """
    async def start(req, server, user_id):
        return {"id": "cap-1", "status": "running"}

    monkeypatch.setattr(main.capture_manager, "start", start)
    server_id = _server_row(signed_in, verified=False)
    # As if the row had been added before this release.
    main.db._conn().execute(
        "UPDATE active_servers SET added_at = ? WHERE id = ?",
        ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(), server_id),
    )
    main.db._conn().commit()

    resp = api_client.post(
        "/api/captures", json={"server_id": server_id, "interface": "eth0"}
    )

    assert resp.status_code == 200


def test_a_self_target_outranks_an_unverified_row(api_client, signed_in, monkeypatch):
    """Both are 400s, but only the self-capture code raises the blocking alert,
    and a row that is both must be reported as the worse of the two."""
    monkeypatch.setattr(main.capture_manager, "start", None)
    server_id = _server_row(signed_in, verified=False)
    main.db.set_active_server_self_target(server_id, signed_in, "it is this machine")

    resp = api_client.post(
        "/api/captures", json={"server_id": server_id, "interface": "eth0"}
    )

    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "self_capture"


def test_repointing_a_server_at_a_new_host_drops_its_verification(api_client, signed_in, a_key):
    """A proof that the OLD host was not this machine says nothing about the new
    one -- and keeping it would let a server be repointed at this very machine
    and carry a verification it never earned."""
    server_id = _server_row(signed_in, verified=True)

    api_client.put(
        f"/api/servers/{server_id}",
        json=_add_body(hostname=OTHER_HOST),
    )

    row = main.db.get_active_server(server_id, signed_in)
    assert row["kernel_verified_at"] == ""
